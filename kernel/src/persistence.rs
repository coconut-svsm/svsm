// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2025-2026 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Functionality related to persistent SVSM storage.

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

use core::{
    fmt::Debug,
    future::Future,
    mem,
    ops::{self, Range, RangeInclusive},
    pin, task,
};

use cocoon_tpm_crypto::rng;
use cocoon_tpm_storage::{
    blkdev::{
        NvBlkDev, NvBlkDevFuture, NvBlkDevIoError, NvBlkDevReadRequest, NvBlkDevWriteRequest,
    },
    fs::{
        NvFs, NvFsError, NvFsFuture, NvFsIoError, NvFsUnlinkCursor, TransactionCommitError,
        cocoonfs::{self, CocoonFs},
    },
    nvblkdev_err_internal, nvfs_err_internal,
};
use cocoon_tpm_utils_async::sync_types;
use cocoon_tpm_utils_common::{
    alloc::{box_try_new, try_alloc_zeroizing_vec},
    fixed_vec::FixedVec,
    zeroize::Zeroizing,
};

use crate::r#async::{SvsmSyncTypes, task_busypoll_to_completion};
use crate::block::{BLOCK_DEVICE, BlockDeviceError, api::BlockDriver};
use crate::crypto::get_svsm_rng;
use crate::error::SvsmError;
use crate::fs::FsError;
use crate::mm::alloc::AllocError;
use crate::types::PAGE_SHIFT;
use crate::utils::immut_after_init::ImmutAfterInitCell;

/// Wrapper around [`BlockDriver`] implementors, itself implementing the `cocoon-tpm-storage`
/// crate's [`NvBlkDev`] block device abstraction.
struct SvsmNvBlkDev<D: 'static + ops::Deref<Target: BlockDriver> + Send + Sync + Unpin> {
    driver: D,
    io_block_size_128b_log2: u32,
}

impl<D: ops::Deref<Target: BlockDriver> + Send + Sync + Unpin> SvsmNvBlkDev<D> {
    fn new(driver: D) -> Self {
        // We got to store the block size in order to avoid TOCTOU issues, c.f. the
        // NvBlkDev::io_block_size_128b_log2() docs.
        let io_block_size_log2 = driver.block_size_log2() as u32;
        let io_block_size_128b_log2 = io_block_size_log2.saturating_sub(7);
        Self {
            driver,
            io_block_size_128b_log2,
        }
    }
}

impl<D: 'static + ops::Deref<Target: BlockDriver> + Send + Sync + Unpin> NvBlkDev
    for SvsmNvBlkDev<D>
{
    fn io_block_size_128b_log2(&self) -> u32 {
        self.io_block_size_128b_log2
    }

    fn io_blocks(&self) -> u64 {
        ((self.driver.size() as u64) >> self.io_block_size_128b_log2) >> 7
    }

    fn preferred_io_blocks_bulk_log2(&self) -> u32 {
        (PAGE_SHIFT as u32)
            .saturating_sub(self.io_block_size_128b_log2)
            .saturating_sub(7)
    }

    type ResizeFuture = SvsmNvBlkDevResizeFuture;

    fn resize(&self, _io_blocks_count: u64) -> Result<Self::ResizeFuture, NvBlkDevIoError> {
        Ok(SvsmNvBlkDevResizeFuture)
    }

    type ReadFuture<R: NvBlkDevReadRequest> = SvsmNvBlkDevReadFuture<R>;

    fn read<R: NvBlkDevReadRequest>(
        &self,
        request: R,
    ) -> Result<Result<Self::ReadFuture<R>, (R, NvBlkDevIoError)>, NvBlkDevIoError> {
        Ok(Ok(SvsmNvBlkDevReadFuture {
            request: Some(request),
            bounce_buffer: FixedVec::new_empty(),
        }))
    }

    type WriteFuture<R: NvBlkDevWriteRequest> = SvsmNvBlkDevWriteFuture<R>;

    fn write<R: NvBlkDevWriteRequest>(
        &self,
        request: R,
    ) -> Result<Result<Self::WriteFuture<R>, (R, NvBlkDevIoError)>, NvBlkDevIoError> {
        Ok(Ok(SvsmNvBlkDevWriteFuture {
            request: Some(request),
            bounce_buffer: FixedVec::new_empty(),
        }))
    }

    type FlushQueuedWritesFuture = SvsmNvBlkDevFlushQueuedWritesFuture;

    fn flush_queued_writes(&self) -> Result<Self::FlushQueuedWritesFuture, NvBlkDevIoError> {
        Ok(SvsmNvBlkDevFlushQueuedWritesFuture)
    }

    type WriteBarrierFuture = SvsmNvBlkDevWriteSyncFuture;

    fn write_barrier(&self) -> Result<Self::WriteBarrierFuture, NvBlkDevIoError> {
        Ok(SvsmNvBlkDevWriteSyncFuture)
    }

    type WriteSyncFuture = SvsmNvBlkDevWriteSyncFuture;

    fn write_sync(&self) -> Result<Self::WriteSyncFuture, NvBlkDevIoError> {
        Ok(SvsmNvBlkDevWriteSyncFuture)
    }

    type TrimFuture = SvsmNvBlkDevTrimFuture;

    fn trim(
        &self,
        io_block_index: u64,
        io_blocks_count: u64,
    ) -> Result<Self::TrimFuture, NvBlkDevIoError> {
        Ok(SvsmNvBlkDevTrimFuture {
            io_block_index,
            io_blocks_count,
            zeroes_buffer: FixedVec::new_empty(),
        })
    }
}

impl<D: 'static + ops::Deref<Target: BlockDriver> + Send + Sync + Unpin> Debug for SvsmNvBlkDev<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SvsmNvBlkDev").finish()
    }
}

/// Convert a [`SvsmError`] to a [`NvBlkDevIoError`].
fn svsm_error_to_nvblkdev_io_error(e: SvsmError) -> NvBlkDevIoError {
    match e {
        SvsmError::Block(BlockDeviceError::Failed) => NvBlkDevIoError::IoFailure,
        SvsmError::Alloc(AllocError::OutOfMemory) => NvBlkDevIoError::MemoryAllocationFailure,
        _ => NvBlkDevIoError::IoFailure,
    }
}

/// [`NvBlkDev::ResizeFuture`] implementation for [`SvsmNvBlkDev`].
#[derive(Debug)]
struct SvsmNvBlkDevResizeFuture;

impl<D: 'static + ops::Deref<Target: BlockDriver> + Send + Sync + Unpin>
    NvBlkDevFuture<SvsmNvBlkDev<D>> for SvsmNvBlkDevResizeFuture
{
    type Output = Result<(), NvBlkDevIoError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        _dev: &SvsmNvBlkDev<D>,
        _cx: &mut core::task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        task::Poll::Ready(Err(NvBlkDevIoError::OperationNotSupported))
    }
}

/// [`NvBlkDev::ReadFuture`] implementation for [`SvsmNvBlkDev`].
#[derive(Debug)]
struct SvsmNvBlkDevReadFuture<R: NvBlkDevReadRequest> {
    request: Option<R>,
    bounce_buffer: FixedVec<u8, 7>,
}

impl<D: 'static + ops::Deref<Target: BlockDriver> + Send + Sync + Unpin, R: NvBlkDevReadRequest>
    NvBlkDevFuture<SvsmNvBlkDev<D>> for SvsmNvBlkDevReadFuture<R>
{
    type Output = Result<(R, Result<(), NvBlkDevIoError>), NvBlkDevIoError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        dev: &SvsmNvBlkDev<D>,
        _cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let dev_io_block_size_128b_log2 = dev.io_block_size_128b_log2();
        let preferred_dev_io_blocks_bulk_log2 = dev.preferred_io_blocks_bulk_log2();
        let dev_io_blocks = dev.io_blocks();

        let this = pin::Pin::into_inner(self);
        let mut request = match this.request.take() {
            Some(request) => request,
            None => return task::Poll::Ready(Err(nvblkdev_err_internal!())),
        };

        let region = request.region().clone();
        if region.chunk_size_128b_log2() >= dev_io_block_size_128b_log2 {
            // The buffers are all larger than (by a fixed power of two multiple of) the device
            // block size. No bounce buffer needed.
            let block_size_128b_log2 = if region.is_aligned(region.chunk_size_128b_log2()) {
                region.chunk_size_128b_log2()
            } else if region.chunk_size_128b_log2()
                >= preferred_dev_io_blocks_bulk_log2 + dev_io_block_size_128b_log2
                && region
                    .is_aligned(preferred_dev_io_blocks_bulk_log2 + dev_io_block_size_128b_log2)
            {
                preferred_dev_io_blocks_bulk_log2 + dev_io_block_size_128b_log2
            } else {
                debug_assert!(region.is_aligned(dev_io_block_size_128b_log2));
                dev_io_block_size_128b_log2
            };
            let blocks_iter = match region.aligned_blocks_iter(block_size_128b_log2) {
                Ok(blocks_iter) => blocks_iter,
                Err(_) => return task::Poll::Ready(Ok((request, Err(nvblkdev_err_internal!())))),
            };
            for (physical_block_index, block_chunks) in blocks_iter {
                let block_begin_128b = physical_block_index << block_size_128b_log2;
                if block_begin_128b >= dev_io_blocks << dev_io_block_size_128b_log2
                    || ((dev_io_blocks << dev_io_block_size_128b_log2) - block_begin_128b)
                        >> block_size_128b_log2
                        == 0
                {
                    return task::Poll::Ready(Ok((
                        request,
                        Err(NvBlkDevIoError::IoBlockOutOfRange),
                    )));
                }

                for (offset_in_block_128b, chunk_range) in block_chunks {
                    // The buffer size is >= the iteration block size.
                    debug_assert_eq!(offset_in_block_128b, 0);
                    let buf = match request.get_destination_buffer(&chunk_range) {
                        Ok(buf) => buf,
                        Err(e) => return task::Poll::Ready(Ok((request, Err(e)))),
                    };
                    let buf = match buf {
                        Some(buf) => buf,
                        None => {
                            continue;
                        }
                    };

                    let dev_block_id =
                        (block_begin_128b + offset_in_block_128b) >> dev_io_block_size_128b_log2;
                    let dev_block_id = match usize::try_from(dev_block_id) {
                        Ok(dev_block_id) => dev_block_id,
                        Err(_) => {
                            // The dev_io_blocks has been derived from BlockDriver::size(), which is
                            // an usize.
                            return task::Poll::Ready(Ok((request, Err(nvblkdev_err_internal!()))));
                        }
                    };
                    if let Err(e) = dev.driver.read_blocks(dev_block_id, buf) {
                        log::error!(
                            "block device read failed: error={e:?}, position={}, size={}",
                            (block_begin_128b + offset_in_block_128b) << 7,
                            1u64 << (block_size_128b_log2 + 7)
                        );
                        return task::Poll::Ready(Ok((
                            request,
                            Err(svsm_error_to_nvblkdev_io_error(e)),
                        )));
                    }
                }
            }
        } else {
            // The buffers are smaller than the volume block size, going through the bounce buffer
            // is necessary.
            let block_size_128b_log2 = dev_io_block_size_128b_log2;

            if this.bounce_buffer.is_empty() {
                this.bounce_buffer =
                    match FixedVec::new_with_default(1usize << (block_size_128b_log2 + 7)) {
                        Ok(bounce_buffer) => bounce_buffer,
                        Err(_) => {
                            return task::Poll::Ready(Ok((
                                request,
                                Err(NvBlkDevIoError::MemoryAllocationFailure),
                            )));
                        }
                    };
            }

            let blocks_iter = match region.aligned_blocks_iter(block_size_128b_log2) {
                Ok(blocks_iter) => blocks_iter,
                Err(_) => return task::Poll::Ready(Ok((request, Err(nvblkdev_err_internal!())))),
            };
            for (physical_block_index, block_chunks) in blocks_iter {
                let block_begin_128b = physical_block_index << block_size_128b_log2;
                if block_begin_128b >= dev_io_blocks << dev_io_block_size_128b_log2
                    || ((dev_io_blocks << dev_io_block_size_128b_log2) - block_begin_128b)
                        >> block_size_128b_log2
                        == 0
                {
                    return task::Poll::Ready(Ok((
                        request,
                        Err(NvBlkDevIoError::IoBlockOutOfRange),
                    )));
                }

                let dev_block_id = block_begin_128b >> dev_io_block_size_128b_log2;
                let dev_block_id = match usize::try_from(dev_block_id) {
                    Ok(dev_block_id) => dev_block_id,
                    Err(_) => {
                        // The dev_io_blocks has been derived from BlockDriver::size(), which is an
                        // usize.
                        return task::Poll::Ready(Ok((request, Err(nvblkdev_err_internal!()))));
                    }
                };
                if let Err(e) = dev
                    .driver
                    .read_blocks(dev_block_id, &mut this.bounce_buffer)
                {
                    log::error!(
                        "block device read failed: error={e:?}, position={}, size={}",
                        block_begin_128b << 7,
                        1u64 << (block_size_128b_log2 + 7)
                    );
                    return task::Poll::Ready(Ok((
                        request,
                        Err(svsm_error_to_nvblkdev_io_error(e)),
                    )));
                }

                for (offset_in_block_128b, chunk_range) in block_chunks {
                    let buf = match request.get_destination_buffer(&chunk_range) {
                        Ok(buf) => buf,
                        Err(e) => return task::Poll::Ready(Ok((request, Err(e)))),
                    };
                    let buf = match buf {
                        Some(buf) => buf,
                        None => continue,
                    };

                    let buf_len = buf.len();
                    debug_assert_eq!(buf_len, 1usize << (region.chunk_size_128b_log2() + 7));
                    let offset_in_block = (offset_in_block_128b << 7) as usize;
                    buf.copy_from_slice(
                        &this.bounce_buffer[offset_in_block..offset_in_block + buf_len],
                    );
                }
            }
        }

        task::Poll::Ready(Ok((request, Ok(()))))
    }
}

/// [`NvBlkDev::WriteFuture`] implementation for [`SvsmNvBlkDev`].
#[derive(Debug)]
struct SvsmNvBlkDevWriteFuture<R: NvBlkDevWriteRequest> {
    request: Option<R>,
    bounce_buffer: FixedVec<u8, 7>,
}

impl<D: 'static + ops::Deref<Target: BlockDriver> + Send + Sync + Unpin, R: NvBlkDevWriteRequest>
    NvBlkDevFuture<SvsmNvBlkDev<D>> for SvsmNvBlkDevWriteFuture<R>
{
    type Output = Result<(R, Result<(), NvBlkDevIoError>), NvBlkDevIoError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        dev: &SvsmNvBlkDev<D>,
        _cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let dev_io_block_size_128b_log2 = dev.io_block_size_128b_log2();
        let preferred_dev_io_blocks_bulk_log2 = dev.preferred_io_blocks_bulk_log2();
        let dev_io_blocks = dev.io_blocks();

        let this = pin::Pin::into_inner(self);
        let request = match this.request.take() {
            Some(request) => request,
            None => return task::Poll::Ready(Err(nvblkdev_err_internal!())),
        };

        let region = request.region().clone();
        if region.chunk_size_128b_log2() >= dev_io_block_size_128b_log2 {
            // The buffers are all larger than (by a fixed power of two multiple of) the volume
            // block size. No bounce buffer needed.
            let block_size_128b_log2 = if region.is_aligned(region.chunk_size_128b_log2()) {
                region.chunk_size_128b_log2()
            } else if region.chunk_size_128b_log2()
                >= preferred_dev_io_blocks_bulk_log2 + dev_io_block_size_128b_log2
                && region
                    .is_aligned(preferred_dev_io_blocks_bulk_log2 + dev_io_block_size_128b_log2)
            {
                preferred_dev_io_blocks_bulk_log2 + dev_io_block_size_128b_log2
            } else {
                debug_assert!(region.is_aligned(dev_io_block_size_128b_log2));
                dev_io_block_size_128b_log2
            };
            let blocks_iter = match region.aligned_blocks_iter(block_size_128b_log2) {
                Ok(blocks_iter) => blocks_iter,
                Err(_) => return task::Poll::Ready(Ok((request, Err(nvblkdev_err_internal!())))),
            };
            for (physical_block_index, block_chunks) in blocks_iter {
                let block_begin_128b = physical_block_index << block_size_128b_log2;
                if block_begin_128b >= dev_io_blocks << dev_io_block_size_128b_log2
                    || ((dev_io_blocks << dev_io_block_size_128b_log2) - block_begin_128b)
                        >> block_size_128b_log2
                        == 0
                {
                    return task::Poll::Ready(Ok((
                        request,
                        Err(NvBlkDevIoError::IoBlockOutOfRange),
                    )));
                }

                for (offset_in_block_128b, chunk_range) in block_chunks {
                    // The buffer size is >= the iteration block size.
                    debug_assert_eq!(offset_in_block_128b, 0);
                    let buf = match request.get_source_buffer(&chunk_range) {
                        Ok(buf) => buf,
                        Err(e) => return task::Poll::Ready(Ok((request, Err(e)))),
                    };

                    let dev_block_id =
                        (block_begin_128b + offset_in_block_128b) >> dev_io_block_size_128b_log2;
                    let dev_block_id = match usize::try_from(dev_block_id) {
                        Ok(dev_block_id) => dev_block_id,
                        Err(_) => {
                            // The dev_io_blocks has been derived from BlockDriver::size(), which is
                            // an usize.
                            return task::Poll::Ready(Ok((request, Err(nvblkdev_err_internal!()))));
                        }
                    };
                    if let Err(e) = dev.driver.write_blocks(dev_block_id, buf) {
                        log::error!(
                            "block device write failed: error={e:?}, position={}, size={}",
                            (block_begin_128b + offset_in_block_128b) << 7,
                            1u64 << (block_size_128b_log2 + 7)
                        );
                        return task::Poll::Ready(Ok((
                            request,
                            Err(svsm_error_to_nvblkdev_io_error(e)),
                        )));
                    }
                }
            }
        } else {
            // The buffers are smaller than the volume block size, going through the bounce buffer
            // is necessary.
            let block_size_128b_log2 = dev_io_block_size_128b_log2;

            if this.bounce_buffer.is_empty() {
                this.bounce_buffer =
                    match FixedVec::new_with_default(1usize << (block_size_128b_log2 + 7)) {
                        Ok(bounce_buffer) => bounce_buffer,
                        Err(_) => {
                            return task::Poll::Ready(Ok((
                                request,
                                Err(NvBlkDevIoError::MemoryAllocationFailure),
                            )));
                        }
                    };
            }

            let blocks_iter = match region.aligned_blocks_iter(block_size_128b_log2) {
                Ok(blocks_iter) => blocks_iter,
                Err(_) => return task::Poll::Ready(Ok((request, Err(nvblkdev_err_internal!())))),
            };
            for (physical_block_index, block_chunks) in blocks_iter {
                let block_begin_128b = physical_block_index << block_size_128b_log2;
                if block_begin_128b >= dev_io_blocks << dev_io_block_size_128b_log2
                    || ((dev_io_blocks << dev_io_block_size_128b_log2) - block_begin_128b)
                        >> block_size_128b_log2
                        == 0
                {
                    return task::Poll::Ready(Ok((
                        request,
                        Err(NvBlkDevIoError::IoBlockOutOfRange),
                    )));
                }

                for (offset_in_block_128b, chunk_range) in block_chunks {
                    let buf = match request.get_source_buffer(&chunk_range) {
                        Ok(buf) => buf,
                        Err(e) => return task::Poll::Ready(Ok((request, Err(e)))),
                    };

                    let buf_len = buf.len();
                    debug_assert_eq!(buf_len, 1usize << (region.chunk_size_128b_log2() + 7));
                    let offset_in_block = (offset_in_block_128b << 7) as usize;
                    this.bounce_buffer[offset_in_block..offset_in_block + buf_len]
                        .copy_from_slice(buf);
                }

                let dev_block_id = block_begin_128b >> dev_io_block_size_128b_log2;
                let dev_block_id = match usize::try_from(dev_block_id) {
                    Ok(dev_block_id) => dev_block_id,
                    Err(_) => {
                        // The dev_io_blocks has been derived from BlockDriver::size(), which is an
                        // usize.
                        return task::Poll::Ready(Ok((request, Err(nvblkdev_err_internal!()))));
                    }
                };
                if let Err(e) = dev.driver.write_blocks(dev_block_id, &this.bounce_buffer) {
                    log::error!(
                        "block device write failed: error={e:?}, position={}, size={}",
                        block_begin_128b << 7,
                        1u64 << (block_size_128b_log2 + 7)
                    );
                    return task::Poll::Ready(Ok((
                        request,
                        Err(svsm_error_to_nvblkdev_io_error(e)),
                    )));
                }
            }
        }

        task::Poll::Ready(Ok((request, Ok(()))))
    }
}

/// [`NvBlkDev::FlushQueuedWritesFuture`] implementation for [`SvsmNvBlkDev`].
#[derive(Debug)]
struct SvsmNvBlkDevFlushQueuedWritesFuture;

impl<D: 'static + ops::Deref<Target: BlockDriver> + Send + Sync + Unpin>
    NvBlkDevFuture<SvsmNvBlkDev<D>> for SvsmNvBlkDevFlushQueuedWritesFuture
{
    type Output = Result<(), NvBlkDevIoError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        _dev: &SvsmNvBlkDev<D>,
        _cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        // Any pending write operations need to get "completed with unspecified" result here.  This
        // can only manifest itself in how subsequently issued writes to overlapping storage regions
        // are possibly getting ordered relative to the flushed/cancelled ones. One would hope that
        // there is no moving of older request to after newer conflicting ones happening anywhere in
        // the stack. So avoid issuing yet another write barrier here.
        task::Poll::Ready(Ok(()))
    }
}

/// [`NvBlkDev::WriteSyncFuture`] implementation for [`SvsmNvBlkDev`].
///
/// Also used for the [`NvBlkDev::WriteBarrierFuture`].
#[derive(Debug)]
struct SvsmNvBlkDevWriteSyncFuture;

impl<D: 'static + ops::Deref<Target: BlockDriver> + Send + Sync + Unpin>
    NvBlkDevFuture<SvsmNvBlkDev<D>> for SvsmNvBlkDevWriteSyncFuture
{
    type Output = Result<(), NvBlkDevIoError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        dev: &SvsmNvBlkDev<D>,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        if let Err(e) = dev.driver.flush() {
            log::error!("block device flush request failed: error={e:?}");
            return task::Poll::Ready(Err(svsm_error_to_nvblkdev_io_error(e)));
        }

        task::Poll::Ready(Ok(()))
    }
}

/// [`NvBlkDev::TrimFuture`] implementation for [`SvsmNvBlkDev`].
#[derive(Debug)]
struct SvsmNvBlkDevTrimFuture {
    io_block_index: u64,
    io_blocks_count: u64,
    zeroes_buffer: FixedVec<u8, 7>,
}

impl<D: 'static + ops::Deref<Target: BlockDriver> + Send + Sync + Unpin>
    NvBlkDevFuture<SvsmNvBlkDev<D>> for SvsmNvBlkDevTrimFuture
{
    type Output = Result<(), NvBlkDevIoError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        dev: &SvsmNvBlkDev<D>,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        // The BlockDriver trait, and ultimately the VirtIOBlk, don't seem to provide DISCARD
        // functionality. Write zeroes so that the host can still apply compression (if trimming is
        // even enabled for the filesystem instance).
        let dev_io_block_size_128b_log2 = dev.io_block_size_128b_log2();
        let dev_io_blocks = dev.io_blocks();
        if self.io_blocks_count == 0 {
            return task::Poll::Ready(Ok(()));
        } else if self.io_block_index > dev_io_blocks
            || dev_io_blocks - self.io_block_index < self.io_blocks_count
        {
            return task::Poll::Ready(Err(NvBlkDevIoError::IoBlockOutOfRange));
        }

        let this = pin::Pin::into_inner(self);
        if this.zeroes_buffer.is_empty() {
            this.zeroes_buffer =
                match FixedVec::new_with_default(1usize << (dev_io_block_size_128b_log2 + 7)) {
                    Ok(zeroes_buffer) => zeroes_buffer,
                    Err(_) => {
                        return task::Poll::Ready(Err(NvBlkDevIoError::MemoryAllocationFailure));
                    }
                };
        }

        for i in 0..this.io_blocks_count {
            let dev_block_id = match usize::try_from(this.io_block_index + i) {
                Ok(dev_block_id) => dev_block_id,
                Err(_) => {
                    // The dev_io_blocks has been derived from BlockDriver::size(), which is an
                    // usize.
                    return task::Poll::Ready(Err(nvblkdev_err_internal!()));
                }
            };
            if let Err(e) = dev.driver.write_blocks(dev_block_id, &this.zeroes_buffer) {
                log::error!(
                    "block device zeroization write failed: error={e:?}, position={}, size={}",
                    (dev_block_id as u64) << (dev_io_block_size_128b_log2 + 7),
                    1u64 << (dev_io_block_size_128b_log2 + 7)
                );
                return task::Poll::Ready(Err(svsm_error_to_nvblkdev_io_error(e)));
            }
        }

        task::Poll::Ready(Ok(()))
    }
}

fn nvfs_error_to_svsm_error(e: NvFsError) -> SvsmError {
    match e {
        NvFsError::MemoryAllocationFailure => SvsmError::Alloc(AllocError::OutOfMemory),
        NvFsError::IoError(NvFsIoError::IoFailure) => SvsmError::Block(BlockDeviceError::Failed),
        _ => SvsmError::Block(BlockDeviceError::Failed),
    }
}

type SvsmCocoonFsType = CocoonFs<SvsmSyncTypes, SvsmNvBlkDev<&'static dyn BlockDriver>>;
type SvsmCocoonFsSyncRcPtrType =
    <<SvsmSyncTypes as sync_types::SyncTypes>::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>
    ::SyncRcPtr<SvsmCocoonFsType>;
type SvsmCocoonFsSyncRcPtrRefType<'a> =
    <SvsmCocoonFsSyncRcPtrType as sync_types::SyncRcPtr<SvsmCocoonFsType>>::SyncRcPtrRef<'a>;

static SVSM_COCOONFS_INSTANCE: ImmutAfterInitCell<pin::Pin<SvsmCocoonFsSyncRcPtrType>> =
    ImmutAfterInitCell::uninit();

/// Instantiate a [`cocoonfs::ReadFsMetadataFuture`].
///
/// The `cocoonfs::ReadFsMetadataFuture` is huge, and by instantiating it in an `inline(never)`
/// function and `Box`ing it right after, the stack allocations required for the moves are hopefully
/// getting freed up quickly again.
#[inline(never)]
fn instantiate_cocoonfs_read_fs_metadata_fut(
    blkdev: SvsmNvBlkDev<&'static dyn BlockDriver>,
) -> Result<Box<cocoonfs::ReadFsMetadataFuture<SvsmNvBlkDev<&'static dyn BlockDriver>>>, NvFsError>
{
    let read_fs_metadata_fut =
        cocoonfs::ReadFsMetadataFuture::new(blkdev).map_err(|(_blkdev, e)| e)?;
    box_try_new(read_fs_metadata_fut).map_err(NvFsError::from)
}

/// Instantiate a [`cocoonfs::OpenFsFuture`].
///
/// The `cocoonfs::OpenFsFuture` is huge, and by instantiating it in an `inline(never)` function and
/// `Box`ing it right after, the stack allocations required for the moves are hopefully getting
/// freed up quickly again.
#[allow(clippy::type_complexity)]
#[inline(never)]
fn instantiate_cocoonfs_open_fut(
    blkdev: SvsmNvBlkDev<&'static dyn BlockDriver>,
    fs_metadata: cocoonfs::FsMetadata,
    key: Zeroizing<Vec<u8>>,
) -> Result<
    Box<cocoonfs::OpenFsFuture<SvsmSyncTypes, SvsmNvBlkDev<&'static dyn BlockDriver>>>,
    NvFsError,
> {
    let rng = box_try_new(get_svsm_rng().map_err(NvFsError::from)?).map_err(NvFsError::from)?;
    let cocoonfs_open_fut = cocoonfs::OpenFsFuture::new(blkdev, Some(fs_metadata), key, false, rng)
        .map_err(|(_blkdev, _key, _rng, e)| e)?;
    box_try_new(cocoonfs_open_fut).map_err(NvFsError::from)
}

/// Persistence metadata info returned by [`persistence_discover()`].
///
/// `PersistenceBootstrapInfo` gets returned by [`persistence_discover()`], is supposed to serve as
/// input to the attestation, and, once the key has been obtained, to eventually get passed to
/// [`persistence_init()`] for the unlocking.
#[allow(missing_debug_implementations)]
pub struct PersistenceBootstrapInfo {
    blkdev: SvsmNvBlkDev<&'static dyn BlockDriver>,
    fs_metadata: cocoonfs::FsMetadata,
}

impl PersistenceBootstrapInfo {
    /// Access the metadata.
    pub fn get_fs_metadata(&self) -> &cocoonfs::FsMetadata {
        &self.fs_metadata
    }
}

/// Obtain persistence bootstrap info from block devices, if any.
///
/// Persistence initialization is a split operation. In a first step, the metadata is read from any
/// block devices via `persistence_discover()`, if any. That metadata is then served as input to the
/// attestation procedure in order to obtain a key. Eventually, the bootstrap info and the key get
/// passed to `persistence_init()` for the unlocking.
///
/// # See also:
///
/// * [`persistence_init()`]
pub fn persistence_discover() -> Result<Option<PersistenceBootstrapInfo>, SvsmError> {
    // Inspect the global BLOCK_DEVICE and see if there's a CocoonFs on it, either already formatted
    // or one with a mkfsinfo header, which will get formatted transparently at first filesystem
    // opening time.
    log::debug!("attempting to find persistent CocoonFs storage...");
    let blkdev = match BLOCK_DEVICE.try_get_inner().ok() {
        Some(blkdev) => SvsmNvBlkDev::new(&**blkdev),
        None => {
            log::debug!("no block device found");
            return Ok(None);
        }
    };

    let mut read_fs_metadata_fut =
        instantiate_cocoonfs_read_fs_metadata_fut(blkdev).map_err(nvfs_error_to_svsm_error)?;
    match task_busypoll_to_completion(|cx| {
        Future::poll(pin::Pin::new(&mut read_fs_metadata_fut), cx)
    }) {
        Ok((blkdev, Ok(fs_metadata))) => {
            // Found one, return it.
            log::debug!("found persistent CocoonFs storage");
            Ok(Some(PersistenceBootstrapInfo {
                blkdev,
                fs_metadata,
            }))
        }
        Ok((_blkdev, Err(e))) => {
            if e == NvFsError::from(cocoonfs::FormatError::InvalidImageHeader) {
                log::debug!("skipping over block device with no CocoonFs header");
            } else {
                log::error!("failed to read CocoonFs metadata from block device: {e:?}");
            }
            // No CocoonFs block device available.
            log::info!("no persistent CocoonFs storage found");
            Ok(None)
        }
        Err(e) => {
            // If not even the blkdev is getting returned back, it's likely an internal error of
            // the implementation.
            log::error!("failed to read CocoonFs metadata from block device: {e:?}");
            Err(nvfs_error_to_svsm_error(e))
        }
    }
}

/// Finalize the initialization of the persistence subsystem.
///
/// Must get invoked at most once at startup, any subsequent reinitialization attempt will result in
/// a panic.
///
/// The successfully opened CocoonFs instance, if any, will henceforth be used to serve all
/// the SVSM's persistence related needs.
///
/// # Arguments:
///
/// * `bootstrap_info` - The bootstrap info previously obtained from [`persistence_discover()`] and
///   provided to the attestation in order to obtain the `key`.
/// * `key` - The CocoonFs root key used (indirectly) for authentication and encryption.
///
/// # See also:
///
/// * [`persistence_discover()`]
pub fn persistence_init(
    bootstrap_info: PersistenceBootstrapInfo,
    key: &[u8],
) -> Result<(), SvsmError> {
    let PersistenceBootstrapInfo {
        blkdev,
        fs_metadata,
    } = bootstrap_info;

    // Make a copy for the OpenFsFuture.
    let mut owned_key = try_alloc_zeroizing_vec(key.len())
        .map_err(|_| SvsmError::Alloc(AllocError::OutOfMemory))?;
    owned_key.copy_from_slice(key);

    let mut cocoonfs_open_fut = match instantiate_cocoonfs_open_fut(blkdev, fs_metadata, owned_key)
    {
        Ok(cocoonfs_open_fut) => cocoonfs_open_fut,
        Err(e) => {
            log::error!("failed to initiate CocoonFs opening operation: {e:?}");
            return Err(nvfs_error_to_svsm_error(e));
        }
    };

    match task_busypoll_to_completion(|cx| Future::poll(pin::Pin::new(&mut cocoonfs_open_fut), cx))
    {
        Ok((_rng, Ok(cocoonfs_instance))) => {
            SVSM_COCOONFS_INSTANCE
                .init(cocoonfs_instance)
                .expect("SVSM CocoonFs instance already initialized");
            log::info!("persistent CocoonFs storage opened successfully");
            Ok(())
        }
        Ok((_, Err((_, _, e)))) | Err(e) => {
            log::error!("failed to open CocoonFs block device: {e:?}");
            Err(nvfs_error_to_svsm_error(e))
        }
    }
}

/// Test whether persistence functionality is available.
///
/// Persistence functionality is available only if a block device with a valid CocoonFs instance on
/// it could get opened successfully from [`persistence_init()`].
///
/// `persistence_available()` may get invoked even if [`persistence_init()`] has not been run at all,
/// in which case it would report `false`.
pub fn persistence_available() -> bool {
    SVSM_COCOONFS_INSTANCE.try_get_inner().is_ok()
}

/// Instantiate a [`CocoonFs::StartTransactionFut`].
///
/// The [`CocoonFs::StartTransactionFut`] is not exactly small -- by instantiating it in an
/// `inline(never)` function and `Box`ing it right after, the stack allocations required for the
/// moves are hopefully getting freed up quickly again.
#[inline(never)]
fn instantiate_cocoonfs_start_transaction_fut(
    fs_instance: &pin::Pin<SvsmCocoonFsSyncRcPtrRefType<'_>>,
) -> Result<Box<<SvsmCocoonFsType as NvFs>::StartTransactionFut>, NvFsError> {
    let start_transaction_fut = SvsmCocoonFsType::start_transaction(fs_instance, None);
    box_try_new(start_transaction_fut).map_err(NvFsError::from)
}

/// Instantiate a [`CocoonFs::CommitTransactionFut`].
///
/// The [`CocoonFs::CommitTransactionFut`] is not exactly small -- by instantiating it in an
/// `inline(never)` function and `Box`ing it right after, the stack allocations required for the
/// moves are hopefully getting freed up quickly again.
#[inline(never)]
fn instantiate_cocoonfs_commit_transaction_fut(
    fs_instance: &pin::Pin<SvsmCocoonFsSyncRcPtrRefType<'_>>,
    transaction: <SvsmCocoonFsType as NvFs>::Transaction,
    issue_sync: bool,
) -> Result<Box<<SvsmCocoonFsType as NvFs>::CommitTransactionFut>, NvFsError> {
    let commit_transaction_fut =
        SvsmCocoonFsType::commit_transaction(fs_instance, transaction, None, None, issue_sync);
    box_try_new(commit_transaction_fut).map_err(NvFsError::from)
}

/// Instantiate a [`CocoonFs::WriteInodeFut`].
///
/// The [`CocoonFs::WriteInodeFut`] is not exactly small -- by instantiating it in an
/// `inline(never)` function and `Box`ing it right after, the stack allocations required for the
/// moves are hopefully getting freed up quickly again.
#[inline(never)]
fn instantiate_cocoonfs_write_inode_fut(
    fs_instance: &pin::Pin<SvsmCocoonFsSyncRcPtrRefType<'_>>,
    transaction: <SvsmCocoonFsType as NvFs>::Transaction,
    inode: u64,
    data: Zeroizing<Vec<u8>>,
) -> Result<Box<<SvsmCocoonFsType as NvFs>::WriteInodeFut>, NvFsError> {
    let write_inode_fut =
        SvsmCocoonFsType::write_inode(fs_instance, transaction, inode, 0, 0, data);
    box_try_new(write_inode_fut).map_err(NvFsError::from)
}

/// Instantiate a [`CocoonFs::ReadInodeFut`].
///
/// The [`CocoonFs::ReadInodeFut`] is not exactly small -- by instantiating it in an
/// `inline(never)` function and `Box`ing it right after, the stack allocations required for the
/// moves are hopefully getting freed up quickly again.
#[inline(never)]
fn instantiate_cocoonfs_read_inode_fut(
    fs_instance: &pin::Pin<SvsmCocoonFsSyncRcPtrRefType<'_>>,
    inode: u64,
) -> Result<Box<<SvsmCocoonFsType as NvFs>::ReadInodeFut>, NvFsError> {
    let read_inode_fut = SvsmCocoonFsType::read_inode(fs_instance, None, inode);
    box_try_new(read_inode_fut).map_err(NvFsError::from)
}

/// Synchronously write data to an inode on persistent storage.
///
/// If the `inode` does not exist yet, it will get created. All of the inode's contents will get
/// replaced with `data`.
///
/// The inode data writes are all-or-nothing and atomic: on successful completion, all of the
/// `inode`'s data has been replaced with the new `data`, whereas on error its original contents are
/// retained. Furthermore, there is a total order among all (successful) writes ever issued to the
/// backing persistent storage volume, possibly to different target inodes even.
///
/// `persistence_write_inode_sync()` assumes ownership of the `data` buffer for the duration of the
/// operation. It gets returned back unmodified to the caller on success.
///
/// Any error propagated back to the caller indicates an actual problem -- in particular requests to
/// retry received from the backing filesystem implementation are handled transparently within
/// `persistence_write_inode_sync()` itself.
///
/// # Arguments:
///
/// * `inode` - Number of the inode to update.
/// * `data` - The data to write to `inode`.
/// * `issue_sync` - Whether or not to issue a sync request to the underlying storage after the
///   write has completed. That's best effort though and relies on the host to behave well.
///
/// # See also:
///
/// * [`PersistenceMultiOp`].
#[allow(unused)]
pub fn persistence_write_inode_sync(
    inode: u64,
    mut data: Zeroizing<Vec<u8>>,
    issue_sync: bool,
) -> Result<Zeroizing<Vec<u8>>, SvsmError> {
    let fs_instance = match SVSM_COCOONFS_INSTANCE.try_get_inner().ok() {
        Some(fs_instance) => <pin::Pin<SvsmCocoonFsSyncRcPtrType> as sync_types::SyncRcPtr<
            SvsmCocoonFsType,
        >>::as_ref(fs_instance),
        None => {
            return Err(SvsmError::FileSystem(FsError::NotSupported));
        }
    };

    let mut rng = match get_svsm_rng() {
        Ok(rng) => rng,
        Err(e) => {
            log::error!("persistence write: failed to get rng instance: {e:?}");
            return Err(nvfs_error_to_svsm_error(NvFsError::from(e)));
        }
    };

    loop {
        let mut transaction = match instantiate_cocoonfs_start_transaction_fut(&fs_instance)
            .and_then(|mut start_transaction_fut| {
                task_busypoll_to_completion(|cx| {
                    NvFsFuture::poll(
                        pin::Pin::new(&mut *start_transaction_fut),
                        &fs_instance,
                        &mut rng,
                        cx,
                    )
                })
            }) {
            Ok(transaction) => transaction,
            Err(NvFsError::Retry) => continue,
            Err(e) => {
                log::error!("persistence write: failed to start transaction: {e:?}");
                return Err(nvfs_error_to_svsm_error(e));
            }
        };

        // The Future instantiation step can fail only due to memory allocation
        // failures. NvFsError::Retry is potentially getting returned only by the actual polling, in
        // which case 'data' needs to get restored for the retry.
        {
            let mut write_inode_fut = match instantiate_cocoonfs_write_inode_fut(
                &fs_instance,
                transaction,
                inode,
                data,
            ) {
                Ok(write_inode_fut) => write_inode_fut,
                Err(e) => {
                    log::error!(
                        "persistence write: failed to stage inode write at transaction: {e:?}"
                    );
                    return Err(nvfs_error_to_svsm_error(e));
                }
            };
            (transaction, data) = match task_busypoll_to_completion(|cx| {
                NvFsFuture::poll(
                    pin::Pin::new(&mut *write_inode_fut),
                    &fs_instance,
                    &mut rng,
                    cx,
                )
            }) {
                (returned_data, Ok((transaction, Ok(())))) => (transaction, returned_data),
                (returned_data, Ok((_, Err(NvFsError::Retry))) | Err(NvFsError::Retry)) => {
                    data = returned_data;
                    continue;
                }
                (_, Ok((_, Err(e))) | Err(e)) => {
                    log::error!(
                        "persistence write: failed to stage inode write at transaction: {e:?}"
                    );
                    return Err(nvfs_error_to_svsm_error(e));
                }
            };
        }

        if let Err(e) =
            instantiate_cocoonfs_commit_transaction_fut(&fs_instance, transaction, issue_sync)
                .and_then(|mut commit_transaction_fut| {
                    task_busypoll_to_completion(|cx| {
                        NvFsFuture::poll(
                            pin::Pin::new(&mut *commit_transaction_fut),
                            &fs_instance,
                            &mut rng,
                            cx,
                        )
                    })
                    .map_err(|e| match e {
                        TransactionCommitError::LogStateClean { reason } => reason,
                        TransactionCommitError::LogStateIndeterminate { reason } => reason,
                    })
                })
        {
            if e == NvFsError::Retry {
                continue;
            }

            log::error!("persistence write: failed to commit transaction: {e:?}");
            return Err(nvfs_error_to_svsm_error(e));
        }

        break;
    }

    Ok(data)
}

/// Synchronously read data from an inode on persistent storage.
///
/// In case the `inode` does not exist, `None` is returned, otherwise all of the inode's data
/// is returned wrapped in `Some`. Note that a non-existing inode and an existing one with
/// empty data are considered different.
///
/// Any error propagated back to the caller indicates an actual problem -- in particular requests to
/// retry received from the backing filesystem implementation are handled transparently within
/// `persistence_read_inode_sync()` itself.
///
/// # Arguments:
///
/// * `inode` - Number of the inode whose data to read.
#[allow(unused)]
pub fn persistence_read_inode_sync(inode: u64) -> Result<Option<Zeroizing<Vec<u8>>>, SvsmError> {
    let fs_instance = match SVSM_COCOONFS_INSTANCE.try_get_inner().ok() {
        Some(fs_instance) => <pin::Pin<SvsmCocoonFsSyncRcPtrType> as sync_types::SyncRcPtr<
            SvsmCocoonFsType,
        >>::as_ref(fs_instance),
        None => {
            return Err(SvsmError::FileSystem(FsError::NotSupported));
        }
    };

    let mut rng = match get_svsm_rng() {
        Ok(rng) => rng,
        Err(e) => {
            log::error!("persistence read: failed to get rng instance: {e:?}");
            return Err(nvfs_error_to_svsm_error(NvFsError::from(e)));
        }
    };

    loop {
        match instantiate_cocoonfs_read_inode_fut(&fs_instance, inode).and_then(
            |mut read_inode_fut| {
                task_busypoll_to_completion(|cx| {
                    NvFsFuture::poll(
                        pin::Pin::new(&mut *read_inode_fut),
                        &fs_instance,
                        &mut rng,
                        cx,
                    )
                })
            },
        ) {
            Ok((_read_context, Ok(result))) => {
                break Ok(result.map(|read_result| read_result.1));
            }
            Ok((_, Err(NvFsError::Retry))) | Err(NvFsError::Retry) => (),
            Ok((_, Err(e))) | Err(e) => {
                log::error!("persistence read: failed to read inode data: {e:?}");
                break Err(nvfs_error_to_svsm_error(e));
            }
        }
    }
}

/// Error returned by various [`PersistenceMultiOp`] primitives.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PersistenceMultiOpMemoryAllocationFailure;

impl From<PersistenceMultiOpMemoryAllocationFailure> for SvsmError {
    fn from(_value: PersistenceMultiOpMemoryAllocationFailure) -> Self {
        SvsmError::Alloc(AllocError::OutOfMemory)
    }
}

/// Staged sequence of persistent storage operations to commit atomically.
///
/// A sequence of inode [write](Self::stage_inode_write) and/or
/// [unlinking](Self::stage_inode_range_unlinking) may get staged at a [`PersistenceMultiOp`]
/// instance for eventual [commit](persistence_commit_multi_op_sync) to storage in one atomic step.
///
/// # See also:
///
/// * [`persistence_commit_multi_op_sync()`].
#[derive(Debug)]
pub struct PersistenceMultiOp {
    /// Inode ranges staged for unlinking.
    ///
    /// The following invariants are held:
    /// - The list contains no empty inode range.
    /// - The inode ranges are all disjunct.
    /// - The list is sorted by inode numbers.
    ///
    /// Furthermore, no entry from [`inode_writes`](Self::inode_writes) is contained in any of the
    /// `inode_unlink_ranges` entries.
    inode_unlink_ranges: Vec<RangeInclusive<u64>>,

    /// Pairs of inode numbers and associated data to write to each respectively.
    ///
    /// The following invariants are held:
    /// - The inode numers are all distinct.
    /// - The list is sorted by inode numbers.
    ///
    /// Furthermore, no entry from `inode_writes` is contained in any of the
    /// [`inode_unlink_ranges](Self::inode_unlink_ranges)` entries.
    inode_writes: Vec<(u64, Zeroizing<Vec<u8>>)>,
}

impl PersistenceMultiOp {
    /// Instantiate an empty [`PersistenceMultiOp`].
    pub fn new() -> Self {
        Self {
            inode_unlink_ranges: Vec::new(),
            inode_writes: Vec::new(),
        }
    }

    /// Find the [`inode_unlink_ranges`](Self::inode_unlink_ranges) entries overlapping with a specified range.
    ///
    /// Find the index range into (sorted) [`inode_unlink_ranges`](Self::inode_unlink_ranges) that
    /// spans any elements overlapping with the specified `query_inode_range`. In case an
    /// [empty](Range::is_empty) index range is returned, there is no overlapping element and the
    /// returned [`Range::start`] denotes the insertion point for `query_inode_range`.
    ///
    /// # Arguments:
    ///
    /// * `query_inode_range` - The inode range to search for. It must be non-empty.
    fn inode_unlink_ranges_find_overlapping(
        &self,
        query_inode_range: &RangeInclusive<u64>,
    ) -> Range<usize> {
        debug_assert!(!query_inode_range.is_empty());
        // Find the first entry in the sorted self.inode_unlink_ranges[] that possibly overlaps with the
        // query range, if any. It is the first entry that has an end >= query_inode_range.start().
        let b = self
            .inode_unlink_ranges
            .partition_point(|inode_unlink_range| {
                inode_unlink_range.end() < query_inode_range.start()
            });
        // Find the first entry in the sorted self.inode_unlink_ranges[b..] that does not overlap with
        // the query range, if any. It is the first entry that has a start > query_inode_range.end().
        let e = b + self.inode_unlink_ranges[b..].partition_point(|inode_unlink_range| {
            inode_unlink_range.start() <= query_inode_range.end()
        });

        b..e
    }

    /// Insert an inode range into [`inode_unlink_ranges`](Self::inode_unlink_ranges).
    ///
    /// Insert `inode_unlink_range` into [`inode_unlink_ranges`](Self::inode_unlink_ranges), merging
    /// with preexisting entries as is required for maintaining the documented invariants.
    ///
    /// # Arguments:
    ///
    /// * `inode_unlink_range` - The inode range to insert.
    fn inode_unlink_ranges_insert(
        &mut self,
        inode_unlink_range: &RangeInclusive<u64>,
    ) -> Result<(), PersistenceMultiOpMemoryAllocationFailure> {
        if inode_unlink_range.is_empty() {
            return Ok(());
        }

        let overlapping = self.inode_unlink_ranges_find_overlapping(inode_unlink_range);
        if overlapping.is_empty() {
            // No overlapping preexisting entry, insert at the indicated position.
            if self.inode_unlink_ranges.try_reserve(1).is_err() {
                return Err(PersistenceMultiOpMemoryAllocationFailure);
            }
            let insertion_pos = overlapping.start;
            self.inode_unlink_ranges
                .insert(insertion_pos, inode_unlink_range.clone());
        } else {
            // Replace the preexisting overlapping entries by the union.
            let inode_unlink_range = RangeInclusive::new(
                *inode_unlink_range
                    .start()
                    .min(self.inode_unlink_ranges[overlapping.start].start()),
                *inode_unlink_range
                    .end()
                    .max(self.inode_unlink_ranges[overlapping.end - 1].end()),
            );
            self.inode_unlink_ranges[overlapping.start] = inode_unlink_range;
            self.inode_unlink_ranges
                .drain(overlapping.start + 1..overlapping.end);
        }

        Ok(())
    }

    /// Remove an inode range from [`inode_unlink_ranges`](Self::inode_unlink_ranges).
    ///
    /// Remove any overlap with `inode_range` from
    /// [`inode_unlink_ranges`](Self::inode_unlink_ranges), trimming any existing entries as is
    /// required for maintaining the documented invariants.
    ///
    /// # Arguments:
    ///
    /// * `inode_range` - The inode range to remove.
    fn inode_unlink_ranges_remove(
        &mut self,
        inode_range: &RangeInclusive<u64>,
    ) -> Result<(), PersistenceMultiOpMemoryAllocationFailure> {
        if inode_range.is_empty() {
            return Ok(());
        }

        let mut overlapping = self.inode_unlink_ranges_find_overlapping(inode_range);
        if overlapping.is_empty() {
            return Ok(());
        }

        if overlapping.end == overlapping.start + 1
            && self.inode_unlink_ranges[overlapping.start].start() < inode_range.start()
            && self.inode_unlink_ranges[overlapping.start].end() > inode_range.end()
        {
            // The inode_range is contained properly in a single inode_unlink_ranges[] entry that
            // must get split.
            if self.inode_unlink_ranges.try_reserve(1).is_err() {
                return Err(PersistenceMultiOpMemoryAllocationFailure);
            }
            self.inode_unlink_ranges.insert(
                overlapping.end,
                RangeInclusive::new(
                    *inode_range.end() + 1,
                    *self.inode_unlink_ranges[overlapping.start].end(),
                ),
            );
            self.inode_unlink_ranges[overlapping.start] = RangeInclusive::new(
                *self.inode_unlink_ranges[overlapping.start].start(),
                *inode_range.start() - 1,
            );
        } else {
            // Possibly trim the overlapping preexisting head and tail entries, if the remaining
            // parts are non-trivial, and remove the ones contained fully in the inode_range.
            if self.inode_unlink_ranges[overlapping.start].start() < inode_range.start() {
                self.inode_unlink_ranges[overlapping.start] = RangeInclusive::new(
                    *self.inode_unlink_ranges[overlapping.start].start(),
                    *inode_range.start() - 1,
                );
                overlapping.start += 1;
            }
            if self.inode_unlink_ranges[overlapping.end - 1].end() > inode_range.end() {
                self.inode_unlink_ranges[overlapping.end - 1] = RangeInclusive::new(
                    *inode_range.end() + 1,
                    *self.inode_unlink_ranges[overlapping.end - 1].end(),
                );
                overlapping.end -= 1;
            }
            // A split would have been handled in the other branch above.
            debug_assert!(overlapping.start <= overlapping.end);
            self.inode_unlink_ranges.drain(overlapping);
        }

        Ok(())
    }

    /// Find the [`inode_writes`](Self::inode_writes) entries contained within a specified range.
    ///
    /// Find the index range into (sorted) [`inode_writes`](Self::inode_writes) that
    /// spans any elements contained within the specified `query_inode_range`.
    ///
    /// # Arguments:
    ///
    /// * `query_inode_range` - The inode range to search for. It must be non-empty.
    fn inode_writes_find_overlapping(
        &self,
        query_inode_range: &RangeInclusive<u64>,
    ) -> Range<usize> {
        let b = self
            .inode_writes
            .partition_point(|inode_write| inode_write.0 < *query_inode_range.start());
        let e = b + self
            .inode_writes
            .partition_point(|inode_write| inode_write.0 <= *query_inode_range.end());
        b..e
    }

    /// Stage an inode unlinking operation.
    ///
    /// Register all inodes in the `inode_unlink_range` for unlinking. Any previously [staged
    /// writes](Self::stage_inode_write) to inodes in that range will be dismissed.
    ///
    /// # Arguments:
    ///
    /// * `inode_unlink_range` - The range of inodes to unlink.
    pub fn stage_inode_range_unlinking(
        &mut self,
        inode_unlink_range: RangeInclusive<u64>,
    ) -> Result<(), PersistenceMultiOpMemoryAllocationFailure> {
        if inode_unlink_range.is_empty() {
            return Ok(());
        }

        self.inode_unlink_ranges_insert(&inode_unlink_range)?;

        // Remove any overlapping inode_writes entries.
        self.inode_writes
            .drain(self.inode_writes_find_overlapping(&inode_unlink_range));
        Ok(())
    }

    /// Stage an inode data write operation.
    ///
    /// Setup a write of `data` to the inode identified by `inode`. Partial writes are not supported
    /// and all if the `inode`'s` data on storage will get replaced with `data`. Any previously
    /// [stage unlinking operation](Self::stage_inode_range_unlinking) for `inode` will get
    /// dismissed. If the `inode` does not exist yet, it will get created at
    /// commit time.
    ///
    /// # Arguments:
    ///
    /// * `inode` - The inode to write to.
    /// * `data` - The data to write to `inode`.
    pub fn stage_inode_write(
        &mut self,
        inode: u64,
        data: Zeroizing<Vec<u8>>,
    ) -> Result<(), PersistenceMultiOpMemoryAllocationFailure> {
        let insertion_pos = match self
            .inode_writes
            .binary_search_by(|inode_write| inode_write.0.cmp(&inode))
        {
            Ok(matching_pos) => {
                // Update the matching preexisting entry and return.
                self.inode_writes[matching_pos].1 = data;
                return Ok(());
            }
            Err(insertion_pos) => insertion_pos,
        };

        // Do the memory allocation before removing any matching unlinking entry, so that a failure
        // will leave self in the original state.
        if self.inode_writes.try_reserve(1).is_err() {
            return Err(PersistenceMultiOpMemoryAllocationFailure);
        }

        self.inode_unlink_ranges_remove(&(inode..=inode))?;
        self.inode_writes.insert(insertion_pos, (inode, data));

        Ok(())
    }
}

impl Default for PersistenceMultiOp {
    fn default() -> Self {
        Self::new()
    }
}

/// Commit a [`PersistenceMultiOp`] to storage.
struct CommitPersistenceMultiOpFuture<FS: NvFs> {
    ops: PersistenceMultiOp,
    issue_sync: bool,
    fut_state: CommitPersistenceMultiOpFutureState<FS>,
}

/// Internal [`CommitPersistenceMultiOpFuture`] state-machine state.
enum CommitPersistenceMultiOpFutureState<FS: NvFs> {
    Init,
    StartTransaction {
        start_transaction_fut: FS::StartTransactionFut,
    },
    InstantiateUnlinkCursor {
        next_staged_inode_unlink_ranges_index: usize,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable self.
        transaction: Option<FS::Transaction>,
    },
    AdvanceUnlinkCursor {
        cur_staged_inode_unlink_ranges_index: usize,
        cursor_next_fut: <FS::UnlinkCursor as NvFsUnlinkCursor<FS>>::NextFut,
    },
    UnlinkInode {
        cur_staged_inode_unlink_ranges_index: usize,
        cursor_unlink_fut: <FS::UnlinkCursor as NvFsUnlinkCursor<FS>>::UnlinkInodeFut,
    },
    WriteInodePrepare {
        next_staged_inode_writes_index: usize,
        // Is mandatory, lives in an Option<> only so that it can be taken out of a mutable self.
        transaction: Option<FS::Transaction>,
    },
    WriteInode {
        cur_staged_inode_writes_index: usize,
        write_fut: FS::WriteInodeFut,
    },
    CommitTransaction {
        commit_transaction_fut: FS::CommitTransactionFut,
    },
    Done,
}

impl<FS: NvFs> CommitPersistenceMultiOpFuture<FS> {
    /// Instantiate a [`CommitPersistenceMultiOpFuture`].
    ///
    /// # Arguments:
    ///
    /// * `ops` - The [`PersistenceMultiOp`] to commit to persistent storage.
    /// * `issue_sync` - Whether or not to issue a sync request to the underlying storage after the
    ///   writes have completed. That's best effort though and relies on the host to behave well.
    fn new(ops: PersistenceMultiOp, issue_sync: bool) -> Self {
        Self {
            ops,
            issue_sync,
            fut_state: CommitPersistenceMultiOpFutureState::Init,
        }
    }
}

impl<FS: NvFs> NvFsFuture<FS> for CommitPersistenceMultiOpFuture<FS>
where
    FS::Transaction: Send,
{
    type Output = Result<(), NvFsError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        fs_instance: &FS::SyncRcPtrRef<'_>,
        rng: &mut dyn rng::RngCoreDispatchable,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        // SAFETY: the Pin is only relevant for the inner NvFsFutures, and these all get repinned below.
        let this = unsafe { pin::Pin::into_inner_unchecked(self) };

        loop {
            match &mut this.fut_state {
                CommitPersistenceMultiOpFutureState::Init => {
                    // Complete early in case there's nothing to do.
                    if this.ops.inode_unlink_ranges.is_empty() && this.ops.inode_writes.is_empty() {
                        this.fut_state = CommitPersistenceMultiOpFutureState::Done;
                        return task::Poll::Ready(Ok(()));
                    }

                    this.fut_state = CommitPersistenceMultiOpFutureState::StartTransaction {
                        start_transaction_fut: FS::start_transaction(fs_instance, None),
                    };
                }
                CommitPersistenceMultiOpFutureState::StartTransaction {
                    start_transaction_fut,
                } => {
                    // SAFETY: is a projection Pin.
                    let start_transaction_fut =
                        unsafe { pin::Pin::new_unchecked(start_transaction_fut) };
                    let transaction =
                        match NvFsFuture::poll(start_transaction_fut, fs_instance, rng, cx) {
                            task::Poll::Ready(Ok(transaction)) => transaction,
                            task::Poll::Ready(Err(e)) => {
                                this.fut_state = CommitPersistenceMultiOpFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    // Proceed to apply the staged ops at the transaction. If there's nothing
                    // to unlink, proceed directly to handling the inode write ops.
                    this.fut_state = if !this.ops.inode_unlink_ranges.is_empty() {
                        CommitPersistenceMultiOpFutureState::InstantiateUnlinkCursor {
                            next_staged_inode_unlink_ranges_index: 0,
                            transaction: Some(transaction),
                        }
                    } else {
                        CommitPersistenceMultiOpFutureState::WriteInodePrepare {
                            next_staged_inode_writes_index: 0,
                            transaction: Some(transaction),
                        }
                    };
                }
                CommitPersistenceMultiOpFutureState::InstantiateUnlinkCursor {
                    next_staged_inode_unlink_ranges_index,
                    transaction,
                } => {
                    let transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => {
                            this.fut_state = CommitPersistenceMultiOpFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    if *next_staged_inode_unlink_ranges_index == this.ops.inode_unlink_ranges.len()
                    {
                        // All done with the unlinking ops, proceed to handling the inode writes, if any.
                        this.fut_state = CommitPersistenceMultiOpFutureState::WriteInodePrepare {
                            next_staged_inode_writes_index: 0,
                            transaction: Some(transaction),
                        };
                        continue;
                    }

                    let unlink_cursor = match FS::unlink_cursor(
                        fs_instance,
                        transaction,
                        this.ops.inode_unlink_ranges[*next_staged_inode_unlink_ranges_index]
                            .clone(),
                    ) {
                        Ok(Ok(unlink_cursor)) => unlink_cursor,
                        Err(e) | Ok(Err((_, e))) => {
                            if e == NvFsError::Retry {
                                // Our transaction became stale due to a concurrent NvFs transaction
                                // commit. Start all over.
                                this.fut_state = CommitPersistenceMultiOpFutureState::Init;
                                continue;
                            }

                            this.fut_state = CommitPersistenceMultiOpFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                    };

                    // Advance the unlink_cursor to the first existing inode in the range.
                    this.fut_state = CommitPersistenceMultiOpFutureState::AdvanceUnlinkCursor {
                        cur_staged_inode_unlink_ranges_index:
                            *next_staged_inode_unlink_ranges_index,
                        cursor_next_fut: unlink_cursor.next(),
                    };
                }
                CommitPersistenceMultiOpFutureState::AdvanceUnlinkCursor {
                    cur_staged_inode_unlink_ranges_index,
                    cursor_next_fut,
                } => {
                    // SAFETY: is a projection Pin.
                    let cursor_next_fut = unsafe { pin::Pin::new_unchecked(cursor_next_fut) };
                    let (unlink_cursor, at_end) =
                        match NvFsFuture::poll(cursor_next_fut, fs_instance, rng, cx) {
                            task::Poll::Ready(Ok((unlink_cursor, Ok(cur_inode)))) => {
                                (unlink_cursor, cur_inode.is_none())
                            }
                            task::Poll::Ready(Err(e) | Ok((_, Err(e)))) => {
                                if e == NvFsError::Retry {
                                    // Our transaction became stale due to a concurrent NvFs transaction
                                    // commit. Start all over.
                                    this.fut_state = CommitPersistenceMultiOpFutureState::Init;
                                    continue;
                                }

                                this.fut_state = CommitPersistenceMultiOpFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                            task::Poll::Pending => return task::Poll::Pending,
                        };

                    this.fut_state = if !at_end {
                        // Unlink the current inode at point.
                        CommitPersistenceMultiOpFutureState::UnlinkInode {
                            cur_staged_inode_unlink_ranges_index:
                                *cur_staged_inode_unlink_ranges_index,
                            cursor_unlink_fut: unlink_cursor.unlink_current_inode(),
                        }
                    } else {
                        // The current inode range has been exhausted. Proceed to the next, if any.
                        let transaction = match unlink_cursor.into_transaction() {
                            Ok(transaction) => transaction,
                            Err(e) => {
                                if e == NvFsError::Retry {
                                    // Our transaction became stale due to a concurrent NvFs transaction
                                    // commit. Start all over.
                                    this.fut_state = CommitPersistenceMultiOpFutureState::Init;
                                    continue;
                                }

                                this.fut_state = CommitPersistenceMultiOpFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                        };
                        CommitPersistenceMultiOpFutureState::InstantiateUnlinkCursor {
                            next_staged_inode_unlink_ranges_index:
                                *cur_staged_inode_unlink_ranges_index + 1,
                            transaction: Some(transaction),
                        }
                    };
                }
                CommitPersistenceMultiOpFutureState::UnlinkInode {
                    cur_staged_inode_unlink_ranges_index,
                    cursor_unlink_fut,
                } => {
                    // SAFETY: is a projection Pin.
                    let cursor_unlink_fut = unsafe { pin::Pin::new_unchecked(cursor_unlink_fut) };
                    let unlink_cursor =
                        match NvFsFuture::poll(cursor_unlink_fut, fs_instance, rng, cx) {
                            task::Poll::Ready(Ok((unlink_cursor, Ok(())))) => unlink_cursor,
                            task::Poll::Ready(Err(e) | Ok((_, Err(e)))) => {
                                if e == NvFsError::Retry {
                                    // Our transaction became stale due to a concurrent NvFs transaction
                                    // commit. Start all over.
                                    this.fut_state = CommitPersistenceMultiOpFutureState::Init;
                                    continue;
                                }

                                this.fut_state = CommitPersistenceMultiOpFutureState::Done;
                                return task::Poll::Ready(Err(e));
                            }
                            task::Poll::Pending => return task::Poll::Pending,
                        };
                    // Advance the unlink_cursor to the next inode in the range, if any.
                    this.fut_state = CommitPersistenceMultiOpFutureState::AdvanceUnlinkCursor {
                        cur_staged_inode_unlink_ranges_index: *cur_staged_inode_unlink_ranges_index,
                        cursor_next_fut: unlink_cursor.next(),
                    };
                }
                CommitPersistenceMultiOpFutureState::WriteInodePrepare {
                    next_staged_inode_writes_index,
                    transaction,
                } => {
                    let transaction = match transaction.take() {
                        Some(transaction) => transaction,
                        None => {
                            this.fut_state = CommitPersistenceMultiOpFutureState::Done;
                            return task::Poll::Ready(Err(nvfs_err_internal!()));
                        }
                    };

                    // If all pending inode write requests have been processed, proceed to the transaction commit.
                    if *next_staged_inode_writes_index == this.ops.inode_writes.len() {
                        this.fut_state = CommitPersistenceMultiOpFutureState::CommitTransaction {
                            commit_transaction_fut: FS::commit_transaction(
                                fs_instance,
                                transaction,
                                None,
                                None,
                                this.issue_sync,
                            ),
                        };
                        continue;
                    }

                    let (inode, data) = &mut this.ops.inode_writes[*next_staged_inode_writes_index];
                    let inode = *inode;
                    // Temporarily steal the data buffer. It will get returned back upon write_fut completion.
                    let data = mem::take(data);
                    this.fut_state = CommitPersistenceMultiOpFutureState::WriteInode {
                        cur_staged_inode_writes_index: *next_staged_inode_writes_index,
                        write_fut: FS::write_inode(fs_instance, transaction, inode, 0, 0, data),
                    };
                }
                CommitPersistenceMultiOpFutureState::WriteInode {
                    cur_staged_inode_writes_index,
                    write_fut,
                } => {
                    // SAFETY: is a projection Pin.
                    let write_fut = unsafe { pin::Pin::new_unchecked(write_fut) };
                    let transaction = match NvFsFuture::poll(write_fut, fs_instance, rng, cx) {
                        task::Poll::Ready((data, result)) => {
                            // Reinstall the temporarily stolen data back.
                            this.ops.inode_writes[*cur_staged_inode_writes_index].1 = data;

                            match result {
                                Ok((transaction, Ok(()))) => transaction,
                                Err(e) | Ok((_, Err(e))) => {
                                    if e == NvFsError::Retry {
                                        // Our transaction became stale due to a concurrent NvFs transaction
                                        // commit. Start all over.
                                        this.fut_state = CommitPersistenceMultiOpFutureState::Init;
                                        continue;
                                    }

                                    this.fut_state = CommitPersistenceMultiOpFutureState::Done;
                                    return task::Poll::Ready(Err(e));
                                }
                            }
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                    this.fut_state = CommitPersistenceMultiOpFutureState::WriteInodePrepare {
                        next_staged_inode_writes_index: *cur_staged_inode_writes_index + 1,
                        transaction: Some(transaction),
                    };
                }
                CommitPersistenceMultiOpFutureState::CommitTransaction {
                    commit_transaction_fut,
                } => {
                    // SAFETY: is a projection Pin.
                    let commit_transaction_fut =
                        unsafe { pin::Pin::new_unchecked(commit_transaction_fut) };
                    match NvFsFuture::poll(commit_transaction_fut, fs_instance, rng, cx) {
                        task::Poll::Ready(Ok(())) => {
                            // All done.
                            this.fut_state = CommitPersistenceMultiOpFutureState::Done;
                            return task::Poll::Ready(Ok(()));
                        }
                        task::Poll::Ready(Err(TransactionCommitError::LogStateClean {
                            reason: e,
                        })) => {
                            if e == NvFsError::Retry {
                                // Our transaction became stale due to a concurrent NvFs transaction
                                // commit. Start all over.
                                this.fut_state = CommitPersistenceMultiOpFutureState::Init;
                                continue;
                            }

                            this.fut_state = CommitPersistenceMultiOpFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Ready(Err(TransactionCommitError::LogStateIndeterminate {
                            reason: e,
                        })) => {
                            // In case the NvFs journal log is in an indeterminate state,
                            // something's seriously off. In order to avoid indefinite loops, do not
                            // attempt to retry on NvFsError::Retry. Note that NvFsError::Retry
                            // shouldn't get appear here anyway, but make the non-handling explicit.
                            this.fut_state = CommitPersistenceMultiOpFutureState::Done;
                            return task::Poll::Ready(Err(e));
                        }
                        task::Poll::Pending => return task::Poll::Pending,
                    };
                }
                CommitPersistenceMultiOpFutureState::Done => unreachable!(),
            }
        }
    }
}

/// Instantiate a [`CommitPersistenceMultiOpFuture`].
///
/// The [`CommitPersistenceMultiOpFuture`] is huge, and by instantiating it in an `inline(never)`
/// function and `Box`ing it right after, the stack allocations required for the moves are hopefully
/// getting freed up quickly again.
#[inline(never)]
fn instantiate_commit_multi_op_fut<FS: NvFs>(
    ops: PersistenceMultiOp,
    issue_sync: bool,
) -> Result<Box<CommitPersistenceMultiOpFuture<FS>>, NvFsError> {
    box_try_new(CommitPersistenceMultiOpFuture::new(ops, issue_sync)).map_err(NvFsError::from)
}

/// Synchronously commit a [`PersistenceMultiOp`] to storage.
///
/// Apply the operations staged at `ops` atomically to storage.
///
/// Any error propagated back to the caller indicates an actual problem -- in particular requests to
/// retry received from the backing filesystem implementation are handled transparently within
/// `persistence_commit_multi_op_sync()` itself.
///
/// # Arguments:
///
/// * `ops` - The [`PersistenceMultiOp`] to commit to persistent storage.
/// * `issue_sync` - Whether or not to issue a sync request to the underlying storage after the
///   writes have completed. That's best effort though and relies on the host to behave well.
#[allow(unused)]
pub fn persistence_commit_multi_op_sync(
    ops: PersistenceMultiOp,
    issue_sync: bool,
) -> Result<(), SvsmError> {
    let fs_instance = match SVSM_COCOONFS_INSTANCE.try_get_inner().ok() {
        Some(fs_instance) => <pin::Pin<SvsmCocoonFsSyncRcPtrType> as sync_types::SyncRcPtr<
            SvsmCocoonFsType,
        >>::as_ref(fs_instance),
        None => {
            return Err(SvsmError::FileSystem(FsError::NotSupported));
        }
    };

    let mut rng = match get_svsm_rng() {
        Ok(rng) => rng,
        Err(e) => {
            log::error!("persistence read: failed to get rng instance: {e:?}");
            return Err(nvfs_error_to_svsm_error(NvFsError::from(e)));
        }
    };

    instantiate_commit_multi_op_fut::<SvsmCocoonFsType>(ops, issue_sync)
        .and_then(|mut commit_multi_op_fut| {
            task_busypoll_to_completion(|cx| {
                NvFsFuture::poll(
                    pin::Pin::new(&mut *commit_multi_op_fut),
                    &fs_instance,
                    &mut rng,
                    cx,
                )
            })
        })
        .map_err(nvfs_error_to_svsm_error)
}

/// The 64-bit CocoonFS inode number is split into two halves: the upper
/// 32 bits are statically assigned to each service here, and the lower
/// 32 bits are managed by the service itself. Namespace 0 is reserved:
/// although CocoonFS currently only reserves the first 16 inodes for
/// internal use, all inodes with the upper 32 bits set to zero are kept
/// reserved for simplicity.
#[derive(Clone, Copy, Debug)]
#[repr(u32)]
pub enum InodeNamespace {
    Reserved = 0,
    Tpm = 1,
    Uefi = 2,
}

impl InodeNamespace {
    fn inode(self, local: u32) -> u64 {
        (self as u64) << 32 | local as u64
    }
}

/// Trait for subsystem-specific inode enums.
///
/// SVSM services can define their own enum of local inode numbers and
/// implement this trait to bind it to an [`InodeNamespace`]. The
/// [`inode()`](Inode::inode) method combines the namespace and local
/// index into a full 64-bit inode number.
pub trait Inode: Into<u32> {
    const NAMESPACE: InodeNamespace;

    fn inode(self) -> u64 {
        const {
            assert!(!matches!(Self::NAMESPACE, InodeNamespace::Reserved));
        }
        Self::NAMESPACE.inode(self.into())
    }
}
