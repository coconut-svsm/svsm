// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2025-2026 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Functionality related to persistent SVSM storage.

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

use core::{fmt::Debug, future::Future, ops, pin, task};

use cocoon_tpm_storage::{
    blkdev::{
        NvBlkDev, NvBlkDevFuture, NvBlkDevIoError, NvBlkDevReadRequest, NvBlkDevWriteRequest,
    },
    fs::{
        NvFs, NvFsError, NvFsFuture, NvFsIoError, TransactionCommitError,
        cocoonfs::{self, CocoonFs},
    },
    nvblkdev_err_internal,
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

/// Convert a [`SvsmError` to a [`NvBlkDevIoError`].
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
            let dev_block_id = (this.io_block_index + i) >> dev_io_block_size_128b_log2;
            let dev_block_id = match usize::try_from(dev_block_id) {
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
    /// Access the matadata.
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
    // or one with with a mkfsinfo header, which will get formatted transparently at first
    // filesystem opening time.
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

/// Persistence inode numbers allocated statically for specific SVSM uses.
///
/// Usable inode numbers start at `6`.
#[derive(Debug)]
#[repr(u64)]
pub enum SvsmPersistenceStaticInode {
    Demo = 16u64,
}

pub fn persistence_demo() {
    if !persistence_available() {
        return;
    }

    let data = match persistence_read_inode_sync(SvsmPersistenceStaticInode::Demo as u64) {
        Ok(data) => data,
        Err(_) => {
            log::error!("persistence demo: failed to read inode data");
            return;
        }
    };
    let mut boot_counter = match data {
        Some(data) => {
            let mut boot_counter = [0u8; 4];
            let l = data.len().min(4);
            boot_counter[..l].copy_from_slice(&data[..l]);
            let boot_counter = u32::from_le_bytes(boot_counter);
            log::info!("persistence demo: boot counter read back is {boot_counter}");
            boot_counter
        }
        None => {
            log::info!("persistence demo: no boot counter found yet");
            0
        }
    };

    boot_counter += 1;

    // This splats on allocation failure, but it's only a demo.
    let data = Zeroizing::new(boot_counter.to_le_bytes().to_vec());
    match persistence_write_inode_sync(SvsmPersistenceStaticInode::Demo as u64, data, true) {
        Ok(_) => log::info!("persistence demo: successfully wrote updated boot counter"),
        Err(e) => log::error!("persistence demo: boot counter updating write failed: {e:?})"),
    };
}
