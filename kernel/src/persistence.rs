// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Functionality related to persistent SVSM storage.

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

use core::{fmt::Debug, future::Future, pin, task};

use cocoon_tpm_storage::{
    blkdev::{
        NvBlkDev, NvBlkDevFuture, NvBlkDevIoError, NvBlkDevReadRequest, NvBlkDevWriteRequest,
    },
    fs::{
        cocoonfs::{self, CocoonFs},
        NvFsError, NvFsIoError,
    },
    nvblkdev_err_internal,
};
use cocoon_tpm_utils_async::sync_types;
use cocoon_tpm_utils_common::{alloc::box_try_new, fixed_vec::FixedVec, zeroize::Zeroizing};

use crate::address::PhysAddr;
use crate::block::{api::BlockDriver, virtio_blk::VirtIOBlkDriver, BlockDeviceError};
use crate::crypto::get_svsm_rng;
use crate::error::SvsmError;
use crate::fw_cfg::FwCfg;
use crate::mm::alloc::AllocError;
use crate::platform::SVSM_PLATFORM;
use crate::r#async::{task_busypoll_to_completion, SvsmSyncTypes};
use crate::types::PAGE_SHIFT;
use crate::utils::immut_after_init::ImmutAfterInitCell;

/// Wrapper around [`BlockDriver`] implementors, itself implementing the `cocoon-tpm-storage`
/// crate's [`NvBlkDev`] block device abstraction.
struct SvsmNvBlkDev {
    driver: Box<dyn BlockDriver + Send + Sync>,
    io_block_size_128b_log2: u32,
}

impl SvsmNvBlkDev {
    fn new(driver: Box<dyn BlockDriver + Send + Sync>) -> Self {
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

impl NvBlkDev for SvsmNvBlkDev {
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

impl Debug for SvsmNvBlkDev {
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

impl NvBlkDevFuture<SvsmNvBlkDev> for SvsmNvBlkDevResizeFuture {
    type Output = Result<(), NvBlkDevIoError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        _dev: &SvsmNvBlkDev,
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

impl<R: NvBlkDevReadRequest> NvBlkDevFuture<SvsmNvBlkDev> for SvsmNvBlkDevReadFuture<R> {
    type Output = Result<(R, Result<(), NvBlkDevIoError>), NvBlkDevIoError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        dev: &SvsmNvBlkDev,
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
                            "block device read failed: error={:?}, position={}, size={}",
                            e,
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
                        "block device read failed: error={:?}, position={}, size={}",
                        e,
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

impl<R: NvBlkDevWriteRequest> NvBlkDevFuture<SvsmNvBlkDev> for SvsmNvBlkDevWriteFuture<R> {
    type Output = Result<(R, Result<(), NvBlkDevIoError>), NvBlkDevIoError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        dev: &SvsmNvBlkDev,
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
                            "block device write failed: error={:?}, position={}, size={}",
                            e,
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
                        "block device write failed: error={:?}, position={}, size={}",
                        e,
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

/// [`NvBlkDev::WriteSyncFuture`] implementation for [`SvsmNvBlkDev`].
///
/// Also used for the [`NvBlkDev::WriteBarrierFuture`].
#[derive(Debug)]
struct SvsmNvBlkDevWriteSyncFuture;

impl NvBlkDevFuture<SvsmNvBlkDev> for SvsmNvBlkDevWriteSyncFuture {
    type Output = Result<(), NvBlkDevIoError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        dev: &SvsmNvBlkDev,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        if let Err(e) = dev.driver.flush() {
            log::error!("block device flush request failed: error={:?}", e);
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

impl NvBlkDevFuture<SvsmNvBlkDev> for SvsmNvBlkDevTrimFuture {
    type Output = Result<(), NvBlkDevIoError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        dev: &SvsmNvBlkDev,
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
                    "block device zeroization write failed: error={:?}, position={}, size={}",
                    e,
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

type SvsmCocoonFsType = CocoonFs<SvsmSyncTypes, SvsmNvBlkDev>;
type SvsmCocoonFsSyncRcPtrType =
    <<SvsmSyncTypes as sync_types::SyncTypes>::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>
    ::SyncRcPtr<SvsmCocoonFsType>;

static SVSM_COCOONFS_INSTANCE: ImmutAfterInitCell<Option<pin::Pin<SvsmCocoonFsSyncRcPtrType>>> =
    ImmutAfterInitCell::uninit();

/// Instantiate a [`cocoonfs::OpenFsFuture`].
///
/// The `cocoonfs::OpenFsFuture` is huge, and by instantiating it in an `inline(never)` function and
/// `Box`ing it right after, the stack allocations required for the moves are hopefully getting
/// freed up quickly again.
#[inline(never)]
fn instantiate_cocoonfs_open_fut(
    blkdev: SvsmNvBlkDev,
    key: Zeroizing<Vec<u8>>,
) -> Result<Box<cocoonfs::OpenFsFuture<SvsmSyncTypes, SvsmNvBlkDev>>, NvFsError> {
    let rng = box_try_new(get_svsm_rng().map_err(NvFsError::from)?).map_err(NvFsError::from)?;
    let cocoonfs_open_fut = match cocoonfs::OpenFsFuture::new(blkdev, key, false, rng) {
        Ok(cocoonfs_open_fut) => cocoonfs_open_fut,
        Err((_blkdev, _key, _rng, e)) => return Err(e),
    };
    box_try_new(cocoonfs_open_fut).map_err(NvFsError::from)
}

/// Initialize the persistence subsystem.
///
/// Must get invoked at most once at startup, any subsequent reinitialization attempt will result in
/// a panic.
///
/// Iterate over available block devices and attempt to open a CocoonFs instance with the provided
/// `key` on each, until one that works has been found. Any CocoonFs instances that appear to have a
/// valid filesystem, header but that could not get opened successfully, e.g. because the
/// authentication with `key` failed, are getting reported in the log and being skipped over. In
/// case a CocoonFs "filesystem creation info header" is being encountered in the search, the
/// filesystem is formatted for use with `key` in the course.
///
/// The first successfully opened CocoonFs instance, if any, will henceforth be used to serve all
/// the SVSM's persistence related needs.
///
/// # Arguments:
///
/// * `key` - The CocoonFs root key used (indirectly) for authentication and encryption.
pub fn persistence_init(mut key: Zeroizing<Vec<u8>>) -> Result<(), SvsmError> {
    // Iterate through all Virtio block devices and see if there's a CocoonFs on it, either already
    // formatted or one with with a mkfsinfo header, which will get formatted transparently at first
    // filesystem opening time.
    log::debug!("attempting to find persistent CocoonFs storage...");
    let cfg = FwCfg::new(SVSM_PLATFORM.get_io_port());
    for virtio_blk in cfg
        .get_virtio_mmio_addresses()
        .unwrap_or_default()
        .iter()
        .filter_map(|a| VirtIOBlkDriver::new(PhysAddr::from(*a)).ok())
    {
        let virtio_blk =
            box_try_new(virtio_blk).map_err(|_| SvsmError::Alloc(AllocError::OutOfMemory))?;
        let blkdev = SvsmNvBlkDev::new(virtio_blk);
        let mut cocoonfs_open_fut = match instantiate_cocoonfs_open_fut(blkdev, key) {
            Ok(cocoonfs_open_fut) => cocoonfs_open_fut,
            Err(e) => {
                log::error!("failed to initiate CocoonFs opening operation: {:?}", e);
                return Err(nvfs_error_to_svsm_error(e));
            }
        };

        key = match task_busypoll_to_completion(|cx| {
            Future::poll(pin::Pin::new(&mut cocoonfs_open_fut), cx)
        }) {
            Ok((_rng, Ok(cocoonfs_instance))) => {
                SVSM_COCOONFS_INSTANCE
                    .init(Some(cocoonfs_instance))
                    .expect("SVSM CocoonFs instance already initialized");
                log::info!("persistent CocoonFs storage opened successfully");
                return Ok(());
            }
            Ok((_rng, Err((_chip, key, e)))) => {
                if e == NvFsError::from(cocoonfs::FormatError::InvalidImageHeaderMagic) {
                    log::debug!("skipping over block device with no CocoonFs header");
                } else if e == NvFsError::from(cocoonfs::FormatError::InvalidImageHeaderChecksum) {
                    log::warn!("skipping over block device with invalid CocoonFs header checksum");
                } else {
                    log::error!(
                        "failed to open CocoonFs block device: {:?}, trying next one, if any",
                        e
                    );
                }
                key
            }
            Err(e) => {
                // If not even the key is getting returned back, it's likely an internal error of
                // the implementation.
                log::error!("failed to open CocoonFs block device: {:?}", e);
                return Err(nvfs_error_to_svsm_error(e));
            }
        };
    }

    // No CocoonFs block device available.
    log::info!("no persistent CocoonFs storage found");
    SVSM_COCOONFS_INSTANCE
        .init(None)
        .expect("SVSM CocoonFs instance already initialized");

    Ok(())
}

/// Test whether persistence functionality is available.
///
/// Persistence functionality is available only if a block device with a valid CocoonFs instance on
/// it could get opened successfully from [`persistence_init()`].
///
/// `persistence_available()` may get invoked even if [`persistence_init()`] has not been run at all,
/// in which case it would report `false`.
pub fn persistence_available() -> bool {
    SVSM_COCOONFS_INSTANCE
        .try_get_inner()
        .ok()
        .and_then(|i| i.as_ref())
        .is_some()
}
