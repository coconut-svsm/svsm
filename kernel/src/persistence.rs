// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Functionality related to persistent SVSM storage.

extern crate alloc;
use alloc::boxed::Box;

use core::{fmt::Debug, pin, task};

use cocoon_tpm_storage::{
    blkdev::{
        NvBlkDev, NvBlkDevFuture, NvBlkDevIoError, NvBlkDevReadRequest, NvBlkDevWriteRequest,
    },
    nvblkdev_err_internal,
};
use cocoon_tpm_utils_common::fixed_vec::FixedVec;

use crate::block::{api::BlockDriver, BlockDeviceError};
use crate::error::SvsmError;
use crate::mm::alloc::AllocError;
use crate::types::PAGE_SHIFT;

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
