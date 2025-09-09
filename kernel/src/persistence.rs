// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Functionality related to persistent SVSM storage.

extern crate alloc;
use alloc::boxed::Box;

use core::{fmt::Debug, pin, task};

use cocoon_tpm_storage::{
    chip::{NvChip, NvChipFuture, NvChipIoError, NvChipReadRequest, NvChipWriteRequest},
    nvchip_err_internal,
};
use cocoon_tpm_utils_common::fixed_vec::FixedVec;

use crate::block::{api::BlockDriver, BlockDeviceError};
use crate::error::SvsmError;
use crate::mm::alloc::AllocError;
use crate::types::PAGE_SHIFT;

/// Wrapper around [`BlockDriver`] implementors, itself implementing the `cocoon-tpm-storage`
/// crate's [`NvChip`] block device abstraction.
pub struct SvsmBlockDriverNvChip {
    driver: Box<dyn BlockDriver + Send + Sync>,
    io_block_size_128b_log2: u32,
}

impl SvsmBlockDriverNvChip {
    fn new(driver: Box<dyn BlockDriver + Send + Sync>) -> Self {
        // We got to store the block size in order to avoid TOCTOU issues, c.f. the
        // Nvchip::chip_io_block_size_128b_log2() docs.
        let io_block_size_log2 = driver.block_size_log2() as u32;
        let io_block_size_128b_log2 = io_block_size_log2.saturating_sub(7);
        Self {
            driver,
            io_block_size_128b_log2,
        }
    }
}

impl NvChip for SvsmBlockDriverNvChip {
    fn chip_io_block_size_128b_log2(&self) -> u32 {
        self.io_block_size_128b_log2
    }

    fn chip_io_blocks(&self) -> u64 {
        ((self.driver.size() as u64) >> self.io_block_size_128b_log2) >> 7
    }

    fn preferred_chip_io_blocks_bulk_log2(&self) -> u32 {
        (PAGE_SHIFT as u32)
            .saturating_sub(self.io_block_size_128b_log2)
            .saturating_sub(7)
    }

    type ResizeFuture = SvsmBlockDriverNvChipResizeFuture;

    fn resize(&self, _chip_io_blocks_count: u64) -> Result<Self::ResizeFuture, NvChipIoError> {
        Ok(SvsmBlockDriverNvChipResizeFuture)
    }

    type ReadFuture<R: NvChipReadRequest> = SvsmBlockDriverNvChipReadFuture<R>;

    fn read<R: NvChipReadRequest>(
        &self,
        request: R,
    ) -> Result<Result<Self::ReadFuture<R>, (R, NvChipIoError)>, NvChipIoError> {
        Ok(Ok(SvsmBlockDriverNvChipReadFuture {
            request: Some(request),
            bounce_buffer: FixedVec::new_empty(),
        }))
    }

    type WriteFuture<R: NvChipWriteRequest> = SvsmBlockDriverNvChipWriteFuture<R>;

    fn write<R: NvChipWriteRequest>(
        &self,
        request: R,
    ) -> Result<Result<Self::WriteFuture<R>, (R, NvChipIoError)>, NvChipIoError> {
        Ok(Ok(SvsmBlockDriverNvChipWriteFuture {
            request: Some(request),
            bounce_buffer: FixedVec::new_empty(),
        }))
    }

    type WriteBarrierFuture = SvsmBlockDriverNvChipWriteSyncFuture;

    fn write_barrier(&self) -> Result<Self::WriteBarrierFuture, NvChipIoError> {
        Ok(SvsmBlockDriverNvChipWriteSyncFuture)
    }

    type WriteSyncFuture = SvsmBlockDriverNvChipWriteSyncFuture;

    fn write_sync(&self) -> Result<Self::WriteSyncFuture, NvChipIoError> {
        Ok(SvsmBlockDriverNvChipWriteSyncFuture)
    }

    type TrimFuture = SvsmBlockDriverNvChipTrimFuture;

    fn trim(
        &self,
        chip_io_block_index: u64,
        chip_io_blocks_count: u64,
    ) -> Result<Self::TrimFuture, NvChipIoError> {
        Ok(SvsmBlockDriverNvChipTrimFuture {
            chip_io_block_index,
            chip_io_blocks_count,
            zeroes_buffer: FixedVec::new_empty(),
        })
    }
}

impl Debug for SvsmBlockDriverNvChip {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SvsmBlockDriverNvChip").finish()
    }
}

/// Convert a [`SvsmError` to a [`NvChipIoError`].
fn svsm_error_to_chip_io_error(e: SvsmError) -> NvChipIoError {
    match e {
        SvsmError::Block(BlockDeviceError::Failed) => NvChipIoError::IoFailure,
        SvsmError::Alloc(AllocError::OutOfMemory) => NvChipIoError::MemoryAllocationFailure,
        _ => NvChipIoError::IoFailure,
    }
}

/// [`NvChip::ResizeFuture`] implementation for [`SvsmBlockDriverNvChip`].
#[derive(Debug)]
pub struct SvsmBlockDriverNvChipResizeFuture;

impl NvChipFuture<SvsmBlockDriverNvChip> for SvsmBlockDriverNvChipResizeFuture {
    type Output = Result<(), NvChipIoError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        _chip: &SvsmBlockDriverNvChip,
        _cx: &mut core::task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        task::Poll::Ready(Err(NvChipIoError::OperationNotSupported))
    }
}

/// [`NvChip::ReadFuture`] implementation for [`SvsmBlockDriverNvChip`].
#[derive(Debug)]
pub struct SvsmBlockDriverNvChipReadFuture<R: NvChipReadRequest> {
    request: Option<R>,
    bounce_buffer: FixedVec<u8, 7>,
}

impl<R: NvChipReadRequest> NvChipFuture<SvsmBlockDriverNvChip>
    for SvsmBlockDriverNvChipReadFuture<R>
{
    type Output = Result<(R, Result<(), NvChipIoError>), NvChipIoError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        chip: &SvsmBlockDriverNvChip,
        _cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();
        let preferred_chip_io_blocks_bulk_log2 = chip.preferred_chip_io_blocks_bulk_log2();
        let chip_io_blocks = chip.chip_io_blocks();

        let this = pin::Pin::into_inner(self);
        let mut request = match this.request.take() {
            Some(request) => request,
            None => return task::Poll::Ready(Err(nvchip_err_internal!())),
        };

        let region = request.region().clone();
        if region.chunk_size_128b_log2() >= chip_io_block_size_128b_log2 {
            // The buffers are all larger than (by a fixed power of two multiple of) the
            // device block size. No bounce buffer needed.
            let block_size_128b_log2 = if region.is_aligned(region.chunk_size_128b_log2()) {
                region.chunk_size_128b_log2()
            } else if region.chunk_size_128b_log2()
                >= preferred_chip_io_blocks_bulk_log2 + chip_io_block_size_128b_log2
                && region
                    .is_aligned(preferred_chip_io_blocks_bulk_log2 + chip_io_block_size_128b_log2)
            {
                preferred_chip_io_blocks_bulk_log2 + chip_io_block_size_128b_log2
            } else {
                debug_assert!(region.is_aligned(chip_io_block_size_128b_log2));
                chip_io_block_size_128b_log2
            };
            let blocks_iter = match region.aligned_blocks_iter(block_size_128b_log2) {
                Ok(blocks_iter) => blocks_iter,
                Err(_) => return task::Poll::Ready(Ok((request, Err(nvchip_err_internal!())))),
            };
            for (physical_block_index, block_chunks) in blocks_iter {
                let block_begin_128b = physical_block_index << block_size_128b_log2;
                if block_begin_128b >= chip_io_blocks << chip_io_block_size_128b_log2
                    || ((chip_io_blocks << chip_io_block_size_128b_log2) - block_begin_128b)
                        >> block_size_128b_log2
                        == 0
                {
                    return task::Poll::Ready(Ok((request, Err(NvChipIoError::IoBlockOutOfRange))));
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

                    let chip_block_id =
                        (block_begin_128b + offset_in_block_128b) >> chip_io_block_size_128b_log2;
                    let chip_block_id = match usize::try_from(chip_block_id) {
                        Ok(chip_block_id) => chip_block_id,
                        Err(_) => {
                            // The chip_io_blocks has been derived from BlockDriver::size(),
                            // which is an usize.
                            return task::Poll::Ready(Ok((request, Err(nvchip_err_internal!()))));
                        }
                    };
                    if let Err(e) = chip.driver.read_blocks(chip_block_id, buf) {
                        log::error!(
                            "block device read failed: error={:?}, position={}, size={}",
                            e,
                            (block_begin_128b + offset_in_block_128b) << 7,
                            1u64 << (block_size_128b_log2 + 7)
                        );
                        return task::Poll::Ready(Ok((
                            request,
                            Err(svsm_error_to_chip_io_error(e)),
                        )));
                    }
                }
            }
        } else {
            // The buffers are smaller than the volume block size, going through the bounce
            // buffer is necessary.
            let block_size_128b_log2 = chip_io_block_size_128b_log2;

            if this.bounce_buffer.is_empty() {
                this.bounce_buffer =
                    match FixedVec::new_with_default(1usize << (block_size_128b_log2 + 7)) {
                        Ok(bounce_buffer) => bounce_buffer,
                        Err(_) => {
                            return task::Poll::Ready(Ok((
                                request,
                                Err(NvChipIoError::MemoryAllocationFailure),
                            )));
                        }
                    };
            }

            let blocks_iter = match region.aligned_blocks_iter(block_size_128b_log2) {
                Ok(blocks_iter) => blocks_iter,
                Err(_) => return task::Poll::Ready(Ok((request, Err(nvchip_err_internal!())))),
            };
            for (physical_block_index, block_chunks) in blocks_iter {
                let block_begin_128b = physical_block_index << block_size_128b_log2;
                if block_begin_128b >= chip_io_blocks << chip_io_block_size_128b_log2
                    || ((chip_io_blocks << chip_io_block_size_128b_log2) - block_begin_128b)
                        >> block_size_128b_log2
                        == 0
                {
                    return task::Poll::Ready(Ok((request, Err(NvChipIoError::IoBlockOutOfRange))));
                }

                let chip_block_id = block_begin_128b >> chip_io_block_size_128b_log2;
                let chip_block_id = match usize::try_from(chip_block_id) {
                    Ok(chip_block_id) => chip_block_id,
                    Err(_) => {
                        // The chip_io_blocks has been derived from BlockDriver::size(),
                        // which is an usize.
                        return task::Poll::Ready(Ok((request, Err(nvchip_err_internal!()))));
                    }
                };
                if let Err(e) = chip
                    .driver
                    .read_blocks(chip_block_id, &mut this.bounce_buffer)
                {
                    log::error!(
                        "block device read failed: error={:?}, position={}, size={}",
                        e,
                        block_begin_128b << 7,
                        1u64 << (block_size_128b_log2 + 7)
                    );
                    return task::Poll::Ready(Ok((request, Err(svsm_error_to_chip_io_error(e)))));
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

/// [`NvChip::WriteFuture`] implementation for [`SvsmBlockDriverNvChip`].
#[derive(Debug)]
pub struct SvsmBlockDriverNvChipWriteFuture<R: NvChipWriteRequest> {
    request: Option<R>,
    bounce_buffer: FixedVec<u8, 7>,
}

impl<R: NvChipWriteRequest> NvChipFuture<SvsmBlockDriverNvChip>
    for SvsmBlockDriverNvChipWriteFuture<R>
{
    type Output = Result<(R, Result<(), NvChipIoError>), NvChipIoError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        chip: &SvsmBlockDriverNvChip,
        _cx: &mut task::Context<'_>,
    ) -> task::Poll<Self::Output> {
        let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();
        let preferred_chip_io_blocks_bulk_log2 = chip.preferred_chip_io_blocks_bulk_log2();
        let chip_io_blocks = chip.chip_io_blocks();

        let this = pin::Pin::into_inner(self);
        let request = match this.request.take() {
            Some(request) => request,
            None => return task::Poll::Ready(Err(nvchip_err_internal!())),
        };

        let region = request.region().clone();
        if region.chunk_size_128b_log2() >= chip_io_block_size_128b_log2 {
            // The buffers are all larger than (by a fixed power of two multiple of) the
            // volume block size. No bounce buffer needed.
            let block_size_128b_log2 = if region.is_aligned(region.chunk_size_128b_log2()) {
                region.chunk_size_128b_log2()
            } else if region.chunk_size_128b_log2()
                >= preferred_chip_io_blocks_bulk_log2 + chip_io_block_size_128b_log2
                && region
                    .is_aligned(preferred_chip_io_blocks_bulk_log2 + chip_io_block_size_128b_log2)
            {
                preferred_chip_io_blocks_bulk_log2 + chip_io_block_size_128b_log2
            } else {
                debug_assert!(region.is_aligned(chip_io_block_size_128b_log2));
                chip_io_block_size_128b_log2
            };
            let blocks_iter = match region.aligned_blocks_iter(block_size_128b_log2) {
                Ok(blocks_iter) => blocks_iter,
                Err(_) => return task::Poll::Ready(Ok((request, Err(nvchip_err_internal!())))),
            };
            for (physical_block_index, block_chunks) in blocks_iter {
                let block_begin_128b = physical_block_index << block_size_128b_log2;
                if block_begin_128b >= chip_io_blocks << chip_io_block_size_128b_log2
                    || ((chip_io_blocks << chip_io_block_size_128b_log2) - block_begin_128b)
                        >> block_size_128b_log2
                        == 0
                {
                    return task::Poll::Ready(Ok((request, Err(NvChipIoError::IoBlockOutOfRange))));
                }

                for (offset_in_block_128b, chunk_range) in block_chunks {
                    // The buffer size is >= the iteration block size.
                    debug_assert_eq!(offset_in_block_128b, 0);
                    let buf = match request.get_source_buffer(&chunk_range) {
                        Ok(buf) => buf,
                        Err(e) => return task::Poll::Ready(Ok((request, Err(e)))),
                    };

                    let chip_block_id =
                        (block_begin_128b + offset_in_block_128b) >> chip_io_block_size_128b_log2;
                    let chip_block_id = match usize::try_from(chip_block_id) {
                        Ok(chip_block_id) => chip_block_id,
                        Err(_) => {
                            // The chip_io_blocks has been derived from BlockDriver::size(),
                            // which is an usize.
                            return task::Poll::Ready(Ok((request, Err(nvchip_err_internal!()))));
                        }
                    };
                    if let Err(e) = chip.driver.write_blocks(chip_block_id, buf) {
                        log::error!(
                            "block device write failed: error={:?}, position={}, size={}",
                            e,
                            (block_begin_128b + offset_in_block_128b) << 7,
                            1u64 << (block_size_128b_log2 + 7)
                        );
                        return task::Poll::Ready(Ok((
                            request,
                            Err(svsm_error_to_chip_io_error(e)),
                        )));
                    }
                }
            }
        } else {
            // The buffers are smaller than the volume block size, going through the bounce
            // buffer is necessary.
            let block_size_128b_log2 = chip_io_block_size_128b_log2;

            if this.bounce_buffer.is_empty() {
                this.bounce_buffer =
                    match FixedVec::new_with_default(1usize << (block_size_128b_log2 + 7)) {
                        Ok(bounce_buffer) => bounce_buffer,
                        Err(_) => {
                            return task::Poll::Ready(Ok((
                                request,
                                Err(NvChipIoError::MemoryAllocationFailure),
                            )));
                        }
                    };
            }

            let blocks_iter = match region.aligned_blocks_iter(block_size_128b_log2) {
                Ok(blocks_iter) => blocks_iter,
                Err(_) => return task::Poll::Ready(Ok((request, Err(nvchip_err_internal!())))),
            };
            for (physical_block_index, block_chunks) in blocks_iter {
                let block_begin_128b = physical_block_index << block_size_128b_log2;
                if block_begin_128b >= chip_io_blocks << chip_io_block_size_128b_log2
                    || ((chip_io_blocks << chip_io_block_size_128b_log2) - block_begin_128b)
                        >> block_size_128b_log2
                        == 0
                {
                    return task::Poll::Ready(Ok((request, Err(NvChipIoError::IoBlockOutOfRange))));
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

                let chip_block_id = block_begin_128b >> chip_io_block_size_128b_log2;
                let chip_block_id = match usize::try_from(chip_block_id) {
                    Ok(chip_block_id) => chip_block_id,
                    Err(_) => {
                        // The chip_io_blocks has been derived from BlockDriver::size(),
                        // which is an usize.
                        return task::Poll::Ready(Ok((request, Err(nvchip_err_internal!()))));
                    }
                };
                if let Err(e) = chip.driver.write_blocks(chip_block_id, &this.bounce_buffer) {
                    log::error!(
                        "block device write failed: error={:?}, position={}, size={}",
                        e,
                        block_begin_128b << 7,
                        1u64 << (block_size_128b_log2 + 7)
                    );
                    return task::Poll::Ready(Ok((request, Err(svsm_error_to_chip_io_error(e)))));
                }
            }
        }

        task::Poll::Ready(Ok((request, Ok(()))))
    }
}

/// [`NvChip::WriteSyncFuture`] implementation for [`SvsmBlockDriverNvChip`].
///
/// Also used for the [`NvChip::WriteBarrierFuture`].
#[derive(Debug)]
pub struct SvsmBlockDriverNvChipWriteSyncFuture;

impl NvChipFuture<SvsmBlockDriverNvChip> for SvsmBlockDriverNvChipWriteSyncFuture {
    type Output = Result<(), NvChipIoError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        chip: &SvsmBlockDriverNvChip,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        if let Err(e) = chip.driver.flush() {
            log::error!("block device flush request failed: error={:?}", e);
            return task::Poll::Ready(Err(svsm_error_to_chip_io_error(e)));
        }

        task::Poll::Ready(Ok(()))
    }
}

/// [`NvChip::TrimFuture`] implementation for [`SvsmBlockDriverNvChip`].
#[derive(Debug)]
pub struct SvsmBlockDriverNvChipTrimFuture {
    chip_io_block_index: u64,
    chip_io_blocks_count: u64,
    zeroes_buffer: FixedVec<u8, 7>,
}

impl NvChipFuture<SvsmBlockDriverNvChip> for SvsmBlockDriverNvChipTrimFuture {
    type Output = Result<(), NvChipIoError>;

    fn poll(
        self: pin::Pin<&mut Self>,
        chip: &SvsmBlockDriverNvChip,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        // The BlockDriver trait, and ultimately the VirtIOBlk, don't seem to provide DISCARD
        // functionality. Write zeroes so that the host can still apply compression (if trimming is
        // even enabled for the filesystem instance).
        let chip_io_block_size_128b_log2 = chip.chip_io_block_size_128b_log2();
        let chip_io_blocks = chip.chip_io_blocks();
        if self.chip_io_blocks_count == 0 {
            return task::Poll::Ready(Ok(()));
        } else if self.chip_io_block_index > chip_io_blocks
            || chip_io_blocks - self.chip_io_block_index < self.chip_io_blocks_count
        {
            return task::Poll::Ready(Err(NvChipIoError::IoBlockOutOfRange));
        }

        let this = pin::Pin::into_inner(self);
        if this.zeroes_buffer.is_empty() {
            this.zeroes_buffer =
                match FixedVec::new_with_default(1usize << (chip_io_block_size_128b_log2 + 7)) {
                    Ok(zeroes_buffer) => zeroes_buffer,
                    Err(_) => {
                        return task::Poll::Ready(Err(NvChipIoError::MemoryAllocationFailure));
                    }
                };
        }

        for i in 0..this.chip_io_blocks_count {
            let chip_block_id = (this.chip_io_block_index + i) >> chip_io_block_size_128b_log2;
            let chip_block_id = match usize::try_from(chip_block_id) {
                Ok(chip_block_id) => chip_block_id,
                Err(_) => {
                    // The chip_io_blocks has been derived from BlockDriver::size(),
                    // which is an usize.
                    return task::Poll::Ready(Err(nvchip_err_internal!()));
                }
            };
            if let Err(e) = chip.driver.write_blocks(chip_block_id, &this.zeroes_buffer) {
                log::error!(
                    "block device zeroization write failed: error={:?}, position={}, size={}",
                    e,
                    (chip_block_id as u64) << (chip_io_block_size_128b_log2 + 7),
                    1u64 << (chip_io_block_size_128b_log2 + 7)
                );
                return task::Poll::Ready(Err(svsm_error_to_chip_io_error(e)));
            }
        }

        task::Poll::Ready(Ok(()))
    }
}
