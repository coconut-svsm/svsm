// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Functionality related to persistent SVSM storage.

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

use core::{fmt::Debug, future::Future, pin, task};

use cocoon_tpm_storage::{
    chip::{NvChip, NvChipFuture, NvChipIoError, NvChipReadRequest, NvChipWriteRequest},
    fs::{
        cocoonfs::{CocoonFs, CocoonFsFormatError, CocoonFsOpenFsFuture},
        NvFs, NvFsError, NvFsFuture, NvFsIoError, TransactionCommitError,
    },
    nvchip_err_internal,
};
use cocoon_tpm_utils_async::sync_types;
use cocoon_tpm_utils_common::{alloc::box_try_new, fixed_vec::FixedVec, zeroize::Zeroizing};

use crate::address::PhysAddr;
use crate::block::{api::BlockDriver, virtio_blk::VirtIOBlkDriver, BlockDeviceError};
use crate::crypto::get_svsm_rng;
use crate::error::SvsmError;
use crate::fs::FsError;
use crate::fw_cfg::FwCfg;
use crate::mm::alloc::AllocError;
use crate::platform::SVSM_PLATFORM;
use crate::r#async::{task_busypoll_to_completion, SvsmSyncTypes};
use crate::types::PAGE_SHIFT;
use crate::utils::immut_after_init::ImmutAfterInitCell;

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

fn nvfs_error_to_svsm_error(e: NvFsError) -> SvsmError {
    match e {
        NvFsError::MemoryAllocationFailure => SvsmError::Alloc(AllocError::OutOfMemory),
        NvFsError::IoError(NvFsIoError::IoFailure) => SvsmError::Block(BlockDeviceError::Failed),
        _ => SvsmError::Block(BlockDeviceError::Failed),
    }
}

type SvsmCocoonFsType = CocoonFs<SvsmSyncTypes, SvsmBlockDriverNvChip>;
type SvsmCocoonFsSyncRcPtrType =
    <<SvsmSyncTypes as sync_types::SyncTypes>::SyncRcPtrFactory as sync_types::SyncRcPtrFactory>
    ::SyncRcPtr<SvsmCocoonFsType>;
type SvsmCocoonFsSyncRcPtrRefType<'a> =
    <SvsmCocoonFsSyncRcPtrType as sync_types::SyncRcPtr<SvsmCocoonFsType>>::SyncRcPtrRef<'a>;

static SVSM_COCOONFS_INSTANCE: ImmutAfterInitCell<Option<pin::Pin<SvsmCocoonFsSyncRcPtrType>>> =
    ImmutAfterInitCell::uninit();

/// Instantiate a [`CocoonFsOpenFsFuture`].
///
/// The CocoonFsOpenFsFuture is huge, and by instantiating it in an `inline(never)` function and
/// `Box`ing it right after, the stack allocations required for the moves are hopefully getting
/// freed up quickly again.
#[inline(never)]
fn instantiate_cocoonfs_open_fut(
    chip: SvsmBlockDriverNvChip,
    key: Zeroizing<Vec<u8>>,
) -> Result<Box<CocoonFsOpenFsFuture<SvsmSyncTypes, SvsmBlockDriverNvChip>>, NvFsError> {
    let rng = box_try_new(get_svsm_rng().map_err(NvFsError::from)?).map_err(NvFsError::from)?;
    let cocoonfs_open_fut = match CocoonFsOpenFsFuture::new(chip, key, false, rng) {
        Ok(cocoonfs_open_fut) => cocoonfs_open_fut,
        Err((_chip, _key, _rng, e)) => return Err(e),
    };
    box_try_new(cocoonfs_open_fut).map_err(NvFsError::from)
}

/// Initialize the persistence subsystem.
///
/// Iterate over available block devices and attempt to open a CocoonFs instance with the provided
/// `key` on each, until one that works has been found. Any CocoonFs instances that appear to have a
/// valid filesystem, header but that could not get opened successfully, e.g. because the
/// authentication with `key` failed, are getting reported in the log and being skipped over. In
/// case a CocoonFs "filesystem creation info header" is being encountered in the search, the
/// filesystem is formatted for used with `key` in the course.
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
        let chip = SvsmBlockDriverNvChip::new(virtio_blk);
        let mut cocoonfs_open_fut = match instantiate_cocoonfs_open_fut(chip, key) {
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
                if e == NvFsError::from(CocoonFsFormatError::InvalidImageHeaderMagic) {
                    log::debug!("skipping over block device with no CocoonFs header");
                } else if e == NvFsError::from(CocoonFsFormatError::InvalidImageHeaderChecksum) {
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
pub fn persistence_available() -> bool {
    SVSM_COCOONFS_INSTANCE.is_some()
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
    inode: u32,
    data: Zeroizing<Vec<u8>>,
) -> Result<Box<<SvsmCocoonFsType as NvFs>::WriteInodeFut>, NvFsError> {
    let write_inode_fut = SvsmCocoonFsType::write_inode(fs_instance, transaction, inode, data);
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
    inode: u32,
) -> Result<Box<<SvsmCocoonFsType as NvFs>::ReadInodeFut>, NvFsError> {
    let read_inode_fut = SvsmCocoonFsType::read_inode(fs_instance, None, inode);
    box_try_new(read_inode_fut).map_err(NvFsError::from)
}

/// Synchronously write data to an inode on persistent storage.
///
/// If the `inode` does not exist yet, it will get created. All of the inode's contents will get
/// replaced with `data`.
///
/// `persistence_write_inode_sync()` assumes ownership of the `data` buffer for the duration of the
/// operation. It gets returned back unmodified to the caller on success.
///
/// # Arguments:
///
/// * `inode` - Number of the inode to update.
/// * `data` - The data to write to `inode`.
/// * `issue_sync` - Whether or not to issue a sync request to the underlying storage after the
///   write has completed. That's best effort though and relies on the host to behave well.
#[allow(unused)]
pub fn persistence_write_inode_sync(
    inode: u32,
    data: Zeroizing<Vec<u8>>,
    issue_sync: bool,
) -> Result<Zeroizing<Vec<u8>>, SvsmError> {
    let fs_instance = match SVSM_COCOONFS_INSTANCE.as_ref() {
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
            log::error!("persistence write: failed to get rng instance: {:?}", e);
            return Err(nvfs_error_to_svsm_error(NvFsError::from(e)));
        }
    };

    let transaction = match instantiate_cocoonfs_start_transaction_fut(&fs_instance).and_then(
        |mut start_transaction_fut| {
            task_busypoll_to_completion(|cx| {
                NvFsFuture::poll(
                    pin::Pin::new(&mut *start_transaction_fut),
                    &fs_instance,
                    &mut rng,
                    cx,
                )
            })
        },
    ) {
        Ok(transaction) => transaction,
        Err(e) => {
            log::error!("persistence write: failed to start transaction: {:?}", e);
            return Err(nvfs_error_to_svsm_error(e));
        }
    };

    let (transaction, data) = match instantiate_cocoonfs_write_inode_fut(
        &fs_instance,
        transaction,
        inode,
        data,
    )
    .and_then(|mut write_inode_fut| {
        task_busypoll_to_completion(|cx| {
            NvFsFuture::poll(
                pin::Pin::new(&mut *write_inode_fut),
                &fs_instance,
                &mut rng,
                cx,
            )
        })
        .and_then(|(transaction, data, result)| result.and(Ok((transaction, data))))
    }) {
        Ok((transaction, data)) => (transaction, data),
        Err(e) => {
            log::error!(
                "persistence write: failed to stage inode write at transaction: {:?}",
                e
            );
            return Err(nvfs_error_to_svsm_error(e));
        }
    };

    if let Err(e) =
        instantiate_cocoonfs_commit_transaction_fut(&fs_instance, transaction, issue_sync).and_then(
            |mut commit_transaction_fut| {
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
            },
        )
    {
        log::error!("persistence write: failed to commit transaction: {:?}", e);
        return Err(nvfs_error_to_svsm_error(e));
    }

    Ok(data)
}

/// Synchronously read data from an inode on persistent storage.
///
/// In case the `inode` does not exist, `None` is returned, otherwise all of the inode's data
/// is returned wrapped in `Some`. Note that a non-existing inode and an existing one with
/// empty data are considered different.
///
/// # Arguments:
///
/// * `inode` - Number of the inode whose data to read.
#[allow(unused)]
pub fn persistence_read_inode_sync(inode: u32) -> Result<Option<Zeroizing<Vec<u8>>>, SvsmError> {
    let fs_instance = match SVSM_COCOONFS_INSTANCE.as_ref() {
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
            log::error!("persistence read: failed to get rng instance: {:?}", e);
            return Err(nvfs_error_to_svsm_error(NvFsError::from(e)));
        }
    };

    match instantiate_cocoonfs_read_inode_fut(&fs_instance, inode).and_then(|mut read_inode_fut| {
        task_busypoll_to_completion(|cx| {
            NvFsFuture::poll(
                pin::Pin::new(&mut *read_inode_fut),
                &fs_instance,
                &mut rng,
                cx,
            )
        })
    }) {
        Ok((_read_context, Ok(data))) => Ok(data),
        Ok((_, Err(e))) | Err(e) => {
            log::error!("persistence read: failed to read inode data: {:?}", e);
            Err(nvfs_error_to_svsm_error(e))
        }
    }
}
