// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use super::TaskPointer;
use crate::address::{Address, VirtAddr};
use crate::error::SvsmError;
use crate::fs::{Directory, open_read};
use crate::mm::vm::VMFileMappingFlags;
use crate::mm::zero_user_mem;
use crate::mm::{USER_MEM_END, mmap_user};
use crate::task::{create_user_task, current_task, finish_user_task, schedule};
use crate::types::PAGE_SIZE;
use crate::utils::align_up;
use alloc::boxed::Box;
use alloc::sync::Arc;
use elf::{Elf64File, Elf64PhdrFlags};

use alloc::string::String;

#[derive(Debug)]
pub struct UserExecInfo {
    binary: String,
}

impl UserExecInfo {
    pub fn new(binary: String) -> Self {
        Self { binary }
    }
}

fn convert_elf_phdr_flags(flags: Elf64PhdrFlags) -> VMFileMappingFlags {
    let mut vm_flags = VMFileMappingFlags::Fixed;

    if flags.contains(Elf64PhdrFlags::WRITE) {
        vm_flags |= VMFileMappingFlags::Write | VMFileMappingFlags::Private;
    }

    if flags.contains(Elf64PhdrFlags::EXECUTE) {
        vm_flags |= VMFileMappingFlags::Execute;
    }

    vm_flags
}

/// Returns the name of the binary file without preceeding directories. This is
/// used as the official task name.
fn task_name(binary: &str) -> &str {
    let mut items = binary.split('/').filter(|x| !x.is_empty());
    match items.nth_back(0) {
        Some(p) => p,
        None => "unknown",
    }
}

/// Loads and executes an user-mode ELF binary into the current tasks address
/// space.
///
/// # Arguments
///
/// * info: Instance of [`UserExecInfo`] describing the user-mode task.
///
/// # Returns
///
/// [`Ok(TaskPointer)`] on success, [`Err(SvsmError)`] on failure.
pub fn exec(info: UserExecInfo) -> Result<u64, SvsmError> {
    let fh = open_read(&info.binary)?;
    let file_size = fh.size();

    let current_task = current_task();

    let vstart = current_task.mmap_kernel_guard(
        VirtAddr::new(0),
        Some(&fh),
        0,
        file_size,
        VMFileMappingFlags::Read,
    )?;

    // SAFETY: `vstart` has just been mapped using `file_size` as the size,
    // so it is safe to create a slice of the same size.
    let buf = unsafe { vstart.to_slice::<u8>(file_size) };
    let elf_bin = Elf64File::read(buf).map_err(|_| SvsmError::Mem)?;

    let alloc_info = elf_bin.image_load_vaddr_alloc_info();
    let virt_base = alloc_info.range.vaddr_begin;
    let entry = elf_bin.get_entry(virt_base);

    for seg in elf_bin.image_load_segment_iter(virt_base) {
        let virt_start = VirtAddr::from(seg.vaddr_range.vaddr_begin);
        let virt_end = VirtAddr::from(seg.vaddr_range.vaddr_end);
        let file_offset = seg.file_range.offset_begin;
        let mem_size = virt_end - virt_start;
        let file_size = seg.file_range.offset_end - seg.file_range.offset_begin;
        let flags = convert_elf_phdr_flags(seg.flags);

        // Handle unaligned VirtAddr and Offset
        let map_start = virt_start.page_align();
        let mem_map_size = mem_size + virt_start.page_offset();

        if file_size == 0 {
            // No file backing - Map the segment with anonymous memory
            mmap_user(map_start, None, 0, mem_map_size, flags)?;
            continue;
        }

        if file_size > mem_size {
            return Err(SvsmError::Elf(elf::ElfError::InvalidFileRange));
        }

        let page_offset = virt_start.page_offset();
        if file_offset % PAGE_SIZE != page_offset {
            return Err(SvsmError::Elf(elf::ElfError::UnalignedSegmentAddress));
        }

        let map_offset = file_offset - page_offset;
        let file_map_size = file_size + page_offset;
        mmap_user(map_start, Some(&fh), map_offset, file_map_size, flags)?;

        let file_map_size_aligned = align_up(file_map_size, PAGE_SIZE);
        let zero_end = file_map_size_aligned.min(mem_map_size);

        // Zero the part of the last file-backed page covered by p_memsz but not
        // by p_filesz.  mmap_user() maps whole pages, so this would otherwise
        // expose bytes following the segment in the ELF file.
        if zero_end > file_map_size && seg.flags.contains(Elf64PhdrFlags::WRITE) {
            zero_user_mem(map_start + file_map_size, zero_end - file_map_size)?;
        }

        if file_map_size_aligned < mem_map_size {
            let remaining_len = mem_map_size - file_map_size_aligned;
            mmap_user(
                map_start + file_map_size_aligned,
                None,
                0,
                remaining_len,
                flags,
            )?;
        }
    }

    // Make sure the mapping is gone before calling schedule
    drop(vstart);

    // Setup 64k of task stack
    let user_stack_size: usize = 64 * 1024;
    let stack_flags: VMFileMappingFlags = VMFileMappingFlags::Fixed | VMFileMappingFlags::Write;
    let stack_addr = USER_MEM_END - user_stack_size;
    mmap_user(stack_addr, None, 0, user_stack_size, stack_flags)?;

    Ok(entry)
}

/// Starts a new task and sets it up for loading and executing a user-mode
/// binary.
///
/// # Arguments
///
/// * binary: Path to file in the file-system
/// * root: Root directory associated with the new task
///
/// # Returns
///
/// [`Ok(TaskPointer)`] on success, [`Err(SvsmError)`] on failure.
pub fn exec_user<S: Into<String>>(
    binary: S,
    root: Arc<dyn Directory>,
) -> Result<TaskPointer, SvsmError> {
    let info = Box::new(UserExecInfo::new(binary.into()));
    let name = Arc::from(task_name(&info.binary));
    let new_task = create_user_task(info, root, name)?;

    finish_user_task(new_task.clone());
    schedule();

    Ok(new_task)
}
