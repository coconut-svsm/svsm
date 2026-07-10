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
    pub fn new(b: &str) -> Self {
        Self {
            binary: String::from(b),
        }
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
fn task_name(binary: &str) -> String {
    let mut items = binary.split('/').filter(|x| !x.is_empty());
    match items.nth_back(0) {
        Some(p) => String::from(p),
        None => String::from("unknown"),
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
        let virt_end = VirtAddr::from(seg.vaddr_range.vaddr_end).align_up(PAGE_SIZE);
        let file_offset = seg.file_range.offset_begin;
        let len = virt_end - virt_start;
        let file_size = seg.file_range.offset_end - seg.file_range.offset_begin;
        let flags = convert_elf_phdr_flags(seg.flags);

        if file_offset > 0 {
            if file_size > len {
                return Err(SvsmError::Elf(elf::ElfError::InvalidFileRange));
            }

            // Handle unaligned VirtAddr and Offset
            let start_aligned = virt_start.page_align();
            let offset = file_offset - virt_start.page_offset();
            let size = file_size + virt_start.page_offset();
            mmap_user(start_aligned, Some(&fh), offset, size, flags)?;

            let size_aligned = align_up(size, PAGE_SIZE);
            if size_aligned < len {
                let start_anon = start_aligned.const_add(size_aligned);
                let remaining_len = len - size_aligned;
                mmap_user(start_anon, None, 0, remaining_len, flags)?;
            }
        } else {
            mmap_user(virt_start, None, 0, len, flags)?;
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
///
/// # Returns
///
/// [`Ok(TaskPointer)`] on success, [`Err(SvsmError)`] on failure.
pub fn exec_user(binary: &str, root: Arc<dyn Directory>) -> Result<TaskPointer, SvsmError> {
    let info = Box::new(UserExecInfo::new(binary));
    let new_task = create_user_task(info, root, task_name(binary))?;

    finish_user_task(new_task.clone());
    schedule();

    Ok(new_task)
}
