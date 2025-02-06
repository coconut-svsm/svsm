// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::address::{Address, VirtAddr};
use crate::error::SvsmError;
use crate::fs::{open_read, Directory};
use crate::mm::vm::VMFileMappingFlags;
use crate::mm::USER_MEM_END;
use crate::task::{create_user_task, current_task, finish_user_task, schedule};
use crate::types::PAGE_SIZE;
use crate::utils::align_up;
use alloc::sync::Arc;
use elf::{Elf64File, Elf64PhdrFlags};

use alloc::string::String;

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

/// Loads and executes an ELF binary in user-mode.
///
/// # Arguments
///
/// * binary: Path to file in the file-system
///
/// # Returns
///
/// [`Ok(tid)`] on success, [`Err(SvsmError)`] on failure.
pub fn exec_user(binary: &str, root: Arc<dyn Directory>) -> Result<u32, SvsmError> {
    let fh = open_read(binary)?;
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

    let new_task = create_user_task(entry.try_into().unwrap(), root, task_name(binary))?;

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
            new_task.mmap_user(start_aligned, Some(&fh), offset, size, flags)?;

            let size_aligned = align_up(size, PAGE_SIZE);
            if size_aligned < len {
                let start_anon = start_aligned.const_add(size_aligned);
                let remaining_len = len - size_aligned;
                new_task.mmap_user(start_anon, None, 0, remaining_len, flags)?;
            }
        } else {
            new_task.mmap_user(virt_start, None, 0, len, flags)?;
        }
    }

    // Make sure the mapping is gone before calling schedule
    drop(vstart);

    // Setup 64k of task stack
    let user_stack_size: usize = 64 * 1024;
    let stack_flags: VMFileMappingFlags = VMFileMappingFlags::Fixed | VMFileMappingFlags::Write;
    let stack_addr = USER_MEM_END - user_stack_size;
    new_task.mmap_user(stack_addr, None, 0, user_stack_size, stack_flags)?;

    finish_user_task(new_task.clone());
    schedule();

    Ok(new_task.get_task_id())
}
