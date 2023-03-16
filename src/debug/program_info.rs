// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Nicolai Stange <nstange@suse.de>
//
// vim: ts=4 sw=4 et

use crate::elf;
use crate::types::VirtAddr;
use crate::utils::immut_after_init::ImmutAfterInitCell;

pub static PROGRAM_INFO: ImmutAfterInitCell<ProgramInfo> =
    ImmutAfterInitCell::new(ProgramInfo::default());

pub struct ProgramInfo {
    pub load_base: usize, // The offset, in two's complement, between actual
                          // program mapping in memory the virtual addresses
                          // from the executable file.
}

impl ProgramInfo {
    const fn default() -> Self {
        ProgramInfo { load_base: 0 }
    }

    pub fn reduce_loaded_program_vaddr(&self, vaddr: VirtAddr) -> VirtAddr {
        vaddr.wrapping_sub(self.load_base)
    }
}

pub fn program_info_init(loaded_image_virt_start: u64, elf_file: &elf::Elf64File) {
    let load_base = elf_file.load_base(loaded_image_virt_start) as usize;
    let program_info = ProgramInfo { load_base };
    unsafe { PROGRAM_INFO.reinit(program_info) };
}
