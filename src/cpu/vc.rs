// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::idt::X86Regs;
use crate::cpu::extable::handle_exception_table;

pub fn handle_vc_exception(regs: &mut X86Regs) {
    let err = regs.error_code;
    let rip = regs.rip;

    if !handle_exception_table(regs) {
        panic!(
            "Unhandled #VC exception RIP {:#018x} error code: {:#018x}",
            rip, err
        );
    }
}
