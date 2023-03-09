// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

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
