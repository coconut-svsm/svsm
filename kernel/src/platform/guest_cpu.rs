// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

pub trait GuestCpuState {
    fn get_tpr(&self) -> u8;
    fn set_tpr(&mut self, tpr: u8);
    fn queue_interrupt(&mut self, irq: u8);
    fn try_deliver_interrupt_immediately(&mut self, irq: u8) -> bool;
    fn in_intr_shadow(&self) -> bool;
    fn interrupts_enabled(&self) -> bool;
    fn check_and_clear_pending_interrupt_event(&mut self) -> u8;
    fn check_and_clear_pending_virtual_interrupt(&mut self) -> u8;
    fn disable_alternate_injection(&mut self);
}
