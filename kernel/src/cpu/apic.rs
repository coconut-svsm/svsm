// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

use crate::cpu::percpu::PerCpuShared;
use crate::platform::guest_cpu::GuestCpuState;

use bitfield_struct::bitfield;

const APIC_REGISTER_APIC_ID: u64 = 0x802;
const APIC_REGISTER_TPR: u64 = 0x808;
const APIC_REGISTER_PPR: u64 = 0x80A;
const APIC_REGISTER_EOI: u64 = 0x80B;
const APIC_REGISTER_ISR_0: u64 = 0x810;
const APIC_REGISTER_ISR_7: u64 = 0x817;
const APIC_REGISTER_IRR_0: u64 = 0x820;
const APIC_REGISTER_IRR_7: u64 = 0x827;
const APIC_REGISTER_ICR: u64 = 0x830;
const APIC_REGISTER_SELF_IPI: u64 = 0x83F;

#[derive(Debug, PartialEq)]
enum IcrDestFmt {
    Dest = 0,
    OnlySelf = 1,
    AllWithSelf = 2,
    AllButSelf = 3,
}

impl IcrDestFmt {
    const fn into_bits(self) -> u64 {
        self as _
    }
    const fn from_bits(value: u64) -> Self {
        match value {
            3 => Self::AllButSelf,
            2 => Self::AllWithSelf,
            1 => Self::OnlySelf,
            _ => Self::Dest,
        }
    }
}

#[derive(Debug, PartialEq)]
enum IcrMessageType {
    Fixed = 0,
    Unknown = 3,
    Nmi = 4,
    Init = 5,
    Sipi = 6,
    ExtInt = 7,
}

impl IcrMessageType {
    const fn into_bits(self) -> u64 {
        self as _
    }
    const fn from_bits(value: u64) -> Self {
        match value {
            7 => Self::ExtInt,
            6 => Self::Sipi,
            5 => Self::Init,
            4 => Self::Nmi,
            0 => Self::Fixed,
            _ => Self::Unknown,
        }
    }
}

#[bitfield(u64)]
struct ApicIcr {
    pub vector: u8,
    #[bits(3)]
    pub message_type: IcrMessageType,
    pub destination_mode: bool,
    pub delivery_status: bool,
    rsvd_13: bool,
    pub assert: bool,
    pub trigger_mode: bool,
    #[bits(2)]
    pub remote_read_status: usize,
    #[bits(2)]
    pub destination_shorthand: IcrDestFmt,
    #[bits(12)]
    rsvd_31_20: u64,
    pub destination: u32,
}

#[derive(Clone, Copy, Debug)]
pub enum ApicError {
    ApicError,
}

#[derive(Default, Clone, Copy, Debug)]
pub struct LocalApic {
    irr: [u32; 8],
    allowed_irr: [u32; 8],
    isr_stack_index: usize,
    isr_stack: [u8; 16],
    update_required: bool,
    interrupt_delivered: bool,
    interrupt_queued: bool,
}

impl LocalApic {
    pub fn new() -> Self {
        LocalApic {
            irr: [0; 8],
            allowed_irr: [0; 8],
            isr_stack_index: 0,
            isr_stack: [0; 16],
            update_required: false,
            interrupt_delivered: false,
            interrupt_queued: false,
        }
    }

    fn scan_irr(&self) -> u8 {
        // Scan to find the highest pending IRR vector.
        for (i, irr) in self.irr.into_iter().enumerate().rev() {
            if irr != 0 {
                let bit_index = 31 - irr.leading_zeros();
                let vector = (i as u32) * 32 + bit_index;
                return vector.try_into().unwrap();
            }
        }
        0
    }

    fn remove_irr(&mut self, irq: u8) {
        self.irr[irq as usize >> 5] &= !(1 << (irq & 31));
    }

    fn insert_irr(&mut self, irq: u8) {
        self.irr[irq as usize >> 5] |= 1 << (irq & 31);
    }

    fn rewind_pending_interrupt(&mut self, irq: u8) {
        let new_index = self.isr_stack_index.checked_sub(1).unwrap();
        assert!(self.isr_stack.get(new_index) == Some(&irq));
        self.insert_irr(irq);
        self.isr_stack_index = new_index;
        self.update_required = true;
    }

    pub fn check_delivered_interrupts<T: GuestCpuState>(&mut self, cpu_state: &mut T) {
        // Check to see if a previously delivered interrupt is still pending.
        // If so, move it back to the IRR.
        if self.interrupt_delivered {
            let irq = cpu_state.check_and_clear_pending_interrupt_event();
            if irq != 0 {
                self.rewind_pending_interrupt(irq);
            }
            self.interrupt_delivered = false;
        }

        // Check to see if a previously queued interrupt is still pending.
        // If so, move it back to the IRR.
        if self.interrupt_queued {
            let irq = cpu_state.check_and_clear_pending_virtual_interrupt();
            if irq != 0 {
                self.rewind_pending_interrupt(irq);
            }
            self.interrupt_queued = false;
        }
    }

    fn get_ppr_with_tpr(&self, tpr: u8) -> u8 {
        // Determine the priority of the current in-service interrupt, if any.
        let ppr = if self.isr_stack_index != 0 {
            self.isr_stack[self.isr_stack_index]
        } else {
            0
        };

        // The PPR is the higher of the in-service interrupt priority and the
        // task priority.
        if (ppr >> 4) > (tpr >> 4) {
            ppr
        } else {
            tpr
        }
    }

    fn get_ppr<T: GuestCpuState>(&self, cpu_state: &T) -> u8 {
        self.get_ppr_with_tpr(cpu_state.get_tpr())
    }

    fn deliver_interrupt_immediately<T: GuestCpuState>(
        &mut self,
        irq: u8,
        cpu_state: &mut T,
    ) -> bool {
        if !cpu_state.interrupts_enabled() || cpu_state.in_intr_shadow() {
            false
        } else {
            // This interrupt can only be delivered if it is a higher priority
            // than the processor's current priority.
            let ppr = self.get_ppr(cpu_state);
            if (irq >> 4) <= (ppr >> 4) {
                false
            } else {
                cpu_state.try_deliver_interrupt_immediately(irq)
            }
        }
    }

    pub fn present_interrupts<T: GuestCpuState>(&mut self, cpu_state: &mut T) {
        if self.update_required {
            // Make sure that all previously delivered interrupts have been
            // processed before attempting to process any more.
            self.check_delivered_interrupts(cpu_state);

            let irq = self.scan_irr();
            let current_priority = if self.isr_stack_index != 0 {
                self.isr_stack[self.isr_stack_index - 1]
            } else {
                0
            };

            // This interrupt is a candidate for delivery only if its priority
            // exceeds the priority of the highest priority interrupt currently
            // in service.  This check does not consider TPR, because an
            // interrupt lower in priority than TPR must be queued for delivery
            // as soon as TPR is lowered.
            if (irq & 0xF0) > (current_priority & 0xF0) {
                // Determine whether this interrupt can be injected
                // immediately.  If not, queue it for delivery when possible.
                if self.deliver_interrupt_immediately(irq, cpu_state) {
                    self.interrupt_delivered = true;
                } else {
                    cpu_state.queue_interrupt(irq);
                    self.interrupt_queued = true;
                }

                // Mark this interrupt in-service.  It will be recalled if
                // the ISR is examined again before the interrupt is actually
                // delivered.
                self.remove_irr(irq);
                self.isr_stack[self.isr_stack_index] = irq;
                self.isr_stack_index += 1;
            }
            self.update_required = false;
        }
    }

    pub fn perform_eoi(&mut self) {
        // Pop any in-service interrupt from the stack, and schedule the APIC
        // for reevaluation.
        if self.isr_stack_index != 0 {
            self.isr_stack_index -= 1;
            self.update_required = true;
        }
    }

    fn get_isr(&self, index: usize) -> u32 {
        let mut value = 0;
        for isr in self.isr_stack.into_iter().take(self.isr_stack_index) {
            if (usize::from(isr >> 5)) == index {
                value |= 1 << (isr & 0x1F)
            }
        }
        value
    }

    fn post_interrupt(&mut self, irq: u8) {
        // Set the appropriate bit in the IRR.  Once set, signal that interrupt
        // processing is required before returning to the guest.
        self.insert_irr(irq);
        self.update_required = true;
    }

    pub fn read_register<T: GuestCpuState>(
        &mut self,
        cpu_shared: &PerCpuShared,
        cpu_state: &mut T,
        register: u64,
    ) -> Result<u64, ApicError> {
        // Rewind any undelivered interrupt so it is reflected in any register
        // read.
        self.check_delivered_interrupts(cpu_state);

        match register {
            APIC_REGISTER_APIC_ID => Ok(u64::from(cpu_shared.apic_id())),
            APIC_REGISTER_IRR_0..=APIC_REGISTER_IRR_7 => {
                let offset = register - APIC_REGISTER_IRR_0;
                let index: usize = offset.try_into().unwrap();
                Ok(self.irr[index] as u64)
            }
            APIC_REGISTER_ISR_0..=APIC_REGISTER_ISR_7 => {
                let offset = register - APIC_REGISTER_ISR_0;
                Ok(self.get_isr(offset.try_into().unwrap()) as u64)
            }
            APIC_REGISTER_TPR => Ok(cpu_state.get_tpr() as u64),
            APIC_REGISTER_PPR => Ok(self.get_ppr(cpu_state) as u64),
            _ => Err(ApicError::ApicError),
        }
    }

    fn handle_icr_write(&mut self, value: u64) -> Result<(), ApicError> {
        let icr = ApicIcr::from(value);

        // Only fixed interrupts can be handled.
        if icr.message_type() != IcrMessageType::Fixed {
            return Err(ApicError::ApicError);
        }

        // Only asserted edge-triggered interrupts can be handled.
        if icr.trigger_mode() || !icr.assert() {
            return Err(ApicError::ApicError);
        }

        // FIXME - support destinations other than self.
        if icr.destination_shorthand() != IcrDestFmt::OnlySelf {
            return Err(ApicError::ApicError);
        }

        self.post_interrupt(icr.vector());

        Ok(())
    }

    pub fn write_register<T: GuestCpuState>(
        &mut self,
        cpu_state: &mut T,
        register: u64,
        value: u64,
    ) -> Result<(), ApicError> {
        // Rewind any undelivered interrupt so it is correctly processed by
        // any register write.
        self.check_delivered_interrupts(cpu_state);

        match register {
            APIC_REGISTER_TPR => {
                // TPR must be an 8-bit value.
                if value > 0xFF {
                    Err(ApicError::ApicError)
                } else {
                    cpu_state.set_tpr((value & 0xFF) as u8);
                    Ok(())
                }
            }
            APIC_REGISTER_EOI => {
                self.perform_eoi();
                Ok(())
            }
            APIC_REGISTER_ICR => self.handle_icr_write(value),
            APIC_REGISTER_SELF_IPI => {
                if value > 0xFF {
                    Err(ApicError::ApicError)
                } else {
                    self.post_interrupt((value & 0xFF) as u8);
                    Ok(())
                }
            }
            _ => Err(ApicError::ApicError),
        }
    }
    pub fn configure_vector(&mut self, vector: u8, allowed: bool) {
        let index = (vector >> 5) as usize;
        let mask = 1 << (vector & 31);
        if allowed {
            self.allowed_irr[index] |= mask;
        } else {
            self.allowed_irr[index] &= !mask;
        }
    }
}
