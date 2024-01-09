// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

use crate::platform::guest_cpu::GuestCpuState;

#[derive(Clone, Copy, Debug, Default)]
pub struct LocalApic {
    irr: [u32; 8],
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
}
