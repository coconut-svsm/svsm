// SPDX-License-Identifier: MIT OR Apache-2.0
//

use core::num::NonZeroU8;

use crate::address::VirtAddr;
use crate::cpu::msr::write_msr;
use crate::cpu::shadow_stack::ISST_ADDR;
use crate::cpu::tss::IST_DF;
use crate::locking::RWLock;

percpu! {
    static ISST: RWLock<Isst>;
    static DOUBLE_FAULT_SHADOW_STACK: Option<VirtAddr>;
}

pub fn init_double_fault_shadow_stack(stack: Option<VirtAddr>) {
    assert!(DOUBLE_FAULT_SHADOW_STACK.init(stack).is_ok());
}

pub fn double_fault_shadow_stack() -> Option<VirtAddr> {
    DOUBLE_FAULT_SHADOW_STACK.with(|stack| *stack)
}

pub fn init_isst(double_fault_shadow_stack: Option<VirtAddr>) {
    assert!(ISST.init(RWLock::new(Isst::default())).is_ok());
    if let Some(stack) = double_fault_shadow_stack {
        ISST.with(|isst| isst.write_noblock().set(IST_DF, stack));
    }
}

pub fn load_isst() {
    ISST.with(|isst| {
        let isst = isst.as_ptr();
        // SAFETY: ISST is already setup when this is called.
        unsafe { write_msr(ISST_ADDR, isst as u64) };
    });
}

#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct Isst {
    _reserved: u64,
    entries: [VirtAddr; 7],
}

impl Isst {
    pub fn set(&mut self, index: NonZeroU8, addr: VirtAddr) {
        // ISST entries start at index 1
        let index = usize::from(index.get() - 1);
        self.entries[index] = addr;
    }
}
