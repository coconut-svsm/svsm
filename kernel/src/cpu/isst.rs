use core::num::NonZeroU8;

use crate::address::VirtAddr;

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
