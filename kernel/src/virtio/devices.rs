use super::hal::*;
use core::ptr::NonNull;
use virtio_drivers::device::blk::VirtIOBlk;
use virtio_drivers::transport::mmio::MmioTransport;
use virtio_drivers::PAGE_SIZE;

use crate::address::PhysAddr;
use crate::locking::SpinLock;
use crate::mm::global_memory::{map_global_range_4k_shared, GlobalRangeGuard};
use crate::mm::pagetable::PTEntryFlags;

pub struct VirtIOBlkDevice {
    pub device: SpinLock<VirtIOBlk<SvsmHal, MmioTransport<SvsmHal>>>,
    _mmio_space: GlobalRangeGuard,
}

impl core::fmt::Debug for VirtIOBlkDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtIOBlkDevice").finish()
    }
}

impl VirtIOBlkDevice {
    pub fn new(mmio_base: PhysAddr) -> Self {
        virtio_init();

        let mem = map_global_range_4k_shared(mmio_base, PAGE_SIZE, PTEntryFlags::data())
            .expect("Error mapping MMIO range");
        let header = NonNull::new(mem.addr().as_mut_ptr()).unwrap();

        // SAFETY: `header` is the MMIO config area; we have to trust the content is valid.
        let transport = unsafe { MmioTransport::<SvsmHal>::new(header).unwrap() };

        let blk = VirtIOBlk::new(transport).expect("Failed to create blk driver");

        VirtIOBlkDevice {
            device: SpinLock::new(blk),
            _mmio_space: mem,
        }
    }
}
