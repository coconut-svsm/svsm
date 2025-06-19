// SPDX-License-Identifier: MIT
//
// Copyright (c) 2025 SUSE LLC
// Copyright (c) 2025 AMD Inc.
//
// Author: Joerg Roedel <joerg.roedel@amd.com>

use crate::address::VirtAddr;
use crate::error::SvsmError;
use crate::locking::SpinLock;
use crate::mm::pagetable::PTEntryFlags;
use crate::mm::vm::VMR;
use crate::mm::{alloc::AllocError, SIZE_LEVEL3, SVSM_PERTASK_BASE};
use crate::utils::bitmap_allocator::{BitmapAllocator, BitmapAllocator1024};
use crate::utils::MemoryRegion;

static KTASK_VADDR_BITMAP: SpinLock<BitmapAllocator1024> =
    SpinLock::new(BitmapAllocator1024::new_empty());

// The task virtual range guard manages the allocation of a task virtual
// address range within the task address space.  The address range is reserved
// as long as the guard continues to exist.
#[derive(Debug)]
struct TaskVirtualRegionGuard {
    index: usize,
}

impl TaskVirtualRegionGuard {
    fn alloc() -> Result<Self, SvsmError> {
        let index = KTASK_VADDR_BITMAP
            .lock()
            .alloc(1, 0)
            .ok_or(SvsmError::Alloc(AllocError::OutOfMemory))?;
        Ok(Self { index })
    }

    fn vaddr_region(&self) -> MemoryRegion<VirtAddr> {
        const SPAN: usize = SIZE_LEVEL3 / BitmapAllocator1024::CAPACITY;
        let base = SVSM_PERTASK_BASE + (self.index * SPAN);
        MemoryRegion::<VirtAddr>::new(base, SPAN)
    }
}

impl Drop for TaskVirtualRegionGuard {
    fn drop(&mut self) {
        KTASK_VADDR_BITMAP.lock().free(self.index, 1);
    }
}

pub struct TaskMM {
    /// Virtual address region that has been allocated for this task.
    /// This is not referenced but must be stored so that it is dropped when
    /// the Task is dropped.
    _ktask_region: TaskVirtualRegionGuard,

    /// Task virtual memory range for use at CPL 0
    vm_kernel_range: VMR,

    /// Task virtual memory range for use at CPL 3 - None for kernel tasks
    vm_user_range: Option<VMR>,
}

impl TaskMM {
    /// Creates and initializes a new `TaskMM` structure.
    ///
    /// # Arguments
    ///
    /// * `user_vmr` - Optional `[VMR]` for the user-mode portion of the tasks address space.
    ///
    /// # Returns
    ///
    /// `Ok(TaskMM)` on success, `Err(SvsmError)` on failure.
    pub fn create(user_vmr: Option<VMR>) -> Result<Self, SvsmError> {
        let ktask_region = TaskVirtualRegionGuard::alloc()?;
        let vaddr_region = ktask_region.vaddr_region();
        let vm_kernel_range = VMR::new(
            vaddr_region.start(),
            vaddr_region.end(),
            PTEntryFlags::empty(),
        );
        // SAFETY: The selected kernel mode task address range is the only
        // range that will live within the top-level entry associated with the
        // task address space.
        unsafe {
            vm_kernel_range.initialize()?;
        }

        Ok(TaskMM {
            _ktask_region: ktask_region,
            vm_kernel_range,
            vm_user_range: user_vmr,
        })
    }

    /// Return a reference to the `[VMR]` for the per-task kernel region.
    ///
    /// # Returns
    ///
    /// Reference to the kernel region `[VMR]`.
    pub fn kernel_range(&self) -> &VMR {
        &self.vm_kernel_range
    }

    /// Return an otional reference to the `[VMR]` for the per-task user region.
    ///
    /// # Returns
    ///
    /// `Some(&VMR)` referencing the user-mode `[VMR]` for a user-task, `None` otherwise.
    pub fn user_range(&self) -> Option<&VMR> {
        self.vm_user_range.as_ref()
    }

    /// Checks whether the task has a user-mode `[VMR]`.
    ///
    /// # Returns
    ///
    /// `True` if user-mode `[VMR]` is present, `False` otherwise.
    pub fn has_user(&self) -> bool {
        self.vm_user_range.is_some()
    }
}
