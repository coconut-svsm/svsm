// SPDX-License-Identifier: MIT
//
// Copyright (c) 2025 SUSE LLC
// Copyright (c) 2025 AMD Inc.
//
// Author: Joerg Roedel <joerg.roedel@amd.com>

extern crate alloc;
use core::borrow::Borrow;

use alloc::sync::Arc;

use crate::error::SvsmError;
use crate::mm::pagetable::PTEntryFlags;
use crate::mm::vm::{ContextVMR, VMR};

#[derive(Debug)]
pub struct TaskMM {
    /// Task virtual memory range for use at CPL 0
    vm_kernel_range: ContextVMR,

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
        let vm_kernel_range = ContextVMR::new(PTEntryFlags::empty());
        vm_kernel_range.initialize();

        Ok(TaskMM {
            vm_kernel_range,
            vm_user_range: user_vmr,
        })
    }

    /// Return a reference to the [`ContextVMR`] for the per-task kernel region.
    ///
    /// # Returns
    ///
    /// Reference to the kernel region [`ContextVMR`].
    pub fn kernel_range(&self) -> &ContextVMR {
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
}

impl Borrow<ContextVMR> for Arc<TaskMM> {
    fn borrow(&self) -> &ContextVMR {
        self.kernel_range()
    }
}
