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
use crate::mm::vm::{PrivateVmAllocator, TaskVmAllocator, VmRange, Vmr};
use crate::mm::{AddrSpaceDescriptor, SVSM_PERTASK, USER_MEM};

/// The per-task kernel-mode virtual memory range.
#[derive(Debug)]
pub struct TaskVm;

impl VmRange for TaskVm {
    const DESCRIPTOR: AddrSpaceDescriptor = SVSM_PERTASK;
    const PT_FLAGS: PTEntryFlags = PTEntryFlags::empty();
    type Allocator = TaskVmAllocator;
}

/// The per-task user-mode virtual memory range.
#[derive(Debug)]
pub struct UserVm;

impl VmRange for UserVm {
    const DESCRIPTOR: AddrSpaceDescriptor = USER_MEM;
    const PT_FLAGS: PTEntryFlags = PTEntryFlags::USER;
    type Allocator = PrivateVmAllocator<Self>;
}

#[derive(Debug)]
pub struct TaskMM {
    /// Task virtual memory range for use at CPL 0
    vm_kernel_range: Vmr<TaskVm>,

    /// Task virtual memory range for use at CPL 3 - None for kernel tasks
    vm_user_range: Option<Vmr<UserVm>>,
}

impl TaskMM {
    /// Creates and initializes a new `TaskMM` structure.
    ///
    /// # Arguments
    ///
    /// * `user_vmr` - Optional `[Vmr]` for the user-mode portion of the tasks address space.
    ///
    /// # Returns
    ///
    /// `Ok(TaskMM)` on success, `Err(SvsmError)` on failure.
    pub fn create(user_vmr: Option<Vmr<UserVm>>) -> Result<Self, SvsmError> {
        let vm_kernel_range = Vmr::new();
        vm_kernel_range.initialize()?;

        Ok(TaskMM {
            vm_kernel_range,
            vm_user_range: user_vmr,
        })
    }

    /// Return a reference to the `[Vmr]` for the per-task kernel region.
    ///
    /// # Returns
    ///
    /// Reference to the kernel region `[Vmr]`.
    pub fn kernel_range(&self) -> &Vmr<TaskVm> {
        &self.vm_kernel_range
    }

    /// Return an otional reference to the `[Vmr]` for the per-task user region.
    ///
    /// # Returns
    ///
    /// `Some(&VMR)` referencing the user-mode `[Vmr]` for a user-task, `None` otherwise.
    pub fn user_range(&self) -> Option<&Vmr<UserVm>> {
        self.vm_user_range.as_ref()
    }
}

impl Borrow<Vmr<TaskVm>> for Arc<TaskMM> {
    fn borrow(&self) -> &Vmr<TaskVm> {
        self.kernel_range()
    }
}
