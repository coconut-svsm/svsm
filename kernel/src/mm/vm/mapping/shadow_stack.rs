// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    address::{Address, PhysAddr, VirtAddr},
    cpu::shadow_stack,
    error::SvsmError,
    mm::{pagetable::PTEntryFlags, vm::VirtualMapping, PageRef, PAGE_SIZE},
};

#[derive(Debug)]
pub enum ShadowStackInit {
    /// The initial shadow stack used by a CPU.
    ///
    /// This won't place any tokens on the shadow stack.
    Init,
    /// A shadow stack to be used during normal execution of a task.
    ///
    /// This will create a shadow stack with a shadow stack restore token.
    Normal {
        /// The address instruction that will be executed by the task.
        first_return: usize,
    },
    /// A shadow stack to be used during context switches.
    ///
    /// This will create a shadow stack with a shadow stack restore token.
    ContextSwitch,
    /// A shadow stack to be used for exception handling (either in PL0_SSP or
    /// in the ISST).
    ///
    /// This will create a shadow stack with a supervisor shadow stack token.
    Exception,
}

/// Mapping to be used as a kernel stack. This maps a stack including guard
/// pages at the top and bottom.
#[derive(Debug)]
pub struct VMKernelShadowStack {
    page: PageRef,
}

impl VMKernelShadowStack {
    /// Create a new [`VMKernelShadowStack`].
    ///
    /// # Returns
    ///
    /// Initialized shadow stack & initial SSP value on success, Err(SvsmError::Mem) on error
    pub fn new(base: VirtAddr, init: ShadowStackInit) -> Result<(Self, VirtAddr), SvsmError> {
        let page = PageRef::new()?;

        // Initialize the shadow stack.
        let mut chunk = [0; 16];
        let ssp = match init {
            ShadowStackInit::Normal { first_return } => {
                let (token_bytes, rip_bytes) = chunk.split_at_mut(8);

                // Create a shadow stack restore token.
                let token_addr = base + PAGE_SIZE - 16;
                let token = (token_addr + 8).bits() + shadow_stack::MODE_64BIT;
                token_bytes.copy_from_slice(&token.to_ne_bytes());

                rip_bytes.copy_from_slice(&first_return.to_ne_bytes());

                token_addr
            }
            ShadowStackInit::ContextSwitch => {
                let (_, token_bytes) = chunk.split_at_mut(8);

                // Create a shadow stack restore token.
                let token_addr = base + PAGE_SIZE - 8;
                let token = (token_addr + 8).bits() + shadow_stack::MODE_64BIT;
                token_bytes.copy_from_slice(&token.to_ne_bytes());

                token_addr
            }
            ShadowStackInit::Exception => {
                let (_, token_bytes) = chunk.split_at_mut(8);

                // Create a supervisor shadow stack token.
                let token_addr = base + PAGE_SIZE - 8;
                let token = token_addr.bits();
                token_bytes.copy_from_slice(&token.to_ne_bytes());

                token_addr
            }
            ShadowStackInit::Init => base + PAGE_SIZE - 8,
        };

        page.write(PAGE_SIZE - chunk.len(), &chunk);

        Ok((VMKernelShadowStack { page }, ssp))
    }
}

impl VirtualMapping for VMKernelShadowStack {
    fn mapping_size(&self) -> usize {
        PAGE_SIZE
    }

    fn map(&self, offset: usize) -> Option<PhysAddr> {
        assert_eq!(offset, 0);
        Some(self.page.phys_addr())
    }

    fn pt_flags(&self, _offset: usize) -> PTEntryFlags {
        // The CPU requires shadow stacks to be dirty and not writable.
        PTEntryFlags::NX | PTEntryFlags::ACCESSED | PTEntryFlags::DIRTY
    }
}
