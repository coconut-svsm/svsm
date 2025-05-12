// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

extern crate alloc;

use alloc::collections::btree_map::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use core::fmt;
use core::mem::size_of;
use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::address::{Address, VirtAddr};
use crate::cpu::idt::svsm::return_new_task;
use crate::cpu::irq_state::EFLAGS_IF;
use crate::cpu::percpu::{current_task, PerCpu};
use crate::cpu::shadow_stack::is_cet_ss_supported;
use crate::cpu::sse::{get_xsave_area_size, sse_restore_context};
use crate::cpu::{irqs_enable, X86ExceptionContext, X86GeneralRegs};
use crate::error::SvsmError;
use crate::fs::{opendir, stdout_open, Directory, FileHandle};
use crate::locking::{RWLock, SpinLock};
use crate::mm::pagetable::{PTEntryFlags, PageTable};
use crate::mm::vm::{
    Mapping, ShadowStackInit, VMFileMappingFlags, VMKernelShadowStack, VMKernelStack, VMR,
};
use crate::mm::{
    alloc::AllocError, mappings::create_anon_mapping, mappings::create_file_mapping, PageBox,
    VMMappingGuard, SIZE_LEVEL3, SVSM_PERTASK_BASE, SVSM_PERTASK_END,
    SVSM_PERTASK_SHADOW_STACK_BASE_OFFSET, SVSM_PERTASK_STACK_BASE_OFFSET, USER_MEM_END,
    USER_MEM_START,
};
use crate::platform::SVSM_PLATFORM;
use crate::syscall::{Obj, ObjError, ObjHandle};
use crate::types::{SVSM_USER_CS, SVSM_USER_DS};
use crate::utils::bitmap_allocator::{BitmapAllocator, BitmapAllocator1024};
use crate::utils::{is_aligned, MemoryRegion};
use intrusive_collections::{intrusive_adapter, LinkedListAtomicLink};

use super::schedule::{after_task_switch, current_task_terminated, schedule};

pub static KTASK_VADDR_BITMAP: SpinLock<BitmapAllocator1024> =
    SpinLock::new(BitmapAllocator1024::new_empty());

pub const INITIAL_TASK_ID: u32 = 1;

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

#[derive(PartialEq, Debug, Copy, Clone, Default)]
pub enum TaskState {
    RUNNING,
    BLOCKED,
    #[default]
    TERMINATED,
}

#[derive(Clone, Copy, Debug)]
pub enum TaskError {
    // Attempt to close a non-terminated task
    NotTerminated,
    // A closed task could not be removed from the task list
    CloseFailed,
}

impl From<TaskError> for SvsmError {
    fn from(e: TaskError) -> Self {
        Self::Task(e)
    }
}

pub const TASK_FLAG_SHARE_PT: u16 = 0x01;

#[derive(Debug, Default)]
struct TaskIDAllocator {
    next_id: AtomicU32,
}

impl TaskIDAllocator {
    const fn new() -> Self {
        Self {
            next_id: AtomicU32::new(INITIAL_TASK_ID + 1),
        }
    }

    fn next_id(&self) -> u32 {
        let mut id = self.next_id.fetch_add(1, Ordering::Relaxed);
        // Reserve IDs of 0 and 1
        while (id == 0_u32) || (id == INITIAL_TASK_ID) {
            id = self.next_id.fetch_add(1, Ordering::Relaxed);
        }
        id
    }
}

static TASK_ID_ALLOCATOR: TaskIDAllocator = TaskIDAllocator::new();

#[repr(C, packed)]
#[derive(Default, Debug, Clone, Copy)]
pub struct TaskContext {
    pub rsp: u64,
    pub regs: X86GeneralRegs,
    pub flags: u64,
    pub ret_addr: u64,
}

#[repr(C)]
struct TaskSchedState {
    /// Whether this is an idle task
    idle_task: bool,

    /// Current state of the task
    state: TaskState,

    /// CPU this task is currently assigned to
    cpu_index: usize,
}

impl TaskSchedState {
    pub fn panic_on_idle(&mut self, msg: &str) -> &mut Self {
        if self.idle_task {
            panic!("{}", msg);
        }
        self
    }
}

pub struct Task {
    pub rsp: u64,

    pub ssp: VirtAddr,

    /// XSave area
    pub xsa: PageBox<[u8]>,

    pub stack_bounds: MemoryRegion<VirtAddr>,

    pub shadow_stack_base: VirtAddr,

    /// Page table that is loaded when the task is scheduled
    pub page_table: SpinLock<PageBox<PageTable>>,

    /// Virtual address region that has been allocated for this task.
    /// This is not referenced but must be stored so that it is dropped when
    /// the Task is dropped.
    _ktask_region: TaskVirtualRegionGuard,

    /// Task virtual memory range for use at CPL 0
    vm_kernel_range: VMR,

    /// Task virtual memory range for use at CPL 3 - None for kernel tasks
    vm_user_range: Option<VMR>,

    /// State relevant for scheduler
    sched_state: RWLock<TaskSchedState>,

    /// User-visible name of task
    name: String,

    /// ID of the task
    id: u32,

    /// Root directory for this task
    rootdir: Arc<dyn Directory>,

    /// Link to global task list
    list_link: LinkedListAtomicLink,

    /// Link to scheduler run queue
    runlist_link: LinkedListAtomicLink,

    /// Objects shared among threads within the same process
    objs: Arc<RWLock<BTreeMap<ObjHandle, Arc<dyn Obj>>>>,
}

// SAFETY: Send + Sync is required for Arc<Task> to implement Send. All members
// of  `Task` are Send + Sync except for the intrusive_collection links, which
// are only Send. The only access to these is via the intrusive_adapter!
// generated code which does not use them concurrently across threads.  The
// kernal address cell is also not Sync, but this is only populated during
// task creation, and can safely be accessed by multiple threads once it has
// been populated.
unsafe impl Sync for Task {}

pub type TaskPointer = Arc<Task>;

intrusive_adapter!(pub TaskRunListAdapter = TaskPointer: Task { runlist_link: LinkedListAtomicLink });
intrusive_adapter!(pub TaskListAdapter = TaskPointer: Task { list_link: LinkedListAtomicLink });

impl PartialEq for Task {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self, other)
    }
}

impl fmt::Debug for Task {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Task")
            .field("rsp", &self.rsp)
            .field("state", &self.sched_state.lock_read().state)
            .field("id", &self.id)
            .finish()
    }
}

struct CreateTaskArguments {
    // The entry point of the task.  For user tasks, this is a user-mode
    // address, and for kernel tasks, it is a kernel address,
    entry: usize,

    // A start parameter for kernel tasks.
    start_parameter: usize,

    // The name of the task.
    name: String,

    // For a user task, supplies the `VMR` that will represent the user-mode
    // address space.
    vm_user_range: Option<VMR>,

    // The root directory that will be associated with this task.
    rootdir: Arc<dyn Directory>,
}

impl Task {
    fn create_common(cpu: &PerCpu, args: CreateTaskArguments) -> Result<TaskPointer, SvsmError> {
        let mut pgtable = cpu.get_pgtable().clone_shared()?;

        cpu.populate_page_table(&mut pgtable);

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

        let xsa = Self::allocate_xsave_area();
        let xsa_addr = u64::from(xsa.vaddr()) as usize;

        // Determine which kernel-mode entry/exit routines will be used for
        // this task.
        let (entry_return, exit_return) = if args.vm_user_range.is_some() {
            (return_new_task as usize, None)
        } else {
            (run_kernel_task as usize, Some(task_exit as usize))
        };

        let mut shadow_stack_offset = VirtAddr::null();
        let mut shadow_stack_base = VirtAddr::null();
        if is_cet_ss_supported() {
            let shadow_stack;
            let base_token_addr;
            (shadow_stack, base_token_addr, shadow_stack_offset) = VMKernelShadowStack::new(
                vaddr_region.start() + SVSM_PERTASK_SHADOW_STACK_BASE_OFFSET,
                ShadowStackInit::Normal {
                    entry_return,
                    exit_return,
                },
            )?;
            if let Some(base_addr) = base_token_addr {
                shadow_stack_base = base_addr;
            }

            vm_kernel_range.insert_at(
                vaddr_region.start() + SVSM_PERTASK_SHADOW_STACK_BASE_OFFSET,
                Arc::new(Mapping::new(shadow_stack)),
            )?;
        }

        // Call the correct stack creation routine for this task.
        let (stack, raw_bounds, rsp_offset) = if args.vm_user_range.is_some() {
            Self::allocate_utask_stack(cpu, args.entry, xsa_addr)?
        } else {
            Self::allocate_ktask_stack(cpu, args.entry, xsa_addr, args.start_parameter)?
        };
        let stack_start = vaddr_region.start() + SVSM_PERTASK_STACK_BASE_OFFSET;
        vm_kernel_range.insert_at(stack_start, stack)?;

        vm_kernel_range.populate(&mut pgtable);

        // Remap at the per-task offset
        let bounds = MemoryRegion::new(stack_start + raw_bounds.start().into(), raw_bounds.len());
        // Stack frames should be 16b-aligned
        debug_assert!(bounds.end().is_aligned(16));

        Ok(Arc::new(Task {
            rsp: bounds
                .end()
                .checked_sub(rsp_offset)
                .expect("Invalid stack offset from task stack allocator")
                .bits() as u64,
            ssp: shadow_stack_offset,
            xsa,
            stack_bounds: bounds,
            shadow_stack_base,
            page_table: SpinLock::new(pgtable),
            _ktask_region: ktask_region,
            vm_kernel_range,
            vm_user_range: args.vm_user_range,
            sched_state: RWLock::new(TaskSchedState {
                idle_task: false,
                state: TaskState::RUNNING,
                cpu_index: cpu.get_cpu_index(),
            }),
            name: args.name,
            id: TASK_ID_ALLOCATOR.next_id(),
            rootdir: args.rootdir,
            list_link: LinkedListAtomicLink::default(),
            runlist_link: LinkedListAtomicLink::default(),
            objs: Arc::new(RWLock::new(BTreeMap::new())),
        }))
    }

    pub fn create(
        cpu: &PerCpu,
        entry: extern "C" fn(usize),
        start_parameter: usize,
        name: String,
    ) -> Result<TaskPointer, SvsmError> {
        let create_args = CreateTaskArguments {
            entry: entry as usize,
            start_parameter,
            name,
            vm_user_range: None,
            rootdir: opendir("/")?,
        };
        Self::create_common(cpu, create_args)
    }

    pub fn create_user(
        cpu: &PerCpu,
        user_entry: usize,
        root: Arc<dyn Directory>,
        name: String,
    ) -> Result<TaskPointer, SvsmError> {
        let vm_user_range = VMR::new(USER_MEM_START, USER_MEM_END, PTEntryFlags::USER);
        // SAFETY: the user address range is fully aligned to top-level paging
        // boundaries.
        unsafe {
            vm_user_range.initialize_lazy()?;
        }
        let create_args = CreateTaskArguments {
            entry: user_entry,
            start_parameter: 0,
            name,
            vm_user_range: Some(vm_user_range),
            rootdir: root,
        };
        Self::create_common(cpu, create_args)
    }

    pub fn stack_bounds(&self) -> MemoryRegion<VirtAddr> {
        self.stack_bounds
    }

    pub fn get_task_name(&self) -> &String {
        &self.name
    }

    pub fn get_task_id(&self) -> u32 {
        self.id
    }

    pub fn rootdir(&self) -> Arc<dyn Directory> {
        self.rootdir.clone()
    }

    pub fn set_task_running(&self) {
        self.sched_state.lock_write().state = TaskState::RUNNING;
    }

    pub fn set_task_terminated(&self) {
        self.sched_state
            .lock_write()
            .panic_on_idle("Trying to terminate idle task")
            .state = TaskState::TERMINATED;
    }

    pub fn set_task_blocked(&self) {
        self.sched_state
            .lock_write()
            .panic_on_idle("Trying to block idle task")
            .state = TaskState::BLOCKED;
    }

    pub fn is_running(&self) -> bool {
        self.sched_state.lock_read().state == TaskState::RUNNING
    }

    pub fn is_terminated(&self) -> bool {
        self.sched_state.lock_read().state == TaskState::TERMINATED
    }

    pub fn set_idle_task(&self) {
        self.sched_state.lock_write().idle_task = true;
    }

    pub fn is_idle_task(&self) -> bool {
        self.sched_state.lock_read().idle_task
    }

    pub fn update_cpu(&self, new_cpu_index: usize) -> usize {
        let mut state = self.sched_state.lock_write();
        let old_cpu_index = state.cpu_index;
        state.cpu_index = new_cpu_index;
        old_cpu_index
    }

    pub fn handle_pf(&self, vaddr: VirtAddr, write: bool) -> Result<(), SvsmError> {
        self.vm_kernel_range.handle_page_fault(vaddr, write)
    }

    pub fn fault(&self, vaddr: VirtAddr, write: bool) -> Result<(), SvsmError> {
        if vaddr >= USER_MEM_START && vaddr < USER_MEM_END && self.vm_user_range.is_some() {
            let vmr = self.vm_user_range.as_ref().unwrap();
            let mut pgtbl = self.page_table.lock();
            vmr.populate_addr(&mut pgtbl, vaddr);
            vmr.handle_page_fault(vaddr, write)?;
            Ok(())
        } else {
            Err(SvsmError::Mem)
        }
    }

    fn allocate_stack_common() -> Result<(Arc<Mapping>, MemoryRegion<VirtAddr>), SvsmError> {
        let stack = VMKernelStack::new()?;
        let bounds = stack.bounds(VirtAddr::from(0u64));

        let mapping = Arc::new(Mapping::new(stack));

        Ok((mapping, bounds))
    }

    fn allocate_ktask_stack(
        cpu: &PerCpu,
        entry: usize,
        xsa_addr: usize,
        start_parameter: usize,
    ) -> Result<(Arc<Mapping>, MemoryRegion<VirtAddr>, usize), SvsmError> {
        let (mapping, bounds) = Task::allocate_stack_common()?;

        let percpu_mapping = cpu.new_mapping(mapping.clone())?;

        // We need to setup a context on the stack that matches the stack layout
        // defined in switch_context below.
        let stack_tos = percpu_mapping.virt_addr() + bounds.end().bits();
        // Make space for the task termination handler
        let stack_offset = size_of::<u64>();
        let stack_ptr = stack_tos
            .checked_sub(stack_offset)
            .unwrap()
            .as_mut_ptr::<u8>();
        // To ensure stack frames are 16b-aligned, ret_addr must be 16b-aligned
        // so that (%rsp + 8) is 16b-aligned after the ret instruction in
        // switch_context
        debug_assert!(VirtAddr::from(stack_ptr)
            .checked_sub(8)
            .unwrap()
            .is_aligned(16));

        // 'Push' the task frame onto the stack
        unsafe {
            let task_context = stack_ptr
                .sub(size_of::<TaskContext>())
                .cast::<TaskContext>();
            // The processor flags must always be in a default state, unrelated
            // to the flags of the caller.  In particular, interrupts must be
            // disabled because the task switch code expects to execute a new
            // task with interrupts disabled.
            (*task_context).flags = 2;
            // ret_addr
            (*task_context).regs.rdi = entry;
            // xsave area addr
            (*task_context).regs.rsi = xsa_addr;
            // start argument parameter.
            (*task_context).regs.rdx = start_parameter;
            (*task_context).ret_addr = run_kernel_task as *const () as u64;
            // Task termination handler for when entry point returns
            stack_ptr.cast::<u64>().write(task_exit as *const () as u64);
        }

        Ok((mapping, bounds, stack_offset + size_of::<TaskContext>()))
    }

    fn allocate_utask_stack(
        cpu: &PerCpu,
        user_entry: usize,
        xsa_addr: usize,
    ) -> Result<(Arc<Mapping>, MemoryRegion<VirtAddr>, usize), SvsmError> {
        let (mapping, bounds) = Task::allocate_stack_common()?;
        // Do not run user-mode with IRQs enabled on platforms which are not
        // ready for it.
        let iret_rflags: usize = if SVSM_PLATFORM.use_interrupts() {
            2 | EFLAGS_IF
        } else {
            2
        };

        let percpu_mapping = cpu.new_mapping(mapping.clone())?;

        // We need to setup a context on the stack that matches the stack layout
        // defined in switch_context below.
        let stack_tos = percpu_mapping.virt_addr() + bounds.end().bits();
        // Make space for the IRET frame
        let stack_offset = size_of::<X86ExceptionContext>();
        let stack_ptr = stack_tos
            .checked_sub(stack_offset)
            .unwrap()
            .as_mut_ptr::<u8>();
        // To ensure stack frames are 16b-aligned, ret_addr must be 16b-aligned
        // so that (%rsp + 8) is 16b-aligned after the ret instruction in
        // switch_context
        debug_assert!(VirtAddr::from(stack_ptr)
            .checked_sub(8)
            .unwrap()
            .is_aligned(16));

        // 'Push' the task frame onto the stack
        unsafe {
            // Setup IRQ return frame.  User-mode tasks always run with
            // interrupts enabled.
            let mut iret_frame = X86ExceptionContext::default();
            iret_frame.frame.rip = user_entry;
            iret_frame.frame.cs = (SVSM_USER_CS | 3).into();
            iret_frame.frame.flags = iret_rflags;
            iret_frame.frame.rsp = (USER_MEM_END - 8).into();
            iret_frame.frame.ss = (SVSM_USER_DS | 3).into();
            debug_assert!(is_aligned(iret_frame.frame.rsp + 8, 16));

            // Copy IRET frame to stack
            let stack_iret_frame = stack_ptr.cast::<X86ExceptionContext>();
            *stack_iret_frame = iret_frame;

            let mut task_context = TaskContext {
                ret_addr: VirtAddr::from(return_new_task as *const ())
                    .bits()
                    .try_into()
                    .unwrap(),
                ..Default::default()
            };

            // xsave area addr
            task_context.regs.rdi = xsa_addr;
            let stack_task_context = stack_ptr
                .sub(size_of::<TaskContext>())
                .cast::<TaskContext>();
            *stack_task_context = task_context;
        }

        Ok((mapping, bounds, stack_offset + size_of::<TaskContext>()))
    }

    fn allocate_xsave_area() -> PageBox<[u8]> {
        let len = get_xsave_area_size() as usize;
        let xsa = PageBox::<[u8]>::try_new_slice(0u8, NonZeroUsize::new(len).unwrap());
        if xsa.is_err() {
            panic!("Error while allocating xsave area");
        }
        xsa.unwrap()
    }

    pub fn mmap_common(
        vmr: &VMR,
        addr: VirtAddr,
        file: Option<&FileHandle>,
        offset: usize,
        size: usize,
        flags: VMFileMappingFlags,
    ) -> Result<VirtAddr, SvsmError> {
        let mapping = if let Some(f) = file {
            create_file_mapping(f, offset, size, flags)?
        } else {
            create_anon_mapping(size, flags)?
        };

        if flags.contains(VMFileMappingFlags::Fixed) {
            Ok(vmr.insert_at(addr, mapping)?)
        } else {
            Ok(vmr.insert_hint(addr, mapping)?)
        }
    }

    pub fn mmap_kernel(
        &self,
        addr: VirtAddr,
        file: Option<&FileHandle>,
        offset: usize,
        size: usize,
        flags: VMFileMappingFlags,
    ) -> Result<VirtAddr, SvsmError> {
        Self::mmap_common(&self.vm_kernel_range, addr, file, offset, size, flags)
    }

    pub fn mmap_kernel_guard<'a>(
        &'a self,
        addr: VirtAddr,
        file: Option<&FileHandle>,
        offset: usize,
        size: usize,
        flags: VMFileMappingFlags,
    ) -> Result<VMMappingGuard<'a>, SvsmError> {
        let vaddr = Self::mmap_common(&self.vm_kernel_range, addr, file, offset, size, flags)?;
        Ok(VMMappingGuard::new(&self.vm_kernel_range, vaddr))
    }

    pub fn mmap_user(
        &self,
        addr: VirtAddr,
        file: Option<&FileHandle>,
        offset: usize,
        size: usize,
        flags: VMFileMappingFlags,
    ) -> Result<VirtAddr, SvsmError> {
        if self.vm_user_range.is_none() {
            return Err(SvsmError::Mem);
        }

        let vmr = self.vm_user_range.as_ref().unwrap();

        Self::mmap_common(vmr, addr, file, offset, size, flags)
    }

    pub fn munmap_kernel(&self, addr: VirtAddr) -> Result<(), SvsmError> {
        self.vm_kernel_range.remove(addr)?;
        Ok(())
    }

    pub fn munmap_user(&self, addr: VirtAddr) -> Result<(), SvsmError> {
        if self.vm_user_range.is_none() {
            return Err(SvsmError::Mem);
        }

        self.vm_user_range.as_ref().unwrap().remove(addr)?;
        Ok(())
    }

    /// Adds an object to the current task.
    ///
    /// # Arguments
    ///
    /// * `obj` - The object to be added.
    ///
    /// # Returns
    ///
    /// * `Result<ObjHandle, SvsmError>` - Returns the object handle for the object
    ///   to be added if successful, or an `SvsmError` on failure.
    ///
    /// # Errors
    ///
    /// This function will return an error if allocating the object handle fails.
    pub fn add_obj(&self, obj: Arc<dyn Obj>) -> Result<ObjHandle, SvsmError> {
        let mut objs = self.objs.lock_write();
        let last_key = objs
            .keys()
            .last()
            .map_or(Some(0), |k| u32::from(*k).checked_add(1))
            .ok_or(SvsmError::from(ObjError::InvalidHandle))?;
        let id = ObjHandle::new(if last_key != objs.len() as u32 {
            objs.keys()
                .enumerate()
                .find(|(i, &key)| *i as u32 != u32::from(key))
                .unwrap()
                .0 as u32
        } else {
            last_key
        });

        objs.insert(id, obj);

        Ok(id)
    }

    /// Adds an object to the current task and maps it to a given object-id.
    ///
    /// # Arguments
    ///
    /// * `obj` - The object to be added.
    /// * `handle` - Object handle to reference the object.
    ///
    /// # Returns
    ///
    /// * `Result<ObjHandle, SvsmError>` - Returns the object handle for the object
    ///   to be added if successful, or an `SvsmError` on failure.
    ///
    /// # Errors
    ///
    /// This function will return an error if allocating the object handle
    /// fails or the object id is already in use.
    pub fn add_obj_at(&self, obj: Arc<dyn Obj>, handle: ObjHandle) -> Result<ObjHandle, SvsmError> {
        let mut objs = self.objs.lock_write();

        if objs.get(&handle).is_some() {
            return Err(SvsmError::from(ObjError::Busy));
        }

        objs.insert(handle, obj);

        Ok(handle)
    }

    /// Removes an object from the current task.
    ///
    /// # Arguments
    ///
    /// * `id` - The ObjHandle for the object to be removed.
    ///
    /// # Returns
    ///
    /// * `Result<Arc<dyn Obj>>, SvsmError>` - Returns the removed `Arc<dyn Obj>`
    ///   on success, or an `SvsmError` on failure.
    ///
    /// # Errors
    ///
    /// This function will return an error if the object handle id does not
    /// exist in the current task.
    pub fn remove_obj(&self, id: ObjHandle) -> Result<Arc<dyn Obj>, SvsmError> {
        self.objs
            .lock_write()
            .remove(&id)
            .ok_or(ObjError::NotFound.into())
    }

    /// Retrieves an object from the current task.
    ///
    /// # Arguments
    ///
    /// * `id` - The ObjHandle for the object to be retrieved.
    ///
    /// # Returns
    ///
    /// * `Result<Arc<dyn Obj>>, SvsmError>` - Returns the `Arc<dyn Obj>` on
    ///   success, or an `SvsmError` on failure.
    ///
    /// # Errors
    ///
    /// This function will return an error if the object handle id does not exist
    /// in the current task.
    pub fn get_obj(&self, id: ObjHandle) -> Result<Arc<dyn Obj>, SvsmError> {
        self.objs
            .lock_read()
            .get(&id)
            .cloned()
            .ok_or(ObjError::NotFound.into())
    }
}

pub fn is_task_fault(vaddr: VirtAddr) -> bool {
    (vaddr >= USER_MEM_START && vaddr < USER_MEM_END)
        || (vaddr >= SVSM_PERTASK_BASE && vaddr < SVSM_PERTASK_END)
}

fn task_attach_console() {
    let file_handle = stdout_open();
    let obj_handle = ObjHandle::new(0);
    current_task()
        .add_obj_at(file_handle, obj_handle)
        .expect("Failed to attach console");
}

/// Runs the first time a new task is scheduled, in the context of the new
/// task. Any first-time initialization and setup work for a new task that
/// needs to happen in its context must be done here.
/// # Safety
/// The caller is required to verify the correctness of the save area address.
#[no_mangle]
unsafe fn setup_user_task(xsa_addr: u64) {
    // SAFETY: caller needs to make sure xsa_addr is valid and points to a
    // memory region of sufficient size.
    unsafe {
        // Needs to be the first function called here.
        setup_new_task_common(xsa_addr);
    }
    task_attach_console();
}

unsafe fn setup_new_task_common(xsa_addr: u64) {
    // Re-enable IRQs here, as they are still disabled from the
    // schedule()/sched_init() functions. After the context switch the IrqGuard
    // from the previous task is not dropped, which causes IRQs to stay
    // disabled in the new task.
    // This only needs to be done for the first time a task runs. Any
    // subsequent task switches will go through schedule() and there the guard
    // is dropped, re-enabling IRQs.

    irqs_enable();

    // Perform housekeeping actions following a task switch.
    after_task_switch();

    // SAFETY: The caller takes responsibility for the correctness of the save
    // area address.
    unsafe {
        sse_restore_context(xsa_addr);
    }
}

extern "C" fn run_kernel_task(entry: extern "C" fn(usize), xsa_addr: u64, start_parameter: usize) {
    // SAFETY: the save area address is provided by the context switch assembly
    // code.
    unsafe {
        setup_new_task_common(xsa_addr);
    }
    entry(start_parameter);
}

extern "C" fn task_exit() {
    unsafe {
        current_task_terminated();
    }
    schedule();
}

#[cfg(all(test, test_in_svsm))]
mod tests {
    extern crate alloc;
    use crate::task::start_kernel_task;
    use alloc::string::String;
    use core::arch::asm;
    use core::arch::global_asm;

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_media_and_x87_instructions() {
        let ret: u64;
        unsafe {
            asm!("call test_fpu", out("rax") ret, options(att_syntax));
        }

        assert_eq!(ret, 0);
    }

    global_asm!(
        r#"
    .text
    test_fpu:
        movq $0x3ff, %rax
        shl $52, %rax
        // rax contains 1 in Double Precison FP representation
        movd %rax, %xmm1
        movapd %xmm1, %xmm3

        movq $0x400, %rax
        shl $52, %rax
        // rax contains 2 in Double Precison FP representation
        movd %rax, %xmm2

        divsd %xmm2, %xmm3
        movq $0, %rax
        ret
        "#,
        options(att_syntax)
    );

    global_asm!(
        r#"
    .text
    check_fpu:
        movq $1, %rax
        movq $0x3ff, %rbx
        shl $52, %rbx
        // rbx contains 1 in Double Precison FP representation
        movd %rbx, %xmm4
        movapd %xmm4, %xmm6
        comisd %xmm4, %xmm1
        jnz 1f

        movq $0x400, %rbx
        shl $52, %rbx
        // rbx contains 2 in Double Precison FP representation
        movd %rbx, %xmm5
        comisd %xmm5, %xmm2
        jnz 1f

        divsd %xmm5, %xmm6
        comisd %xmm6, %xmm3
        jnz 1f
        movq $0, %rax
    1:
        ret
        "#,
        options(att_syntax)
    );

    global_asm!(
        r#"
    .text
    alter_fpu:
        movq $0x400, %rax
        shl $52, %rax
        // rax contains 2 in Double Precison FP representation
        movd %rax, %xmm1
        movapd %xmm1, %xmm3

        movq $0x3ff, %rax
        shl $52, %rax
        // rax contains 1 in Double Precison FP representation
        movd %rax, %xmm2
        divsd %xmm3, %xmm2
        movq $0, %rax
        ret
        "#,
        options(att_syntax)
    );

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_fpu_context_switch() {
        start_kernel_task(task1, 1, String::from("task1"))
            .expect("Failed to launch request processing task");
    }

    extern "C" fn task1(start_parameter: usize) {
        assert_eq!(start_parameter, 1);

        let ret: u64;
        unsafe {
            asm!("call test_fpu", options(att_syntax));
        }

        start_kernel_task(task2, 2, String::from("task2"))
            .expect("Failed to launch request processing task");

        unsafe {
            asm!("call check_fpu", out("rax") ret, options(att_syntax));
        }
        assert_eq!(ret, 0);
    }

    extern "C" fn task2(start_parameter: usize) {
        assert_eq!(start_parameter, 2);
        unsafe {
            asm!("call alter_fpu", options(att_syntax));
        }
    }
}
