// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

//
// For release builds this module should not be compiled into the
// binary. See the bottom of this file for placeholders that are
// used when the gdb stub is disabled.
//
#[cfg(feature = "enable-gdb")]
pub mod svsm_gdbstub {
    use crate::address::{Address, VirtAddr};
    use crate::cpu::control_regs::read_cr3;
    use crate::cpu::idt::common::{X86ExceptionContext, BP_VECTOR, DB_VECTOR, VC_VECTOR};
    use crate::cpu::percpu::this_cpu;
    use crate::cpu::X86GeneralRegs;
    use crate::error::SvsmError;
    use crate::locking::{LockGuard, SpinLock};
    use crate::mm::guestmem::{read_u8, write_u8};
    use crate::mm::PerCPUPageMappingGuard;
    use crate::platform::SvsmPlatform;
    use crate::serial::{SerialPort, Terminal};
    use crate::task::{is_current_task, TaskContext, INITIAL_TASK_ID, TASKLIST};
    use core::arch::asm;
    use core::fmt;
    use core::sync::atomic::{AtomicBool, Ordering};
    use gdbstub::common::{Signal, Tid};
    use gdbstub::conn::Connection;
    use gdbstub::stub::state_machine::GdbStubStateMachine;
    use gdbstub::stub::{GdbStubBuilder, MultiThreadStopReason};
    use gdbstub::target::ext::base::multithread::{
        MultiThreadBase, MultiThreadResume, MultiThreadResumeOps, MultiThreadSingleStep,
        MultiThreadSingleStepOps,
    };
    use gdbstub::target::ext::base::BaseOps;
    use gdbstub::target::ext::breakpoints::{Breakpoints, SwBreakpoint};
    use gdbstub::target::ext::thread_extra_info::ThreadExtraInfo;
    use gdbstub::target::{Target, TargetError};
    use gdbstub_arch::x86::reg::X86_64CoreRegs;
    use gdbstub_arch::x86::X86_64_SSE;

    const INT3_INSTR: u8 = 0xcc;
    const MAX_BREAKPOINTS: usize = 32;

    // The static mutable reference to the stack is protected by the GDB_STATE lock.
    #[allow(static_mut_refs)]
    pub fn gdbstub_start(platform: &'static dyn SvsmPlatform) -> Result<(), u64> {
        unsafe {
            let mut target = GdbStubTarget::new();
            #[expect(static_mut_refs)]
            let gdb = GdbStubBuilder::new(GdbStubConnection::new(platform))
                .with_packet_buffer(&mut PACKET_BUFFER)
                .build()
                .expect("Failed to initialise GDB stub")
                .run_state_machine(&mut target)
                .expect("Failed to start GDB state machine");
            *GDB_STATE.lock() = Some(SvsmGdbStub { gdb, target });
            GDB_STACK_TOP = GDB_STACK.as_mut_ptr().offset(GDB_STACK.len() as isize - 1);
        }
        GDB_INITIALISED.store(true, Ordering::Relaxed);
        Ok(())
    }

    #[derive(PartialEq, Eq, Debug)]
    enum ExceptionType {
        Debug,
        SwBreakpoint,
        PageFault,
    }

    impl From<usize> for ExceptionType {
        fn from(value: usize) -> Self {
            match value {
                BP_VECTOR => ExceptionType::SwBreakpoint,
                DB_VECTOR => ExceptionType::Debug,
                VC_VECTOR => ExceptionType::Debug,
                _ => ExceptionType::PageFault,
            }
        }
    }

    pub fn handle_debug_exception(ctx: &mut X86ExceptionContext, exception: usize) {
        let exception_type = ExceptionType::from(exception);
        let id = this_cpu().runqueue().lock_read().current_task_id();
        let mut task_ctx = TaskContext {
            regs: X86GeneralRegs {
                r15: ctx.regs.r15,
                r14: ctx.regs.r14,
                r13: ctx.regs.r13,
                r12: ctx.regs.r12,
                r11: ctx.regs.r11,
                r10: ctx.regs.r10,
                r9: ctx.regs.r9,
                r8: ctx.regs.r8,
                rbp: ctx.regs.rbp,
                rdi: ctx.regs.rdi,
                rsi: ctx.regs.rsi,
                rdx: ctx.regs.rdx,
                rcx: ctx.regs.rcx,
                rbx: ctx.regs.rbx,
                rax: ctx.regs.rax,
            },
            rsp: ctx.frame.rsp as u64,
            flags: ctx.frame.flags as u64,
            ret_addr: ctx.frame.rip as u64,
        };

        // Locking the GDB state for the duration of the stop will cause any other
        // APs that hit a breakpoint to busy-wait until the current CPU releases
        // the GDB state. They will then resume and report the stop state
        // to GDB.
        // One thing to watch out for - if a breakpoint is inadvertently placed in
        // the GDB handling code itself then this will cause a re-entrant state
        // within the same CPU causing a deadlock.
        loop {
            let mut gdb_state = GDB_STATE.lock();
            if let Some(stub) = gdb_state.as_ref() {
                if stub.target.is_single_step != 0 && stub.target.is_single_step != id {
                    continue;
                }
            }

            // SAFETY: swaps the stack with GDB_STACK_TOP, which is held uniquely mutably
            // under the GDB_STACK_LOCK, and then sets the stack to the result of handle_stop,
            // which is the expected behavior.
            unsafe {
                asm!(
                    r#"
                        movq    %rsp, (%rax)
                        movq    %rax, %rsp
                        call    handle_stop
                        popq    %rax
                        movq    %rax, %rsp
                    "#,
                    in("rsi") exception_type as u64,
                    in("rdi") &mut task_ctx,
                    in("rdx") &mut gdb_state,
                    in("rax") GDB_STACK_TOP.expose_provenance(),
                    options(att_syntax));
            }

            ctx.frame.rip = task_ctx.ret_addr as usize;
            ctx.frame.flags = task_ctx.flags as usize;
            ctx.frame.rsp = task_ctx.rsp as usize;
            ctx.regs.rax = task_ctx.regs.rax;
            ctx.regs.rbx = task_ctx.regs.rbx;
            ctx.regs.rcx = task_ctx.regs.rcx;
            ctx.regs.rdx = task_ctx.regs.rdx;
            ctx.regs.rsi = task_ctx.regs.rsi;
            ctx.regs.rdi = task_ctx.regs.rdi;
            ctx.regs.rbp = task_ctx.regs.rbp;
            ctx.regs.r8 = task_ctx.regs.r8;
            ctx.regs.r9 = task_ctx.regs.r9;
            ctx.regs.r10 = task_ctx.regs.r10;
            ctx.regs.r11 = task_ctx.regs.r11;
            ctx.regs.r12 = task_ctx.regs.r12;
            ctx.regs.r13 = task_ctx.regs.r13;
            ctx.regs.r14 = task_ctx.regs.r14;
            ctx.regs.r15 = task_ctx.regs.r15;

            break;
        }
    }

    pub fn debug_break() {
        if GDB_INITIALISED.load(Ordering::Acquire) {
            log::info!("***********************************");
            log::info!("* Waiting for connection from GDB *");
            log::info!("***********************************");
            unsafe {
                asm!("int3");
            }
        }
    }

    static GDB_INITIALISED: AtomicBool = AtomicBool::new(false);
    static GDB_STATE: SpinLock<Option<SvsmGdbStub<'_>>> = SpinLock::new(None);
    static mut PACKET_BUFFER: [u8; 4096] = [0; 4096];
    // Allocate the GDB stack as an array of u64's to ensure 8 byte alignment of the stack.
    static mut GDB_STACK: [u64; 8192] = [0; 8192];
    static mut GDB_STACK_TOP: *mut u64 = core::ptr::null_mut();

    struct GdbTaskContext {
        cr3: usize,
    }

    impl GdbTaskContext {
        #[must_use = "The task switch will have no effect if the context is dropped"]
        fn switch_to_task(id: u32) -> Self {
            let cr3 = if is_current_task(id) {
                0
            } else {
                let tl = TASKLIST.lock();
                let cr3 = read_cr3();
                let task = tl.get_task(id);
                if let Some(task) = task {
                    unsafe {
                        task.page_table.lock().load();
                    }
                    cr3.bits()
                } else {
                    0
                }
            };
            Self { cr3 }
        }
    }

    impl Drop for GdbTaskContext {
        fn drop(&mut self) {
            if self.cr3 != 0 {
                unsafe {
                    asm!("mov %rax, %cr3",
                         in("rax") self.cr3,
                         options(att_syntax));
                }
            }
        }
    }

    struct SvsmGdbStub<'a> {
        gdb: GdbStubStateMachine<'a, GdbStubTarget, GdbStubConnection<'a>>,
        target: GdbStubTarget,
    }

    impl fmt::Debug for SvsmGdbStub<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "SvsmGdbStub")
        }
    }

    #[no_mangle]
    fn handle_stop(
        ctx: &mut TaskContext,
        exception_type: ExceptionType,
        gdb_state: &mut LockGuard<'_, Option<SvsmGdbStub<'_>>>,
    ) {
        let SvsmGdbStub { gdb, mut target } = gdb_state.take().expect("Invalid GDB state");

        target.set_regs(ctx);

        let hardcoded_bp = (exception_type == ExceptionType::SwBreakpoint)
            && !target.is_breakpoint(ctx.ret_addr as usize - 1);

        // If the current address is on a breakpoint then we need to
        // move the IP back by one byte
        if (exception_type == ExceptionType::SwBreakpoint)
            && target.is_breakpoint(ctx.ret_addr as usize - 1)
        {
            ctx.ret_addr -= 1;
        }

        let tid = Tid::new(this_cpu().runqueue().lock_read().current_task_id() as usize)
            .expect("Current task has invalid ID");
        let mut new_gdb = match gdb {
            GdbStubStateMachine::Running(gdb_inner) => {
                let reason = if hardcoded_bp {
                    MultiThreadStopReason::SignalWithThread {
                        tid,
                        signal: Signal::SIGINT,
                    }
                } else if exception_type == ExceptionType::PageFault {
                    MultiThreadStopReason::SignalWithThread {
                        tid,
                        signal: Signal::SIGSEGV,
                    }
                } else {
                    MultiThreadStopReason::SwBreak(tid)
                };
                gdb_inner
                    .report_stop(&mut target, reason)
                    .expect("Failed to handle software breakpoint")
            }
            _ => gdb,
        };

        loop {
            new_gdb = match new_gdb {
                // The first entry into the debugger is via a forced breakpoint during
                // initialisation. The state at this point will be Idle instead of
                // Running.
                GdbStubStateMachine::Idle(mut gdb_inner) => {
                    let byte = gdb_inner
                        .borrow_conn()
                        .read()
                        .expect("Failed to read from GDB port");
                    gdb_inner.incoming_data(&mut target, byte)
                        .expect("Could not open serial port for GDB connection. \
                                Please ensure the virtual machine is configured to provide a second serial port.")
                }
                GdbStubStateMachine::Running(gdb_inner) => {
                    new_gdb = gdb_inner.into();
                    break;
                }
                _ => {
                    panic!("Invalid GDB state when handling breakpoint interrupt");
                }
            };
        }
        if target.is_single_step == tid.get() as u32 {
            ctx.flags |= 0x100;
        } else {
            ctx.flags &= !0x100;
        }
        **gdb_state = Some(SvsmGdbStub {
            gdb: new_gdb,
            target,
        });
    }

    struct GdbStubConnection<'a> {
        serial_port: SerialPort<'a>,
    }

    impl<'a> GdbStubConnection<'a> {
        fn new(platform: &'a dyn SvsmPlatform) -> Self {
            let serial_port = SerialPort::new(platform.get_io_port(), 0x2f8);
            serial_port.init();
            Self { serial_port }
        }

        fn read(&self) -> Result<u8, &'static str> {
            Ok(self.serial_port.get_byte())
        }
    }

    impl Connection for GdbStubConnection<'_> {
        type Error = usize;

        fn write(&mut self, byte: u8) -> Result<(), Self::Error> {
            self.serial_port.put_byte(byte);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    struct GdbStubBreakpoint {
        addr: VirtAddr,
        inst: u8,
    }

    struct GdbStubTarget {
        ctx: *mut TaskContext,
        breakpoints: [GdbStubBreakpoint; MAX_BREAKPOINTS],
        is_single_step: u32,
    }

    // SAFETY: this can only be unsafe via aliasing of the ctx field,
    // which is the exception context on the stack and should not be accessed
    // from any other thread.
    unsafe impl Send for GdbStubTarget {}
    // SAFETY: see safety comment above
    unsafe impl Sync for GdbStubTarget {}

    impl GdbStubTarget {
        const fn new() -> Self {
            Self {
                ctx: core::ptr::null_mut(),
                breakpoints: [GdbStubBreakpoint {
                    addr: VirtAddr::null(),
                    inst: 0,
                }; MAX_BREAKPOINTS],
                is_single_step: 0,
            }
        }

        fn ctx(&self) -> Option<&TaskContext> {
            // SAFETY: this is a pointer to the exception context on the
            // stack, so it is not aliased from a different task. We trust
            // the debug exception handler to pass a well-aligned pointer
            // pointing to valid memory.
            unsafe { self.ctx.as_ref() }
        }

        fn ctx_mut(&mut self) -> Option<&mut TaskContext> {
            // SAFETY: this is a pointer to the exception context on the
            // stack, so it is not aliased from a different task. We trust
            // the debug exception handler to pass a well-aligned pointer
            // pointing to valid memory.
            unsafe { self.ctx.as_mut() }
        }

        fn set_regs(&mut self, ctx: &mut TaskContext) {
            self.ctx = core::ptr::from_mut(ctx)
        }

        fn is_breakpoint(&self, rip: usize) -> bool {
            self.breakpoints.iter().any(|b| b.addr.bits() == rip)
        }

        fn write_bp_address(addr: VirtAddr, value: u8) -> Result<(), SvsmError> {
            // Virtual addresses in code are likely to be in read-only memory. If we
            // can get the physical address for this VA then create a temporary
            // mapping

            let Ok(phys) = this_cpu().get_pgtable().phys_addr(addr) else {
                // The virtual address is not one that SVSM has mapped.
                // Try safely writing it to the original virtual address
                // SAFETY: it is up to the user to ensure that the address we
                // are writing a breakpoint to is valid.
                return unsafe { write_u8(addr, value) };
            };

            let guard = PerCPUPageMappingGuard::create_4k(phys.page_align())?;
            let dst = guard
                .virt_addr()
                .checked_add(phys.page_offset())
                .ok_or(SvsmError::InvalidAddress)?;

            // SAFETY: guard is a new mapped page, non controllable by user.
            // We also checked that the destination address didn't overflow.
            unsafe { write_u8(dst, value) }
        }
    }

    impl Target for GdbStubTarget {
        type Arch = X86_64_SSE;

        type Error = usize;

        fn base_ops(&mut self) -> BaseOps<'_, Self::Arch, Self::Error> {
            BaseOps::MultiThread(self)
        }

        #[inline(always)]
        fn support_breakpoints(
            &mut self,
        ) -> Option<gdbstub::target::ext::breakpoints::BreakpointsOps<'_, Self>> {
            Some(self)
        }
    }

    impl From<&TaskContext> for X86_64CoreRegs {
        fn from(value: &TaskContext) -> Self {
            let mut regs = X86_64CoreRegs::default();
            regs.rip = value.ret_addr;
            regs.regs = [
                value.regs.rax as u64,
                value.regs.rbx as u64,
                value.regs.rcx as u64,
                value.regs.rdx as u64,
                value.regs.rsi as u64,
                value.regs.rdi as u64,
                value.regs.rbp as u64,
                value.rsp,
                value.regs.r8 as u64,
                value.regs.r9 as u64,
                value.regs.r10 as u64,
                value.regs.r11 as u64,
                value.regs.r12 as u64,
                value.regs.r13 as u64,
                value.regs.r14 as u64,
                value.regs.r15 as u64,
            ];
            regs.eflags = value.flags as u32;
            regs
        }
    }

    impl MultiThreadBase for GdbStubTarget {
        fn read_registers(
            &mut self,
            regs: &mut <Self::Arch as gdbstub::arch::Arch>::Registers,
            tid: Tid,
        ) -> gdbstub::target::TargetResult<(), Self> {
            if is_current_task(tid.get() as u32) {
                *regs = X86_64CoreRegs::from(self.ctx().unwrap());
            } else {
                let task = TASKLIST.lock().get_task(tid.get() as u32);
                if let Some(task) = task {
                    // The registers are stored in the top of the task stack as part of the
                    // saved context. We need to switch to the task pagetable to access them.
                    let _task_context = GdbTaskContext::switch_to_task(tid.get() as u32);
                    unsafe {
                        *regs = X86_64CoreRegs::from(&*(task.rsp as *const TaskContext));
                    };
                    regs.regs[7] = task.rsp;
                } else {
                    *regs = <Self::Arch as gdbstub::arch::Arch>::Registers::default();
                }
            }
            Ok(())
        }

        fn write_registers(
            &mut self,
            regs: &<Self::Arch as gdbstub::arch::Arch>::Registers,
            tid: Tid,
        ) -> gdbstub::target::TargetResult<(), Self> {
            if !is_current_task(tid.get() as u32) {
                return Err(TargetError::NonFatal);
            }

            let context = self.ctx_mut().unwrap();

            context.ret_addr = regs.rip;
            context.regs.rax = regs.regs[0] as usize;
            context.regs.rbx = regs.regs[1] as usize;
            context.regs.rcx = regs.regs[2] as usize;
            context.regs.rdx = regs.regs[3] as usize;
            context.regs.rsi = regs.regs[4] as usize;
            context.regs.rdi = regs.regs[5] as usize;
            context.regs.rbp = regs.regs[6] as usize;
            context.rsp = regs.regs[7];
            context.regs.r8 = regs.regs[8] as usize;
            context.regs.r9 = regs.regs[9] as usize;
            context.regs.r10 = regs.regs[10] as usize;
            context.regs.r11 = regs.regs[11] as usize;
            context.regs.r12 = regs.regs[12] as usize;
            context.regs.r13 = regs.regs[13] as usize;
            context.regs.r14 = regs.regs[14] as usize;
            context.regs.r15 = regs.regs[15] as usize;
            context.flags = regs.eflags as u64;
            Ok(())
        }

        fn read_addrs(
            &mut self,
            start_addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
            data: &mut [u8],
            tid: Tid,
        ) -> gdbstub::target::TargetResult<(), Self> {
            // Switch to the task pagetable if necessary. The switch back will
            // happen automatically when the variable falls out of scope
            let _task_context = GdbTaskContext::switch_to_task(tid.get() as u32);
            let start_addr = VirtAddr::from(start_addr);
            for (off, dst) in data.iter_mut().enumerate() {
                let Ok(val) = read_u8(start_addr + off) else {
                    return Err(TargetError::NonFatal);
                };
                *dst = val;
            }
            Ok(())
        }

        fn write_addrs(
            &mut self,
            start_addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
            data: &[u8],
            _tid: Tid,
        ) -> gdbstub::target::TargetResult<(), Self> {
            let start_addr = VirtAddr::from(start_addr);
            for (off, src) in data.iter().enumerate() {
                let dst = start_addr.checked_add(off).ok_or(TargetError::NonFatal)?;

                // SAFETY: We trust the caller of this trait method to provide a valid address.
                // We only cheked that start_adddr + off didn't overflow.
                unsafe { write_u8(dst, *src).map_err(|_| TargetError::NonFatal)? }
            }
            Ok(())
        }

        #[inline(always)]
        fn support_resume(&mut self) -> Option<MultiThreadResumeOps<'_, Self>> {
            Some(self)
        }

        fn list_active_threads(
            &mut self,
            thread_is_active: &mut dyn FnMut(Tid),
        ) -> Result<(), Self::Error> {
            let mut tl = TASKLIST.lock();

            // Get the current task. If this is the first request after the remote
            // GDB has connected then we need to report the current task first.
            // There is no harm in doing this every time the thread list is requested.
            let current_task = this_cpu().runqueue().lock_read().current_task_id();
            if current_task == INITIAL_TASK_ID {
                thread_is_active(Tid::new(INITIAL_TASK_ID as usize).unwrap());
            } else {
                thread_is_active(Tid::new(current_task as usize).unwrap());

                let mut cursor = tl.list().front_mut();
                while cursor.get().is_some() {
                    let this_task = cursor.get().unwrap().get_task_id();
                    if this_task != current_task {
                        thread_is_active(Tid::new(this_task as usize).unwrap());
                    }
                    cursor.move_next();
                }
            }
            Ok(())
        }

        fn support_thread_extra_info(
            &mut self,
        ) -> Option<gdbstub::target::ext::thread_extra_info::ThreadExtraInfoOps<'_, Self>> {
            Some(self)
        }
    }

    impl ThreadExtraInfo for GdbStubTarget {
        fn thread_extra_info(&self, tid: Tid, buf: &mut [u8]) -> Result<usize, Self::Error> {
            // Get the current task from the stopped CPU so we can mark it as stopped
            let tl = TASKLIST.lock();
            let str = match tl.get_task(tid.get() as u32) {
                Some(task) => {
                    if task.is_running() {
                        "Running".as_bytes()
                    } else if task.is_terminated() {
                        "Terminated".as_bytes()
                    } else {
                        "Blocked".as_bytes()
                    }
                }
                None => "Stopped".as_bytes(),
            };
            let mut count = 0;
            for (dst, src) in buf.iter_mut().zip(str) {
                *dst = *src;
                count += 1;
            }
            Ok(count)
        }
    }

    impl MultiThreadResume for GdbStubTarget {
        fn resume(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        #[inline(always)]
        fn support_single_step(&mut self) -> Option<MultiThreadSingleStepOps<'_, Self>> {
            Some(self)
        }

        fn clear_resume_actions(&mut self) -> Result<(), Self::Error> {
            self.is_single_step = 0;
            Ok(())
        }

        fn set_resume_action_continue(
            &mut self,
            _tid: Tid,
            _signal: Option<Signal>,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl MultiThreadSingleStep for GdbStubTarget {
        fn set_resume_action_step(
            &mut self,
            tid: Tid,
            _signal: Option<Signal>,
        ) -> Result<(), Self::Error> {
            self.is_single_step = tid.get() as u32;
            Ok(())
        }
    }

    impl Breakpoints for GdbStubTarget {
        #[inline(always)]
        fn support_sw_breakpoint(
            &mut self,
        ) -> Option<gdbstub::target::ext::breakpoints::SwBreakpointOps<'_, Self>> {
            Some(self)
        }

        #[inline(always)]
        fn support_hw_breakpoint(
            &mut self,
        ) -> Option<gdbstub::target::ext::breakpoints::HwBreakpointOps<'_, Self>> {
            None
        }

        #[inline(always)]
        fn support_hw_watchpoint(
            &mut self,
        ) -> Option<gdbstub::target::ext::breakpoints::HwWatchpointOps<'_, Self>> {
            None
        }
    }

    impl SwBreakpoint for GdbStubTarget {
        fn add_sw_breakpoint(
            &mut self,
            addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
            _kind: <Self::Arch as gdbstub::arch::Arch>::BreakpointKind,
        ) -> gdbstub::target::TargetResult<bool, Self> {
            // Find a free breakpoint slot
            let Some(free_bp) = self.breakpoints.iter_mut().find(|b| b.addr.is_null()) else {
                return Ok(false);
            };
            // The breakpoint works by taking the opcode at the bp address, storing
            // it and replacing it with an INT3 instruction
            let vaddr = VirtAddr::from(addr);
            let Ok(inst) = read_u8(vaddr) else {
                return Ok(false);
            };
            let Ok(_) = GdbStubTarget::write_bp_address(vaddr, INT3_INSTR) else {
                return Ok(false);
            };
            *free_bp = GdbStubBreakpoint { addr: vaddr, inst };
            Ok(true)
        }

        fn remove_sw_breakpoint(
            &mut self,
            addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
            _kind: <Self::Arch as gdbstub::arch::Arch>::BreakpointKind,
        ) -> gdbstub::target::TargetResult<bool, Self> {
            let vaddr = VirtAddr::from(addr);
            let Some(bp) = self.breakpoints.iter_mut().find(|b| b.addr == vaddr) else {
                return Ok(false);
            };
            let Ok(_) = GdbStubTarget::write_bp_address(vaddr, bp.inst) else {
                return Ok(false);
            };
            bp.addr = VirtAddr::null();
            Ok(true)
        }
    }

    #[cfg(test)]
    pub mod tests {
        extern crate alloc;

        use super::ExceptionType;
        use crate::cpu::idt::common::{BP_VECTOR, VC_VECTOR};
        use alloc::vec;
        use alloc::vec::Vec;

        #[test]
        fn exception_type_from() {
            let exceptions: Vec<ExceptionType> = [VC_VECTOR, BP_VECTOR, 0]
                .iter()
                .map(|e| ExceptionType::from(*e))
                .collect();
            assert_eq!(
                exceptions,
                vec![
                    ExceptionType::Debug,
                    ExceptionType::SwBreakpoint,
                    ExceptionType::PageFault
                ]
            );
        }
    }
}

#[cfg(not(feature = "enable-gdb"))]
pub mod svsm_gdbstub {
    use crate::cpu::X86ExceptionContext;
    use crate::platform::SvsmPlatform;

    pub fn gdbstub_start(_platform: &'static dyn SvsmPlatform) -> Result<(), u64> {
        Ok(())
    }

    pub fn handle_debug_exception(_ctx: &mut X86ExceptionContext, _exception: usize) {}

    pub fn debug_break() {}
}
