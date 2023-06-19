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
    extern crate alloc;

    use crate::address::{Address, VirtAddr};
    use crate::cpu::control_regs::read_cr3;
    use crate::cpu::idt::X86ExceptionContext;
    use crate::cpu::percpu::this_cpu;
    use crate::error::SvsmError;
    use crate::locking::SpinLock;
    use crate::mm::guestmem::{read_u8, write_u8};
    use crate::mm::PerCPUPageMappingGuard;
    use crate::serial::{SerialPort, Terminal};
    use crate::svsm_console::SVSMIOPort;
    use crate::task::{is_current_task, TaskContext, TaskState, INITIAL_TASK_ID, TASKS};
    use core::arch::asm;
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

    pub fn gdbstub_start() -> Result<(), u64> {
        unsafe {
            let mut target = GdbStubTarget::new();
            let gdb = GdbStubBuilder::new(GdbStubConnection::new())
                .with_packet_buffer(&mut PACKET_BUFFER)
                .build()
                .expect("Failed to initialise GDB stub")
                .run_state_machine(&mut target)
                .expect("Failed to start GDB state machine");
            *GDB_STATE.lock() = Some(SvsmGdbStub { gdb, target });
            GDB_STACK_TOP = GDB_STACK.as_mut_ptr().offset(GDB_STACK.len() as isize - 1) as u64;
        }
        GDB_INITIALISED.store(true, Ordering::Relaxed);
        Ok(())
    }

    enum ExceptionType {
        Debug,
        SwBreakpoint,
    }

    pub fn handle_bp_exception(ctx: &mut X86ExceptionContext) {
        handle_exception(ctx, ExceptionType::SwBreakpoint);
    }

    pub fn handle_db_exception(ctx: &mut X86ExceptionContext) {
        handle_exception(ctx, ExceptionType::Debug);
    }

    fn handle_exception(ctx: &mut X86ExceptionContext, exception_type: ExceptionType) {
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
                in("rdi") ctx,
                in("rax") GDB_STACK_TOP,
                options(att_syntax));
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
    static GDB_STATE: SpinLock<Option<SvsmGdbStub>> = SpinLock::new(None);
    static GDB_IO: SVSMIOPort = SVSMIOPort::new();
    static mut GDB_SERIAL: SerialPort = SerialPort {
        driver: &GDB_IO,
        port: 0x2f8,
    };
    static mut PACKET_BUFFER: [u8; 4096] = [0; 4096];
    // Allocate the GDB stack as an array of u64's to ensure 8 byte alignment of the stack.
    static mut GDB_STACK: [u64; 8192] = [0; 8192];
    static mut GDB_STACK_TOP: u64 = 0;

    struct GdbTaskContext {
        cr3: usize,
    }

    impl GdbTaskContext {
        fn switch_to_task(id: u32) -> Self {
            let cr3 = if is_current_task(id) {
                0
            } else {
                let tl = TASKS.lock();
                let cr3 = read_cr3();
                let task_node = tl.get_task(id);
                if let Some(task_node) = task_node {
                    task_node.task.borrow_mut().page_table.lock().load();
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
        gdb: GdbStubStateMachine<'a, GdbStubTarget, GdbStubConnection>,
        target: GdbStubTarget,
    }

    #[no_mangle]
    fn handle_stop(ctx: &mut X86ExceptionContext, bp_exception: bool) {
        // Locking the GDB state for the duration of the stop will cause any other
        // APs that hit a breakpoint to busy-wait until the current CPU releases
        // the GDB state. They will then resume and report the stop state
        // to GDB.
        // One thing to watch out for - if a breakpoint is inadvertently placed in
        // the GDB handling code itself then this will cause a re-entrant state
        // within the same CPU causing a deadlock.
        let mut gdb_state = GDB_STATE.lock();
        let SvsmGdbStub { gdb, mut target } = gdb_state.take().unwrap_or_else(|| {
            panic!("Invalid GDB state");
        });

        target.set_regs(ctx);

        let hardcoded_bp = bp_exception && !target.is_breakpoint(ctx.frame.rip - 1);

        // If the current address is on a breakpoint then we need to
        // move the IP back by one byte
        if bp_exception && target.is_breakpoint(ctx.frame.rip - 1) {
            ctx.frame.rip -= 1;
        }

        let tid = match &this_cpu().current_task {
            Some(t) => Tid::new(t.task.borrow().id as usize).unwrap(),
            None => Tid::new(1).unwrap(),
        };

        let mut new_gdb = match gdb {
            GdbStubStateMachine::Running(gdb_inner) => {
                let reason = if hardcoded_bp {
                    MultiThreadStopReason::SignalWithThread {
                        tid,
                        signal: Signal::SIGINT,
                    }
                } else {
                    MultiThreadStopReason::SwBreak(tid)
                };
                match gdb_inner.report_stop(&mut target, reason) {
                    Ok(gdb) => gdb,
                    Err(_) => panic!("Failed to handle software breakpoint"),
                }
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
                    match gdb_inner.incoming_data(&mut target, byte) {
                        Ok(gdb) => gdb,
                        Err(_) => panic!("Could not open serial port for GDB connection. \
                                    Please ensure the virtual machine is configured to provide a second serial port.")
                    }
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
        if target.is_single_step {
            ctx.frame.flags |= 0x100;
        } else {
            ctx.frame.flags &= !0x100;
        }
        *gdb_state = Some(SvsmGdbStub {
            gdb: new_gdb,
            target,
        });
    }

    struct GdbStubConnection;

    impl GdbStubConnection {
        pub const fn new() -> Self {
            Self {}
        }

        pub fn read(&mut self) -> Result<u8, &'static str> {
            unsafe { Ok(GDB_SERIAL.get_byte()) }
        }
    }

    impl Connection for GdbStubConnection {
        type Error = usize;

        fn write(&mut self, byte: u8) -> Result<(), Self::Error> {
            unsafe {
                GDB_SERIAL.put_byte(byte);
            }
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
        ctx: usize,
        breakpoints: [GdbStubBreakpoint; MAX_BREAKPOINTS],
        is_single_step: bool,
    }

    impl GdbStubTarget {
        pub const fn new() -> Self {
            Self {
                ctx: 0,
                breakpoints: [GdbStubBreakpoint {
                    addr: VirtAddr::null(),
                    inst: 0,
                }; MAX_BREAKPOINTS],
                is_single_step: false,
            }
        }

        pub fn set_regs(&mut self, ctx: &X86ExceptionContext) {
            self.ctx = (ctx as *const _) as usize;
        }

        fn is_breakpoint(&self, rip: usize) -> bool {
            self.breakpoints.iter().any(|b| b.addr.bits() == rip)
        }

        fn write_bp_address(addr: VirtAddr, value: u8) -> Result<(), SvsmError> {
            // Virtual addresses in code are likely to be in read-only memory. If we
            // can get the physical address for this VA then create a temporary
            // mapping

            let Ok(phys) = this_cpu().get_pgtable().phys_addr(addr) else {
                // The virtual address is not one that SVSM has mapped. Try safely
                // writing it to the original virtual address
                return unsafe { write_u8(addr, value) };
            };

            let guard = PerCPUPageMappingGuard::create_4k(phys.page_align())?;
            unsafe { write_u8(guard.virt_addr().offset(phys.page_offset()), value) }
        }
    }

    impl Target for GdbStubTarget {
        type Arch = X86_64_SSE;

        type Error = usize;

        fn base_ops(&mut self) -> gdbstub::target::ext::base::BaseOps<'_, Self::Arch, Self::Error> {
            BaseOps::MultiThread(self)
        }

        #[inline(always)]
        fn support_breakpoints(
            &mut self,
        ) -> Option<gdbstub::target::ext::breakpoints::BreakpointsOps<'_, Self>> {
            Some(self)
        }
    }

    impl From<&X86ExceptionContext> for X86_64CoreRegs {
        fn from(value: &X86ExceptionContext) -> Self {
            let mut regs = X86_64CoreRegs::default();
            regs.rip = value.frame.rip as u64;
            regs.regs = [
                value.regs.rax as u64,
                value.regs.rbx as u64,
                value.regs.rcx as u64,
                value.regs.rdx as u64,
                value.regs.rsi as u64,
                value.regs.rdi as u64,
                value.regs.rbp as u64,
                value.frame.rsp as u64,
                value.regs.r8 as u64,
                value.regs.r9 as u64,
                value.regs.r10 as u64,
                value.regs.r11 as u64,
                value.regs.r12 as u64,
                value.regs.r13 as u64,
                value.regs.r14 as u64,
                value.regs.r15 as u64,
            ];
            regs.eflags = value.frame.flags as u32;
            regs.segments.cs = value.frame.cs as u32;
            regs.segments.ss = value.frame.ss as u32;
            regs
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
                0_u64,
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
            regs.segments.cs = value.seg.cs as u32;
            regs.segments.ds = value.seg.ds as u32;
            regs.segments.es = value.seg.es as u32;
            regs.segments.fs = value.seg.fs as u32;
            regs.segments.gs = value.seg.gs as u32;
            regs.segments.ss = value.seg.ss as u32;
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
                unsafe {
                    let context = (self.ctx as *const X86ExceptionContext).as_ref().unwrap();
                    *regs = X86_64CoreRegs::from(context);
                }
            } else {
                let task = TASKS.lock().get_task(tid.get() as u32);
                if let Some(task_node) = task {
                    // The registers are stored in the top of the task stack as part of the
                    // saved context. We need to switch to the task pagetable to access them.
                    let _task_context = GdbTaskContext::switch_to_task(tid.get() as u32);
                    let task = task_node.task.borrow();
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
            _tid: Tid,
        ) -> gdbstub::target::TargetResult<(), Self> {
            unsafe {
                let context = (self.ctx as *mut X86ExceptionContext).as_mut().unwrap();

                context.frame.rip = regs.rip as usize;
                context.regs.rax = regs.regs[0] as usize;
                context.regs.rbx = regs.regs[1] as usize;
                context.regs.rcx = regs.regs[2] as usize;
                context.regs.rdx = regs.regs[3] as usize;
                context.regs.rsi = regs.regs[4] as usize;
                context.regs.rdi = regs.regs[5] as usize;
                context.regs.rbp = regs.regs[6] as usize;
                context.frame.rsp = regs.regs[7] as usize;
                context.regs.r8 = regs.regs[8] as usize;
                context.regs.r9 = regs.regs[9] as usize;
                context.regs.r10 = regs.regs[10] as usize;
                context.regs.r11 = regs.regs[11] as usize;
                context.regs.r12 = regs.regs[12] as usize;
                context.regs.r13 = regs.regs[13] as usize;
                context.regs.r14 = regs.regs[14] as usize;
                context.regs.r15 = regs.regs[15] as usize;
                context.frame.flags = regs.eflags as usize;
                context.frame.cs = regs.segments.cs as usize;
                context.frame.ss = regs.segments.ss as usize;
            }
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
            for (offset, value) in data.iter_mut().enumerate() {
                unsafe {
                    match read_u8(VirtAddr::from(start_addr + offset as u64)) {
                        Ok(val) => *value = val,
                        Err(_) => {
                            return Err(TargetError::NonFatal);
                        }
                    }
                }
            }
            Ok(())
        }

        fn write_addrs(
            &mut self,
            start_addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
            data: &[u8],
            _tid: Tid,
        ) -> gdbstub::target::TargetResult<(), Self> {
            for (offset, value) in data.iter().enumerate() {
                unsafe {
                    if write_u8(VirtAddr::from(start_addr + offset as u64), *value).is_err() {
                        return Err(TargetError::NonFatal);
                    }
                }
            }
            Ok(())
        }

        #[inline(always)]
        fn support_resume(&mut self) -> Option<MultiThreadResumeOps<Self>> {
            Some(self)
        }

        fn list_active_threads(
            &mut self,
            thread_is_active: &mut dyn FnMut(gdbstub::common::Tid),
        ) -> Result<(), Self::Error> {
            let mut tl = TASKS.lock();

            let mut any_scheduled = false;

            if tl.tree().is_empty() {
                // Task list has not been initialised yet. Report a single thread
                // for the current CPU
                thread_is_active(Tid::new(INITIAL_TASK_ID as usize).unwrap());
            } else {
                let mut cursor = tl.tree().front_mut();
                while cursor.get().is_some() {
                    if cursor.get().unwrap().task.borrow().state == TaskState::SCHEDULED {
                        any_scheduled = true;
                        break;
                    }
                    cursor.move_next();
                }
                if any_scheduled {
                    let mut cursor = tl.tree().front_mut();
                    while cursor.get().is_some() {
                        thread_is_active(
                            Tid::new(cursor.get().unwrap().task.borrow().id as usize).unwrap(),
                        );
                        cursor.move_next();
                    }
                } else {
                    thread_is_active(Tid::new(INITIAL_TASK_ID as usize).unwrap());
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
            let tl = TASKS.lock();
            let current_task = this_cpu().current_task.as_ref().map(|t| t.task.borrow());

            let str = match tl.get_task(tid.get() as u32) {
                Some(t) => {
                    let t = t.task.borrow();
                    match t.state {
                        TaskState::RUNNING => "Stopped".as_bytes(),
                        TaskState::SCHEDULED => {
                            // The task is running on a CPU. If it is this CPU then the task has
                            // stopped otherwise we cannot report on its state
                            if current_task.is_some() && (current_task.unwrap().id == t.id) {
                                "Stopped".as_bytes()
                            } else {
                                "Running".as_bytes()
                            }
                        }
                        TaskState::TERMINATED => "Terminated".as_bytes(),
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
            self.is_single_step = false;
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
            _tid: Tid,
            _signal: Option<Signal>,
        ) -> Result<(), Self::Error> {
            self.is_single_step = true;
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
            let Some(free_bp) = self.breakpoints.iter().position(|&b| b.addr.is_null() ) else {
                return Ok(false);
            };
            // The breakpoint works by taking the opcode at the bp address, storing
            // it and replacing it with an INT3 instruction
            let vaddr = VirtAddr::from(addr);
            let inst = unsafe { read_u8(vaddr) };
            let Ok(inst) = inst else {
                return Ok(false);
            };
            let Ok(_) = GdbStubTarget::write_bp_address(vaddr, INT3_INSTR) else {
                return Ok(false);
            };
            self.breakpoints[free_bp] = GdbStubBreakpoint { addr: vaddr, inst };
            Ok(true)
        }

        fn remove_sw_breakpoint(
            &mut self,
            addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
            _kind: <Self::Arch as gdbstub::arch::Arch>::BreakpointKind,
        ) -> gdbstub::target::TargetResult<bool, Self> {
            let vaddr = VirtAddr::from(addr);
            let Some(matching_bp) = self.breakpoints.iter().position(|&b| b.addr == vaddr) else {
                return Ok(false);
            };
            let Ok(_) = GdbStubTarget::write_bp_address(vaddr, self.breakpoints[matching_bp].inst) else {
                return Ok(false);
            };
            self.breakpoints[matching_bp].addr = VirtAddr::null();
            Ok(true)
        }
    }
}

#[cfg(not(feature = "enable-gdb"))]
pub mod svsm_gdbstub {
    use crate::cpu::X86ExceptionContext;

    pub fn gdbstub_start() -> Result<(), u64> {
        Ok(())
    }

    pub fn handle_bp_exception(_ctx: &mut X86ExceptionContext) {}

    pub fn handle_db_exception(_ctx: &mut X86ExceptionContext) {}

    pub fn debug_break() {}
}
