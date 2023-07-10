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
    use crate::cpu::percpu::this_cpu;
    use crate::cpu::X86ExceptionContext;
    use crate::error::SvsmError;
    use crate::mm::guestmem::{read_u8, write_u8};
    use crate::mm::PerCPUPageMappingGuard;
    use crate::serial::{SerialPort, Terminal};
    use crate::svsm_console::SVSMIOPort;
    use core::arch::asm;
    use gdbstub::conn::Connection;
    use gdbstub::stub::state_machine::GdbStubStateMachine;
    use gdbstub::stub::{GdbStubBuilder, SingleThreadStopReason};
    use gdbstub::target::ext::base::singlethread::{
        SingleThreadBase, SingleThreadResume, SingleThreadResumeOps, SingleThreadSingleStep,
        SingleThreadSingleStepOps,
    };
    use gdbstub::target::ext::base::BaseOps;
    use gdbstub::target::ext::breakpoints::{Breakpoints, SwBreakpoint};
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
            GDB_STATE = Some(SvsmGdbStub { gdb, target });
        }
        Ok(())
    }

    pub fn handle_bp_exception(ctx: &mut X86ExceptionContext) {
        handle_stop(ctx, true);
    }

    pub fn handle_db_exception(ctx: &mut X86ExceptionContext) {
        handle_stop(ctx, false);
    }

    pub fn debug_break() {
        if unsafe { GDB_STATE.is_some() } {
            log::info!("***********************************");
            log::info!("* Waiting for connection from GDB *");
            log::info!("***********************************");
            unsafe {
                asm!("int3");
            }
        }
    }

    static mut GDB_STATE: Option<SvsmGdbStub> = None;
    static GDB_IO: SVSMIOPort = SVSMIOPort::new();
    static mut GDB_SERIAL: SerialPort = SerialPort {
        driver: &GDB_IO,
        port: 0x2f8,
    };
    static mut PACKET_BUFFER: [u8; 4096] = [0; 4096];

    struct SvsmGdbStub<'a> {
        gdb: GdbStubStateMachine<'a, GdbStubTarget, GdbStubConnection>,
        target: GdbStubTarget,
    }

    fn handle_stop(ctx: &mut X86ExceptionContext, bp_exception: bool) {
        let SvsmGdbStub { gdb, mut target } = unsafe {
            GDB_STATE.take().unwrap_or_else(|| {
                panic!("GDB stub not initialised!");
            })
        };

        target.set_regs(ctx);

        // If the current address is on a breakpoint then we need to
        // move the IP back by one byte
        if bp_exception && target.is_breakpoint(ctx.frame.rip - 1) {
            ctx.frame.rip -= 1;
        }

        let mut new_gdb = match gdb {
            GdbStubStateMachine::Running(gdb_inner) => {
                match gdb_inner.report_stop(&mut target, SingleThreadStopReason::SwBreak(())) {
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
                    log::info!("Invalid GDB state when handling breakpoint interrupt");
                    return;
                }
            };
        }
        if target.is_single_step {
            ctx.frame.flags |= 0x100;
        } else {
            ctx.frame.flags &= !0x100;
        }
        unsafe {
            GDB_STATE = Some(SvsmGdbStub {
                gdb: new_gdb,
                target,
            })
        };
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
                return write_u8(addr, value);
            };

            let guard = PerCPUPageMappingGuard::create_4k(phys.page_align())?;
            write_u8(guard.virt_addr() + phys.page_offset(), value)
        }
    }

    impl Target for GdbStubTarget {
        type Arch = X86_64_SSE;

        type Error = usize;

        fn base_ops(&mut self) -> gdbstub::target::ext::base::BaseOps<'_, Self::Arch, Self::Error> {
            BaseOps::SingleThread(self)
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

    impl SingleThreadBase for GdbStubTarget {
        fn read_registers(
            &mut self,
            regs: &mut <Self::Arch as gdbstub::arch::Arch>::Registers,
        ) -> gdbstub::target::TargetResult<(), Self> {
            unsafe {
                let context = (self.ctx as *mut X86ExceptionContext).as_ref().unwrap();
                *regs = X86_64CoreRegs::from(context);
            }

            Ok(())
        }

        fn write_registers(
            &mut self,
            regs: &<Self::Arch as gdbstub::arch::Arch>::Registers,
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
        ) -> gdbstub::target::TargetResult<(), Self> {
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
        ) -> gdbstub::target::TargetResult<(), Self> {
            let start_addr = VirtAddr::from(start_addr);
            for (off, src) in data.iter().enumerate() {
                if write_u8(start_addr + off, *src).is_err() {
                    return Err(TargetError::NonFatal);
                }
            }
            Ok(())
        }

        #[inline(always)]
        fn support_resume(&mut self) -> Option<SingleThreadResumeOps<Self>> {
            Some(self)
        }
    }

    impl SingleThreadResume for GdbStubTarget {
        fn resume(&mut self, _signal: Option<gdbstub::common::Signal>) -> Result<(), Self::Error> {
            self.is_single_step = false;
            Ok(())
        }

        #[inline(always)]
        fn support_single_step(&mut self) -> Option<SingleThreadSingleStepOps<'_, Self>> {
            Some(self)
        }
    }

    impl SingleThreadSingleStep for GdbStubTarget {
        fn step(&mut self, _signal: Option<gdbstub::common::Signal>) -> Result<(), Self::Error> {
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
}

#[cfg(not(feature = "enable-gdb"))]
pub mod svsm_gdbstub {
    use crate::cpu::X86ExceptionContext;

    pub fn gdbstub_start() -> Result<(), u64> {
        Ok(())
    }

    pub fn handle_bp_exception(_regs: &mut X86ExceptionContext) {}

    pub fn handle_db_exception(_regs: &mut X86ExceptionContext) {}

    pub fn debug_break() {}
}
