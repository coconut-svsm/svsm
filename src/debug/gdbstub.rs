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
    use crate::cpu::X86Regs;
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

    pub fn handle_bp_exception(regs: &mut X86Regs) {
        handle_stop(regs, true);
    }

    pub fn handle_db_exception(regs: &mut X86Regs) {
        handle_stop(regs, false);
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

    fn handle_stop(regs: &mut X86Regs, bp_exception: bool) {
        let SvsmGdbStub { gdb, mut target } = unsafe {
            GDB_STATE.take().unwrap_or_else(|| {
                panic!("GDB stub not initialised!");
            })
        };

        target.set_regs(regs);

        // If the current address is on a breakpoint then we need to
        // move the IP back by one byte
        if bp_exception && target.is_breakpoint(regs.rip - 1) {
            regs.rip -= 1;
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
                        .map_err(|_| 1 as u64)
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
            regs.flags |= 0x100;
        } else {
            regs.flags &= !0x100;
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
            let res = unsafe { Ok(GDB_SERIAL.get_byte()) };
            res
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
        regs: usize,
        breakpoints: [GdbStubBreakpoint; MAX_BREAKPOINTS],
        is_single_step: bool,
    }

    impl GdbStubTarget {
        pub const fn new() -> Self {
            Self {
                regs: 0,
                breakpoints: [GdbStubBreakpoint {
                    addr: VirtAddr::null(),
                    inst: 0,
                }; MAX_BREAKPOINTS],
                is_single_step: false,
            }
        }

        pub fn set_regs(&mut self, regs: &X86Regs) {
            self.regs = (regs as *const _) as usize;
        }

        fn is_breakpoint(&self, rip: usize) -> bool {
            self.breakpoints
                .iter()
                .find(|&b| b.addr.bits() == rip)
                .is_some()
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
            return unsafe { write_u8(guard.virt_addr().offset(phys.page_offset()), value) };
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

    impl SingleThreadBase for GdbStubTarget {
        fn read_registers(
            &mut self,
            regs: &mut <Self::Arch as gdbstub::arch::Arch>::Registers,
        ) -> gdbstub::target::TargetResult<(), Self> {
            unsafe {
                let context = (self.regs as *mut X86Regs).as_mut().unwrap();

                regs.rip = context.rip as u64;
                regs.regs = [
                    context.rax as u64,
                    context.rbx as u64,
                    context.rcx as u64,
                    context.rdx as u64,
                    context.rsi as u64,
                    context.rdi as u64,
                    context.rbp as u64,
                    context.rsp as u64,
                    context.r8 as u64,
                    context.r9 as u64,
                    context.r10 as u64,
                    context.r11 as u64,
                    context.r12 as u64,
                    context.r13 as u64,
                    context.r14 as u64,
                    context.r15 as u64,
                ];
                regs.eflags = context.flags as u32;
                regs.segments.cs = context.cs as u32;
                regs.segments.ss = context.ss as u32;
            }

            Ok(())
        }

        fn write_registers(
            &mut self,
            regs: &<Self::Arch as gdbstub::arch::Arch>::Registers,
        ) -> gdbstub::target::TargetResult<(), Self> {
            unsafe {
                let context = (self.regs as *mut X86Regs).as_mut().unwrap();

                context.rip = regs.rip as usize;
                context.rax = regs.regs[0] as usize;
                context.rbx = regs.regs[1] as usize;
                context.rcx = regs.regs[2] as usize;
                context.rdx = regs.regs[3] as usize;
                context.rsi = regs.regs[4] as usize;
                context.rdi = regs.regs[5] as usize;
                context.rbp = regs.regs[6] as usize;
                context.rsp = regs.regs[7] as usize;
                context.r8 = regs.regs[8] as usize;
                context.r9 = regs.regs[9] as usize;
                context.r10 = regs.regs[10] as usize;
                context.r11 = regs.regs[11] as usize;
                context.r12 = regs.regs[12] as usize;
                context.r13 = regs.regs[13] as usize;
                context.r14 = regs.regs[14] as usize;
                context.r15 = regs.regs[15] as usize;
                context.flags = regs.eflags as usize;
                context.cs = regs.segments.cs as usize;
                context.ss = regs.segments.ss as usize;
            }
            Ok(())
        }

        fn read_addrs(
            &mut self,
            start_addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
            data: &mut [u8],
        ) -> gdbstub::target::TargetResult<(), Self> {
            for offset in 0..data.len() {
                unsafe {
                    match read_u8(VirtAddr::from(start_addr + offset as u64)) {
                        Ok(val) => data[offset] = val,
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
        ) -> gdbstub::target::TargetResult<(), Self> {
            for offset in 0..data.len() {
                unsafe {
                    if write_u8(VirtAddr::from(start_addr + offset as u64), data[offset]).is_err() {
                        return Err(TargetError::NonFatal);
                    }
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
    use crate::cpu::X86Regs;

    pub fn gdbstub_start() -> Result<(), u64> {
        Ok(())
    }

    pub fn handle_bp_exception(_regs: &mut X86Regs) {}

    pub fn handle_db_exception(_regs: &mut X86Regs) {}

    pub fn debug_break() {}
}
