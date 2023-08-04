// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

use core::{
    arch::global_asm,
    ffi::{c_char, CStr},
};

use crate::cpu::{
    efer::{read_efer, write_efer, EFERFlags},
    msr::write_msr,
    percpu::this_cpu,
};
use crate::types::{SVSM_CS, SVSM_USER_CS32};

use super::schedule;

pub enum SyscallRet {
    Ok,
    Unknown,
    Terminate,
}

extern "C" {
    static syscall_entry: u64;
}

const MSR_STAR: u32 = 0xc000_0081;
const MSR_LSTAR: u32 = 0xc000_0082;
const MSR_SFMASK: u32 = 0xc000_0084;

#[no_mangle]
extern "C" fn syscall_handler(index: u32, param1: u64) -> u64 {
    let ret = match index {
        // exit
        0 => SyscallRet::Terminate,
        // log
        1 => {
            unsafe {
                let str = CStr::from_ptr(param1 as *const c_char);
                log::info!("{}", str.to_str().unwrap());
            }
            SyscallRet::Ok
        }
        // sleep
        2 => SyscallRet::Ok,
        _ => {
            log::info!("Invalid syscall received: {}", index);
            SyscallRet::Unknown
        }
    };
    schedule();
    ret as u64
}

pub fn init_syscall() {
    let mut efer = read_efer();
    efer.insert(EFERFlags::SCE);
    write_efer(efer);

    let sysret_cs = SVSM_USER_CS32 as u64;
    let syscall_cs = SVSM_CS as u64;
    write_msr(MSR_STAR, sysret_cs << 48 | syscall_cs << 32);
    unsafe {
        write_msr(MSR_LSTAR, (&syscall_entry as *const u64) as u64);
    }
    // FIXME: Find correct mask for flags
    write_msr(MSR_SFMASK, 0);
}

#[no_mangle]
extern "C" fn get_kernel_rsp() -> u64 {
    let task_node = this_cpu()
        .runqueue()
        .lock_read()
        .current_task()
        .expect("Invalid current task");
    let rsp = task_node
        .task
        .lock_read()
        .user
        .as_ref()
        .expect("Syscall from kernel task")
        .kernel_rsp;
    rsp
}

global_asm!(
    r#"
        .text
    syscall_entry:
        // Switch to the task kernel stack
        push    %rcx            // User-mode return address

        // Syscall arguments
        push    %rsi
        push    %rdi

        call    get_kernel_rsp
        pop     %rdi
        pop     %rsi

        subq    $8, %rax
        movq    %rsp, (%rax)
        mov     %rax, %rsp

        call    syscall_handler

        // Check to see if the task requested termination
        cmp     $2, %rax            // SyscallRet::Terminate
        jne     ret_user

        addq    $8, %rsp            // Skip user mode return address
        // Kernel stack frame should now be within launch_user_entry()
        ret

    ret_user:
        pop     %rsp
        pop     %rcx
        movq    $0x202, %r11
        sysretq
        "#,
    options(att_syntax)
);
