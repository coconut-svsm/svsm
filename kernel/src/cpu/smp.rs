// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::acpi::tables::ACPICPUInfo;
use crate::address::Address;
use crate::cpu::percpu::{this_cpu, this_cpu_shared, PerCpu};
use crate::cpu::shadow_stack::{is_cet_ss_supported, SCetFlags, MODE_64BIT, S_CET};
use crate::cpu::sse::sse_init;
use crate::enable_shadow_stacks;
use crate::error::SvsmError;
use crate::platform::SvsmPlatform;
use crate::platform::SVSM_PLATFORM;
use crate::requests::{request_loop, request_processing_main};
use crate::task::{create_kernel_task, schedule_init};
use crate::utils::immut_after_init::immut_after_init_set_multithreaded;

fn start_cpu(platform: &dyn SvsmPlatform, apic_id: u32) -> Result<(), SvsmError> {
    let start_rip: u64 = (start_ap as *const u8) as u64;
    let percpu = PerCpu::alloc(apic_id)?;
    let pgtable = this_cpu().get_pgtable().clone_shared()?;
    percpu.setup(platform, pgtable)?;

    let context = percpu.get_initial_context(start_rip);
    platform.start_cpu(percpu, &context)?;

    let percpu_shared = percpu.shared();
    while !percpu_shared.is_online() {}
    Ok(())
}

pub fn start_secondary_cpus(platform: &dyn SvsmPlatform, cpus: &[ACPICPUInfo]) {
    immut_after_init_set_multithreaded();
    let mut count: usize = 0;
    for c in cpus.iter().filter(|c| c.apic_id != 0 && c.enabled) {
        log::info!("Launching AP with APIC-ID {}", c.apic_id);
        start_cpu(platform, c.apic_id).expect("Failed to bring CPU online");
        count += 1;
    }
    log::info!("Brought {} AP(s) online", count);
}

#[no_mangle]
fn start_ap() {
    let percpu = this_cpu();

    if is_cet_ss_supported() {
        enable_shadow_stacks!(percpu);
    }

    percpu
        .setup_on_cpu(&**SVSM_PLATFORM)
        .expect("setup_on_cpu() failed");

    percpu
        .setup_idle_task(ap_request_loop)
        .expect("Failed to allocated idle task for AP");

    // Send a life-sign
    log::info!("AP with APIC-ID {} is online", this_cpu().get_apic_id());

    // Set CPU online so that BSP can proceed
    this_cpu_shared().set_online();

    sse_init();
    schedule_init();
}

#[no_mangle]
pub extern "C" fn ap_request_loop() {
    create_kernel_task(request_processing_main).expect("Failed to launch request processing task");
    request_loop();
    panic!("Returned from request_loop!");
}
