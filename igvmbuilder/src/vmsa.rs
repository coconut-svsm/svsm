// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use std::mem::size_of;

use igvm::snp_defs::{SevFeatures, SevVmsa};
use igvm::IgvmDirectiveHeader;
use igvm_defs::IgvmNativeVpContextX64;
use zerocopy::FromZeroes;

use crate::cmd_options::SevExtraFeatures;
use crate::stage2_stack::Stage2Stack;

pub fn construct_start_context() -> Box<IgvmNativeVpContextX64> {
    let mut context_box = IgvmNativeVpContextX64::new_box_zeroed();
    let context = context_box.as_mut();

    // Establish CS as a 32-bit code selector.
    context.code_attributes = 0xc09b;
    context.code_limit = 0xffffffff;
    context.code_selector = 0x08;

    // Establish all data segments as generic data selectors.
    context.data_attributes = 0xa093;
    context.data_limit = 0xffffffff;
    context.data_selector = 0x10;

    // CR0.PE | CR0.NE | CR0.ET.
    context.cr0 = 0x31;

    // CR4.MCE.
    context.cr4 = 0x40;

    context.rflags = 2;
    context.rip = 0x10000;
    context.rsp = context.rip - size_of::<Stage2Stack>() as u64;

    context_box
}

fn vmsa_convert_attributes(attributes: u16) -> u16 {
    (attributes & 0xFF) | ((attributes >> 4) & 0xF00)
}

pub fn construct_vmsa(
    context: &IgvmNativeVpContextX64,
    gpa_start: u64,
    vtom: u64,
    compatibility_mask: u32,
    extra_features: &Vec<SevExtraFeatures>,
) -> IgvmDirectiveHeader {
    let mut vmsa_box = SevVmsa::new_box_zeroed();
    let vmsa = vmsa_box.as_mut();

    // Copy GPRs.
    vmsa.rax = context.rax;
    vmsa.rcx = context.rcx;
    vmsa.rdx = context.rdx;
    vmsa.rbx = context.rbx;
    vmsa.rsp = context.rsp;
    vmsa.rbp = context.rbp;
    vmsa.rsi = context.rsi;
    vmsa.rdi = context.rdi;
    vmsa.r8 = context.r8;
    vmsa.r9 = context.r9;
    vmsa.r10 = context.r10;
    vmsa.r11 = context.r11;
    vmsa.r12 = context.r12;
    vmsa.r13 = context.r13;
    vmsa.r14 = context.r14;
    vmsa.r15 = context.r15;

    // Configure other initial state registers.
    vmsa.rip = context.rip;
    vmsa.rflags = context.rflags;

    // Configure selectors.
    vmsa.cs.selector = context.code_selector;
    vmsa.cs.attrib = vmsa_convert_attributes(context.code_attributes);
    vmsa.cs.base = context.code_base as u64;
    vmsa.cs.limit = context.code_limit;

    vmsa.ds.attrib = vmsa_convert_attributes(context.data_attributes);
    vmsa.ds.limit = context.data_limit;
    vmsa.ds.base = context.data_base as u64;
    vmsa.ds.selector = context.data_selector;
    vmsa.ss = vmsa.ds;
    vmsa.es = vmsa.ds;
    vmsa.fs = vmsa.ds;
    vmsa.gs = vmsa.ds;
    vmsa.gs.base = context.gs_base;

    vmsa.idtr.base = context.idtr_base;
    vmsa.idtr.limit = context.idtr_limit as u32;
    vmsa.gdtr.base = context.gdtr_base;
    vmsa.gdtr.limit = context.gdtr_limit as u32;

    // Configure control registers.
    vmsa.cr0 = context.cr0;
    vmsa.cr3 = context.cr3;
    vmsa.cr4 = context.cr4;

    // Include EFER.SVME on SNP platforms.
    vmsa.efer = context.efer | 0x1000;

    // Configure non-zero reset state.
    vmsa.pat = 0x0007040600070406;
    vmsa.xcr0 = 1;

    let mut features = SevFeatures::new();
    features.set_snp(true);
    features.set_restrict_injection(true);
    if vtom != 0 {
        vmsa.virtual_tom = vtom;
        features.set_vtom(true);
    }

    for extra_f in extra_features {
        match extra_f {
            SevExtraFeatures::ReflectVc => features.set_reflect_vc(true),
            SevExtraFeatures::AlternateInjection => features.set_alternate_injection(true),
            SevExtraFeatures::DebugSwap => features.set_debug_swap(true),
            SevExtraFeatures::PreventHostIBS => features.set_prevent_host_ibs(true),
            SevExtraFeatures::SNPBTBIsolation => features.set_snp_btb_isolation(true),
            SevExtraFeatures::VmplSSS => features.set_vmpl_supervisor_shadow_stack(true),
            SevExtraFeatures::SecureTscEn => features.set_secure_tsc(true),
            SevExtraFeatures::VmsaRegProt => features.set_vmsa_reg_protection(true),
            SevExtraFeatures::SmtProtection => features.set_smt_protection(true),
        }
    }

    vmsa.sev_features = features;

    IgvmDirectiveHeader::SnpVpContext {
        gpa: gpa_start,
        compatibility_mask,
        vp_index: 0,
        vmsa: vmsa_box,
    }
}
