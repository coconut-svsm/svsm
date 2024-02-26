// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use std::error::Error;
use std::mem::size_of;

use igvm::snp_defs::{SevFeatures, SevVmsa};
use igvm::IgvmDirectiveHeader;
use zerocopy::FromZeroes;

use crate::stage2_stack::Stage2Stack;

pub fn construct_vmsa(
    gpa_start: u64,
    vtom: u64,
    compatibility_mask: u32,
) -> Result<IgvmDirectiveHeader, Box<dyn Error>> {
    let mut vmsa_box = SevVmsa::new_box_zeroed();
    let vmsa = vmsa_box.as_mut();

    // Establish CS as a 32-bit code selector.
    vmsa.cs.attrib = 0xc9b;
    vmsa.cs.limit = 0xffffffff;
    vmsa.cs.selector = 0x08;

    // Establish all data segments as generic data selectors.
    vmsa.ds.attrib = 0xa93;
    vmsa.ds.limit = 0xffffffff;
    vmsa.ds.selector = 0x10;
    vmsa.ss = vmsa.ds;
    vmsa.es = vmsa.ds;
    vmsa.fs = vmsa.ds;
    vmsa.gs = vmsa.ds;

    // EFER.SVME.
    vmsa.efer = 0x1000;

    // CR0.PE | CR0.NE.
    vmsa.cr0 = 0x21;

    // CR4.MCE.
    vmsa.cr4 = 0x40;

    vmsa.pat = 0x0007040600070406;
    vmsa.xcr0 = 1;
    vmsa.rflags = 2;
    vmsa.rip = 0x10000;
    vmsa.rsp = vmsa.rip - size_of::<Stage2Stack>() as u64;

    let mut features = SevFeatures::new();
    features.set_snp(true);
    features.set_restrict_injection(true);
    if vtom != 0 {
        vmsa.virtual_tom = vtom;
        features.set_vtom(true);
    }
    vmsa.sev_features = features;

    Ok(IgvmDirectiveHeader::SnpVpContext {
        gpa: gpa_start,
        compatibility_mask,
        vp_index: 0,
        vmsa: vmsa_box,
    })
}
