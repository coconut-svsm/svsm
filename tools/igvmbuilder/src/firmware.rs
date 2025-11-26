// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use std::error::Error;

use bootlib::igvm_params::{IgvmGuestContext, IgvmParamBlockFwInfo};
use igvm::IgvmDirectiveHeader;

use crate::cmd_options::CmdOptions;
use crate::igvm_firmware::IgvmFirmware;
use crate::ovmf_firmware::OvmfFirmware;

pub trait Firmware {
    fn directives(&self) -> &Vec<IgvmDirectiveHeader>;
    fn get_guest_context(&self) -> Option<IgvmGuestContext>;
    fn get_vtom(&self) -> u64;
    fn get_fw_info(&self) -> IgvmParamBlockFwInfo;
}

pub fn parse_firmware(
    options: &CmdOptions,
    parameter_count: u32,
    compatibility_mask: u32,
) -> Result<Box<dyn Firmware>, Box<dyn Error>> {
    if let Some(filename) = &options.firmware {
        match options.hypervisor {
            crate::cmd_options::Hypervisor::Qemu => {
                OvmfFirmware::parse(filename, parameter_count, compatibility_mask)
            }
            crate::cmd_options::Hypervisor::HyperV => {
                IgvmFirmware::parse(filename, parameter_count, compatibility_mask)
            }
            crate::cmd_options::Hypervisor::Vanadium => {
                OvmfFirmware::parse(filename, parameter_count, compatibility_mask)
            }
        }
    } else {
        Err("No firmware filename specified".into())
    }
}
