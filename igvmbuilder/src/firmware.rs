// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use std::error::Error;
use std::fs::File;
use std::io::Read;

use crate::cmd_options::CmdOptions;
use crate::igvm_params::IgvmParamBlockFwInfo;
use crate::ovmfmeta::parse_ovmf;

#[derive(Default)]
pub struct Firmware {
    fw_info: IgvmParamBlockFwInfo,
    vtom: u64,
}

impl Firmware {
    pub fn parse(options: &CmdOptions) -> Result<Option<Self>, Box<dyn Error>> {
        let mut firmware = Firmware::default();
        if let Some(filename) = &options.firmware {
            match options.hypervisor {
                crate::cmd_options::Hypervisor::QEMU => {
                    let mut in_file = File::open(filename)?;
                    let len = in_file.metadata()?.len() as usize;
                    if len > 0xffffffff {
                        return Err("OVMF firmware is too large".into());
                    }
                    let mut data = vec![0u8; len];
                    if in_file.read(&mut data)? != len {
                        return Err("Failed to read OVMF file".into());
                    }
                    parse_ovmf(&data, &mut firmware.fw_info)?;

                    // OVMF must be located to end at 4GB.
                    firmware.fw_info.start = (0xffffffff - len + 1) as u32;
                    firmware.fw_info.size = len as u32;
                }
                crate::cmd_options::Hypervisor::HyperV => {
                    // Read and parse Hyper-V firmware.
                    // Populate vtom if present in firmware.
                    todo!()
                }
            }
            Ok(Some(firmware))
        } else {
            Ok(None)
        }
    }

    pub fn get_fw_info(&self) -> IgvmParamBlockFwInfo {
        self.fw_info
    }

    pub fn get_vtom(&self) -> u64 {
        self.vtom
    }
}
