// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use release::COCONUT_VERSION;

use crate::protocols::ocp::requests::add_ocp_object;
use crate::protocols::ocp::source::{OcpObject, OcpSource};
use crate::protocols::ocp::source::{OcpSourceInfo, OcpSourceType};

use crate::address::PhysAddr;
use crate::fs::{FsObj, GuestBuffer, open_read};
use crate::mm::guestmem::copy_slice_to_guest;
use crate::protocols::errors::SvsmReqError;

#[derive(Debug)]
struct OcpSvsmObject {
    sources: Vec<Arc<dyn OcpSource>>,
    details: OcpSourceInfo,
}

impl OcpSvsmObject {
    fn new() -> Self {
        Self {
            sources: Vec::new(),
            details: OcpSourceInfo::new_object("SVSM"),
        }
    }

    fn add_source(&mut self, source: Arc<dyn OcpSource>) {
        // todo remove mut
        self.sources.push(source);
    }
}

impl OcpObject for OcpSvsmObject {
    fn get_source(&self, name: &str) -> Option<Arc<dyn OcpSource>> {
        self.sources
            .iter()
            .find(|s| s.get_info().get_name() == name)
            .cloned()
    }

    fn get_info(&self) -> &OcpSourceInfo {
        &self.details
    }

    fn get_name(&self) -> &str {
        self.details.get_name()
    }

    fn get_source_count(&self) -> usize {
        self.sources.len()
    }

    fn for_each_source(
        &self,
        f: &mut dyn FnMut(&Arc<dyn OcpSource>) -> Result<bool, SvsmReqError>,
    ) -> Result<(), SvsmReqError> {
        for s in self.sources.iter() {
            if !f(s)? {
                break;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct SvsmVersion {
    source: OcpSourceInfo,
    version: String,
}

impl SvsmVersion {
    fn new() -> Self {
        Self {
            source: OcpSourceInfo::new(false, "svsm_version", OcpSourceType::Bytes),
            version: format!("{COCONUT_VERSION}\0"),
        }
    }
}

impl OcpSource for SvsmVersion {
    fn get_info(&self) -> &OcpSourceInfo {
        &self.source
    }

    fn write_to_guest(&self, offset: u32, gpa: PhysAddr, size: u32) -> Result<u32, SvsmReqError> {
        let version_bytes = self.version.as_bytes();
        let len = version_bytes.len();

        if offset as usize >= len {
            return Ok(0);
        }

        let end = (offset as usize + size as usize).min(len);

        let bytes_to_copy = end - offset as usize;

        let version_slice = &version_bytes[offset as usize..end];

        copy_slice_to_guest(version_slice, gpa)?;

        Ok(bytes_to_copy as u32)
    }
}

#[derive(Debug)]
struct LogBuffer {
    source: OcpSourceInfo,
}

impl LogBuffer {
    fn new() -> Self {
        Self {
            source: OcpSourceInfo::new(false, "log_buffer", OcpSourceType::Bytes),
        }
    }
}

impl OcpSource for LogBuffer {
    fn get_info(&self) -> &OcpSourceInfo {
        &self.source
    }

    fn write_to_guest(&self, offset: u32, gpa: PhysAddr, size: u32) -> Result<u32, SvsmReqError> {
        let log_hanlde = open_read("Log/logfile").unwrap();
        let fs_obj = FsObj::new_file(log_hanlde);
        fs_obj.seek_abs(offset as usize)?;
        let mut buffer = GuestBuffer::new(gpa, size as usize);
        Ok(fs_obj.read_buffer(&mut buffer).map(|b| b as u32)?)
    }
}

pub fn add_svsm_object() {
    let mut svsm_obj = OcpSvsmObject::new();

    let svsm_version = SvsmVersion::new();

    svsm_obj.add_source(Arc::new(svsm_version));

    let log_buffer = LogBuffer::new();
    svsm_obj.add_source(Arc::new(log_buffer));

    let _ = add_ocp_object(Arc::new(svsm_obj));
}
