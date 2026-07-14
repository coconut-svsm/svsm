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

use crate::protocols::ocp::api::{OcpObjectOperations, OcpSourceOperations};
use crate::protocols::ocp::details::{
    OcpObjectDetails, OcpObjectType, OcpSourceDetails, OcpSourceType,
};
use crate::protocols::ocp::map::add_ocp_object;

use crate::address::PhysAddr;
use crate::fs::{FsObj, GuestBuffer, open_read};
use crate::mm::guestmem::copy_slice_to_guest;
use crate::protocols::errors::SvsmReqError;
use crate::protocols::ocp::map::get_first_free_index;

use core::slice::Iter;
use core::sync::atomic::{AtomicU32, Ordering};

#[derive(Debug)]
struct OcpSvsmObject {
    ocp_source_entries: Vec<Arc<dyn OcpSourceOperations>>,
    details: OcpObjectDetails,
}

impl OcpSvsmObject {
    fn new(category: OcpObjectType, sup_index: u32) -> Self {
        Self {
            ocp_source_entries: Vec::new(),
            details: OcpObjectDetails::new(category, sup_index),
        }
    }

    fn add_source(&mut self, source: Arc<dyn OcpSourceOperations>) {
        // todo remove mut
        self.ocp_source_entries.push(source);
        self.details.increase_count();
    }
}

impl OcpObjectOperations for OcpSvsmObject {
    fn get_object_source_by_index(&self, sub_index: u32) -> Option<Arc<dyn OcpSourceOperations>> {
        self.ocp_source_entries.get(sub_index as usize).cloned()
    }

    fn get_object_sources(
        &self,
        first: u32,
        num_entries: u32,
    ) -> Iter<'_, Arc<dyn OcpSourceOperations>> {
        let sources_len = self.ocp_source_entries.len();
        let start = (first as usize).min(sources_len);
        let end = ((first + num_entries) as usize).min(sources_len);

        self.ocp_source_entries[start..end].iter()
    }

    fn get_object_details(&self) -> &OcpObjectDetails {
        &self.details
    }
}

#[derive(Debug)]
struct SvsmVersion {
    source: OcpSourceDetails,
    version: String,
}

impl SvsmVersion {
    fn new(sup_index: u32, sub_index: u32) -> Self {
        Self {
            source: OcpSourceDetails::new(
                sup_index,
                sub_index,
                false,
                "svsm_version",
                OcpSourceType::StaticString,
            ),
            version: format!("{COCONUT_VERSION}\0"),
        }
    }
}

impl OcpSourceOperations for SvsmVersion {
    fn get_source_details(&self) -> &OcpSourceDetails {
        &self.source
    }

    fn read(&self, offset: u32, gpa: PhysAddr, size: u32) -> Result<u32, SvsmReqError> {
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
    source: OcpSourceDetails,
}

impl LogBuffer {
    fn new(sup_index: u32, sub_index: u32) -> Self {
        Self {
            source: OcpSourceDetails::new(
                sup_index,
                sub_index,
                false,
                "log_buffer",
                OcpSourceType::String,
            ),
        }
    }
}

impl OcpSourceOperations for LogBuffer {
    fn get_source_details(&self) -> &OcpSourceDetails {
        &self.source
    }

    fn read(&self, offset: u32, gpa: PhysAddr, size: u32) -> Result<u32, SvsmReqError> {
        let log_hanlde = open_read("Log/logfile").unwrap();
        let fs_obj = FsObj::new_file(log_hanlde);
        fs_obj.seek_abs(offset as usize)?;
        let mut buffer = GuestBuffer::new(gpa, size as usize);
        Ok(fs_obj.read_buffer(&mut buffer).map(|b| b as u32)?)
    }
}

#[derive(Debug)]
struct TestWriteSource {
    source: OcpSourceDetails,
    state: AtomicU32,
}

impl TestWriteSource {
    fn new(sup_index: u32, sub_index: u32) -> Self {
        Self {
            source: OcpSourceDetails::new(
                sup_index,
                sub_index,
                true,
                "write_source",
                OcpSourceType::Integer,
            ),
            state: AtomicU32::new(0),
        }
    }
}

impl OcpSourceOperations for TestWriteSource {
    fn get_source_details(&self) -> &OcpSourceDetails {
        &self.source
    }

    fn read(&self, _offset: u32, gpa: PhysAddr, _size: u32) -> Result<u32, SvsmReqError> {
        // simplified read implementation for testing purposes
        let state = self.state.load(Ordering::Acquire);
        let state_bytes = state.to_le_bytes();

        copy_slice_to_guest(&state_bytes, gpa)?;

        Ok(4)
    }

    fn write(&self, _offset: u32, _gpa: PhysAddr, _size: u32) -> Result<u32, SvsmReqError> {
        // simplified write implementation for testing purposes
        let current_state = self.state.load(Ordering::Acquire);
        self.state.store(current_state + 1, Ordering::Release);
        Ok(4)
    }
}

pub fn add_svsm_object() {
    let sup_index = get_first_free_index().unwrap();

    let mut svsm_obj = OcpSvsmObject::new(OcpObjectType::Svsm, sup_index);

    let svsm_version = SvsmVersion::new(sup_index, 0);

    svsm_obj.add_source(Arc::new(svsm_version));

    let test_write_source = TestWriteSource::new(sup_index, 1);
    svsm_obj.add_source(Arc::new(test_write_source));

    let log_buffer = LogBuffer::new(sup_index, 2);
    svsm_obj.add_source(Arc::new(log_buffer));

    add_ocp_object(sup_index, Arc::new(svsm_obj));
}
