// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

extern crate alloc;

use super::details::{OcpObjectDetails, OcpSourceDetails};

use crate::{address::PhysAddr, protocols::errors::SvsmReqError};

use alloc::sync::Arc;
use core::{fmt::Debug, slice::Iter};

/// Operations required for an OCP object
pub trait OcpObjectOperations: Debug + Send + Sync {
    fn read(
        &self,
        _offset: u32,
        _gpa: PhysAddr,
        _size: u32,
        _sub_index: u32,
    ) -> Result<u32, SvsmReqError> {
        Err(SvsmReqError::unsupported_call())
    }
    fn write(
        &self,
        _offset: u32,
        _gpa: PhysAddr,
        _size: u32,
        _sub_index: u32,
    ) -> Result<u32, SvsmReqError> {
        Err(SvsmReqError::unsupported_call())
    }
    fn get_object_details(&self) -> &OcpObjectDetails;
    fn get_object_sources(
        &self,
        first: u32,
        num_entries: u32,
    ) -> Iter<'_, Arc<dyn OcpSourceOperations>>;
}

pub trait OcpSourceOperations: Debug + Send + Sync {
    fn read(&self, _offset: u32, _gpa: PhysAddr, _size: u32) -> Result<u32, SvsmReqError> {
        Err(SvsmReqError::unsupported_call())
    }

    fn write(&self, _offset: u32, _gpa: PhysAddr, _size: u32) -> Result<u32, SvsmReqError> {
        Err(SvsmReqError::unsupported_call())
    }

    fn get_source_details(&self) -> &OcpSourceDetails;
}
