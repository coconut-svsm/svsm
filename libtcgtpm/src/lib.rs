// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 IBM Corporation
//
// Author: Claudio Carvalho <cclaudio@linux.ibm.com>

//! This crate provides the libtcgtpm definitions used by the COCONUT-SVSM
//! for the vTPM.

#![no_std]

/// C bindings
pub mod bindings {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(unused)]
    #![allow(improper_ctypes)]

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
