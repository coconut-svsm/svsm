// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 IBM Corporation
//
// Author: Claudio Carvalho <cclaudio@linux.ibm.com>

//! This crate provides the libtcgtpm definitions used by the COCONUT-SVSM
//! for the vTPM.
//!
//! # Build metadata consumed
//!
//! From `libcrt` (`links = "crt"`):
//!
//! | Env var               | Usage                                             |
//! |-----------------------|---------------------------------------------------|
//! | `DEP_CRT_INCLUDE_DIR` | C runtime headers for bindgen and TPM compilation |
//!
//! From `cocoon-tpm-ossl-bare-sys` (`links = "ossl"`):
//!
//! | Env var                         | Usage                                         |
//! |---------------------------------|-----------------------------------------------|
//! | `DEP_OSSL_OSSL_INCLUDE_DIR`     | Generated OpenSSL headers for TPM compilation |
//! | `DEP_OSSL_OSSL_SRC_INCLUDE_DIR` | OpenSSL source headers for TPM compilation    |
//! | `DEP_OSSL_OSSL_LIB_DIR`         | OpenSSL library path for TPM compilation      |

#![no_std]

// Ensure these crates are linked — they provide libcrypto.a and libcrt.a
// that the tcgtpm C libraries depend on.
#[allow(unused_extern_crates)]
extern crate cocoon_tpm_ossl_bare_sys;
#[allow(unused_extern_crates)]
extern crate libcrt;

/// C bindings
pub mod bindings {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(unused)]
    #![allow(improper_ctypes)]

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
