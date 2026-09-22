// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2026 Red Hat
//
// Author: Oliver Steffen <osteffen@redhat.com>

//! SVSM-specific target integration for `cocoon-tpm-ossl-bare-sys`.
//!
//! This crate supplies the build configuration that
//! `cocoon-tpm-ossl-bare-sys` needs to compile OpenSSL for the SVSM
//! target. It is wired in via Cargo's `links` metadata
//! (`links = "ossl-bare-sys-target-integration"`).
//!
//! Intended to be replaced by a Cargo path/patch override when building
//! `cocoon-tpm-ossl-bare-sys` for a different target environment.
//!
//! # Build metadata consumed
//!
//! From `libcrt` (`links = "crt"`):
//!
//! | Env var               | Usage                                           |
//! |-----------------------|-------------------------------------------------|
//! | `DEP_CRT_INCLUDE_DIR` | Included in `CPPFLAGS` and `BINDGEN_CFLAGS`     |
//!
//! # Build metadata provided
//!
//! | Key                    | Env var consumed as                                            | Description                                           |
//! |------------------------|----------------------------------------------------------------|-------------------------------------------------------|
//! | `CONFIGURE_CONFIG_FILE`| `DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_CONFIGURE_CONFIG_FILE`   | Path to the OpenSSL target configuration file         |
//! | `CONFIGURE_TARGET`     | `DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_CONFIGURE_TARGET`        | OpenSSL `Configure` target name (e.g. `SVSM`)         |
//! | `CONFIGURE_ARGS`       | `DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_CONFIGURE_ARGS`          | Extra arguments passed to OpenSSL `Configure`         |
//! | `CPPFLAGS`             | `DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_CPPFLAGS`                | C preprocessor flags (include paths)                  |
//! | `CFLAGS`               | `DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_CFLAGS`                  | C compiler code-generation flags                      |
//! | `BINDGEN_CFLAGS`       | `DEP_OSSL_BARE_SYS_TARGET_INTEGRATION_BINDGEN_CFLAGS`          | Extra clang flags for bindgen                         |

#![no_std]
