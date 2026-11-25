// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2026 Red Hat
//
// Author: Oliver Steffen <osteffen@redhat.com>

//! C runtime library for the SVSM target.
//!
//! Builds a minimal C runtime (libc headers and static library) from the
//! bundled C sources. For bare-metal targets the build script links the
//! static library itself; the headers are exposed to dependent crates via
//! Cargo `links` metadata (`links = "crt"`).
//!
//! # Build metadata provided
//!
//! | Key           | Env var consumed as   | Description                        |
//! |---------------|-----------------------|------------------------------------|
//! | `INCLUDE_DIR` | `DEP_CRT_INCLUDE_DIR` | Path to the C runtime header files |

#![no_std]
