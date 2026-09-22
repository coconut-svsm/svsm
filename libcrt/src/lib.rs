// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2026 Red Hat
//
// Author: Oliver Steffen <osteffen@redhat.com>

//! C runtime library for the SVSM target.
//!
//! Builds a minimal C runtime (libc headers and static library) from the
//! bundled C sources. The build script exposes the result to dependent
//! crates via Cargo `links` metadata (`links = "crt"`).
//!
//! # Build metadata provided
//!
//! | Key           | Env var consumed as     | Description                         |
//! |---------------|-------------------------|-------------------------------------|
//! | `INCLUDE_DIR` | `DEP_CRT_INCLUDE_DIR`   | Path to the C runtime header files  |
//! | `LIB_DIR`     | `DEP_CRT_LIB_DIR`       | Path to the compiled static library |

#![no_std]
