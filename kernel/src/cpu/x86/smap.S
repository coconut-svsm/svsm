// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Thomas Leroy <tleroy@suse.de>

.code64

.section .text
.macro asm_clac
        .if !CFG_NOSMAP
        clac
        .endif
.endm

.macro asm_stac
        .if !CFG_NOSMAP
        stac
        .endif
.endm
