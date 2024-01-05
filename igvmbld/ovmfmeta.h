// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

#pragma once

#include <stdint.h>
#include "igvm_defs.h"

int parse_ovmf_metadata(const char *ovmf_filename, IgvmParamBlock *params);