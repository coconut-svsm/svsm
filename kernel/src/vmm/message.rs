// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

use crate::protocols::RequestParams;

#[derive(Clone, Copy, Debug)]
pub enum GuestExitMessage {
    NoMappings,
    Svsm((u32, u32, RequestParams)),
}
