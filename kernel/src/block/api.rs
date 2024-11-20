// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc.
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Oliver Steffen <osteffen@redhat.com>

use crate::error::SvsmError;

pub trait BlockDriver {
    fn read_blocks(&self, block_id: usize, buf: &mut [u8]) -> Result<(), SvsmError>;
    fn write_blocks(&self, block_id: usize, buf: &[u8]) -> Result<(), SvsmError>;
    fn block_size_log2(&self) -> u8;
    fn size(&self) -> usize;
    fn flush(&self) -> Result<(), SvsmError>;
}
