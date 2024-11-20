// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc.
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Oliver Steffen <osteffen@redhat.com>

#[derive(Debug)]
pub enum BlockDeviceError {
    Failed, // ToDo: insert proper errors
}

pub trait BlockDriver {
    fn read_blocks(&self, block_id: usize, buf: &mut [u8]) -> Result<(), BlockDeviceError>;
    fn write_blocks(&self, block_id: usize, buf: &[u8]) -> Result<(), BlockDeviceError>;
    fn block_size_log2(&self) -> u8;
    fn size(&self) -> usize;
}
