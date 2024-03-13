// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use hmac_sha512::sha384::Hash;
use zerocopy::AsBytes;

#[repr(u8)]
#[derive(AsBytes, Debug, Copy, Clone)]
pub enum PageType {
    Normal = 1,
    Vmsa = 2,
    Zero = 3,
    Unmeasured = 4,
    Secrets = 5,
    Cpuid = 6,
}

#[repr(C, packed)]
#[derive(AsBytes, Debug)]
pub struct PageInfo {
    digest_cur: [u8; 48],
    contents: [u8; 48],
    length: u16,
    page_type: PageType,
    imi_page: u8,
    reserved: u8,
    vmpl1_perms: u8,
    vmpl2_perms: u8,
    vmpl3_perms: u8,
    gpa: u64,
}

impl PageInfo {
    pub fn new_normal_page(digest_cur: [u8; 48], gpa: u64, data: &Vec<u8>) -> Self {
        Self {
            digest_cur,
            contents: Hash::hash(data),
            length: 0x70,
            page_type: PageType::Normal,
            imi_page: 0,
            reserved: 0,
            vmpl1_perms: 0,
            vmpl2_perms: 0,
            vmpl3_perms: 0,
            gpa,
        }
    }

    pub fn new_vmsa_page(digest_cur: [u8; 48], gpa: u64, data: &Vec<u8>) -> Self {
        Self {
            digest_cur,
            contents: Hash::hash(data),
            length: 0x70,
            page_type: PageType::Vmsa,
            imi_page: 0,
            reserved: 0,
            vmpl1_perms: 0,
            vmpl2_perms: 0,
            vmpl3_perms: 0,
            gpa,
        }
    }

    pub fn new_zero_page(digest_cur: [u8; 48], gpa: u64) -> Self {
        Self::internal_new_unmeasured_page(digest_cur, gpa, PageType::Zero)
    }

    pub fn new_unmeasured_page(digest_cur: [u8; 48], gpa: u64) -> Self {
        Self::internal_new_unmeasured_page(digest_cur, gpa, PageType::Unmeasured)
    }

    pub fn new_secrets_page(digest_cur: [u8; 48], gpa: u64) -> Self {
        Self::internal_new_unmeasured_page(digest_cur, gpa, PageType::Secrets)
    }

    pub fn new_cpuid_page(digest_cur: [u8; 48], gpa: u64) -> Self {
        Self::internal_new_unmeasured_page(digest_cur, gpa, PageType::Cpuid)
    }

    fn internal_new_unmeasured_page(digest_cur: [u8; 48], gpa: u64, page_type: PageType) -> Self {
        Self {
            digest_cur,
            contents: [0u8; 48],
            length: 0x70,
            page_type,
            imi_page: 0,
            reserved: 0,
            vmpl1_perms: 0,
            vmpl2_perms: 0,
            vmpl3_perms: 0,
            gpa,
        }
    }

    pub fn update_hash(&self) -> [u8; 48] {
        Hash::hash(self.as_bytes())
    }
}
