// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Carlos López <carlos.lopez@suse.com>

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;
use svsm::address::VirtAddr;
use svsm::mm::alloc::{
    allocate_file_page, allocate_page, allocate_pages, allocate_slab_page, allocate_zeroed_page,
    free_page, get_order, TestRootMem,
};
use svsm::mm::PageRef;
use svsm::types::PAGE_SIZE;

const WRITE_BYTE: u8 = 0x66;
const POISON_BYTE: u8 = 0xfa;
const MIN_ROOT_MEM_SIZE: usize = 0x80000;
const MAX_ROOT_MEM_SIZE: usize = 0x100000;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    root_mem_size: usize,
    actions: Vec<Action>,
}

/// Actions during a fuzzing run
#[derive(Debug, Arbitrary)]
enum Action {
    /// Allocate a regular page
    Allocate,
    /// Allocate a slab page
    AllocateSlab(u16),
    /// Allocate pages of higher order
    AllocatePages(usize),
    /// Allocate a zeroed page
    AllocateZeroed,
    /// Allocate a file page
    AllocateFile,
    /// Write data to an allocated page
    WritePage(usize),
    /// Read data from an allocated & initialized page
    ReadPage(usize),
    /// Free an allocated page
    Free(usize),
    /// Allocate a page ref
    AllocateFilePageRef,
    /// Clone a page ref, increasing its refcount
    CloneFilePageRef(usize),
    /// Drop a page ref, decreasing its refcount
    DropFilePageRef(usize),
}

#[inline]
fn get_idx<T>(v: &[T], idx: usize) -> Option<usize> {
    idx.checked_rem(v.len())
}

#[inline]
fn get_item<T>(v: &[T], idx: usize) -> Option<&T> {
    let idx = get_idx(v, idx)?;
    // SAFETY: we modulo the index to be within range
    Some(unsafe { v.get_unchecked(idx) })
}

/// # Safety
///
/// The caller must guarantee that the address is valid for the size
/// of a page.
#[inline]
unsafe fn fill_page(page: VirtAddr, byte: u8) {
    // SAFETY: the caller must guarantee that the page is valid
    unsafe { page.as_mut_ptr::<u8>().write_bytes(byte, PAGE_SIZE) }
}

#[inline]
fn adjust_mem_size(size: usize) -> usize {
    MIN_ROOT_MEM_SIZE + (size % (MAX_ROOT_MEM_SIZE - MIN_ROOT_MEM_SIZE + 1))
}

fuzz_target!(|inp: FuzzInput| {
    let _mem = TestRootMem::setup(adjust_mem_size(inp.root_mem_size));

    // Regular pages
    let mut pages = Vec::new();
    // Initialized regular pages
    let mut inited = BTreeSet::new();
    // Page refs
    let mut pagerefs = Vec::new();

    for action in inp.actions.into_iter() {
        match action {
            Action::Allocate => {
                if let Ok(page) = allocate_page() {
                    pages.push(page);
                }
            }
            Action::AllocateSlab(size) => {
                if let Ok(page) = allocate_slab_page(size) {
                    pages.push(page);
                }
            }
            Action::AllocatePages(size) => {
                if let Ok(page) = allocate_pages(get_order(size)) {
                    pages.push(page);
                }
            }
            Action::AllocateZeroed => {
                if let Ok(page) = allocate_zeroed_page() {
                    pages.push(page);
                    inited.insert(page);
                }
            }
            Action::AllocateFile => {
                if let Ok(page) = allocate_file_page() {
                    pages.push(page);
                    // File pages are zeroed
                    inited.insert(page);
                }
            }
            Action::WritePage(idx) => {
                if let Some(page) = get_item(&pages, idx).copied() {
                    // SAFETY: the page is valid, since we stored it
                    // earlier in `pages`.
                    unsafe { fill_page(page, WRITE_BYTE) };
                    inited.insert(page);
                }
            }
            Action::ReadPage(idx) => {
                if let Some(page) = get_item(&pages, idx) {
                    if inited.contains(page) {
                        let page_off = idx % PAGE_SIZE;
                        // SAFETY: the page is valid, since we stored
                        // it earlier in `pages`.
                        let val = unsafe { page.as_ptr::<u8>().add(page_off).read_volatile() };
                        assert!(val == 0 || val == WRITE_BYTE);
                    }
                }
            }
            Action::AllocateFilePageRef => {
                if let Ok(pageref) = PageRef::new() {
                    pagerefs.push(pageref);
                }
            }
            Action::DropFilePageRef(idx) => {
                if let Some(idx) = get_idx(&pagerefs, idx) {
                    let _ = pagerefs.swap_remove(idx);
                }
            }
            Action::CloneFilePageRef(idx) => {
                if let Some(pageref) = get_item(&pagerefs, idx) {
                    pagerefs.push(pageref.clone());
                }
            }
            Action::Free(idx) => {
                if let Some(idx) = get_idx(&pages, idx) {
                    let page = pages.swap_remove(idx);
                    inited.remove(&page);
                    // SAFETY: the page is valid, since we stored it
                    // earlier in `pages`.
                    unsafe { fill_page(page, POISON_BYTE) };
                    free_page(page);
                }
            }
        }
    }

    for page in pages.into_iter() {
        free_page(page);
    }

    pagerefs.clear();
});
