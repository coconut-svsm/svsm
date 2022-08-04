// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

// Custom Vec implementation
// Written while following https://doc.rust-lang.org/nomicon/vec/vec.html

use crate::lib::{alloc, dealloc, realloc, handle_alloc_error};
use core::ops::{Deref, DerefMut};
use core::marker::PhantomData;
use core::alloc::Layout;
use core::ptr;
use core::mem;

struct RawVec<T> {
    ptr         : ptr::NonNull<T>,
    capacity    : usize,
    _marker     : PhantomData<T>,
}

// Implement Send and Sync for RawVec<T> iff T is Send/Sync
unsafe impl<T : Send> Send for RawVec<T> {}
unsafe impl<T : Sync> Sync for RawVec<T> {}

impl<T> RawVec<T> {
    const fn new() -> Self {
        assert!(mem::size_of::<T>() != 0, "Zero sized elements not supported in RawVec");
        RawVec {
            ptr      : ptr::NonNull::dangling(),
            capacity : 0,
            _marker  : PhantomData,
        }
    }

    fn grow(&mut self) {
        let (new_capacity, new_layout) = if self.capacity == 0 {
            (1, Layout::array::<T>(1).unwrap())
        } else {
            let capacity = self.capacity * 2;
            let layout = Layout::array::<T>(capacity).unwrap();
            (capacity, layout)
        };

        let new_ptr = if self.capacity == 0 {
            unsafe { alloc(new_layout) }
        } else {
            let layout  = Layout::array::<T>(self.capacity).unwrap();
            let ptr     = self.ptr.as_ptr() as *mut u8;
            unsafe { realloc(ptr, layout, new_layout.size()) }
        };

        self.ptr = match ptr::NonNull::new(new_ptr as *mut T) {
            Some(p) => p,
            None => handle_alloc_error(new_layout),
        };

        self.capacity = new_capacity;
    }
}

impl<T> Drop for RawVec<T> {
    fn drop(&mut self) {
        if self.capacity != 0 {
            let layout = Layout::array::<T>(self.capacity).unwrap();
            unsafe { dealloc(self.ptr.as_ptr() as *mut u8, layout); }
        }
    }
}

pub struct Vec<T> {
    buf         : RawVec<T>,
    length      : usize,
}

// Implement Send and Sync for Vec<T> iff T is Send/Sync
unsafe impl<T : Send> Send for Vec<T> {}
unsafe impl<T : Sync> Sync for Vec<T> {}

impl <T> Vec<T> {
    fn ptr(&self) -> *mut T {
        self.buf.ptr.as_ptr()
    }

    fn capacity(&self) -> usize {
        self.buf.capacity
    }

    pub const fn new() -> Self {
        assert!(mem::size_of::<T>() != 0, "No zero sized elements allowed");
        Vec {
            buf     : RawVec::new(),
            length  : 0,
        }
    }

    pub fn push(&mut self, elem : T) {
        if self.length == self.capacity() { self.buf.grow(); }

        unsafe {
            ptr::write(self.ptr().add(self.length), elem);
        }

        self.length += 1;
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.length == 0 {
            None
        } else {
            self.length -= 1;
            unsafe { Some(ptr::read(self.ptr().add(self.length))) }
        }
    }

    pub fn insert(&mut self, index : usize, elem : T) {
        assert!(index <= self.length, "Vec index out of bounds");
        if self.length == self.capacity() { self.buf.grow(); }
        unsafe {
            ptr::copy(self.ptr().add(index),
                      self.ptr().add(index + 1),
                      self.length - index);
            ptr::write(self.ptr().add(index), elem);
        }
        self.length += 1;
    }

    pub fn remove(&mut self, index : usize) -> T {
        assert!(index < self.length, "Vec index out of bounds");
        unsafe {
            self.length -= 1;
            let result = ptr::read(self.ptr().add(index));
            ptr::copy(self.ptr().add(index + 1),
                      self.ptr().add(index),
                      self.length - index);
            result
        }
    }

    pub fn drain(&mut self) -> Drain<T> {
        unsafe {
            let iter = RawValIter::new(&self);

            self.length = 0;

            Drain {
                iter : iter,
                vec  : PhantomData,
            }
        }
    }
}

impl<T> Drop for Vec<T> {
    fn drop(&mut self) {
        if self.length != 0 {
            while let Some(_) = self.pop() { }
        }
    }
}

impl<T> Deref for Vec<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        unsafe { core::slice::from_raw_parts(self.ptr(), self.length) }
    }
}

impl<T> DerefMut for Vec<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr(), self.length) }
    }
}

struct RawValIter<T> {
    start   : *const T,
    end     : *const T,
}

impl<T> RawValIter<T> {
    unsafe fn new(slice : &[T]) -> Self {
        RawValIter {
            start   : slice.as_ptr(),
            end     : if slice.len() == 0 {
                          slice.as_ptr()
                      } else {
                          slice.as_ptr().add(slice.len())
                      }
        }
    }
}

impl<T> Iterator for RawValIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        if self.start == self.end {
            None
        } else {
            unsafe {
                let result = ptr::read(self.start);
                self.start = self.start.offset(1);
                Some(result)
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = (self.end as usize - self.start as usize) / mem::size_of::<T>();
        (len, Some(len))
    }
}

impl<T> DoubleEndedIterator for RawValIter<T> {
    fn next_back(&mut self) -> Option<T> {
        if self.start == self.end {
            None
        } else {
            unsafe {
                self.end = self.end.offset(-1);
                Some(ptr::read(self.end))
            }
        }
    }
}

pub struct IntoIter<T> {
    _buf        : RawVec<T>,
    iter        : RawValIter<T>
}

impl<T> IntoIterator for Vec<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;
    
    fn into_iter(self) -> IntoIter<T> {
        unsafe {
            let iter = RawValIter::new(&self);
            let buf  = ptr::read(&self.buf);

            mem::forget(self);

            IntoIter {
                iter        : iter,
                _buf        : buf,
            }
        }
    }
}

impl<T> Iterator for IntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        self.iter.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<T> DoubleEndedIterator for IntoIter<T> {
    fn next_back(&mut self) -> Option<T> {
        self.iter.next_back()
    }
}

impl<T> Drop for IntoIter<T> {
    fn drop(&mut self) {
        for _ in &mut *self { }
    }
}

pub struct Drain<'a, T: 'a> {
    vec     : PhantomData<&'a mut Vec<T>>,
    iter    : RawValIter<T>,
}

impl<'a, T> Iterator for Drain<'a, T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        self.iter.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'a, T> DoubleEndedIterator for Drain<'a, T> {
    fn next_back(&mut self) -> Option<T> {
        self.iter.next_back()
    }
}

impl<'a, T> Drop for Drain<'a, T> {
    fn drop(&mut self) {
        for _ in &mut *self { }
    }
}
