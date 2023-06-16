/*
 * Copyright (c) 2023 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::{
    fmt,
    marker::PhantomData,
    mem,
    ops::{Deref, DerefMut, Range},
    slice,
    sync::atomic::{AtomicUsize, Ordering},
};

struct Buffer<T: Sized> {
    size: usize,
    buffer: *mut T,

    _marker: PhantomData<T>,
}

impl<T> Buffer<T> {
    fn new(capacity: usize) -> Self {
        let capacity = capacity.next_power_of_two();
        let buffer = {
            let mut v = Vec::with_capacity(capacity);
            let p = v.as_mut_ptr();
            mem::forget(v);
            p
        };
        Self {
            size: capacity,
            buffer,
            _marker: PhantomData,
        }
    }
}

impl<T> Drop for Buffer<T> {
    fn drop(&mut self) {
        // SAFETY:
        // - `self.buffer` was allocated by self
        // - `self.size` was the allocated vec size
        unsafe {
            Vec::from_raw_parts(self.buffer, 0, self.size);
        }
    }
}

struct RefCounter<T> {
    ref_count: AtomicUsize,
    buffer: Buffer<T>,
}

/// `Allocator<T>` for `FixedBuffer<T>`
///
/// `Allocator<T>` is used to create fixed buffers.
/// The allocator holds a fixed sized memory and use it to allocate fixed buffers.
///
/// `Allocator<T>` and `FixedBuffer<T>`s it allocated share a same `RefCounter<T>`.
/// The memory is released when `ref_count == 0`, that is when `Allocator<T>` and
/// all its `FixedBuffer<T>`s are dropped.
pub struct Allocator<T> {
    allocated: usize,

    counter: *mut RefCounter<T>,
}

impl<T> Allocator<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            allocated: 0,
            counter: Box::into_raw(Box::new(RefCounter {
                ref_count: AtomicUsize::new(1),
                buffer: Buffer::new(capacity),
            })),
        }
    }

    fn counter(&self) -> &RefCounter<T> {
        // SAFETY:
        // - `self.counter` is valid if `ref_count > 0`
        unsafe { &*self.counter }
    }

    pub fn allocate(&mut self, size: usize) -> Option<FixedBuffer<T>> {
        let counter = self.counter();
        if self.allocated + size > counter.buffer.size {
            return None;
        }

        counter.ref_count.fetch_add(1, Ordering::Release);
        let b = Some(FixedBuffer {
            start: self.allocated,
            len: size,
            counter: self.counter,
        });
        self.allocated += size;
        b
    }
}

impl<T> Drop for Allocator<T> {
    fn drop(&mut self) {
        let counter = self.counter();
        if counter.ref_count.fetch_sub(1, Ordering::Acquire) != 1 {
            return;
        }
        // SAFETY:
        // - Last referer drops `self.counter`
        unsafe {
            mem::drop(Box::from_raw(self.counter));
        }
    }
}

/// Fixed size buffer
///
/// Allocated by `Allocator<T>`.
///
/// Different buffers allocated by the same `Allocator<T>` use separated segments of
/// the same buffer to avoid race.
pub struct FixedBuffer<T> {
    start: usize,
    len: usize,

    counter: *mut RefCounter<T>,
}

unsafe impl<T: Send> Send for FixedBuffer<T> {}
unsafe impl<T: Send> Sync for FixedBuffer<T> {}

impl<T> FixedBuffer<T> {
    fn counter(&self) -> &RefCounter<T> {
        // SAFETY:
        // - `self.counter` is valid if `ref_count > 0`
        unsafe { &*self.counter }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn truncate<I: Into<usize> + Copy>(&mut self, range: Range<I>) {
        self.start += self.len.min(range.start.into());
        self.len = (range.end.into() - range.start.into()).min(self.len);
    }
}

impl<T: Copy> Clone for FixedBuffer<T> {
    /// Copies a `FixedBuffer<T>`
    ///
    /// Rather expensive because it allocates a new dedicated buffer.
    /// Should be avoided if possible.
    fn clone(&self) -> Self {
        let mut allocator = Allocator::new(self.len());
        let mut new_buffer = allocator.allocate(self.len()).unwrap();
        new_buffer.copy_from_slice(self);
        new_buffer
    }
}

impl<T> Drop for FixedBuffer<T> {
    fn drop(&mut self) {
        let counter = self.counter();
        if counter.ref_count.fetch_sub(1, Ordering::Acquire) != 1 {
            return;
        }
        // SAFETY:
        // - Last referer drops `self.counter`
        unsafe {
            mem::drop(Box::from_raw(self.counter));
        }
    }
}

impl<T> Deref for FixedBuffer<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        // SAFETY:
        // - The buffer is allocated by `Vec[T]`
        // - Range `self.start`..`self.len` will not exceed buffer boundaries
        // - Buffer of different `FixedBuffer<T>`s will not overlap.
        unsafe {
            slice::from_raw_parts(
                self.counter().buffer.buffer.offset(self.start as isize),
                self.len,
            )
        }
    }
}

impl<T> DerefMut for FixedBuffer<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY:
        // - The buffer is allocated by `Vec[T]`
        // - Range `self.start`..`self.len` will not exceed buffer boundaries
        // - Buffer of different `FixedBuffer<T>`s will not overlap.
        unsafe {
            slice::from_raw_parts_mut(
                self.counter().buffer.buffer.offset(self.start as isize),
                self.len,
            )
        }
    }
}

impl<T> AsRef<[T]> for FixedBuffer<T> {
    fn as_ref(&self) -> &[T] {
        self
    }
}

impl<T: fmt::Debug> fmt::Debug for FixedBuffer<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: &[T] = &self;
        s.fmt(f)
    }
}

impl<T: PartialEq> PartialEq for FixedBuffer<T> {
    fn eq(&self, other: &Self) -> bool {
        let s: &[T] = self;
        let other: &[T] = other;
        s.eq(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation() {
        let mut size = 65536;
        let mut allocator: Allocator<u8> = Allocator::new(size);
        while size > 0 {
            size >>= 1;
            let buffer = allocator.allocate(size);
            assert_ne!(buffer, None);
        }
        // just 1 byte left
        let buffer = allocator.allocate(2);
        assert_eq!(buffer, None);
        let buffer = allocator.allocate(1);
        assert_ne!(buffer, None);
        let buffer = allocator.allocate(1);
        assert_eq!(buffer, None);
    }

    #[test]
    fn modification() {
        let mut allocator = Allocator::new(1024);
        let mut front = allocator.allocate(512).unwrap();
        let mut check = allocator.allocate(1).unwrap();
        let mut tail = allocator.allocate(511).unwrap();
        check.copy_from_slice(&[42u8]);
        front.copy_from_slice(&[233u8; 512]);
        tail.copy_from_slice(&[125u8; 511]);
        assert_eq!(&check[0], &42u8);
    }

    #[test]
    fn truncation() {
        let mut allocator = Allocator::new(1024);
        let mut buffer = allocator.allocate(512).unwrap();
        for i in 0..512 {
            buffer[i] = i as u8;
        }
        buffer.truncate(10..20usize);
        for i in 0..10 {
            assert_eq!(&buffer[i], &(10 + i as u8))
        }
    }
}
