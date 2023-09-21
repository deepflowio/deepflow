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
    ptr, slice,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Weak,
    },
    time::Instant,
};

use crate::counter::{Counter, CounterType, CounterValue, RefCountable};

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

    stats: Arc<StatsCounter>,
    creation_time: Instant,
}

impl<T> RefCounter<T> {
    fn new(capacity: usize, stats: Arc<StatsCounter>) -> Self {
        stats.concurrent.fetch_add(1, Ordering::Relaxed);
        Self {
            ref_count: AtomicUsize::new(1),
            buffer: Buffer::new(capacity),
            stats,
            creation_time: Instant::now(),
        }
    }
}

impl<T> Drop for RefCounter<T> {
    fn drop(&mut self) {
        self.stats.concurrent.fetch_sub(1, Ordering::Relaxed);
        self.stats.max_alive.fetch_max(
            self.creation_time.elapsed().as_nanos() as u64,
            Ordering::Relaxed,
        );
    }
}

struct InnerAllocator<T> {
    allocated: usize,
    counter: *mut RefCounter<T>,
}

impl<T> InnerAllocator<T> {
    fn new(capacity: usize, stats: Arc<StatsCounter>) -> Self {
        Self {
            allocated: 0,
            counter: Box::into_raw(Box::new(RefCounter::new(capacity, stats))),
        }
    }

    fn counter(&self) -> &RefCounter<T> {
        // SAFETY:
        // - `self.counter` is valid if `ref_count > 0`
        unsafe { &*self.counter }
    }

    unsafe fn allocate(&mut self, size: usize) -> (*mut RefCounter<T>, usize) {
        let counter = self.counter();
        if self.allocated + size > counter.buffer.size {
            return (ptr::null_mut(), 0);
        }

        let index = self.allocated;
        counter.ref_count.fetch_add(1, Ordering::Release);
        self.allocated += size;

        (self.counter, index)
    }
}

impl<T> Drop for InnerAllocator<T> {
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

/// `Allocator<T>` for `BatchedBuffer<T>`
///
/// `Allocator<T>` is used to create fixed buffers.
/// The allocator holds a fixed sized memory and use it to allocate fixed buffers.
///
/// `Allocator<T>` and `BatchedBuffer<T>`s it allocated share a same `RefCounter<T>`.
/// The memory is released when `ref_count == 0`, that is when `Allocator<T>` and
/// all its `BatchedBuffer<T>`s are dropped.
pub struct Allocator<T> {
    capacity: usize,
    inner: InnerAllocator<T>,

    stats: Arc<StatsCounter>,
}

#[derive(Default)]
pub struct StatsCounter {
    batch_size: usize,

    new: AtomicU64,
    concurrent: AtomicU64,

    max_alive: AtomicU64,
}

impl RefCountable for StatsCounter {
    fn get_counters(&self) -> Vec<Counter> {
        let (new, concurrent) = (
            self.new.swap(0, Ordering::Relaxed),
            self.concurrent.load(Ordering::Relaxed),
        );
        vec![
            ("new", CounterType::Counted, CounterValue::Unsigned(new)),
            (
                "new_bytes",
                CounterType::Counted,
                CounterValue::Unsigned(self.batch_size as u64 * new),
            ),
            (
                "concurrent",
                CounterType::Counted,
                CounterValue::Unsigned(concurrent),
            ),
            (
                "concurrent_bytes",
                CounterType::Counted,
                CounterValue::Unsigned(self.batch_size as u64 * concurrent),
            ),
            (
                "max_alive",
                CounterType::Counted,
                CounterValue::Unsigned(self.max_alive.swap(0, Ordering::Relaxed)),
            ),
        ]
    }
}

impl<T> Allocator<T> {
    pub fn new(capacity: usize) -> Self {
        let stats = Arc::new(StatsCounter {
            batch_size: capacity * mem::size_of::<T>(),
            ..Default::default()
        });
        Self {
            capacity,
            inner: InnerAllocator::new(capacity, stats.clone()),
            stats,
        }
    }

    pub fn counter(&self) -> Weak<StatsCounter> {
        Arc::downgrade(&self.stats)
    }

    fn ensure_capacity(&mut self, size: usize) {
        if self.inner.allocated + size > self.capacity {
            // old `InnerAllocator` will drop
            self.inner = InnerAllocator::new(self.capacity, self.stats.clone());
            self.stats.new.fetch_add(1, Ordering::Relaxed);
        }
    }

    // UNSAFE: T not initialized
    unsafe fn allocate_one_uninit(&mut self) -> BatchedBox<T> {
        self.ensure_capacity(1);

        let (counter, index) = self.inner.allocate(1);
        // capacity checked, `counter` should not be null
        assert!(
            !counter.is_null(),
            "allocate {} failed: allocated={} capacity={}",
            1,
            self.inner.allocated,
            self.capacity
        );

        BatchedBox { index, counter }
    }

    pub fn allocate_one_with(&mut self, value: T) -> BatchedBox<T> {
        unsafe {
            // SAFETY:
            // - item in box is initialized
            let mut b = self.allocate_one_uninit();
            ptr::write(b.as_mut_ptr(), value);
            b
        }
    }
}

impl<T: Copy> Allocator<T> {
    // UNSAFE: T not initialized
    unsafe fn allocate_uninit(&mut self, size: usize) -> BatchedBuffer<T> {
        self.ensure_capacity(size);

        let (counter, index) = self.inner.allocate(size);
        // capacity checked, `counter` should not be null
        assert!(!counter.is_null());

        BatchedBuffer {
            start: index,
            len: size,
            counter,
        }
    }

    // allocate and copy values to buffer
    pub fn allocate_with(&mut self, values: &[T]) -> BatchedBuffer<T> {
        unsafe {
            // SAFETY:
            // - T is `Copy`
            // - both `values` and `b` are valid for `values.len() * size_of::<T>()` bytes
            let len = values.len();
            let mut b = self.allocate_uninit(len);
            ptr::copy_nonoverlapping(values.as_ptr(), b.as_mut_ptr(), len);
            b
        }
    }
}

impl<T: Copy + Default> Allocator<T> {
    pub fn allocate(&mut self, size: usize) -> BatchedBuffer<T> {
        unsafe {
            // SAFETY:
            // - buffer is initialized
            let mut b = self.allocate_uninit(size);
            let value = T::default();
            for i in 0..b.len {
                ptr::write(b.as_mut_ptr().offset(i as isize), value);
            }
            b
        }
    }
}

impl<T: Default> Allocator<T> {
    pub fn allocate_one(&mut self) -> BatchedBox<T> {
        self.allocate_one_with(T::default())
    }
}

/// Batch allocated buffer
///
/// Allocated by `Allocator<T>`.
///
/// Different buffers allocated by the same `Allocator<T>` use separated segments of
/// the same buffer to avoid race.
pub struct BatchedBuffer<T: Copy> {
    start: usize,
    len: usize,

    counter: *mut RefCounter<T>,
}

unsafe impl<T: Copy + Send> Send for BatchedBuffer<T> {}
unsafe impl<T: Copy + Send> Sync for BatchedBuffer<T> {}

impl<T: Copy> BatchedBuffer<T> {
    fn counter(&self) -> &RefCounter<T> {
        // SAFETY:
        // - `self.counter` is valid if `ref_count > 0`
        unsafe { &*self.counter }
    }

    fn as_ptr(&self) -> *const T {
        unsafe {
            // SAFETY:
            // - `self.start` will not exceed buffer boundaries
            self.counter().buffer.buffer.offset(self.start as isize) as *const T
        }
    }

    fn as_mut_ptr(&mut self) -> *mut T {
        unsafe {
            // SAFETY:
            // - `self.start` will not exceed buffer boundaries
            self.counter().buffer.buffer.offset(self.start as isize)
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn truncate<I: Into<usize> + Copy>(&mut self, range: Range<I>) {
        self.start += self.len.min(range.start.into());
        self.len = (range.end.into() - range.start.into()).min(self.len);
    }
}

impl<T: Copy> Clone for BatchedBuffer<T> {
    /// Copies a `BatchedBuffer<T>`
    ///
    /// Rather expensive because it allocates a new dedicated buffer.
    /// Should be avoided if possible.
    fn clone(&self) -> Self {
        let mut allocator: Allocator<T> = Allocator::new(self.len);
        unsafe {
            // SAFETY:
            // - buffer is initialized
            // - buffers have the same length
            // - T is Copy, no memory violation
            let mut nb = allocator.allocate_uninit(self.len);
            ptr::copy_nonoverlapping(self.as_ptr(), nb.as_mut_ptr(), self.len);
            nb
        }
    }
}

impl<T: Copy> Drop for BatchedBuffer<T> {
    fn drop(&mut self) {
        // don't need to release items for T: Copy

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

impl<T: Copy> Deref for BatchedBuffer<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        // SAFETY:
        // - The buffer is allocated by `Vec[T]`
        // - Range `self.start`..`self.len` will not exceed buffer boundaries
        // - Buffer of different `BatchedBuffer<T>`s will not overlap.
        unsafe { slice::from_raw_parts(self.as_ptr(), self.len) }
    }
}

impl<T: Copy> DerefMut for BatchedBuffer<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY:
        // - The buffer is allocated by `Vec[T]`
        // - Range `self.start`..`self.len` will not exceed buffer boundaries
        // - Buffer of different `BatchedBuffer<T>`s will not overlap.
        unsafe { slice::from_raw_parts_mut(self.as_mut_ptr(), self.len) }
    }
}

impl<T: Copy> AsRef<[T]> for BatchedBuffer<T> {
    fn as_ref(&self) -> &[T] {
        self
    }
}

impl<T: Copy + fmt::Debug> fmt::Debug for BatchedBuffer<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: &[T] = &self;
        s.fmt(f)
    }
}

impl<T: Copy + PartialEq> PartialEq for BatchedBuffer<T> {
    fn eq(&self, other: &Self) -> bool {
        let s: &[T] = self;
        let other: &[T] = other;
        s.eq(other)
    }
}

/// Batch allocated box
///
/// Allocated by `Allocator<T>`.
///
/// Different boxes allocated by the same `Allocator<T>` use separated segments of
/// the same buffer to avoid race.
pub struct BatchedBox<T> {
    index: usize,

    counter: *mut RefCounter<T>,
}

unsafe impl<T: Send> Send for BatchedBox<T> {}
unsafe impl<T: Send> Sync for BatchedBox<T> {}

impl<T> BatchedBox<T> {
    fn counter(&self) -> &RefCounter<T> {
        // SAFETY:
        // - `self.counter` is valid if `ref_count > 0`
        unsafe { &*self.counter }
    }

    fn as_ptr(&self) -> *const T {
        unsafe {
            // SAFETY:
            // - Offset `self.index` is valid for present `BatchedBox`
            self.counter().buffer.buffer.offset(self.index as isize) as *const T
        }
    }

    fn as_mut_ptr(&mut self) -> *mut T {
        unsafe {
            // SAFETY:
            // - Offset `self.index` is valid for present `BatchedBox`
            self.counter().buffer.buffer.offset(self.index as isize)
        }
    }
}

impl<T: Clone> Clone for BatchedBox<T> {
    /// Copies a `BatchedBox<T>`
    ///
    /// Rather expensive because it allocates a new dedicated buffer.
    /// Should be avoided if possible.
    fn clone(&self) -> Self {
        let mut allocator: Allocator<T> = Allocator::new(1);
        unsafe {
            // SAFETY:
            // - item in box is initialized
            let mut b = allocator.allocate_one_uninit();
            ptr::write(b.as_mut_ptr(), self.as_ref().clone());
            b
        }
    }
}

impl<T> Drop for BatchedBox<T> {
    fn drop(&mut self) {
        // release T in buffer
        // SAFETY:
        // - Offset `self.start` is valid for this `BatchedBox`
        // - T is owned by `BatchedBox`
        unsafe {
            ptr::drop_in_place(self.as_mut_ptr());
        }

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

impl<T> Deref for BatchedBox<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY:
        // - The buffer is allocated by `Vec[T]`
        // - Index `self.index` will not exceed buffer boundaries
        unsafe { &*self.as_ptr() }
    }
}

impl<T> DerefMut for BatchedBox<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY:
        // - The buffer is allocated by `Vec[T]`
        // - Index `self.index` will not exceed buffer boundaries
        // - Different `BatchedBox<T>`s will not have same index.
        unsafe { &mut *self.as_mut_ptr() }
    }
}

impl<T> AsRef<T> for BatchedBox<T> {
    fn as_ref(&self) -> &T {
        self
    }
}

impl<T: fmt::Debug> fmt::Debug for BatchedBox<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: &T = &self;
        s.fmt(f)
    }
}

impl<T: PartialEq> PartialEq for BatchedBox<T> {
    fn eq(&self, other: &Self) -> bool {
        let s: &T = self;
        let other: &T = other;
        s.eq(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_allocation() {
        let mut allocator: Allocator<u8> = Allocator::new(1024);
        for i in 0..4096 {
            let _ = allocator.allocate_one_with(i as u8);
        }
    }

    #[test]
    fn batch_allocation() {
        let mut size = 65536;
        let mut allocator: Allocator<u8> = Allocator::new(size << 1);
        // must preserve at least one reference to buffer
        // or the memory location might be reused
        let mut first_buffer = allocator.allocate(size);
        first_buffer[0] = 42;
        size >>= 1;
        let old_location = allocator.inner.counter;
        while size > 0 {
            let mut buffer = allocator.allocate(size);
            buffer[0] = size as u8;
            assert_eq!(allocator.inner.counter, old_location);
            size >>= 1;
        }

        // just 1 byte left, will trigger new buffer allocation
        let buffer = allocator.allocate(2);
        // validate buffer not reused
        assert_ne!(first_buffer[0], buffer[0]);
        assert_ne!(allocator.inner.counter, old_location);
    }

    #[test]
    fn modification() {
        let mut allocator = Allocator::new(1024);
        let mut front = allocator.allocate(512);
        let mut check = allocator.allocate(1);
        let mut tail = allocator.allocate(511);
        check.copy_from_slice(&[42u8]);
        front.copy_from_slice(&[233u8; 512]);
        tail.copy_from_slice(&[125u8; 511]);
        assert_eq!(&check[0], &42u8);
    }

    #[test]
    fn truncation() {
        let mut allocator = Allocator::new(1024);
        let mut buffer = allocator.allocate(512);
        for i in 0..512 {
            buffer[i] = i as u8;
        }
        buffer.truncate(10..20usize);
        for i in 0..10 {
            assert_eq!(&buffer[i], &(10 + i as u8))
        }
    }
}
