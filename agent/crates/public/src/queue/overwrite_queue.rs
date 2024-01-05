/*
 * Copyright (c) 2024 Yunshan Networks
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

use std::cmp;
use std::iter::Iterator;
use std::marker::PhantomData;
use std::mem::{self, MaybeUninit};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Condvar, Mutex,
};
use std::time::{Duration, Instant};

use super::Error;
use crate::counter as stats;

pub fn bounded<T>(size: usize) -> (Sender<T>, Receiver<T>, StatsHandle<T>) {
    RefCounter::new(OverwriteQueue::with_capacity(size))
}

#[derive(Debug, Default)]
pub struct Counter {
    pub input: AtomicU64,
    pub output: AtomicU64,
    pub overwritten: AtomicU64,
}

// fixed size MPSC overwrite queue implemented with ring buffer
struct OverwriteQueue<T: Sized> {
    size: usize,

    buffer: *mut T,

    start: AtomicUsize,
    end: AtomicUsize,

    reader_lock: Mutex<()>,
    writer_lock: Mutex<()>,
    notify: Condvar,

    terminated: AtomicBool,

    counter: Counter,

    _marker: PhantomData<T>,
}

impl<T> OverwriteQueue<T> {
    pub fn with_capacity(size: usize) -> Self {
        let size = size.next_power_of_two();
        let buffer = {
            let mut v = Vec::with_capacity(size);
            let p = v.as_mut_ptr();
            mem::forget(v);
            p
        };

        Self {
            size,
            buffer,
            start: AtomicUsize::new(0),
            end: AtomicUsize::new(0),
            reader_lock: Mutex::new(()),
            writer_lock: Mutex::new(()),
            notify: Condvar::new(),
            terminated: AtomicBool::new(false),
            counter: Counter::default(),
            _marker: PhantomData,
        }
    }

    pub fn terminated(&self) -> bool {
        self.terminated.load(Ordering::Relaxed)
    }

    unsafe fn raw_send(&self, msgs: *const T, count: usize) -> Result<(), Error<T>> {
        if self.terminated.load(Ordering::Acquire) {
            return Err(Error::Terminated(None, None));
        }
        if count > self.size {
            return Err(Error::BatchTooLarge(None));
        }
        let _lock = self.writer_lock.lock().unwrap();
        let start = self.start.load(Ordering::Acquire);
        let raw_end = self.end.load(Ordering::Acquire);
        // the value of end will be less than start if it was wrapped
        // unwrap it for easy comparison
        let end = if raw_end < start {
            raw_end + 2 * self.size
        } else {
            raw_end
        };
        assert!(end - start <= self.size);
        // queue full
        if end - start + count > self.size {
            let _lock = self.reader_lock.lock().unwrap();
            // start could be modified by recv, check again
            let start = self.start.load(Ordering::Acquire);
            let end = if raw_end < start {
                raw_end + 2 * self.size
            } else {
                raw_end
            };
            assert!(end - start <= self.size);
            let free_space = self.size - (end - start);
            if free_space < count {
                let to_overwrite = count - free_space;
                for i in 0..to_overwrite {
                    self.buffer
                        .add((start + i) & (self.size - 1))
                        .drop_in_place();
                }
                self.start.store(
                    (start + to_overwrite) & (2 * self.size - 1),
                    Ordering::Release,
                );
                self.counter
                    .overwritten
                    .fetch_add(to_overwrite as u64, Ordering::Relaxed);
            }
        }
        let free_after_end = self.size - (raw_end & (self.size - 1));
        if free_after_end >= count {
            self.buffer
                .add(raw_end & (self.size - 1))
                .copy_from_nonoverlapping(msgs, count);
        } else {
            self.buffer
                .add(raw_end & (self.size - 1))
                .copy_from_nonoverlapping(msgs, free_after_end);
            self.buffer
                .copy_from_nonoverlapping(msgs.add(free_after_end), count - free_after_end);
        }
        self.end
            .store((raw_end + count) & (2 * self.size - 1), Ordering::Release);
        self.counter
            .input
            .fetch_add(count as u64, Ordering::Relaxed);
        self.notify.notify_one();
        Ok(())
    }

    unsafe fn raw_recv_timeout(
        &self,
        timeout: Option<Duration>,
        buffer: *mut T,
        buf_size: usize,
    ) -> Result<usize, Error<T>> {
        let mut guard = self.reader_lock.lock().unwrap();
        let mut start = self.start.load(Ordering::Acquire);
        let mut end = self.end.load(Ordering::Acquire);
        if start == end {
            if self.terminated.load(Ordering::Acquire) {
                return Err(Error::Terminated(None, None));
            }
            let now = Instant::now();
            loop {
                guard = match timeout {
                    Some(d) => {
                        let elapsed = now.elapsed();
                        if d > elapsed {
                            self.notify.wait_timeout(guard, d - elapsed).unwrap().0
                        } else {
                            return Err(Error::Timeout);
                        }
                    }
                    None => self.notify.wait(guard).unwrap(),
                };
                start = self.start.load(Ordering::Acquire);
                let new_end = self.end.load(Ordering::Acquire);
                // check for fake notify
                if end != new_end {
                    end = new_end;
                    break;
                }
                if self.terminated.load(Ordering::Acquire) {
                    return Err(Error::Terminated(None, None));
                }
            }
        }
        if end < start {
            end += 2 * self.size;
        }
        assert!(end - start <= self.size);
        let pending = end - start;
        let recv_count = cmp::min(pending, buf_size);
        let count_to_end = self.size - (start & (self.size - 1));
        if count_to_end >= recv_count {
            self.buffer
                .add(start & (self.size - 1))
                .copy_to_nonoverlapping(buffer, recv_count);
        } else {
            self.buffer
                .add(start & (self.size - 1))
                .copy_to_nonoverlapping(buffer, count_to_end);
            self.buffer
                .copy_to_nonoverlapping(buffer.add(count_to_end), recv_count - count_to_end);
        }
        self.start.store(
            (start + recv_count) & (2 * self.size - 1),
            Ordering::Release,
        );
        self.counter
            .output
            .fetch_add(recv_count as u64, Ordering::Relaxed);
        Ok(recv_count)
    }

    pub fn close(&self) {
        let _lock = self.reader_lock.lock().unwrap();
        self.terminated.swap(true, Ordering::Release);
        self.notify.notify_one();
    }
}

impl<T> Drop for OverwriteQueue<T> {
    fn drop(&mut self) {
        let start = self.start.load(Ordering::Acquire);
        let mut end = self.end.load(Ordering::Acquire);
        if end < start {
            end += 2 * self.size;
        }
        assert!(end - start <= self.size);
        for i in start..end {
            let index = i & (self.size - 1);
            unsafe {
                self.buffer.add(index).drop_in_place();
            }
        }

        // deallocate buffer
        unsafe {
            Vec::from_raw_parts(self.buffer, 0, self.size);
        }
    }
}

struct RefCounter<T> {
    senders: AtomicUsize,
    sender_dropped: AtomicBool,
    receiver_dropped: AtomicBool,
    stats_handle_dropped: AtomicBool,
    queue: OverwriteQueue<T>,
}

impl<T> RefCounter<T> {
    pub fn new(queue: OverwriteQueue<T>) -> (Sender<T>, Receiver<T>, StatsHandle<T>) {
        let counter = Box::into_raw(Box::new(RefCounter {
            senders: AtomicUsize::new(1),
            sender_dropped: AtomicBool::new(false),
            receiver_dropped: AtomicBool::new(false),
            stats_handle_dropped: AtomicBool::new(false),
            queue,
        }));
        (
            Sender { counter },
            Receiver { counter },
            StatsHandle { counter },
        )
    }
}

pub struct Sender<T> {
    counter: *mut RefCounter<T>,
}

unsafe impl<T: Send> Send for Sender<T> {}
unsafe impl<T: Send> Sync for Sender<T> {}

impl<T> Sender<T> {
    fn counter(&self) -> &RefCounter<T> {
        unsafe { &*self.counter }
    }

    pub fn terminated(&self) -> bool {
        self.counter().queue.terminated()
    }

    pub fn send(&self, msg: T) -> Result<(), Error<T>> {
        unsafe {
            match self.counter().queue.raw_send(&msg, 1) {
                Ok(_) => {
                    // don't drop because msg is moved into queue
                    mem::forget(msg);
                    Ok(())
                }
                Err(Error::Terminated(..)) => Err(Error::Terminated(Some(msg), None)),
                _ => unreachable!(),
            }
        }
    }

    // This method clears the Vec on success, and leave it as it is on failure
    pub fn send_all(&self, msgs: &mut Vec<T>) -> Result<(), Error<T>> {
        unsafe {
            match self.counter().queue.raw_send(msgs.as_ptr(), msgs.len()) {
                Ok(_) => {
                    // drop the vector without dropping elements within
                    msgs.set_len(0);
                    Ok(())
                }
                Err(Error::Terminated(..)) => Err(Error::Terminated(None, None)),
                Err(Error::BatchTooLarge(_)) => Err(Error::BatchTooLarge(None)),
                _ => unreachable!(),
            }
        }
    }

    pub fn send_large(&self, mut msgs: Vec<T>) -> Result<(), Error<T>> {
        const SEND_BATCH: usize = 1024;
        unsafe {
            for chunk in msgs.chunks(SEND_BATCH) {
                match self.counter().queue.raw_send(chunk.as_ptr(), chunk.len()) {
                    Ok(_) => continue,
                    Err(Error::Terminated(..)) => return Err(Error::Terminated(None, Some(msgs))),
                    _ => unreachable!(),
                }
            }
            // drop the vector without dropping elements within
            msgs.set_len(0);
            Ok(())
        }
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        self.counter().senders.fetch_add(1, Ordering::Relaxed);
        Sender {
            counter: self.counter,
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let counter = self.counter();
        // last sender to drop
        if counter.senders.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.counter().queue.close();
            // the last of senders, receiver or stats handle drops the counter
            self.counter().sender_dropped.store(true, Ordering::Release);
            if self.counter().receiver_dropped.load(Ordering::Acquire)
                && self.counter().stats_handle_dropped.load(Ordering::Acquire)
            {
                unsafe {
                    mem::drop(Box::from_raw(self.counter));
                }
            }
        }
    }
}

pub struct Receiver<T> {
    counter: *mut RefCounter<T>,
}

unsafe impl<T: Send> Send for Receiver<T> {}
unsafe impl<T: Send> Sync for Receiver<T> {}

impl<T> Receiver<T> {
    fn counter(&self) -> &RefCounter<T> {
        unsafe { &*self.counter }
    }

    pub fn terminated(&self) -> bool {
        self.counter().queue.terminated()
    }

    pub fn recv(&self, timeout: Option<Duration>) -> Result<T, Error<T>> {
        unsafe {
            let mut msg = MaybeUninit::<T>::uninit();
            match self
                .counter()
                .queue
                .raw_recv_timeout(timeout, msg.as_mut_ptr(), 1)
            {
                Ok(n) if n == 1 => Ok(msg.assume_init()),
                Err(e) => Err(e),
                _ => unreachable!(),
            }
        }
    }

    pub fn recv_n(&self, n: usize, timeout: Option<Duration>) -> Result<Vec<T>, Error<T>> {
        assert!(n > 0);
        unsafe {
            let mut msgs = Vec::with_capacity(n);
            match self
                .counter()
                .queue
                .raw_recv_timeout(timeout, msgs.as_mut_ptr(), n)
            {
                Ok(count) => {
                    msgs.set_len(count);
                    Ok(msgs)
                }
                Err(e) => Err(e),
            }
        }
    }

    // Clears anything in msgs, and receive at most msgs.capacity() messages
    pub fn recv_all(&self, msgs: &mut Vec<T>, timeout: Option<Duration>) -> Result<(), Error<T>> {
        msgs.clear();
        unsafe {
            let max_recv = msgs.capacity();
            match self
                .counter()
                .queue
                .raw_recv_timeout(timeout, msgs.as_mut_ptr(), max_recv)
            {
                Ok(count) => {
                    msgs.set_len(count);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        self.counter().queue.close();
        // the last of senders, receiver or stats handle drops the counter
        self.counter()
            .receiver_dropped
            .store(true, Ordering::Release);
        if self.counter().sender_dropped.load(Ordering::Acquire)
            && self.counter().stats_handle_dropped.load(Ordering::Acquire)
        {
            unsafe {
                mem::drop(Box::from_raw(self.counter));
            }
        }
    }
}

impl<T> Iterator for Receiver<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.recv(None).ok()
    }
}

pub struct StatsHandle<T> {
    counter: *mut RefCounter<T>,
}

unsafe impl<T: Send> Send for StatsHandle<T> {}
unsafe impl<T: Send> Sync for StatsHandle<T> {}

impl<T> StatsHandle<T> {
    fn counter(&self) -> &RefCounter<T> {
        unsafe { &*self.counter }
    }
}

impl<T> Drop for StatsHandle<T> {
    fn drop(&mut self) {
        // the last of senders, receiver or stats handle drops the counter
        self.counter()
            .stats_handle_dropped
            .store(true, Ordering::Release);
        if self.counter().sender_dropped.load(Ordering::Acquire)
            && self.counter().receiver_dropped.load(Ordering::Acquire)
        {
            unsafe {
                mem::drop(Box::from_raw(self.counter));
            }
        }
    }
}

impl<T: Send> stats::OwnedCountable for StatsHandle<T> {
    fn get_counters(&self) -> Vec<stats::Counter> {
        let queue = &self.counter().queue;
        let start = queue.start.load(Ordering::Relaxed);
        let mut end = queue.end.load(Ordering::Relaxed);
        if end < start {
            end += 2 * queue.size;
        }
        vec![
            (
                "in",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(queue.counter.input.swap(0, Ordering::Relaxed)),
            ),
            (
                "out",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(queue.counter.output.swap(0, Ordering::Relaxed)),
            ),
            (
                "overwritten",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(queue.counter.overwritten.swap(0, Ordering::Relaxed)),
            ),
            (
                "pending",
                stats::CounterType::Gauged,
                stats::CounterValue::Unsigned((end - start) as u64),
            ),
        ]
    }

    fn closed(&self) -> bool {
        self.counter().queue.terminated.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use std::fmt;
    use std::sync::Arc;
    use std::thread;

    use super::*;

    #[derive(Debug)]
    struct CountedU64(u64, Arc<AtomicUsize>);

    impl CountedU64 {
        fn new(id: u64, c: Arc<AtomicUsize>) -> Self {
            c.fetch_add(1, Ordering::Relaxed);
            Self(id, c)
        }
    }

    impl Drop for CountedU64 {
        fn drop(&mut self) {
            self.1.fetch_sub(1, Ordering::Relaxed);
        }
    }

    impl PartialEq for CountedU64 {
        fn eq(&self, other: &CountedU64) -> bool {
            self.0 == other.0
        }
    }
    impl Eq for CountedU64 {}

    impl PartialEq<u64> for CountedU64 {
        fn eq(&self, other: &u64) -> bool {
            self.0 == *other
        }
    }

    impl fmt::Display for CountedU64 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    #[test]
    fn one_element_send_receive() {
        let c = Arc::new(AtomicUsize::new(0));

        {
            let (s, r, _) = bounded(2);
            let h = thread::spawn(move || {
                let co: CountedU64 = r.recv(None).unwrap();
                assert_eq!(co, 42, "expected: 42, result: {}", co);
            });
            s.send(CountedU64::new(42, c.clone())).unwrap();

            h.join().unwrap();
        }

        let c = c.load(Ordering::Acquire);
        assert_eq!(c, 0, "new/drop count mismatch: new - drop = {}", c);
    }

    #[test]
    fn multiple_sender() {
        let c = Arc::new(AtomicUsize::new(0));

        {
            let (s, r, _) = bounded(1024);
            for i in 0..10 {
                let sender = s.clone();
                thread::spawn(move || {
                    if i % 2 == 0 {
                        for j in 1..=10 {
                            sender.send(j).unwrap();
                        }
                    } else {
                        sender
                            .send_all(&mut vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
                            .unwrap();
                    }
                });
            }
            mem::drop(s);

            let mut sum = 0;
            for c in r {
                sum += c;
            }
            assert_eq!(sum, 550, "expected: 550, result: {}", sum);
        }

        let c = c.load(Ordering::Acquire);
        assert_eq!(c, 0, "new/drop count mismatch: new - drop = {}", c);
    }

    #[test]
    fn simple_overwrite() {
        let c = Arc::new(AtomicUsize::new(0));

        {
            let (s, r, _) = bounded(2);

            s.send(CountedU64::new(42, c.clone())).unwrap();
            s.send(CountedU64::new(43, c.clone())).unwrap();
            s.send(CountedU64::new(44, c.clone())).unwrap();

            let co = r.recv(None).unwrap();
            assert_eq!(co, 43, "expected: 43, result: {}", co);
            let co = r.recv(None).unwrap();
            assert_eq!(co, 44, "expected: 44, result: {}", co);
        }

        let c = c.load(Ordering::Acquire);
        assert_eq!(c, 0, "new/drop count mismatch: new - drop = {}", c);
    }

    #[test]
    fn queue_size_calculation() {
        let c = Arc::new(AtomicUsize::new(0));

        {
            let (s, r, _) = bounded(3);

            s.send_all(&mut vec![
                CountedU64::new(42, c.clone()),
                CountedU64::new(43, c.clone()),
                CountedU64::new(44, c.clone()),
                CountedU64::new(45, c.clone()),
            ])
            .unwrap();
            s.send_all(&mut vec![
                CountedU64::new(52, c.clone()),
                CountedU64::new(53, c.clone()),
                CountedU64::new(54, c.clone()),
                CountedU64::new(55, c.clone()),
            ])
            .unwrap();

            let mut vs = Vec::with_capacity(3);
            r.recv_all(&mut vs, None).unwrap();
            let co = r.recv(None).unwrap();
            assert_eq!(co, 55, "expected: 55, result: {}", co);
        }

        let c = c.load(Ordering::Acquire);
        assert_eq!(c, 0, "new/drop count mismatch: new - drop = {}", c);
    }

    #[test]
    fn receive_multiple() {
        let c = Arc::new(AtomicUsize::new(0));

        {
            let (s, r, _) = bounded(2);

            s.send_all(&mut vec![
                CountedU64::new(42, c.clone()),
                CountedU64::new(43, c.clone()),
            ])
            .unwrap();
            s.send(CountedU64::new(44, c.clone())).unwrap();

            let mut co = Vec::with_capacity(2);
            r.recv_all(&mut co, None).unwrap();
            assert_eq!(co, vec![43, 44], "expected: [43, 44], result: {:?}", co);

            s.send_all(&mut vec![
                CountedU64::new(45, c.clone()),
                CountedU64::new(46, c.clone()),
            ])
            .unwrap();
            let co = r.recv_n(100, None).unwrap();
            assert_eq!(co, vec![45, 46], "expected: [45, 46], result: {:?}", co);
        }

        let c = c.load(Ordering::Acquire);
        assert_eq!(c, 0, "new/drop count mismatch: new - drop = {}", c);
    }

    #[test]
    #[should_panic]
    fn recv_empty() {
        let (s, r, _) = bounded(2);
        s.send(42).unwrap();
        r.recv_n(0, None).unwrap();
    }

    #[test]
    fn timeout_and_terminate() {
        let c = Arc::new(AtomicUsize::new(0));

        {
            let (s, r, _) = bounded(2);
            let phase = Arc::new(AtomicUsize::new(0));
            let rphase = phase.clone();

            let h = thread::spawn(move || {
                let phase = rphase;

                let e: Error<CountedU64> = r.recv(Some(Duration::from_millis(10))).err().unwrap();
                assert_eq!(e, Error::Timeout);

                phase.store(1, Ordering::Release);

                let mut co = Vec::with_capacity(100);
                r.recv_all(&mut co, Some(Duration::from_millis(100)))
                    .unwrap();
                assert_eq!(co, vec![42, 43], "expected: [42, 43], result: {:?}", co);

                let e: Error<CountedU64> = r.recv(Some(Duration::from_millis(10))).err().unwrap();
                assert_eq!(e, Error::Terminated(None, None));
            });

            while phase.load(Ordering::Acquire) < 1 {}

            s.send_all(&mut vec![
                CountedU64::new(42, c.clone()),
                CountedU64::new(43, c.clone()),
            ])
            .unwrap();

            // release sender
            mem::drop(s);

            h.join().unwrap();
        }

        let c = c.load(Ordering::Acquire);
        assert_eq!(c, 0, "new/drop count mismatch: new - drop = {}", c);
    }
}
