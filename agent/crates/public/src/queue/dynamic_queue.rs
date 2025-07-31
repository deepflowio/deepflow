use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use arc_swap::ArcSwap;
use crossbeam_queue::ArrayQueue;

use super::Error;
use crate::counter as stats;

pub fn bounded<T>(size: usize) -> (Sender<T>, Receiver<T>, StatsHandle<T>) {
    let q = Arc::new(ArrayQueue::new(size));
    let mut segs = VecDeque::new();
    segs.push_back(q.clone());
    let inner = Arc::new(Inner {
        segments: Mutex::new(segs),
        head: ArcSwap::from(q.clone()),
        tail: ArcSwap::from(q.clone()),
        counter: Counter::default(),
        terminated: AtomicBool::new(false),
    });
    (
        Sender {
            inner: inner.clone(),
        },
        Receiver {
            inner: inner.clone(),
        },
        StatsHandle { inner },
    )
}

#[derive(Debug, Default)]
pub struct Counter {
    pub input: AtomicU64,
    pub output: AtomicU64,
    pub overwritten: AtomicU64,
}

struct Inner<T> {
    segments: Mutex<VecDeque<Arc<ArrayQueue<T>>>>,
    head: ArcSwap<Arc<ArrayQueue<T>>>,
    tail: ArcSwap<Arc<ArrayQueue<T>>>,
    counter: Counter,
    terminated: AtomicBool,
}

pub struct Sender<T> {
    inner: Arc<Inner<T>>,
}

unsafe impl<T: Send> Send for Sender<T> {}
unsafe impl<T: Send> Sync for Sender<T> {}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T> Sender<T> {
    pub fn terminated(&self) -> bool {
        self.inner.terminated.load(Ordering::Relaxed)
    }

    pub fn send(&self, mut msg: T) -> Result<(), Error<T>> {
        loop {
            let q = self.inner.tail.load();
            match q.push(msg) {
                Ok(()) => {
                    self.inner.counter.input.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                Err(m) => {
                    msg = m;
                    let mut segs = self.inner.segments.lock().unwrap();
                    let q = self.inner.tail.load();
                    if q.is_full() {
                        let new_q = Arc::new(ArrayQueue::new(q.capacity() * 2));
                        segs.push_back(new_q.clone());
                        self.inner.tail.store(new_q);
                    }
                }
            }
        }
    }
}

pub struct Receiver<T> {
    inner: Arc<Inner<T>>,
}

unsafe impl<T: Send> Send for Receiver<T> {}
unsafe impl<T: Send> Sync for Receiver<T> {}

impl<T> Clone for Receiver<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T> Receiver<T> {
    fn switch_head(&self) {
        let mut segs = self.inner.segments.lock().unwrap();
        if segs.len() > 1 {
            segs.pop_front();
            if let Some(new_head) = segs.front() {
                self.inner.head.store(new_head.clone());
            }
        }
    }

    pub fn terminated(&self) -> bool {
        self.inner.terminated.load(Ordering::Relaxed)
    }

    pub fn recv(&self, timeout: Option<Duration>) -> Result<T, Error<T>> {
        loop {
            let q = self.inner.head.load();
            match q.pop() {
                Some(v) => {
                    self.inner.counter.output.fetch_add(1, Ordering::Relaxed);
                    return Ok(v);
                }
                None => {
                    self.switch_head();
                    if timeout.is_some() {
                        std::thread::sleep(timeout.unwrap());
                        if q.is_empty() {
                            return Err(Error::Timeout);
                        }
                    } else if self.terminated() {
                        return Err(Error::Terminated(None, None));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn expand_and_recv() {
        let (s, r, _) = bounded(2);
        s.send(1).unwrap();
        s.send(2).unwrap();
        s.send(3).unwrap();

        assert_eq!(r.recv(None).unwrap(), 1);
        assert_eq!(r.recv(None).unwrap(), 2);
        assert_eq!(r.recv(None).unwrap(), 3);
    }

    #[test]
    fn multiple_producers_consumers() {
        let (s, r, _) = bounded::<u64>(4);
        let producers = 4;
        let per_producer = 1000;
        for _ in 0..producers {
            let sender = s.clone();
            thread::spawn(move || {
                for i in 0..per_producer {
                    sender.send(i as u64).unwrap();
                }
            });
        }

        drop(s);

        let mut sum = 0u64;
        while let Ok(v) = r.recv(Some(Duration::from_millis(10))) {
            sum += v;
        }
        let expected: u64 = (0..per_producer as u64).sum::<u64>() * producers as u64;
        assert_eq!(sum, expected);
    }
}

pub struct StatsHandle<T> {
    inner: Arc<Inner<T>>,
}

unsafe impl<T: Send> Send for StatsHandle<T> {}
unsafe impl<T: Send> Sync for StatsHandle<T> {}

impl<T> StatsHandle<T> {
    fn pending(&self) -> u64 {
        let segs = self.inner.segments.lock().unwrap();
        segs.iter().map(|q| q.len() as u64).sum()
    }
}

impl<T: Send> stats::OwnedCountable for StatsHandle<T> {
    fn get_counters(&self) -> Vec<stats::Counter> {
        vec![
            (
                "in",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(self.inner.counter.input.swap(0, Ordering::Relaxed)),
            ),
            (
                "out",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(self.inner.counter.output.swap(0, Ordering::Relaxed)),
            ),
            (
                "overwritten",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(
                    self.inner.counter.overwritten.swap(0, Ordering::Relaxed),
                ),
            ),
            (
                "pending",
                stats::CounterType::Gauged,
                stats::CounterValue::Unsigned(self.pending()),
            ),
        ]
    }

    fn closed(&self) -> bool {
        self.inner.terminated.load(Ordering::Relaxed)
    }
}
