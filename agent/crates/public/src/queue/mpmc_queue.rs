use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}};
use std::time::Duration;

use crossbeam_channel::{bounded, Receiver as CReceiver, RecvTimeoutError, Sender as CSender};

use super::Error;
use crate::counter as stats;

pub fn bounded<T>(size: usize) -> (Sender<T>, Receiver<T>, StatsHandle<T>) {
    let (s, r) = bounded(size);
    let inner = Arc::new(Inner {
        sender: s,
        receiver: r,
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
    sender: CSender<T>,
    receiver: CReceiver<T>,
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
    fn inner(&self) -> &Inner<T> {
        &self.inner
    }

    pub fn terminated(&self) -> bool {
        self.inner.terminated.load(Ordering::Relaxed)
    }

    pub fn send(&self, msg: T) -> Result<(), Error<T>> {
        if self.inner.sender.send(msg).is_err() {
            self.inner.terminated.store(true, Ordering::Release);
            Err(Error::Terminated(None, None))
        } else {
            self.inner.counter.input.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    pub fn send_all(&self, msgs: &mut Vec<T>) -> Result<(), Error<T>> {
        for msg in msgs.drain(..) {
            self.send(msg)?;
        }
        Ok(())
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
    fn inner(&self) -> &Inner<T> {
        &self.inner
    }

    pub fn terminated(&self) -> bool {
        self.inner.terminated.load(Ordering::Relaxed)
    }

    pub fn recv(&self, timeout: Option<Duration>) -> Result<T, Error<T>> {
        let res = match timeout {
            Some(t) => self.inner.receiver.recv_timeout(t).map_err(|e| e),
            None => self.inner.receiver.recv().map_err(|e| RecvTimeoutError::Disconnected),
        };
        match res {
            Ok(v) => {
                self.inner.counter.output.fetch_add(1, Ordering::Relaxed);
                Ok(v)
            }
            Err(RecvTimeoutError::Timeout) => Err(Error::Timeout),
            Err(RecvTimeoutError::Disconnected) => {
                self.inner.terminated.store(true, Ordering::Release);
                Err(Error::Terminated(None, None))
            }
        }
    }

    pub fn recv_n(&self, n: usize, timeout: Option<Duration>) -> Result<Vec<T>, Error<T>> {
        assert!(n > 0);
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            match self.recv(timeout) {
                Ok(v) => out.push(v),
                Err(Error::Timeout) if out.is_empty() => return Err(Error::Timeout),
                Err(Error::Timeout) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    pub fn recv_all(&self, msgs: &mut Vec<T>, timeout: Option<Duration>) -> Result<(), Error<T>> {
        msgs.clear();
        loop {
            match self.recv(timeout) {
                Ok(v) => msgs.push(v),
                Err(Error::Timeout) if msgs.is_empty() => return Err(Error::Timeout),
                Err(Error::Timeout) => break,
                Err(e) => return Err(e),
            }
            if msgs.len() == msgs.capacity() {
                break;
            }
        }
        Ok(())
    }
}

pub struct StatsHandle<T> {
    inner: Arc<Inner<T>>,
}

unsafe impl<T: Send> Send for StatsHandle<T> {}
unsafe impl<T: Send> Sync for StatsHandle<T> {}

impl<T> StatsHandle<T> {
    fn inner(&self) -> &Inner<T> {
        &self.inner
    }
}

impl<T: Send> stats::OwnedCountable for StatsHandle<T> {
    fn get_counters(&self) -> Vec<stats::Counter> {
        let pending = self.inner.receiver.len() as u64;
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
                stats::CounterValue::Unsigned(self.inner.counter.overwritten.swap(0, Ordering::Relaxed)),
            ),
            (
                "pending",
                stats::CounterType::Gauged,
                stats::CounterValue::Unsigned(pending),
            ),
        ]
    }

    fn closed(&self) -> bool {
        self.inner.terminated.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
    use std::thread;

    #[test]
    fn multiple_producers_consumers() {
        let (s, r, _) = bounded::<u64>(1024);
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

        let sum = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();
        let consumers = 4;
        for _ in 0..consumers {
            let receiver = r.clone();
            let sum_cl = sum.clone();
            handles.push(thread::spawn(move || {
                while let Ok(v) = receiver.recv(None) {
                    sum_cl.fetch_add(v, Ordering::Relaxed);
                }
            }));
        }

        drop(s);
        for h in handles { h.join().unwrap(); }
        let expected: u64 = (0..per_producer as u64).sum::<u64>() * producers as u64;
        assert_eq!(sum.load(Ordering::Relaxed), expected);
    }
}
