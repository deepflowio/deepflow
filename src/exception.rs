use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use crate::proto::trident::Exception;

#[derive(Clone, Debug, Default)]
pub struct ExceptionHandler(Arc<AtomicU64>);

impl ExceptionHandler {
    pub fn set(&self, e: Exception) {
        self.0.fetch_or(e as u64, Ordering::SeqCst);
    }

    pub fn clear(&self, e: Exception) {
        self.0.fetch_and(!(e as u64), Ordering::SeqCst);
    }

    pub fn take(&self) -> u64 {
        self.0.swap(0, Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exceptions() {
        let mut expected = 0u64;
        let h = ExceptionHandler::default();

        h.set(Exception::DiskNotEnough);
        expected |= Exception::DiskNotEnough as u64;
        assert_eq!(h.take(), expected);

        let exceptions = vec![
            Exception::DiskNotEnough,
            Exception::MemNotEnough,
            Exception::CorefileTooMany,
            Exception::NpbFuse,
            Exception::NpbNoGwArp,
            Exception::AnalyzerNoGwArp,
        ];
        expected = 0;
        for e in exceptions {
            h.set(e);
            expected |= e as u64;
            assert_eq!(h.0.load(Ordering::Relaxed), expected);
        }

        h.clear(Exception::DiskNotEnough);
        expected &= !(Exception::DiskNotEnough as u64);
        assert_eq!(h.0.load(Ordering::Relaxed), expected);

        assert_eq!(h.take(), expected);
        assert_eq!(h.0.load(Ordering::Relaxed), 0);
    }
}
