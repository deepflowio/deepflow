use std::{
    fmt::Debug,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use log::debug;

use super::{bounded, Error, Receiver, Sender, StatsHandle};

use crate::debug::{QueueDebugger, QUEUE_LEN};

pub struct DebugSender<T> {
    debug: (Sender<String>, Arc<AtomicBool>),
    sender: Sender<T>,
}

impl<T: Debug> DebugSender<T> {
    pub fn send(&self, msg: T) -> Result<(), Error<T>> {
        if self.debug.1.load(Ordering::Relaxed) {
            if let Err(e) = self.debug.0.send(format!("{:?}", msg)) {
                debug!("failed to send: {:?}", e);
            }
        }
        self.sender.send(msg)
    }

    pub fn send_all(&self, msgs: Vec<T>) -> Result<(), Error<T>> {
        if self.debug.1.load(Ordering::Relaxed) {
            for chunk in msgs.chunks(QUEUE_LEN) {
                if let Err(e) = self.debug.0.send_all(
                    chunk
                        .iter()
                        .map(|msg| format!("{:?}", msg))
                        .collect::<Vec<_>>(),
                ) {
                    debug!("failed to send_all: {:?}", e);
                }
            }
        }
        self.sender.send_all(msgs)
    }
}

impl<T> Clone for DebugSender<T> {
    fn clone(&self) -> Self {
        Self {
            debug: self.debug.clone(),
            sender: self.sender.clone(),
        }
    }
}

pub fn bounded_with_debug<T>(
    size: usize,
    name: &'static str,
    debugger: &QueueDebugger,
) -> (DebugSender<T>, Receiver<T>, StatsHandle<T>) {
    let (sender, receiver, handle) = bounded(size);

    let (debug_sender, debug_receiver, _) = bounded(QUEUE_LEN);
    let enabled = Arc::new(AtomicBool::new(false));
    debugger.append_queue(name, debug_receiver, enabled.clone());

    let sender = DebugSender {
        debug: (debug_sender, enabled),
        sender,
    };

    (sender, receiver, handle)
}
