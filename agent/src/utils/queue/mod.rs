mod debug;
mod overwrite_queue;

pub use debug::{bounded_with_debug, DebugSender};
pub use overwrite_queue::{bounded, Counter, Receiver, Sender, StatsHandle};

#[derive(Debug, PartialEq)]
pub enum Error<T> {
    Timeout,
    Terminated(Option<T>, Option<Vec<T>>),
}
