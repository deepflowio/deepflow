mod debugger;
mod error;
mod platform;
mod queue;
mod rpc;

use bincode::{Decode, Encode};
pub use debugger::{Client, ConstructDebugCtx, Debugger};
pub use platform::PlatformMessage;
pub use queue::{QueueDebugger, QueueMessage};
pub use rpc::{ConfigResp, RpcMessage};

use std::str;
use std::time::Duration;

use num_enum::{IntoPrimitive, TryFromPrimitive};

pub const QUEUE_LEN: usize = 1024;
pub const BEACON_INTERVAL: Duration = Duration::from_secs(60);
pub const BEACON_PORT: u16 = 20035;
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(30);
pub const METAFLOW_AGENT_BEACON: &str = "metaflow-agent";
pub const MAX_BUF_SIZE: usize = 9000;

#[derive(PartialEq, Eq, Debug, TryFromPrimitive, IntoPrimitive, Clone, Copy, Encode, Decode)]
#[repr(u8)]
pub enum Module {
    Unknown,
    Rpc,
    Platform,
    List,
    Queue,
}

impl Default for Module {
    fn default() -> Self {
        Module::Unknown
    }
}

#[derive(PartialEq, Debug, Encode, Decode)]
pub struct Beacon {
    pub vtap_id: u16,
    pub hostname: String,
}

#[derive(Encode, Decode, PartialEq, Debug)]
pub struct Message<T> {
    pub module: Module,
    pub msg: T,
}

impl<T> Message<T> {
    pub fn new(module: Module, msg: T) -> Self {
        Self { module, msg }
    }

    pub fn into_inner(self) -> T {
        self.msg
    }
}
