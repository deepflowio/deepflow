/*
 * Copyright (c) 2022 Yunshan Networks
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

mod debugger;
mod error;
#[cfg(target_os = "linux")]
mod platform;
mod queue;
mod rpc;

use bincode::{Decode, Encode};
pub use debugger::{Client, ConstructDebugCtx, Debugger};
#[cfg(target_os = "linux")]
pub use platform::PlatformMessage;
pub use queue::{QueueDebugger, QueueMessage};
pub use rpc::{ConfigResp, RpcMessage};

use std::str;
use std::time::Duration;

use num_enum::{IntoPrimitive, TryFromPrimitive};

pub const QUEUE_LEN: usize = 1024;
pub const BEACON_INTERVAL: Duration = Duration::from_secs(60);
pub const BEACON_PORT: u16 = 30035;
pub const DEBUG_QUEUE_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEEPFLOW_AGENT_BEACON: &str = "deepflow-agent";
pub const MAX_BUF_SIZE: usize = 9000;

#[derive(PartialEq, Eq, Debug, TryFromPrimitive, IntoPrimitive, Clone, Copy, Encode, Decode)]
#[repr(u8)]
pub enum Module {
    Unknown,
    Rpc,
    #[cfg(target_os = "linux")]
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
