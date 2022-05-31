mod debugger;
mod error;
mod platform;
mod queue;
mod rpc;

pub use debugger::{Client, ConstructDebugCtx, Debugger};
pub use platform::PlatformMessage;
pub use queue::{QueueDebugger, QueueMessage};
pub use rpc::{ConfigResp, RpcMessage};

use std::time::Duration;

use log::warn;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};

const MAX_MESSAGE_SIZE: usize = 8196;
// Mesaage<T> 会有一些控制结构， 导致buf会大于MAX_MESSAGE_SIZE
pub const MAX_BUF_SIZE: usize = 9000;
pub const QUEUE_LEN: usize = 1024;
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(30);
pub const BEACON_INTERVAL: Duration = Duration::from_secs(60);
pub const METAFLOW_AGENT_BEACON: &str = "metaflow-agent";

#[derive(PartialEq, Eq, Debug, TryFromPrimitive, IntoPrimitive, Serialize, Deserialize)]
#[repr(u8)]
pub enum Module {
    Rpc,
    Platform,
    Flow,
    List,
    Queue,
    // TEST
    _Test,
    Unknown,
}

impl Default for Module {
    fn default() -> Self {
        Module::Unknown
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Beacon {
    pub vtap_id: u16,
    pub hostname: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Message<T> {
    pub module: Module,
    pub msg: T,
}

impl<T> Message<T> {
    pub fn into_inner(self) -> T {
        self.msg
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
enum TestMessage {
    Small(u64),
    Huge,
    HugeResp(Vec<u64>),
}

impl TestMessage {
    pub fn new_huge() -> Self {
        TestMessage::Huge
    }

    pub fn new_small() -> Self {
        TestMessage::Small(0)
    }
}

fn chunk_string_payload<T>(
    iter: impl IntoIterator<Item = String>,
    truncate_fn: fn(res: &mut Vec<Message<T>>, s: String),
    push_fn: fn(res: &mut Vec<Message<T>>, cache: &mut Option<Vec<String>>),
) -> Vec<Message<T>> {
    let mut res = vec![];
    let mut cache = None;
    let mut cache_bytes = 0;
    for s in iter {
        if s.len() > MAX_MESSAGE_SIZE {
            // String::truncate 削到char的边界的时候会panic
            let mut c = s.into_bytes();
            c.truncate(MAX_MESSAGE_SIZE);
            match String::from_utf8(c) {
                Ok(s) => {
                    truncate_fn(&mut res, s);
                }
                Err(e) => {
                    warn!("{}", e);
                }
            }
        } else if cache_bytes + s.len() < MAX_MESSAGE_SIZE {
            cache_bytes += s.len();
            if cache.is_none() {
                cache.replace(vec![s]);
            } else {
                cache.as_mut().unwrap().push(s);
            }
        } else {
            push_fn(&mut res, &mut cache);

            cache_bytes = s.len();
            cache.replace(vec![s]);
        }
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_ser_de() {
        let msg = TestMessage::new_small();
        let encoded: Vec<u8> = bincode::serialize(&msg).unwrap();
        let decoded: TestMessage = bincode::deserialize(&encoded[..]).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn chunk_string_check() {
        let iter = (1..10)
            .into_iter()
            .map(|i| String::from_utf8(vec![65; i * 1000]).unwrap());

        fn truncate_fn(res: &mut Vec<Message<RpcMessage>>, s: String) {
            res.push(Message {
                module: Module::Rpc,
                msg: RpcMessage::Cidr(Some(vec![s])),
            });
        }

        fn push_fn(res: &mut Vec<Message<RpcMessage>>, cache: &mut Option<Vec<String>>) {
            res.push(Message {
                module: Module::Rpc,
                msg: RpcMessage::Cidr(cache.take()),
            });
        }

        let mut res = chunk_string_payload(iter, truncate_fn, push_fn);
        // [[1000, 2000, 3000], [4000], [5000], [6000], [7000], [8196]]  MAX_MESSAGE_SIZE=8196
        assert_eq!(6, res.len());
        if let RpcMessage::Cidr(Some(v)) = res.remove(0).into_inner() {
            let lens = v.iter().map(|s| s.len()).collect::<Vec<_>>();
            assert_eq!(lens, vec![1000, 2000, 3000]);
        } else {
            assert_eq!(1, 2);
        }

        if let RpcMessage::Cidr(Some(v)) = res.remove(0).into_inner() {
            let lens = v.iter().map(|s| s.len()).collect::<Vec<_>>();
            assert_eq!(lens, vec![4000]);
        } else {
            assert_eq!(1, 2);
        }

        if let RpcMessage::Cidr(Some(v)) = res.remove(0).into_inner() {
            let lens = v.iter().map(|s| s.len()).collect::<Vec<_>>();
            assert_eq!(lens, vec![5000]);
        } else {
            assert_eq!(1, 2);
        }

        if let RpcMessage::Cidr(Some(v)) = res.remove(0).into_inner() {
            let lens = v.iter().map(|s| s.len()).collect::<Vec<_>>();
            assert_eq!(lens, vec![6000]);
        } else {
            assert_eq!(1, 2);
        }

        if let RpcMessage::Cidr(Some(v)) = res.remove(0).into_inner() {
            let lens = v.iter().map(|s| s.len()).collect::<Vec<_>>();
            assert_eq!(lens, vec![7000]);
        } else {
            assert_eq!(1, 2);
        }

        if let RpcMessage::Cidr(Some(v)) = res.remove(0).into_inner() {
            let lens = v.iter().map(|s| s.len()).collect::<Vec<_>>();
            assert_eq!(lens, vec![8196]);
        } else {
            assert_eq!(1, 2);
        }
    }
}
