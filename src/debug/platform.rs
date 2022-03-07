use std::mem;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{
    platform::{ApiWatcher, GenericPoller, Poller},
    utils::net::MacAddr,
};

use super::{chunk_string_payload, Message, Module, MAX_MESSAGE_SIZE};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum PlatformMessage {
    Version(Option<String>),
    WatcherReq(String),
    WatcherRes(Option<Vec<String>>),
    MacMappings(Option<Vec<(u32, MacAddr)>>),
    Fin,
}

pub struct PlatformDebugger {
    api: Arc<ApiWatcher>,
    poller: Arc<GenericPoller>,
}

impl PlatformDebugger {
    pub(super) fn new(api: Arc<ApiWatcher>, poller: Arc<GenericPoller>) -> Self {
        Self { api, poller }
    }

    pub(super) fn watcher(&self, resource: impl AsRef<str>) -> Vec<Message<PlatformMessage>> {
        // entries 字节可能会大于MAX_MESSAGE_SIZE,要分开发送
        let entries = self.api.get_watcher_entries(resource);
        match entries {
            Some(es) => {
                fn truncate_fn(res: &mut Vec<Message<PlatformMessage>>, s: String) {
                    res.push(Message {
                        module: Module::Platform,
                        msg: PlatformMessage::WatcherRes(Some(vec![s])),
                    });
                }

                fn push_fn(
                    res: &mut Vec<Message<PlatformMessage>>,
                    cache: &mut Option<Vec<String>>,
                ) {
                    res.push(Message {
                        module: Module::Platform,
                        msg: PlatformMessage::WatcherRes(cache.take()),
                    });
                }

                let mut res = chunk_string_payload(es, truncate_fn, push_fn);

                res.push(Message {
                    module: Module::Platform,
                    msg: PlatformMessage::Fin,
                });
                res
            }
            None => vec![Message {
                module: Module::Platform,
                msg: PlatformMessage::Fin,
            }],
        }
    }

    pub(super) fn api_version(&self) -> Vec<Message<PlatformMessage>> {
        let v = self.api.get_server_version();
        vec![
            Message {
                module: Module::Platform,
                msg: PlatformMessage::Version(v),
            },
            Message {
                module: Module::Platform,
                msg: PlatformMessage::Fin,
            },
        ]
    }

    pub(super) fn mac_mapping(&self) -> Vec<Message<PlatformMessage>> {
        let mapping = self.poller.get_interface_info().map(|infos| {
            let mut entries = infos
                .into_iter()
                .map(|i| (i.tap_idx, i.mac))
                .collect::<Vec<_>>();
            entries.sort();
            entries
        });

        match mapping {
            Some(m) => {
                let size = mem::size_of::<(u32, MacAddr)>();
                let len = m.len();
                let c = ((size * len) as f64 / MAX_MESSAGE_SIZE as f64).ceil() as usize;
                let chunk_len = len / c;
                let mut res = vec![];
                for chunk in m.chunks(chunk_len) {
                    res.push(Message {
                        module: Module::Platform,
                        msg: PlatformMessage::MacMappings(Some(chunk.to_vec())),
                    });
                }
                res.push(Message {
                    module: Module::Platform,
                    msg: PlatformMessage::Fin,
                });
                res
            }
            None => vec![Message {
                module: Module::Platform,
                msg: PlatformMessage::Fin,
            }],
        }
    }
}
