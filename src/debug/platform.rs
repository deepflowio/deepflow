use std::sync::Arc;

use bincode::{Decode, Encode};

use crate::platform::{ApiWatcher, GenericPoller, Poller};

#[derive(PartialEq, Eq, Debug, Encode, Decode)]
pub enum PlatformMessage {
    Version(Option<String>),
    Watcher(String),
    MacMappings(Option<Vec<(u32, String)>>),
    Fin,
    NotFound,
}

pub struct PlatformDebugger {
    api: Arc<ApiWatcher>,
    poller: Arc<GenericPoller>,
}

impl PlatformDebugger {
    pub(super) fn new(api: Arc<ApiWatcher>, poller: Arc<GenericPoller>) -> Self {
        Self { api, poller }
    }

    pub(super) fn watcher(&self, resource: impl AsRef<str>) -> Vec<PlatformMessage> {
        // entries 字节可能会大于MAX_MESSAGE_SIZE,要分开发送
        let entries = self.api.get_watcher_entries(resource);
        match entries {
            Some(es) => {
                let mut res = es
                    .into_iter()
                    .map(|s| PlatformMessage::Watcher(s))
                    .collect::<Vec<_>>();
                res.push(PlatformMessage::Fin);
                res
            }
            None => vec![PlatformMessage::NotFound],
        }
    }

    pub(super) fn api_version(&self) -> Vec<PlatformMessage> {
        let v = self.api.get_server_version();
        vec![PlatformMessage::Version(v), PlatformMessage::Fin]
    }

    pub(super) fn mac_mapping(&self) -> Vec<PlatformMessage> {
        let mapping = self.poller.get_interface_info().map(|infos| {
            let mut entries = infos
                .into_iter()
                .map(|i| (i.tap_idx, i.mac.to_string()))
                .collect::<Vec<_>>();
            entries.sort();
            entries
        });
        match mapping {
            Some(m) => {
                let res = vec![PlatformMessage::MacMappings(Some(m)), PlatformMessage::Fin];
                res
            }
            None => vec![PlatformMessage::NotFound],
        }
    }
}
