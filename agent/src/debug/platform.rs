/*
 * Copyright (c) 2024 Yunshan Networks
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

use std::sync::Arc;

use bincode::{Decode, Encode};

use crate::platform::{ApiWatcher, GenericPoller, Poller};

#[derive(PartialEq, Eq, Debug, Encode, Decode)]
pub enum PlatformMessage {
    Version(Option<String>),
    Watcher(Vec<u8>),
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
        let mut mappings = self
            .poller
            .get_interface_info()
            .into_iter()
            .map(|i| (i.tap_idx, i.mac.to_string()))
            .collect::<Vec<_>>();
        mappings.sort();
        vec![
            PlatformMessage::MacMappings(Some(mappings)),
            PlatformMessage::Fin,
        ]
    }
}
