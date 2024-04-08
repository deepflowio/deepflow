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

use public::{
    proto::k8s_event::KubernetesEvent,
    sender::{SendMessageType, Sendable},
};

use prost::Message;

#[derive(Debug, Default, Clone)]
pub struct BoxedKubernetesEvent(pub Box<KubernetesEvent>);

impl Sendable for BoxedKubernetesEvent {
    fn encode(self, buf: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        self.0.encode(buf).map(|_| self.0.encoded_len())
    }

    fn message_type(&self) -> SendMessageType {
        SendMessageType::KubernetesEvent
    }
}
