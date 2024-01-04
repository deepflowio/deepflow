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
use public::sender::{SendMessageType, Sendable};
use std::fmt::{Debug, Formatter};

pub struct BoxedProcEvents();

impl Debug for BoxedProcEvents {
    fn fmt(&self, _: &mut Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
}

impl Sendable for BoxedProcEvents {
    fn encode(self, _: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        Ok(0)
    }

    fn message_type(&self) -> SendMessageType {
        SendMessageType::ProcEvents
    }
}
