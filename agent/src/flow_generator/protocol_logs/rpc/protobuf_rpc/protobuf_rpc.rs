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

use public::l7_protocol::L7Protocol;
use serde::Serialize;

use crate::{
    common::{
        flow::FlowPerfStats,
        l7_protocol_info::L7ProtocolInfo,
        l7_protocol_log::{L7ProtocolParserInterface, ParseParam},
        MetaPacket,
    },
    flow_generator::{perf::L7FlowPerf, AppProtoHead, Error, Result},
};

use super::{all_protobuf_rpc_parser, ProtobufRpcLog};

// this is the wrap for ProtobufRpcLog
#[derive(Default, Debug, Clone, Serialize)]
pub struct ProtobufRpcParser {
    parser: Option<ProtobufRpcLog>,
}

impl ProtobufRpcParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn set_rpc_parser(&mut self, parser: ProtobufRpcLog) {
        self.parser = Some(parser);
    }
}

impl L7ProtocolParserInterface for ProtobufRpcParser {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        for mut p in all_protobuf_rpc_parser().into_iter() {
            if p.check_payload(payload, param) {
                self.parser = Some(p);
                return true;
            }
        }
        false
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<Vec<L7ProtocolInfo>> {
        self.parser.as_mut().unwrap().parse_payload(payload, param)
    }

    fn protocol(&self) -> L7Protocol {
        if let Some(p) = self.parser.as_ref() {
            p.protocol()
        } else {
            L7Protocol::ProtobufRPC
        }
    }

    fn reset(&mut self) {
        self.parser.as_mut().unwrap().reset();
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }
}

impl L7FlowPerf for ProtobufRpcParser {
    fn parse(&mut self, packet: &MetaPacket, flow_id: u64) -> Result<()> {
        if self.parser.is_none() {
            if let Some(payload) = packet.get_l4_payload() {
                for mut p in all_protobuf_rpc_parser().into_iter() {
                    if p.parse_payload(payload, &ParseParam::from(packet)).is_ok() {
                        self.parser = Some(p);
                        return Ok(());
                    }
                }
                return Err(Error::L7ProtocolUnknown);
            } else {
                return Err(Error::L7ProtocolUnknown);
            }
        } else {
            self.parser.as_mut().unwrap().parse(packet, flow_id)
        }
    }

    fn data_updated(&self) -> bool {
        return self.parser.as_ref().unwrap().data_updated();
    }

    fn copy_and_reset_data(&mut self, l7_timeout_count: u32) -> FlowPerfStats {
        self.parser
            .as_mut()
            .unwrap()
            .copy_and_reset_data(l7_timeout_count)
    }

    fn app_proto_head(&mut self) -> Option<(AppProtoHead, u16)> {
        self.parser.as_mut().unwrap().app_proto_head()
    }
}
