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

use public::l7_protocol::{L7Protocol, ProtobufRpcProtocol};
use serde::Serialize;

use crate::{
    common::{
        flow::L7PerfStats,
        l7_protocol_info::L7ProtocolInfo,
        l7_protocol_log::{L7ProtocolParserInterface, ParseParam},
    },
    flow_generator::Result,
};

use super::{all_protobuf_rpc_parser, ProtobufRpcLog};

// this is the wrap for ProtobufRpcLog
#[derive(Default, Debug, Serialize)]
pub struct ProtobufRpcWrapLog {
    parser: Option<ProtobufRpcLog>,
}

impl ProtobufRpcWrapLog {
    pub(crate) fn set_rpc_parser(&mut self, parser: ProtobufRpcLog) {
        self.parser = Some(parser);
    }
}

impl L7ProtocolParserInterface for ProtobufRpcWrapLog {
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
        L7Protocol::ProtobufRPC
    }

    fn protobuf_rpc_protocol(&self) -> Option<ProtobufRpcProtocol> {
        self.parser.as_ref().unwrap().protobuf_rpc_protocol()
    }

    fn reset(&mut self) {
        if let Some(p) = self.parser.as_mut() {
            p.reset();
        }
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }

    fn parse_default(&self) -> bool {
        false
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.parser.as_mut().and_then(|p| p.perf_stats())
    }
}
