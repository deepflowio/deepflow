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

mod krpc;
mod protobuf_rpc;

use self::krpc::KrpcLog;
pub use protobuf_rpc::*;

use enum_dispatch::enum_dispatch;
use serde::Serialize;

use crate::{
    common::{
        flow::FlowPerfStats,
        l7_protocol_log::{L7ProtocolParser, L7ProtocolParserInterface, ParseParam},
        MetaPacket,
    },
    config::handler::LogParserAccess,
    flow_generator::{
        perf::L7FlowPerf, protocol_logs::L7ProtocolInfoInterface, AppProtoHead, Result,
    },
};

use public::common::l7_protocol::{L7Protocol, L7ProtocolEnum, ProtobufRpcProtocol};
use public::protocol_logs::l7_protocol_info::L7ProtocolInfo;
use public::protocol_logs::ProtobufRpcInfo;

impl L7ProtocolInfoInterface for ProtobufRpcInfo {
    fn session_id(&self) -> Option<u32> {
        match self {
            ProtobufRpcInfo::KrpcInfo(info) => info.session_id(),
        }
    }

    fn merge_log(&mut self, other: L7ProtocolInfo) -> Result<()> {
        match self {
            ProtobufRpcInfo::KrpcInfo(info) => info.merge_log(other),
        }
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        match self {
            ProtobufRpcInfo::KrpcInfo(info) => info.app_proto_head(),
        }
    }

    fn is_req_resp_end(&self) -> (bool, bool) {
        match self {
            ProtobufRpcInfo::KrpcInfo(info) => info.is_req_resp_end(),
        }
    }
    fn is_tls(&self) -> bool {
        match self {
            ProtobufRpcInfo::KrpcInfo(info) => info.is_tls(),
        }
    }

    fn need_merge(&self) -> bool {
        match self {
            ProtobufRpcInfo::KrpcInfo(info) => info.need_merge(),
        }
    }

    fn skip_send(&self) -> bool {
        match self {
            ProtobufRpcInfo::KrpcInfo(info) => info.skip_send(),
        }
    }
}

pub fn get_protobuf_rpc_parser(proto: ProtobufRpcProtocol) -> L7ProtocolParser {
    let mut p = ProtobufRpcWrapLog::default();
    match proto {
        ProtobufRpcProtocol::Krpc => p.set_rpc_parser(ProtobufRpcLog::KrpcLog(KrpcLog::default())),
    }
    L7ProtocolParser::ProtobufRpcParser(p)
}
// all protobuf rpc parser
#[derive(Debug, Clone, Serialize)]
#[enum_dispatch(L7ProtocolParserInterface, L7FlowPerf)]
pub enum ProtobufRpcLog {
    KrpcLog(KrpcLog),
}

fn all_protobuf_rpc_parser() -> Vec<ProtobufRpcLog> {
    vec![ProtobufRpcLog::KrpcLog(KrpcLog::default())]
}
