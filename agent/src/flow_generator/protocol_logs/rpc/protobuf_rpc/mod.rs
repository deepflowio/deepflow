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

pub use protobuf_rpc::*;

use enum_dispatch::enum_dispatch;
use public::l7_protocol::{L7Protocol, L7ProtocolEnum, ProtobufRpcProtocol};
use serde::Serialize;

use crate::{
    common::{
        flow::FlowPerfStats,
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ProtocolParser, L7ProtocolParserInterface, ParseParam},
        MetaPacket,
    },
    config::handler::LogParserConfig,
    flow_generator::{
        perf::L7FlowPerf, protocol_logs::pb_adapter::L7ProtocolSendLog, AppProtoHead, Result,
    },
};

use self::krpc::{KrpcInfo, KrpcLog};

// all protobuf rpc info
#[derive(Serialize, Clone, Debug)]
#[enum_dispatch(L7ProtocolInfoInterface)]
pub enum ProtobufRpcInfo {
    KrpcInfo(KrpcInfo),
}

impl Into<L7ProtocolSendLog> for ProtobufRpcInfo {
    fn into(self) -> L7ProtocolSendLog {
        match self {
            ProtobufRpcInfo::KrpcInfo(k) => k.into(),
        }
    }
}

pub fn get_protobuf_rpc_parser(proto: ProtobufRpcProtocol) -> L7ProtocolParser {
    let mut p = ProtobufRpcWrapLog::default();
    match proto {
        ProtobufRpcProtocol::Krpc => p.set_rpc_parser(ProtobufRpcLog::KrpcLog(KrpcLog::default())),
    }
    L7ProtocolParser::ProtobufRPC(Box::new(p))
}

// all protobuf rpc parser
#[derive(Debug, Serialize)]
#[enum_dispatch(L7ProtocolParserInterface, L7FlowPerf)]
pub enum ProtobufRpcLog {
    KrpcLog(KrpcLog),
}

fn all_protobuf_rpc_parser() -> Vec<ProtobufRpcLog> {
    vec![ProtobufRpcLog::KrpcLog(KrpcLog::default())]
}
