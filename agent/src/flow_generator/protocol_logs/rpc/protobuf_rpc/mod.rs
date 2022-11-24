mod krpc;
mod protobuf_rpc;

pub use protobuf_rpc::*;

use enum_dispatch::enum_dispatch;
use public::l7_protocol::L7Protocol;
use serde::Serialize;

use crate::{
    common::{
        flow::FlowPerfStats,
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ProtocolParser, L7ProtocolParserInterface, ParseParam},
        MetaPacket,
    },
    config::handler::LogParserAccess,
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

pub fn get_protobuf_rpc_parser(proto: L7Protocol) -> L7ProtocolParser {
    let mut p = ProtobufRpcParser::default();
    match proto {
        L7Protocol::Krpc => p.set_rpc_parser(ProtobufRpcLog::KrpcLog(KrpcLog::default())),
        _ => unreachable!(),
    }
    L7ProtocolParser::ProtobufRpcParser(p)
}

// all protobuf rpc parser
#[derive(Debug, Clone, Serialize)]
#[enum_dispatch(L7ProtocolParserInterface, L7FlowPerf)]
pub(crate) enum ProtobufRpcLog {
    KrpcLog(KrpcLog),
}

fn all_protobuf_rpc_parser() -> Vec<ProtobufRpcLog> {
    vec![ProtobufRpcLog::KrpcLog(KrpcLog::default())]
}
