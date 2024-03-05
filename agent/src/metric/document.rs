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

use std::net::{IpAddr, Ipv4Addr};

use bitflags::bitflags;
use num_enum::TryFromPrimitive;
use prost::Message;
use serde::Serialize;

use super::meter::Meter;

use crate::common::{
    enums::{IpProtocol, TapType},
    flow::{L7Protocol, SignalSource},
    tap_port::TapPort,
};
use public::{
    proto::{integration::opentelemetry::proto::trace::v1::span::SpanKind, metric},
    sender::{SendMessageType, Sendable},
    utils::net::MacAddr,
};

const METRICS_VERSION: u32 = 20220117;
#[derive(Debug)]
pub struct Document {
    pub timestamp: u32,
    pub tagger: Tagger,
    pub meter: Meter,
    pub flags: DocumentFlag,
}

impl Document {
    pub fn new(m: Meter) -> Self {
        Document {
            timestamp: 0,
            tagger: Tagger::default(),
            meter: m,
            flags: DocumentFlag::default(),
        }
    }

    pub fn sequential_merge(&mut self, other: &Document) {
        self.meter.sequential_merge(&other.meter)
    }

    pub fn reverse(&mut self) {
        self.meter.reverse()
    }

    pub fn encode(self, buf: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        let pb_doc: metric::Document = self.into();
        pb_doc.encode(buf).map(|_| pb_doc.encoded_len())
    }
}

impl From<Document> for metric::Document {
    fn from(d: Document) -> Self {
        metric::Document {
            timestamp: d.timestamp,
            tag: Some(d.tagger.into()),
            meter: Some(d.meter.into()),
            flags: d.flags.bits(),
        }
    }
}

#[derive(Debug)]
pub struct BoxedDocument(pub Box<Document>);

impl Sendable for BoxedDocument {
    fn encode(self, buf: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        let pb_doc: metric::Document = (*self.0).into();
        pb_doc.encode(buf).map(|_| pb_doc.encoded_len())
    }

    fn message_type(&self) -> SendMessageType {
        SendMessageType::Metrics
    }

    fn version(&self) -> u32 {
        METRICS_VERSION
    }
}

bitflags! {
    pub struct DocumentFlag: u32 {
        const NONE = 0; // PER_MINUTE_METRICS
        const PER_SECOND_METRICS = 1<<0;
   }
}

impl Default for DocumentFlag {
    fn default() -> Self {
        DocumentFlag::NONE
    }
}

bitflags! {
    pub struct Code:u64 {
        const NONE = 0;

        const IP = 1<<0;
        const L3_EPC_ID = 1<<1;
        const MAC = 1<<11;
        const GPID = 1<<15;

        const IP_PATH = 1<<20;
        const L3_EPC_PATH = 1<<21;
        const MAC_PATH = 1<<31;
        const GPID_PATH = 1<<35;

        const DIRECTION = 1<<40;
        const ACL_GID = 1<<41;
        const PROTOCOL = 1<<42;
        const SERVER_PORT = 1<<43;
        const TAP_TYPE = 1<<45;
        const VTAP_ID = 1<<47;
        const TAP_SIDE = 1<<48;
        const TAP_PORT = 1<<49;
        const L7_PROTOCOL = 1<<51;

        const TUNNEL_IP_ID = 1<<62;
    }
}

impl Code {
    pub fn has_edge_tag(&self) -> bool {
        self.bits() & 0xfffff00000 != 0
    }
}

impl Default for Code {
    fn default() -> Self {
        Code::NONE
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    None,
    ClientToServer = 1 << 0,
    ServerToClient = 1 << 1,
    LocalToLocal = 1 << 2,

    // The following types are added for converting TapSide
    ClientNodeToServer = Direction::ClientToServer as u8 | SIDE_NODE, // client container node, route、SNAT、tunnel
    ServerNodeToClient = Direction::ServerToClient as u8 | SIDE_NODE, // server container node, route、SNAT、tunnel
    ClientHypervisorToServer = Direction::ClientToServer as u8 | SIDE_HYPERVISOR, // client hypervisor, tunnel
    ServerHypervisorToClient = Direction::ServerToClient as u8 | SIDE_HYPERVISOR, // server hypervisor, tunnel
    ClientGatewayHypervisorToServer = Direction::ClientToServer as u8 | SIDE_GATEWAY_HYPERVISOR, // client gateway hypervisor
    ServerGatewayHypervisorToClient = Direction::ServerToClient as u8 | SIDE_GATEWAY_HYPERVISOR, // server gateway hypervisor
    ClientGatewayToServer = Direction::ClientToServer as u8 | SIDE_GATEWAY, // client gateway(In particular, SLB of VIP mechanism, such as Microsoft Cloud MUX, etc.), the interface corresponding to Mac address is vip device
    ServerGatewayToClient = Direction::ServerToClient as u8 | SIDE_GATEWAY, // server gateway(In particular, SLB of VIP mechanism, such as Microsoft Cloud MUX, etc.), the interface corresponding to Mac address is vip device
    ClientProcessToServer = Direction::ClientToServer as u8 | SIDE_PROCESS, // client process
    ServerProcessToClient = Direction::ServerToClient as u8 | SIDE_PROCESS, // server process
    ClientAppToServer = Direction::ClientToServer as u8 | SIDE_APP,         // client app(for otel)
    ServerAppToClient = Direction::ServerToClient as u8 | SIDE_APP,         // server app(for otel)
    App = SIDE_APP,                                                         // app(for otel)
}

impl Default for Direction {
    fn default() -> Self {
        Direction::ClientToServer
    }
}

const SIDE_NODE: u8 = 1 << 3;
const SIDE_HYPERVISOR: u8 = 2 << 3;
const SIDE_GATEWAY_HYPERVISOR: u8 = 3 << 3;
const SIDE_GATEWAY: u8 = 4 << 3;
const SIDE_PROCESS: u8 = 5 << 3;
const SIDE_APP: u8 = 6 << 3;

const MASK_CLIENT_SERVER: u8 = 0x7;
const MASK_SIDE: u8 = 0xf8;

impl Direction {
    pub fn is_client_to_server(self) -> bool {
        self as u8 & MASK_CLIENT_SERVER == Direction::ClientToServer as u8
    }

    pub fn is_server_to_client(self) -> bool {
        self as u8 & MASK_CLIENT_SERVER == Direction::ServerToClient as u8
    }

    pub fn is_gateway(self) -> bool {
        (self as u8 & MASK_SIDE) & (SIDE_GATEWAY | SIDE_GATEWAY_HYPERVISOR) != 0
    }
}

#[derive(Serialize, Debug, PartialEq, Eq, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum TapSide {
    Rest = 0,
    Client = 1 << 0,
    Server = 1 << 1,
    Local = 1 << 2,
    ClientNode = TapSide::Client as u8 | SIDE_NODE,
    ServerNode = TapSide::Server as u8 | SIDE_NODE,
    ClientHypervisor = TapSide::Client as u8 | SIDE_HYPERVISOR,
    ServerHypervisor = TapSide::Server as u8 | SIDE_HYPERVISOR,
    ClientGatewayHypervisor = TapSide::Client as u8 | SIDE_GATEWAY_HYPERVISOR,
    ServerGatewayHypervisor = TapSide::Server as u8 | SIDE_GATEWAY_HYPERVISOR,
    ClientGateway = TapSide::Client as u8 | SIDE_GATEWAY,
    ServerGateway = TapSide::Server as u8 | SIDE_GATEWAY,
    ClientProcess = TapSide::Client as u8 | SIDE_PROCESS,
    ServerProcess = TapSide::Server as u8 | SIDE_PROCESS,
    ClientApp = TapSide::Client as u8 | SIDE_APP,
    ServerApp = TapSide::Server as u8 | SIDE_APP,
    App = SIDE_APP,
}

impl TapSide {
    pub const MAX: Self = Self::ServerApp;
}

impl Default for TapSide {
    fn default() -> Self {
        TapSide::Rest
    }
}

impl From<Direction> for TapSide {
    fn from(direction: Direction) -> Self {
        match direction {
            Direction::ClientToServer => TapSide::Client,
            Direction::ServerToClient => TapSide::Server,
            Direction::LocalToLocal => TapSide::Local,
            Direction::ClientNodeToServer => TapSide::ClientNode,
            Direction::ServerNodeToClient => TapSide::ServerNode,
            Direction::ClientHypervisorToServer => TapSide::ClientHypervisor,
            Direction::ServerHypervisorToClient => TapSide::ServerHypervisor,
            Direction::ClientGatewayHypervisorToServer => TapSide::ClientGatewayHypervisor,
            Direction::ServerGatewayHypervisorToClient => TapSide::ServerGatewayHypervisor,
            Direction::ClientGatewayToServer => TapSide::ClientGateway,
            Direction::ServerGatewayToClient => TapSide::ServerGateway,
            Direction::ClientProcessToServer => TapSide::ClientProcess,
            Direction::ServerProcessToClient => TapSide::ServerProcess,
            Direction::ClientAppToServer => TapSide::ClientApp,
            Direction::ServerAppToClient => TapSide::ServerApp,
            Direction::App => TapSide::App,
            Direction::None => TapSide::Rest,
        }
    }
}

// According to https://github.com/open-telemetry/opentelemetry-proto/blob/main/opentelemetry/proto/trace/v1/trace.proto#L121
impl From<SpanKind> for TapSide {
    fn from(span_kind: SpanKind) -> Self {
        match span_kind {
            SpanKind::Client | SpanKind::Producer => TapSide::ClientApp,
            SpanKind::Server | SpanKind::Consumer => TapSide::ServerApp,
            _ => TapSide::App,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Tagger {
    pub code: Code,

    pub ip: IpAddr,
    pub ip1: IpAddr,

    // 用于区分不同的agent及其不同的pipeline，用于如下场景：
    //   - 和ingester之间的数据传输
    //   - 写入数据库，作用类似_id，序列化为_tid
    pub global_thread_id: u8,
    pub is_ipv6: bool,
    pub l3_epc_id: i16,
    pub l3_epc_id1: i16,
    pub mac: MacAddr,
    pub mac1: MacAddr,

    pub direction: Direction,
    pub tap_side: TapSide,
    pub protocol: IpProtocol,
    pub acl_gid: u16,
    pub server_port: u16, // tunnel_ip_id also uses this field
    pub vtap_id: u16,
    pub tap_port: TapPort,
    pub tap_type: TapType,
    pub l7_protocol: L7Protocol,

    pub gpid: u32,
    pub gpid_1: u32,

    pub otel_service: Option<String>,
    pub otel_instance: Option<String>,
    pub endpoint: Option<String>,
    pub biz_type: u8,
    pub signal_source: SignalSource,
    pub pod_id: u32,
}

impl Default for Tagger {
    fn default() -> Self {
        Tagger {
            code: Code::default(),
            ip: Ipv4Addr::UNSPECIFIED.into(),
            ip1: Ipv4Addr::UNSPECIFIED.into(),

            global_thread_id: 0,
            is_ipv6: false,
            l3_epc_id: -2,
            l3_epc_id1: -2,
            mac: MacAddr::default(),
            mac1: MacAddr::default(),
            direction: Direction::default(),
            tap_side: TapSide::default(),
            protocol: IpProtocol::default(),
            acl_gid: 0,
            server_port: 0,
            vtap_id: 0,
            tap_port: TapPort::default(),
            tap_type: TapType::default(),
            l7_protocol: L7Protocol::default(),

            gpid: 0,
            gpid_1: 0,

            otel_service: None,
            otel_instance: None,
            endpoint: None,
            signal_source: SignalSource::default(),
            pod_id: 0,
            biz_type: 0,
        }
    }
}

impl From<Tagger> for metric::MiniTag {
    fn from(t: Tagger) -> Self {
        let (ip_vec, ip1_vec) = if t.code.has_edge_tag() {
            match (t.ip, t.ip1) {
                (IpAddr::V4(ip4), IpAddr::V4(ip41)) => {
                    (ip4.octets().to_vec(), ip41.octets().to_vec())
                }
                (IpAddr::V6(ip6), IpAddr::V6(ip61)) => {
                    (ip6.octets().to_vec(), ip61.octets().to_vec())
                }
                _ => panic!("{:?} ip, ip1 type mismatch", &t),
            }
        } else {
            match t.ip {
                IpAddr::V4(ip4) => (ip4.octets().to_vec(), vec![]),
                IpAddr::V6(ip6) => (ip6.octets().to_vec(), vec![]),
            }
        };

        let mut code = t.code;
        if code.contains(Code::DIRECTION) && code.has_edge_tag() {
            code.remove(Code::DIRECTION);
            code.insert(Code::TAP_SIDE);
        }
        metric::MiniTag {
            code: code.bits(),
            field: Some(metric::MiniField {
                ip: ip_vec,
                ip1: ip1_vec,
                global_thread_id: t.global_thread_id as u32,
                is_ipv6: t.is_ipv6 as u32,
                l3_epc_id: t.l3_epc_id as i32,
                l3_epc_id1: t.l3_epc_id1 as i32,
                mac: t.mac.into(),
                mac1: t.mac1.into(),
                direction: t.direction as u32,
                tap_side: TapSide::from(t.direction) as u32,
                protocol: u8::from(t.protocol) as u32,
                acl_gid: t.acl_gid as u32,
                server_port: t.server_port as u32,
                vtap_id: t.vtap_id as u32,
                tap_port: t.tap_port.0,
                tap_type: u16::from(t.tap_type) as u32,
                l7_protocol: t.l7_protocol as u32,
                gpid: t.gpid,
                gpid1: t.gpid_1,
                signal_source: t.signal_source as u32,
                app_service: t.otel_service.unwrap_or_default(),
                app_instance: t.otel_instance.unwrap_or_default(),
                endpoint: t.endpoint.unwrap_or_default(),
                pod_id: t.pod_id,
                biz_type: t.biz_type as u32,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn merge_reverse() {
        let mut doc1 = Document::new(Meter::new_flow());
        let mut doc2 = Document::new(Meter::new_flow());
        if let Meter::Flow(ref mut f1) = doc1.meter {
            f1.traffic.packet_tx = 1;
        }
        if let Meter::Flow(ref mut f2) = doc2.meter {
            f2.traffic.packet_tx = 2;
        }
        doc1.sequential_merge(&doc2);
        if let Meter::Flow(ref f1) = doc1.meter {
            assert!(f1.traffic.packet_tx == 3)
        }
        doc1.reverse();
        if let Meter::Flow(ref f1) = doc1.meter {
            assert!(f1.traffic.packet_rx == 3)
        }
    }

    #[test]
    fn encode() {
        let mut doc = Document::new(Meter::new_flow());
        doc.tagger.code = Code::IP | Code::L3_EPC_ID;
        doc.tagger.l3_epc_id = 10;
        doc.timestamp = 100;
        doc.flags = DocumentFlag::PER_SECOND_METRICS;
        if let Meter::Flow(ref mut f) = doc.meter {
            f.traffic.packet_tx = 1;
        }

        let mut buf: Vec<u8> = vec![];
        let encode_len = doc.encode(&mut buf).unwrap();

        let rlt: Result<metric::Document, prost::DecodeError> =
            Message::decode(buf.as_slice().get(..encode_len).unwrap());
        let pb_doc = rlt.unwrap();

        assert_eq!(pb_doc.timestamp, 100);
        assert_eq!(pb_doc.flags, 1);
        assert_eq!(pb_doc.tag.as_ref().unwrap().code, 3);
        assert_eq!(pb_doc.tag.unwrap().field.unwrap().l3_epc_id, 10);
    }

    #[test]
    fn ensure_max_tap_side() {
        let max_tap_side = TapSide::MAX;
        for i in 0..=255 {
            if let Ok(ts) = TapSide::try_from(i) {
                assert!(
                    ts as u8 <= max_tap_side as u8,
                    "value of {:?} is larger than TapSide::MAX {:?}",
                    ts,
                    max_tap_side
                );
            }
        }
    }
}
