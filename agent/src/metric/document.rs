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

use std::net::{IpAddr, Ipv4Addr};

use bitflags::bitflags;

use super::meter::Meter;

use crate::common::{
    enums::{IpProtocol, TapType},
    tap_port::TapPort,
};
use public::common::enums::{Direction, TapSide};
use public::common::l7_protocol::L7Protocol;
use public::proto::metric;
use public::utils::net::MacAddr;

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

        const IP_PATH = 1<<20;
        const L3_EPC_PATH = 1<<21;
        const MAC_PATH = 1<<31;

        const DIRECTION = 1<<40;
        const ACL_GID = 1<<41;
        const PROTOCOL = 1<<42;
        const SERVER_PORT = 1<<43;
        const TAP_TYPE = 1<<45;
        const VTAP_ID = 1<<47;
        const TAP_SIDE = 1<<48;
        const TAP_PORT = 1<<49;
        const L7_PROTOCOL = 1<<51;

        const TAG_TYPE = 1<<62;
        const TAG_VALUE = 1<<63;
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

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum TagType {
    TunnelIpId = 4,
}

impl Default for TagType {
    fn default() -> Self {
        TagType::TunnelIpId
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
    pub server_port: u16,
    pub vtap_id: u16,
    pub tap_port: TapPort,
    pub tap_type: TapType,
    pub l7_protocol: L7Protocol,

    pub tag_type: TagType,
    pub tag_value: u16,
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

            tag_type: TagType::default(),
            tag_value: 0,
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
                _ => panic!("ip, ip1 type mismatch"),
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
                mac1: t.mac.into(),
                direction: t.direction as u32,
                tap_side: TapSide::from(t.direction) as u32,
                protocol: t.protocol as u32,
                acl_gid: t.acl_gid as u32,
                server_port: t.server_port as u32,
                vtap_id: t.vtap_id as u32,
                tap_port: t.tap_port.0,
                tap_type: u16::from(t.tap_type) as u32,
                l7_protocol: t.l7_protocol as u32,
                tag_type: t.tag_type as u32,
                tag_value: t.tag_value as u32,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use public::proto::metric::Document as PbDocument;

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
        let pb_doc: PbDocument = doc.into();
        let _ = pb_doc.encode(&mut buf).unwrap();
        let encode_len = pb_doc.encoded_len();

        let rlt: Result<metric::Document, prost::DecodeError> =
            Message::decode(buf.as_slice().get(..encode_len).unwrap());
        let pb_doc = rlt.unwrap();

        assert_eq!(pb_doc.timestamp, 100);
        assert_eq!(pb_doc.flags, 1);
        assert_eq!(pb_doc.tag.as_ref().unwrap().code, 3);
        assert_eq!(pb_doc.tag.unwrap().field.unwrap().l3_epc_id, 10);
    }
}
