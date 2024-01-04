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

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

use prost::Message;
use public::sender::{SendMessageType, Sendable};
use serde::Serialize;

use super::flow::Flow;
use super::tag::Tag;
use super::TapPort;

use public::proto::flow_log;

const FLOW_LOG_VERSION: u32 = 20220128;
#[derive(Serialize, Default, Clone, Debug)]
pub struct TaggedFlow {
    #[serde(flatten)]
    pub flow: Flow,
    #[serde(skip)]
    pub tag: Tag,
}

impl TaggedFlow {
    pub fn sequential_merge(&mut self, other: &TaggedFlow) {
        self.flow.sequential_merge(&other.flow);
    }
    pub fn reverse(&mut self) {
        self.flow.reverse(false);
        self.tag.reverse();
    }

    // return ClientAddr, RealAddr
    pub fn get_toa_info(&self) -> Option<(SocketAddr, SocketAddr)> {
        if self.flow.flow_key.tap_port.get_nat_source() != TapPort::NAT_SOURCE_TOA {
            return None;
        }
        match (
            self.flow.flow_key.ip_src,
            self.flow.flow_metrics_peers[0].nat_real_ip,
        ) {
            // now support ipv4 only
            (IpAddr::V4(v4_src), IpAddr::V4(v4_real)) => {
                if v4_real == Ipv4Addr::UNSPECIFIED {
                    None
                } else {
                    Some((
                        SocketAddr::V4(SocketAddrV4::new(v4_src, self.flow.flow_key.port_src)),
                        SocketAddr::V4(SocketAddrV4::new(
                            v4_real,
                            self.flow.flow_metrics_peers[0].nat_real_port,
                        )),
                    ))
                }
            }
            _ => None,
        }
    }
}

impl fmt::Display for TaggedFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "flow:{}\n\t tag:{:?}", self.flow, self.tag)
    }
}

#[derive(Debug)]
pub struct BoxedTaggedFlow(pub Box<TaggedFlow>);

impl Sendable for BoxedTaggedFlow {
    fn encode(self, buf: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        let pb_tagged_flow = flow_log::TaggedFlow {
            flow: Some(self.0.flow.into()),
        };
        pb_tagged_flow
            .encode(buf)
            .map(|_| pb_tagged_flow.encoded_len())
    }

    fn to_kv_string(&self, dst: &mut String) {
        let json = serde_json::to_string(&(*self.0)).unwrap();
        dst.push_str(&json);
        dst.push('\n');
    }

    fn file_name(&self) -> &str {
        "l4_flow_log"
    }

    fn message_type(&self) -> SendMessageType {
        SendMessageType::TaggedFlow
    }

    fn version(&self) -> u32 {
        FLOW_LOG_VERSION
    }
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::*;

    use crate::common::{
        decapsulate::TunnelType, flow::FlowPerfStats, flow::L4Protocol, Timestamp,
    };

    // test run: cargo test --package trident --lib -- common::tagged_flow::tests::sequential_merge --exact --nocapture
    #[test]
    fn sequential_merge() {
        let mut f = TaggedFlow::default();
        let mut f1 = TaggedFlow::default();
        f.flow.last_keepalive_seq = 10;
        f.flow.last_keepalive_ack = 11;
        f1.flow.last_keepalive_seq = 0;
        f1.flow.last_keepalive_ack = 21;
        f.flow.flow_metrics_peers[0].byte_count = 10;
        f1.flow.flow_metrics_peers[0].byte_count = 20;
        f.flow.flow_metrics_peers[1].l3_byte_count = 30;
        f1.flow.flow_metrics_peers[1].l3_byte_count = 40;
        f1.flow.flow_perf_stats = Some(Default::default());
        f1.flow.flow_perf_stats.as_mut().unwrap().tcp.rtt_client_max = 100;

        f.sequential_merge(&f1);
        assert_eq!(f.flow.last_keepalive_seq, 10);
        assert_eq!(f.flow.last_keepalive_ack, 21);
        assert_eq!(f.flow.flow_metrics_peers[0].byte_count, 30);
        assert_eq!(f.flow.flow_metrics_peers[1].l3_byte_count, 70);
        assert_eq!(
            f.flow.flow_perf_stats.as_ref().unwrap().tcp.rtt_client_max,
            100
        );
    }

    #[test]
    fn reverse() {
        let mut f = TaggedFlow::default();
        f.flow.tunnel.tx_id = 1;
        f.flow.tunnel.rx_id = 2;
        f.flow.flow_metrics_peers[0].l4_byte_count = 100;
        f.flow.flow_metrics_peers[1].l4_byte_count = 200;
        f.reverse();
        assert_eq!(f.flow.tunnel.tx_id, 2);
        assert_eq!(f.flow.flow_metrics_peers[0].l4_byte_count, 200);
    }

    #[test]
    fn encode() {
        let mut tflow = TaggedFlow::default();
        tflow.flow.flow_key.vtap_id = 5;
        tflow.flow.flow_metrics_peers[1].byte_count = 6;
        tflow.flow.tunnel.tunnel_type = TunnelType::Vxlan;
        tflow.flow.flow_id = 8;
        tflow.flow.start_time = Timestamp::from_nanos(100_000_000_001);
        let mut flow_perf_stats = FlowPerfStats::default();
        flow_perf_stats.l4_protocol = L4Protocol::Tcp;
        flow_perf_stats.tcp.rtt = 10;
        tflow.flow.flow_perf_stats = Some(flow_perf_stats);
        tflow.flow.is_active_service = true;

        let mut buf: Vec<u8> = vec![];
        let boxflow = BoxedTaggedFlow(Box::new(tflow));
        let encoded_len = boxflow.encode(&mut buf).unwrap();
        let rlt: Result<flow_log::TaggedFlow, prost::DecodeError> =
            Message::decode(buf.as_slice().get(..encoded_len).unwrap());

        let pb_flow = rlt.unwrap().flow.unwrap();
        assert_eq!(pb_flow.flow_key.unwrap().vtap_id, 5);
        assert_eq!(pb_flow.metrics_peer_dst.unwrap().byte_count, 6);
        assert_eq!(pb_flow.tunnel.unwrap().tunnel_type, 1);
        assert_eq!(pb_flow.flow_id, 8);
        assert_eq!(pb_flow.start_time, 100_000_000_001);
        assert_eq!(pb_flow.perf_stats.as_ref().unwrap().l4_protocol, 1);
        assert_eq!(pb_flow.is_active_service, 1);
        assert_eq!(pb_flow.perf_stats.unwrap().tcp.unwrap().rtt, 10);
    }
}
