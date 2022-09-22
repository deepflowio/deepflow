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

use std::fmt;

use prost::Message;
use serde::Serialize;

use super::flow::Flow;
use super::tag::Tag;

use crate::proto::flow_log;

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

    pub fn encode(self, buf: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        let pb_tagged_flow = flow_log::TaggedFlow {
            flow: Some(self.flow.into()),
        };
        pb_tagged_flow
            .encode(buf)
            .map(|_| pb_tagged_flow.encoded_len())
    }

    pub fn to_kv_string(&self, dst: &mut String) {
        let json = serde_json::to_string(&self).unwrap();
        dst.push_str(&json);
        dst.push('\n');
    }
}

impl fmt::Display for TaggedFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "flow:{}\n\t tag:{:?}", self.flow, self.tag)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use prost::Message;

    use super::*;

    use crate::common::{decapsulate::TunnelType, flow::FlowPerfStats, flow::L4Protocol};

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
        f1.flow.flow_perf_stats = Some(FlowPerfStats::default());
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
        tflow.flow.start_time = Duration::from_nanos(100_000_000_001);
        let mut flow_perf_stats = FlowPerfStats::default();
        flow_perf_stats.l4_protocol = L4Protocol::Tcp;
        flow_perf_stats.tcp.rtt = 10;
        tflow.flow.flow_perf_stats = Some(flow_perf_stats);
        tflow.flow.is_active_service = true;

        let mut buf: Vec<u8> = vec![];
        let encoded_len = tflow.encode(&mut buf).unwrap();
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
