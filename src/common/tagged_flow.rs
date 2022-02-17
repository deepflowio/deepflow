use std::fmt;

use super::flow::Flow;
use super::tag::Tag;

#[derive(Default)]
pub struct TaggedFlow {
    flow: Flow,
    tag: Tag,
}

impl TaggedFlow {
    pub fn sequential_merge(&mut self, other: &TaggedFlow) {
        self.flow.sequential_merge(&other.flow);
    }
    pub fn reverse(&mut self) {
        self.flow.reverse();
        self.tag.reverse();
    }
}

impl fmt::Display for TaggedFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "flow:{}\n\t tag:{:?}", self.flow, self.tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::flow::FlowPerfStats;

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
}
