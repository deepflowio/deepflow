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

use std::{cmp::max, collections::VecDeque};

use pnet::packet::{
    icmp::{IcmpType, IcmpTypes},
    icmpv6::{Icmpv6Type, Icmpv6Types},
};

use crate::{
    common::{
        flow::{FlowPerfStats, L4Protocol},
        meta_packet::{MetaPacket, ProtocolData},
        Timestamp,
    },
    flow_generator::error::{Error, Result},
};

use super::{L4FlowPerf, ART_MAX};

const MAX_CACHE_COUNT: usize = 16;

#[derive(Debug)]
struct LastIcmp {
    timestamp: Timestamp,
    id_and_seq: u32,
}

#[derive(Debug, Default)]
pub struct IcmpPerf {
    srt_max: Timestamp,
    srt_sum: Timestamp,
    srt_count: u32,
    last_requests: VecDeque<LastIcmp>,
    last_replies: VecDeque<LastIcmp>,
    data_update_flag: bool,
}

impl IcmpPerf {
    pub fn new() -> Self {
        IcmpPerf::default()
    }

    fn set_srt(&mut self, srt: Timestamp) {
        if srt <= ART_MAX {
            self.srt_max = max(self.srt_max, srt);
            self.srt_sum += srt;
            self.srt_count += 1;
            self.data_update_flag = true;
        }
    }

    fn reset(&mut self) {
        self.srt_max = Timestamp::default();
        self.srt_sum = Timestamp::default();
        self.srt_count = 0;
        self.data_update_flag = false;
    }
}

impl L4FlowPerf for IcmpPerf {
    fn parse(&mut self, packet: &MetaPacket, _: bool) -> Result<()> {
        if packet.payload_len == 0 {
            return Err(Error::ZeroPayloadLen);
        }
        let icmp_data = if let ProtocolData::IcmpData(icmp_data) = &packet.protocol_data {
            icmp_data
        } else {
            return Err(Error::InvalidIpProtocol);
        };
        let pkt_timestamp = packet.lookup_key.timestamp;
        let (is_request, is_reply) = if packet.lookup_key.is_ipv4() {
            let icmp_type = IcmpType::new(icmp_data.icmp_type);
            (
                icmp_type == IcmpTypes::EchoRequest,
                icmp_type == IcmpTypes::EchoReply,
            )
        } else {
            let icmp_v6_type = Icmpv6Type::new(icmp_data.icmp_type);
            (
                icmp_v6_type == Icmpv6Types::EchoRequest,
                icmp_v6_type == Icmpv6Types::EchoReply,
            )
        };

        if is_request {
            if let Some(i) = self
                .last_replies
                .iter()
                .position(|l| l.id_and_seq == icmp_data.echo_id_seq)
            {
                if pkt_timestamp <= self.last_replies[i].timestamp {
                    let srt = Timestamp::from(self.last_replies[i].timestamp - pkt_timestamp);
                    self.set_srt(srt);
                }
                self.last_replies.remove(i);
            } else {
                if self.last_requests.len() >= MAX_CACHE_COUNT {
                    let _ = self.last_requests.pop_front();
                }
                self.last_requests.push_back(LastIcmp {
                    timestamp: pkt_timestamp,
                    id_and_seq: icmp_data.echo_id_seq,
                });
            }
        } else if is_reply {
            if let Some(i) = self
                .last_requests
                .iter()
                .position(|l| l.id_and_seq == icmp_data.echo_id_seq)
            {
                if pkt_timestamp >= self.last_requests[i].timestamp {
                    let srt = Timestamp::from(pkt_timestamp - self.last_requests[i].timestamp);
                    self.set_srt(srt);
                }
                self.last_requests.remove(i);
            } else {
                if self.last_replies.len() >= MAX_CACHE_COUNT {
                    let _ = self.last_replies.pop_front();
                }
                self.last_replies.push_back(LastIcmp {
                    timestamp: pkt_timestamp,
                    id_and_seq: icmp_data.echo_id_seq,
                });
            }
        }
        Ok(())
    }

    fn data_updated(&self) -> bool {
        self.data_update_flag
    }

    fn copy_and_reset_data(&mut self, _: bool) -> FlowPerfStats {
        for request_index in (0..self.last_requests.len()).rev() {
            let request = &self.last_requests[request_index];
            if let Some(reply_index) = self
                .last_replies
                .iter()
                .position(|reply| request.id_and_seq == reply.id_and_seq)
            {
                let reply = &self.last_replies[reply_index];
                if request.timestamp <= reply.timestamp {
                    let srt = Timestamp::from(reply.timestamp - request.timestamp);
                    if srt <= ART_MAX {
                        self.srt_max = max(self.srt_max, srt);
                        self.srt_sum += srt;
                        self.srt_count += 1;
                        self.data_update_flag = true;
                    }
                }

                self.last_requests.remove(request_index);
                self.last_replies.remove(reply_index);
            }
        }

        let mut stats = FlowPerfStats::default();
        stats.l4_protocol = L4Protocol::Icmp;
        stats.tcp.srt_max = (self.srt_max.as_nanos() / Timestamp::from_micros(1).as_nanos()) as u32;
        stats.tcp.srt_sum = (self.srt_sum.as_nanos() / Timestamp::from_micros(1).as_nanos()) as u32;
        stats.tcp.srt_count = self.srt_count;
        self.reset();

        stats
    }
}
