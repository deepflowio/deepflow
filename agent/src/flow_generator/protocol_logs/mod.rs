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

pub mod consts;
mod dns;
mod http;
mod mq;
mod parser;
mod rpc;
mod sql;
pub use self::http::{
    check_http_method, get_http_request_version, get_http_resp_info, is_http_v1_payload, HttpLog,
    Httpv2Headers,
};
pub use dns::DnsLog;
pub use mq::{mqtt, KafkaLog, MqttLog};
pub use parser::{AppProtoLogsParser, MetaAppProto};
pub use rpc::{get_protobuf_rpc_parser, DubboHeader, DubboLog, ProtobufRpcWrapLog};
pub use sql::{decode, MysqlHeader, MysqlLog, PostgresqlLog, RedisLog};

use std::{mem::swap, str};

use crate::{
    common::enums::TapType,
    common::flow::{L7Protocol, PacketDirection},
    common::l7_protocol_log::ParseParam,
    common::meta_packet::MetaPacket,
    flow_generator::{Error, Result},
};

pub use public::protocol_logs::*;
use public::{common::enums::TapSide, protocol_logs::l7_protocol_info::L7ProtocolInfo};

const NANOS_PER_MICRO: u64 = 1000;

pub trait L7ProtocolInfoInterface: Into<L7ProtocolSendLog> {
    // 个别协议一个连接可能有子流，这里需要返回流标识，例如http2的stream id
    // ============================================================
    // Returns the stream ID, distinguishing substreams. such as http2 stream id, dns transaction id
    fn session_id(&self) -> Option<u32>;
    // 协议字段合并
    // 返回的错误暂时无视
    // =============================================================
    // merge request and response. now return err will have no effect.
    fn merge_log(&mut self, other: L7ProtocolInfo) -> Result<()>;

    fn app_proto_head(&self) -> Option<AppProtoHead>;
    fn is_tls(&self) -> bool;
    fn skip_send(&self) -> bool;

    // 是否需要进一步合并，目前只有在ebpf有意义，内置协议也只有 EBPF_TYPE_GO_HTTP2_UPROBE 会用到.
    // 除非确实需要多次log合并，否则应该一律返回false
    // =================================================================================
    // should need merge more than once? only ebpf will need merge many times.
    // should always return false when non ebpf.
    fn need_merge(&self) -> bool {
        false
    }
    // 对于需要多次merge的情况下，判断流是否已经结束，只有在need_merge->true的情况下有用
    // 返回 req_end,resp_end
    // ========================================================================
    // when need merge more than once, use to determine if the stream has ended.
    fn is_req_resp_end(&self) -> (bool, bool) {
        (false, false)
    }
}

// You can only define an inherent implementation for a type in the same crate
// where the type was defined. For example, an `impl` block as above is not allowed
// since `Vec` is defined in the standard library.
// so define a trait that has the desired associated functions/types/constants and
// implement the trait for the type in question
// rustc --explain E0116
// rustc --explain E0412
pub trait AppProtoLogsImpl: Sized {
    fn from_ebpf(
        _packet: &MetaPacket,
        _head: AppProtoHead,
        _vtap_id: u16,
        _local_epc: i32,
        _remote_epc: i32,
    ) -> Self {
        unimplemented!()
    }
    fn merge(&mut self, _log: Self) -> Result<()> {
        Ok(())
    }
    fn ebpf_flow_session_id(&self) -> u64 {
        0
    }
}

pub trait AppProtoInfoImpl: Sized {
    fn merge(&mut self, _other: Self) -> Result<()> {
        Ok(())
    }
    fn check(&self) -> bool {
        false
    }
    fn set_packet_seq(&mut self, _param: &ParseParam) {}
    fn can_merge(&self, _resp: &Self) -> bool {
        false
    }
}

impl AppProtoLogsImpl for AppProtoLogsBaseInfo {
    fn from_ebpf(
        packet: &MetaPacket,
        head: AppProtoHead,
        vtap_id: u16,
        local_epc: i32,
        remote_epc: i32,
    ) -> Self {
        let is_src = packet.lookup_key.l2_end_0;
        let direction = packet.direction;
        let mut info = Self {
            start_time: packet.lookup_key.timestamp,
            end_time: packet.lookup_key.timestamp,
            flow_id: packet.socket_id,
            tap_port: packet.tap_port,
            signal_source: packet.signal_source,
            tap_type: TapType::Cloud,
            is_ipv6: packet.lookup_key.dst_ip.is_ipv6(),
            tap_side: if is_src {
                TapSide::ClientProcess
            } else {
                TapSide::ServerProcess
            },

            mac_src: packet.lookup_key.src_mac,
            mac_dst: packet.lookup_key.dst_mac,
            ip_src: packet.lookup_key.src_ip,
            ip_dst: packet.lookup_key.dst_ip,
            port_src: packet.lookup_key.src_port,
            port_dst: packet.lookup_key.dst_port,
            protocol: packet.lookup_key.proto,

            ebpf_type: packet.ebpf_type,
            process_id_0: if is_src { packet.process_id } else { 0 },
            process_id_1: if !is_src { packet.process_id } else { 0 },
            process_kname_0: if is_src {
                packet.process_name.clone()
            } else {
                "".to_string()
            },
            process_kname_1: if !is_src {
                packet.process_name.clone()
            } else {
                "".to_string()
            },

            syscall_trace_id_request: if direction == PacketDirection::ClientToServer {
                packet.syscall_trace_id
            } else {
                0
            },
            syscall_trace_id_response: if direction == PacketDirection::ServerToClient {
                packet.syscall_trace_id
            } else {
                0
            },
            req_tcp_seq: if direction == PacketDirection::ClientToServer {
                packet.tcp_data.seq
            } else {
                0
            },
            resp_tcp_seq: if direction == PacketDirection::ServerToClient {
                packet.tcp_data.seq
            } else {
                0
            },
            syscall_trace_id_thread_0: if direction == PacketDirection::ClientToServer {
                packet.thread_id
            } else {
                0
            },
            syscall_trace_id_thread_1: if direction == PacketDirection::ServerToClient {
                packet.thread_id
            } else {
                0
            },
            syscall_cap_seq_0: if direction == PacketDirection::ClientToServer {
                packet.cap_seq
            } else {
                0
            },
            syscall_cap_seq_1: if direction == PacketDirection::ServerToClient {
                packet.cap_seq
            } else {
                0
            },
            vtap_id,
            head,
            l3_epc_id_src: if is_src { local_epc } else { remote_epc },
            l3_epc_id_dst: if is_src { remote_epc } else { local_epc },
            is_vip_interface_src: false,
            is_vip_interface_dst: false,
        };
        if direction == PacketDirection::ServerToClient {
            swap(&mut info.mac_src, &mut info.mac_dst);
            swap(&mut info.ip_src, &mut info.ip_dst);
            swap(&mut info.l3_epc_id_src, &mut info.l3_epc_id_dst);
            swap(&mut info.port_src, &mut info.port_dst);
            swap(&mut info.process_id_0, &mut info.process_id_1);
            swap(&mut info.process_kname_0, &mut info.process_kname_1);
            info.tap_side = if info.tap_side == TapSide::ClientProcess {
                TapSide::ServerProcess
            } else {
                TapSide::ClientProcess
            };
        }

        info
    }
    // 请求调用回应来合并
    fn merge(&mut self, log: AppProtoLogsBaseInfo) -> Result<()> {
        // adjust protocol when change, now only use for http2 change to grpc.
        if self.head.proto != log.head.proto {
            self.head.proto = log.head.proto;
        }
        if log.process_id_0 > 0 {
            self.process_id_0 = log.process_id_0;
            self.process_kname_0 = log.process_kname_0;
        }
        if log.process_id_1 > 0 {
            self.process_id_1 = log.process_id_1;
            self.process_kname_1 = log.process_kname_1;
        }
        self.syscall_trace_id_thread_1 = log.syscall_trace_id_thread_1;
        self.syscall_cap_seq_1 = log.syscall_cap_seq_1;

        self.start_time = log.start_time.min(self.start_time);
        self.end_time = log.end_time.max(self.start_time);
        match log.head.msg_type {
            LogMessageType::Request if self.req_tcp_seq == 0 && log.req_tcp_seq != 0 => {
                self.req_tcp_seq = log.req_tcp_seq;
            }
            LogMessageType::Response if self.resp_tcp_seq == 0 && log.resp_tcp_seq != 0 => {
                self.resp_tcp_seq = log.resp_tcp_seq;
            }
            _ => {}
        }

        self.syscall_trace_id_response = log.syscall_trace_id_response;
        self.head.msg_type = LogMessageType::Session;

        self.head.rrt = if self.end_time > self.start_time {
            (self.end_time - self.start_time).as_micros() as u64
        } else {
            0
        };
        Ok(())
    }
}

impl AppProtoLogsImpl for AppProtoLogsData {
    fn ebpf_flow_session_id(&self) -> u64 {
        // 取flow_id(即ebpf底层的socket id)的高8位(cpu id)+低24位(socket id的变化增量), 作为聚合id的高32位
        // |flow_id 高8位| flow_id 低24位|proto 8 位|session 低24位|

        // due to grpc is init by http2 and modify during parse, it must reset to http2 when the protocol is grpc.
        let proto = if self.base_info.head.proto == L7Protocol::Grpc {
            if let L7ProtocolInfo::HttpInfo(http) = &self.special_info {
                if http.is_tls() {
                    L7Protocol::Http2TLS
                } else {
                    L7Protocol::Http2
                }
            } else {
                unreachable!()
            }
        } else {
            self.base_info.head.proto
        };

        let flow_id_part =
            (self.base_info.flow_id >> 56 << 56) | (self.base_info.flow_id << 40 >> 8);
        if let Some(session_id) = self.special_info.session_id() {
            flow_id_part | (proto as u64) << 24 | ((session_id as u64) & 0xffffff)
        } else {
            let mut cap_seq = self
                .base_info
                .syscall_cap_seq_0
                .max(self.base_info.syscall_cap_seq_1);
            if self.base_info.head.msg_type == LogMessageType::Request {
                cap_seq += 1;
            };
            flow_id_part | ((proto as u64) << 24) | (cap_seq & 0xffffff)
        }
    }

    fn merge(&mut self, log: Self) -> Result<()> {
        if let Err(err) = self.special_info.merge_log(log.special_info) {
            /*
                if can not merge, return log which can not merge to self.
                the follow circumstance can not merge:
                    when ebpf disorder, http1 can not match req/resp.
            */
            if let Error::L7ProtocolCanNotMerge(special_info) = err {
                return Err(Error::L7LogCanNotMerge(Self {
                    special_info,
                    ..log
                }));
            }
            return Err(err);
        };
        self.base_info.merge(log.base_info)
    }
}

impl L7ProtocolInfoInterface for L7ProtocolInfo {
    fn session_id(&self) -> Option<u32> {
        match self {
            L7ProtocolInfo::DnsInfo(info) => info.session_id(),
            L7ProtocolInfo::HttpInfo(info) => info.session_id(),
            L7ProtocolInfo::MysqlInfo(info) => info.session_id(),
            L7ProtocolInfo::RedisInfo(info) => info.session_id(),
            L7ProtocolInfo::DubboInfo(info) => info.session_id(),
            L7ProtocolInfo::KafkaInfo(info) => info.session_id(),
            L7ProtocolInfo::MqttInfo(info) => info.session_id(),
            L7ProtocolInfo::PostgreInfo(info) => info.session_id(),
            L7ProtocolInfo::ProtobufRpcInfo(info) => info.session_id(),
        }
    }

    fn merge_log(&mut self, other: L7ProtocolInfo) -> Result<()> {
        match self {
            L7ProtocolInfo::DnsInfo(info) => info.merge_log(other),
            L7ProtocolInfo::HttpInfo(info) => info.merge_log(other),
            L7ProtocolInfo::MysqlInfo(info) => info.merge_log(other),
            L7ProtocolInfo::RedisInfo(info) => info.merge_log(other),
            L7ProtocolInfo::DubboInfo(info) => info.merge_log(other),
            L7ProtocolInfo::KafkaInfo(info) => info.merge_log(other),
            L7ProtocolInfo::MqttInfo(info) => info.merge_log(other),
            L7ProtocolInfo::PostgreInfo(info) => info.merge_log(other),
            L7ProtocolInfo::ProtobufRpcInfo(info) => info.merge_log(other),
        }
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        match self {
            L7ProtocolInfo::DnsInfo(info) => info.app_proto_head(),
            L7ProtocolInfo::HttpInfo(info) => info.app_proto_head(),
            L7ProtocolInfo::MysqlInfo(info) => info.app_proto_head(),
            L7ProtocolInfo::RedisInfo(info) => info.app_proto_head(),
            L7ProtocolInfo::DubboInfo(info) => info.app_proto_head(),
            L7ProtocolInfo::KafkaInfo(info) => info.app_proto_head(),
            L7ProtocolInfo::MqttInfo(info) => info.app_proto_head(),
            L7ProtocolInfo::PostgreInfo(info) => info.app_proto_head(),
            L7ProtocolInfo::ProtobufRpcInfo(info) => info.app_proto_head(),
        }
    }

    fn is_req_resp_end(&self) -> (bool, bool) {
        match self {
            L7ProtocolInfo::DnsInfo(info) => info.is_req_resp_end(),
            L7ProtocolInfo::HttpInfo(info) => info.is_req_resp_end(),
            L7ProtocolInfo::MysqlInfo(info) => info.is_req_resp_end(),
            L7ProtocolInfo::RedisInfo(info) => info.is_req_resp_end(),
            L7ProtocolInfo::DubboInfo(info) => info.is_req_resp_end(),
            L7ProtocolInfo::KafkaInfo(info) => info.is_req_resp_end(),
            L7ProtocolInfo::MqttInfo(info) => info.is_req_resp_end(),
            L7ProtocolInfo::PostgreInfo(info) => info.is_req_resp_end(),
            L7ProtocolInfo::ProtobufRpcInfo(info) => info.is_req_resp_end(),
        }
    }
    fn is_tls(&self) -> bool {
        match self {
            L7ProtocolInfo::DnsInfo(info) => info.is_tls(),
            L7ProtocolInfo::HttpInfo(info) => info.is_tls(),
            L7ProtocolInfo::MysqlInfo(info) => info.is_tls(),
            L7ProtocolInfo::RedisInfo(info) => info.is_tls(),
            L7ProtocolInfo::DubboInfo(info) => info.is_tls(),
            L7ProtocolInfo::KafkaInfo(info) => info.is_tls(),
            L7ProtocolInfo::MqttInfo(info) => info.is_tls(),
            L7ProtocolInfo::PostgreInfo(info) => info.is_tls(),
            L7ProtocolInfo::ProtobufRpcInfo(info) => info.is_tls(),
        }
    }

    fn need_merge(&self) -> bool {
        match self {
            L7ProtocolInfo::DnsInfo(info) => info.need_merge(),
            L7ProtocolInfo::HttpInfo(info) => info.need_merge(),
            L7ProtocolInfo::MysqlInfo(info) => info.need_merge(),
            L7ProtocolInfo::RedisInfo(info) => info.need_merge(),
            L7ProtocolInfo::DubboInfo(info) => info.need_merge(),
            L7ProtocolInfo::KafkaInfo(info) => info.need_merge(),
            L7ProtocolInfo::MqttInfo(info) => info.need_merge(),
            L7ProtocolInfo::PostgreInfo(info) => info.need_merge(),
            L7ProtocolInfo::ProtobufRpcInfo(info) => info.need_merge(),
        }
    }

    fn skip_send(&self) -> bool {
        match self {
            L7ProtocolInfo::DnsInfo(info) => info.skip_send(),
            L7ProtocolInfo::HttpInfo(info) => info.skip_send(),
            L7ProtocolInfo::MysqlInfo(info) => info.skip_send(),
            L7ProtocolInfo::RedisInfo(info) => info.skip_send(),
            L7ProtocolInfo::DubboInfo(info) => info.skip_send(),
            L7ProtocolInfo::KafkaInfo(info) => info.skip_send(),
            L7ProtocolInfo::MqttInfo(info) => info.skip_send(),
            L7ProtocolInfo::PostgreInfo(info) => info.skip_send(),
            L7ProtocolInfo::ProtobufRpcInfo(info) => info.skip_send(),
        }
    }
}

fn decode_base64_to_string(value: &str) -> String {
    let bytes = match base64::decode(value) {
        Ok(v) => v,
        Err(_) => return value.to_string(),
    };
    match str::from_utf8(&bytes) {
        Ok(s) => s.to_string(),
        Err(_) => value.to_string(),
    }
}
