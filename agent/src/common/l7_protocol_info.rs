/*
 * Copyright (c) 2023 Yunshan Networks
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

use std::sync::atomic::Ordering;

use super::{flow::PacketDirection, l7_protocol_log::KafkaInfoCache};
use enum_dispatch::enum_dispatch;
use log::{debug, error, warn};
use serde::Serialize;

use crate::{
    common::l7_protocol_log::LogCache,
    flow_generator::{
        protocol_logs::{
            pb_adapter::L7ProtocolSendLog, DnsInfo, DubboInfo, HttpInfo, KafkaInfo, MqttInfo,
            MysqlInfo, PostgreInfo, ProtobufRpcInfo, RedisInfo, SofaRpcInfo,
        },
        AppProtoHead, LogMessageType, Result,
    },
    plugin::CustomInfo,
};

use super::{ebpf::EbpfType, l7_protocol_log::ParseParam};

macro_rules! all_protocol_info {
    ($($name:ident($info_struct:ident)),+$(,)?) => {
        #[derive(Serialize, Debug, Clone)]
        #[enum_dispatch]
        #[serde(untagged)]
        pub enum L7ProtocolInfo {
            $(
                $name($info_struct),
            )+
        }

        impl From<L7ProtocolInfo> for L7ProtocolSendLog{
            fn from(f:L7ProtocolInfo)->L7ProtocolSendLog{
                match f{
                    $(
                        L7ProtocolInfo::$name(info)=>info.into(),
                    )+
                }
            }
        }
    };
}

all_protocol_info!(
    DnsInfo(DnsInfo),
    HttpInfo(HttpInfo),
    MysqlInfo(MysqlInfo),
    RedisInfo(RedisInfo),
    DubboInfo(DubboInfo),
    KafkaInfo(KafkaInfo),
    MqttInfo(MqttInfo),
    PostgreInfo(PostgreInfo),
    ProtobufRpcInfo(ProtobufRpcInfo),
    SofaRpcInfo(SofaRpcInfo),
    CustomInfo(CustomInfo),
    // add new protocol info below
);

#[enum_dispatch(L7ProtocolInfo)]
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

    fn skip_send(&self) -> bool {
        false
    }

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

    fn cal_cache_key(&self, param: &ParseParam) -> u128 {
        /*
            if session id is some: flow id 64bit | 0 32bit | session id 32bit
            if session id is none: flow id 64bit | packet_seq 64bit
        */
        match self.session_id() {
            Some(sid) => ((param.flow_id as u128) << 64) | sid as u128,
            None => {
                ((param.flow_id as u128) << 64)
                    | (if param.ebpf_type != EbpfType::None {
                        if param.direction == PacketDirection::ClientToServer {
                            param.packet_seq + 1
                        } else {
                            param.packet_seq
                        }
                    } else {
                        0
                    }) as u128
            }
        }
    }

    /*
        calculate rrt
        if have previous log cache:
            if previous is req and current is resp and current time > previous time
                rrt = current time - previous time
            if previous is resp and current is req and current time < previous time, likely ebfp disorder
                rrt =  previous time - current time

            otherwise can not calculate rrt, cache current log rrt

        if have no previous log cache, cache the current log rrt
    */
    fn cal_rrt(&self, param: &ParseParam, kafka_info: Option<KafkaInfoCache>) -> Option<u64> {
        let mut perf_cache = param.l7_perf_cache.borrow_mut();
        let cache_key = self.cal_cache_key(param);
        let previous_log_info = perf_cache.rrt_cache.pop(&cache_key);

        let time = param.time;
        let msg_type: LogMessageType = param.direction.into();
        let timeout = param.rrt_timeout as u64;

        if time != 0 {
            let (in_cached_req, timeout_count) = perf_cache
                .timeout_cache
                .get_or_insert_mut(param.flow_id, || (0, 0));

            let Some(previous_log_info) = previous_log_info else {
                if msg_type == LogMessageType::Request {
                    *in_cached_req += 1;
                }
                perf_cache.put(
                    cache_key,
                    LogCache {
                        msg_type: param.direction.into(),
                        time: param.time,
                        kafka_info,
                    },
                );

                param.stats_counter.as_ref().map(|f| {
                    f.l7_perf_cache_len
                        .swap(perf_cache.rrt_cache.len() as u64, Ordering::Relaxed);
                    f.l7_timeout_cache_len
                        .swap(perf_cache.timeout_cache.len() as u64, Ordering::Relaxed)
                });

                return None;
            };

            if previous_log_info.msg_type == LogMessageType::Request {
                if *in_cached_req > 0 {
                    *in_cached_req -= 1;
                }
            }

            // if previous is req and current is resp, calculate the round trip time.
            if previous_log_info.msg_type == LogMessageType::Request
                && msg_type == LogMessageType::Response
                && time > previous_log_info.time
            {
                let rrt = time - previous_log_info.time;
                // timeout, save the latest
                if rrt > timeout {
                    *timeout_count += 1;
                    perf_cache.rrt_cache.put(
                        cache_key,
                        LogCache {
                            msg_type: param.direction.into(),
                            time: param.time,
                            kafka_info,
                        },
                    );
                    None
                } else {
                    Some(rrt)
                }

            // if previous is resp and current is req and previous time gt current time, likely ebpf disorder,
            // calculate the round trip time.
            } else if previous_log_info.msg_type == LogMessageType::Response
                && msg_type == LogMessageType::Request
                && previous_log_info.time > time
            {
                let rrt = previous_log_info.time - time;
                if rrt > timeout {
                    // disorder info rrt unlikely have large rrt gt timeout
                    warn!("l7 log info disorder with long time rrt {}", rrt);
                    // timeout, save latest
                    *timeout_count += 1;
                    perf_cache.rrt_cache.put(cache_key, previous_log_info);
                    None
                } else {
                    Some(rrt)
                }
            } else {
                debug!(
                    "can not calculate rrt, flow_id: {}, previous log type:{:?}, previous time: {}, current log type: {:?}, current time: {}",
                    param.flow_id, previous_log_info.msg_type, previous_log_info.time, msg_type, param.time,
                );

                // save the latest
                if previous_log_info.time > time {
                    if msg_type == LogMessageType::Request {
                        *timeout_count += 1;
                    }
                    if previous_log_info.msg_type == LogMessageType::Request {
                        *in_cached_req += 1;
                    }
                    perf_cache.rrt_cache.put(cache_key, previous_log_info);
                } else {
                    if previous_log_info.msg_type == LogMessageType::Request {
                        *timeout_count += 1;
                    }
                    if msg_type == LogMessageType::Request {
                        *in_cached_req += 1;
                    }
                    perf_cache.rrt_cache.put(
                        cache_key,
                        LogCache {
                            msg_type: param.direction.into(),
                            time: param.time,
                            kafka_info,
                        },
                    );
                }

                param.stats_counter.as_ref().map(|f| {
                    f.l7_perf_cache_len
                        .swap(perf_cache.rrt_cache.len() as u64, Ordering::Relaxed);
                    f.l7_timeout_cache_len
                        .swap(perf_cache.timeout_cache.len() as u64, Ordering::Relaxed);
                });
                None
            }
        } else {
            error!("flow_id: {}, packet time 0", param.flow_id);
            None
        }
    }

    fn get_request_resource_length(&self) -> usize {
        0
    }
}

impl L7ProtocolInfo {
    pub fn is_session_end(&self) -> bool {
        let (req_end, resp_end) = self.is_req_resp_end();
        req_end && resp_end
    }
}
