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

use std::cell::RefMut;

use super::flow::PacketDirection;
use enum_dispatch::enum_dispatch;
use log::{debug, error, warn};
use serde::Serialize;

use crate::{
    common::{
        flow::L7PerfStats,
        l7_protocol_log::{L7PerfCache, LogCache, LogCacheKey},
    },
    flow_generator::{
        protocol_logs::{
            fastcgi::FastCGIInfo, pb_adapter::L7ProtocolSendLog, AmqpInfo, BrpcInfo, DnsInfo,
            DubboInfo, HttpInfo, KafkaInfo, MemcachedInfo, MongoDBInfo, MqttInfo, MysqlInfo,
            NatsInfo, OpenWireInfo, PingInfo, PostgreInfo, PulsarInfo, RedisInfo, RocketmqInfo,
            SofaRpcInfo, TarsInfo, ZmtpInfo,
        },
        AppProtoHead, Result,
    },
    plugin::CustomInfo,
};

use super::l7_protocol_log::ParseParam;
use public::l7_protocol::LogMessageType;

macro_rules! all_protocol_info {
    ($($name:ident($info_struct:ty)),+$(,)?) => {

        #[derive(Serialize, Debug, Clone)]
        #[enum_dispatch]
        #[serde(untagged)]
        pub enum L7ProtocolInfo {
            $(
                $name($info_struct),
            )+
        }

        impl From<L7ProtocolInfo> for L7ProtocolSendLog {
            fn from(f: L7ProtocolInfo) -> Self {
                match f {
                    $(
                        L7ProtocolInfo::$name(info) => info.into(),
                    )+
                }
            }
        }

        impl From<&L7ProtocolInfo> for LogCache {
            fn from(info: &L7ProtocolInfo) -> Self {
                match info {
                    $(
                        L7ProtocolInfo::$name(info) => info.into(),
                    )+
                }
            }
        }
    };
}

cfg_if::cfg_if! {
    if #[cfg(not(feature = "enterprise"))] {
        all_protocol_info!(
            DnsInfo(DnsInfo),
            HttpInfo(HttpInfo),
            MysqlInfo(MysqlInfo),
            RedisInfo(RedisInfo),
            MongoDBInfo(MongoDBInfo),
            MemcachedInfo(MemcachedInfo),
            DubboInfo(DubboInfo),
            FastCGIInfo(FastCGIInfo),
            BrpcInfo(BrpcInfo),
            TarsInfo(TarsInfo),
            KafkaInfo(KafkaInfo),
            MqttInfo(MqttInfo),
            AmqpInfo(AmqpInfo),
            NatsInfo(NatsInfo),
            PulsarInfo(PulsarInfo),
            ZmtpInfo(ZmtpInfo),
            RocketmqInfo(RocketmqInfo),
            PostgreInfo(PostgreInfo),
            OpenWireInfo(OpenWireInfo),
            SofaRpcInfo(SofaRpcInfo),
            PingInfo(PingInfo),
            CustomInfo(CustomInfo),
            // add new protocol info below
        );
    } else {
        all_protocol_info!(
            DnsInfo(DnsInfo),
            HttpInfo(HttpInfo),
            MysqlInfo(MysqlInfo),
            RedisInfo(RedisInfo),
            MongoDBInfo(MongoDBInfo),
            MemcachedInfo(MemcachedInfo),
            DubboInfo(DubboInfo),
            FastCGIInfo(FastCGIInfo),
            BrpcInfo(BrpcInfo),
            TarsInfo(TarsInfo),
            KafkaInfo(KafkaInfo),
            MqttInfo(MqttInfo),
            AmqpInfo(AmqpInfo),
            NatsInfo(NatsInfo),
            PulsarInfo(PulsarInfo),
            ZmtpInfo(ZmtpInfo),
            RocketmqInfo(RocketmqInfo),
            WebSphereMqInfo(crate::flow_generator::protocol_logs::WebSphereMqInfo),
            PostgreInfo(PostgreInfo),
            OpenWireInfo(OpenWireInfo),
            OracleInfo(crate::flow_generator::protocol_logs::OracleInfo),
            SofaRpcInfo(SofaRpcInfo),
            TlsInfo(crate::flow_generator::protocol_logs::TlsInfo),
            SomeIpInfo(crate::flow_generator::protocol_logs::SomeIpInfo),
            PingInfo(PingInfo),
            CustomInfo(CustomInfo),
            Iso8583Info(crate::flow_generator::protocol_logs::rpc::Iso8583Info),
            // add new protocol info below
        );
    }
}

#[enum_dispatch(L7ProtocolInfo)]
pub trait L7ProtocolInfoInterface: Into<L7ProtocolSendLog>
where
    LogCache: for<'a> From<&'a Self>,
{
    // 个别协议一个连接可能有子流，这里需要返回流标识，例如http2的stream id
    // ============================================================
    // Returns the stream ID, distinguishing substreams. such as http2 stream id, dns transaction id
    fn session_id(&self) -> Option<u32>;
    // 协议字段合并
    // 返回的错误暂时无视
    // =============================================================
    // merge request and response. now return err will have no effect.
    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()>;

    fn app_proto_head(&self) -> Option<AppProtoHead>;

    // 是否需要将数据聚合为会话
    // =============================
    // needs to be aggregated into sessions
    fn needs_session_aggregation(&self) -> bool {
        true
    }

    fn is_tls(&self) -> bool;

    fn is_reversed(&self) -> bool {
        false
    }

    fn get_endpoint(&self) -> Option<String> {
        None
    }

    fn get_biz_type(&self) -> u8 {
        0
    }

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

    // load endpoint from cache for *responses*
    // call this before calling `perf_stats` because the latter may remove cached entry
    fn load_endpoint_from_cache<'a>(
        &mut self,
        param: &'a ParseParam,
        is_reversed: bool,
    ) -> Option<String> {
        let key = LogCacheKey::new(param, self.session_id(), is_reversed);
        match param.l7_perf_cache.borrow_mut().rrt_cache.get(&key) {
            Some(cached) if cached.endpoint.is_some() => {
                let log = LogCache {
                    time: param.time,
                    ..LogCache::from(&*self)
                };
                if log.is_response_of(&cached) {
                    return Some(cached.endpoint.as_ref().unwrap().clone());
                }
            }
            _ => (),
        }
        None
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
    fn perf_stats(&self, param: &ParseParam) -> Option<L7PerfStats> {
        if param.time == 0 {
            error!("flow_id: {}, packet time 0", param.flow_id);
            return None;
        }

        let cur_info = LogCache {
            time: param.time,
            ..LogCache::from(self)
        };
        assert!(
            !self.need_merge()
                || self.session_id().is_some() && cur_info.multi_merge_info.is_some()
        );

        if !self.needs_session_aggregation() {
            return Some(L7PerfStats::from(&cur_info));
        }

        if cur_info.msg_type == LogMessageType::Session {
            if cur_info.on_blacklist {
                return None;
            }
            // req/resp not counted for session type
            let mut stats = L7PerfStats::from(&cur_info);
            match param.direction {
                PacketDirection::ClientToServer => stats.inc_req(),
                PacketDirection::ServerToClient => stats.inc_resp(),
            }
            return Some(stats);
        }

        let (mut rtt_cache, mut timeout_cache) = RefMut::map_split(
            param.l7_perf_cache.borrow_mut(),
            |perf_cache: &mut L7PerfCache| {
                (&mut perf_cache.rrt_cache, &mut perf_cache.timeout_cache)
            },
        );
        let key = LogCacheKey::new(param, self.session_id(), self.is_reversed());
        let prev_info = rtt_cache.get_mut(&key);
        let timeout_counter = timeout_cache.get_or_insert_mut(param.flow_id);
        let index = if self.is_reversed() { 1 } else { 0 };

        let Some(prev_info) = prev_info else {
            // If the first log is a request and on blacklist, we still need to put it in cache to handle the response,
            // but it's stats will not be counted.
            //
            // If the first log is a response, it's perf stats will not be counted here.
            // We need to know whether its corresponding request is on blacklist before accounting.
            let ret = if cur_info.msg_type == LogMessageType::Request && !cur_info.on_blacklist {
                timeout_counter.in_cache[index] += 1;
                Some(L7PerfStats::from(&cur_info))
            } else {
                None
            };
            rtt_cache.put(key, cur_info);
            return ret;
        };

        let mut keep_prev = false;
        if let Some(merge_info) = prev_info.multi_merge_info.as_mut() {
            let cur_merge_info = cur_info.multi_merge_info.as_ref().unwrap();
            merge_info.req_end |= cur_merge_info.req_end;
            merge_info.resp_end |= cur_merge_info.resp_end;

            if prev_info.msg_type != cur_info.msg_type && !merge_info.merged {
                merge_info.merged = true;
                if !(prev_info.on_blacklist || cur_info.on_blacklist) {
                    timeout_counter.in_cache[index] =
                        timeout_counter.in_cache[index].saturating_sub(1);
                }
            }

            // keep previous only when
            // 1. multi merge
            // 2. req_end && resp_end == false
            keep_prev = !(merge_info.req_end && merge_info.resp_end);
        } else {
            if prev_info.msg_type == LogMessageType::Request && !prev_info.on_blacklist {
                timeout_counter.in_cache[index] = timeout_counter.in_cache[index].saturating_sub(1);
            }
        }

        if prev_info.is_request_of(&cur_info) {
            let on_blacklist = prev_info.on_blacklist || cur_info.on_blacklist;
            let result = if !on_blacklist {
                // request accounted before
                let mut perf_stats = L7PerfStats::from(&cur_info);

                let rrt = cur_info.time - prev_info.time;
                if rrt > param.rrt_timeout as u64 {
                    match prev_info.multi_merge_info.as_ref() {
                        Some(info) if info.merged => (),
                        _ => timeout_counter.timeout[index] += 1,
                    }
                } else {
                    perf_stats.update_rrt(rrt);
                }

                Some(perf_stats)
            } else {
                None
            };

            if !keep_prev {
                rtt_cache.pop(&key);
            }

            result
        } else if prev_info.is_response_of(&cur_info) {
            // cur_info is request, prev_info is response
            // request not accounted before
            let result = if !cur_info.on_blacklist {
                let mut perf_stats = L7PerfStats::from(&cur_info);

                if !prev_info.on_blacklist {
                    let rrt = prev_info.time - cur_info.time;
                    if rrt > param.rrt_timeout as u64 {
                        warn!("l7 log info disorder with long time rrt {}", rrt);
                        match prev_info.multi_merge_info.as_ref() {
                            Some(info) if info.merged => (),
                            _ => timeout_counter.timeout[index] += 1,
                        }
                    }

                    perf_stats.sequential_merge(&L7PerfStats::from(&*prev_info));
                    perf_stats.update_rrt(rrt);
                }

                Some(perf_stats)
            } else {
                None
            };

            if !keep_prev {
                rtt_cache.pop(&key);
            }

            result
        } else if !self.need_merge() {
            debug!(
                "can not calculate rrt, flow_id: {}, previous log type: {:?}, previous time: {}, current log type: {:?}, current time: {}",
                param.flow_id, prev_info.msg_type, prev_info.time, cur_info.msg_type, cur_info.time,
            );

            if prev_info.time > cur_info.time {
                if !cur_info.on_blacklist && cur_info.msg_type == LogMessageType::Request {
                    timeout_counter.timeout[index] += 1;
                }
                if !prev_info.on_blacklist && prev_info.msg_type == LogMessageType::Request {
                    timeout_counter.in_cache[index] += 1;
                }
                if !cur_info.on_blacklist {
                    Some(L7PerfStats::from(&cur_info))
                } else {
                    None
                }
            } else {
                if !prev_info.on_blacklist && prev_info.msg_type == LogMessageType::Request {
                    timeout_counter.timeout[index] += 1;
                }
                if !cur_info.on_blacklist && cur_info.msg_type == LogMessageType::Request {
                    timeout_counter.in_cache[index] += 1;
                }
                let prev_info = rtt_cache.put(key, cur_info).unwrap();
                if !prev_info.on_blacklist {
                    Some(L7PerfStats::from(&prev_info))
                } else {
                    None
                }
            }
        } else {
            if !prev_info.on_blacklist
                && prev_info.msg_type != cur_info.msg_type
                && !prev_info.multi_merge_info.as_ref().unwrap().merged
            {
                timeout_counter.timeout[index] += 1;
            }
            if !keep_prev {
                rtt_cache.pop(&key);
            }
            if !cur_info.on_blacklist {
                Some(L7PerfStats::from(&cur_info))
            } else {
                None
            }
        }
    }

    // This is not required for UNIX socket data at this time
    fn tcp_seq_offset(&self) -> u32 {
        return 0;
    }

    fn get_request_domain(&self) -> String {
        String::default()
    }

    fn get_request_resource_length(&self) -> usize {
        0
    }

    fn is_on_blacklist(&self) -> bool {
        false
    }
}

impl L7ProtocolInfo {
    pub fn is_session_end(&self) -> bool {
        let (req_end, resp_end) = self.is_req_resp_end();
        req_end && resp_end
    }
}
