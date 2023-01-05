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

use enum_dispatch::enum_dispatch;
use serde::Serialize;

use crate::flow_generator::{
    protocol_logs::{
        pb_adapter::L7ProtocolSendLog, DnsInfo, DubboInfo, HttpInfo, KafkaInfo, MqttInfo,
        MysqlInfo, PostgreInfo, ProtobufRpcInfo, RedisInfo, SofaRpcInfo,
    },
    AppProtoHead, Result,
};

#[macro_export]
macro_rules! log_info_merge {
    ($self:ident,$log_type:ident,$other:ident) => {
        if let L7ProtocolInfo::$log_type(other) = $other {
            if other.start_time < $self.start_time {
                $self.start_time = other.start_time;
            }
            if other.end_time > $self.end_time {
                $self.end_time = other.end_time;
            }
            $self.merge(other);
        }
    };
}

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
    //
    // add new protocol info below
    PostgreInfo(PostgreInfo),
    ProtobufRpcInfo(ProtobufRpcInfo),
    SofaRpcInfo(SofaRpcInfo),
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
}

impl L7ProtocolInfo {
    pub fn is_session_end(&self) -> bool {
        let (req_end, resp_end) = self.is_req_resp_end();
        req_end && resp_end
    }
}
