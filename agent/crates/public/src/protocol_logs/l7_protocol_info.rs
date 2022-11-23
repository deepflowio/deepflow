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
use std::str;

use serde::Serialize;

use super::consts::KAFKA_COMMANDS_STRS;
use super::{
    consts::{get_domain_str, get_request_str, MYSQL_COMMAND_STRS},
    pb_adapter::*,
    DnsInfo, DubboInfo, HttpInfo, KafkaInfo, KrpcInfo, L7Protocol, L7ResponseStatus,
    LogMessageType, MqttInfo, MysqlInfo, PacketKind, PostgreInfo, ProtobufRpcInfo, RedisInfo,
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
            $self.merge(other)?;
        }
    };
}

#[derive(Serialize, Debug, Clone)]
#[serde(untagged)]
pub enum L7ProtocolInfo {
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
}

impl From<L7ProtocolInfo> for L7ProtocolSendLog {
    fn from(f: L7ProtocolInfo) -> L7ProtocolSendLog {
        match f {
            L7ProtocolInfo::DnsInfo(info) => info.into(),
            L7ProtocolInfo::HttpInfo(info) => info.into(),
            L7ProtocolInfo::MysqlInfo(info) => info.into(),
            L7ProtocolInfo::RedisInfo(info) => info.into(),
            L7ProtocolInfo::DubboInfo(info) => info.into(),
            L7ProtocolInfo::KafkaInfo(info) => info.into(),
            L7ProtocolInfo::MqttInfo(info) => info.into(),
            L7ProtocolInfo::PostgreInfo(info) => info.into(),
            L7ProtocolInfo::ProtobufRpcInfo(info) => info.into(),
        }
    }
}

impl From<KafkaInfo> for L7ProtocolSendLog {
    fn from(f: KafkaInfo) -> Self {
        let log = L7ProtocolSendLog {
            req_len: f.req_msg_size,
            resp_len: f.resp_msg_size,
            req: L7Request {
                req_type: KAFKA_COMMANDS_STRS
                    .get(f.api_key as usize)
                    .unwrap_or(&"")
                    .to_string(),
                ..Default::default()
            },
            resp: L7Response {
                status: f.status,
                code: f.status_code,
                ..Default::default()
            },
            ext_info: Some(ExtendedInfo {
                request_id: Some(f.correlation_id),
                ..Default::default()
            }),
            ..Default::default()
        };
        return log;
    }
}

impl Default for MqttInfo {
    fn default() -> Self {
        Self {
            client_id: None,
            version: 0,
            pkt_type: Default::default(),
            req_msg_size: None,
            res_msg_size: None,
            subscribe_topics: None,
            publish_topic: None,
            code: None,
            status: L7ResponseStatus::Ok,
            start_time: 0,
            end_time: 0,
            msg_type: LogMessageType::Other,
        }
    }
}

impl From<MqttInfo> for L7ProtocolSendLog {
    fn from(f: MqttInfo) -> Self {
        let version = match f.version {
            3 => "3.1",
            4 => "3.1.1",
            5 => "5.0",
            _ => "",
        }
        .into();
        let mut topic_str = String::new();
        match f.pkt_type {
            PacketKind::Publish { .. } => {
                if let Some(t) = f.publish_topic {
                    topic_str.push_str(t.as_str());
                }
            }
            PacketKind::Unsubscribe | PacketKind::Subscribe => {
                if let Some(s) = f.subscribe_topics {
                    for i in s {
                        topic_str.push_str(format!("{},", i.name).as_str());
                    }
                    if !topic_str.is_empty() {
                        topic_str.pop();
                    }
                }
            }
            _ => {}
        };
        let log = L7ProtocolSendLog {
            version: Some(version),
            req_len: f.req_msg_size,
            resp_len: f.res_msg_size,
            req: L7Request {
                req_type: f.pkt_type.to_string(),
                domain: f.client_id.unwrap_or_default(),
                resource: topic_str,
                ..Default::default()
            },
            resp: L7Response {
                status: f.status,
                code: f.code,
                ..Default::default()
            },
            ..Default::default()
        };
        return log;
    }
}

impl From<DubboInfo> for L7ProtocolSendLog {
    fn from(f: DubboInfo) -> Self {
        let endpoint = format!("{}/{}", f.service_name, f.method_name);
        L7ProtocolSendLog {
            req_len: f.req_msg_size,
            resp_len: f.resp_msg_size,
            version: Some(f.dubbo_version),
            req: L7Request {
                resource: f.service_name.clone(),
                req_type: f.method_name.clone(),
                endpoint,
                ..Default::default()
            },
            resp: L7Response {
                status: f.resp_status,
                code: f.status_code,
                ..Default::default()
            },
            trace_info: Some(TraceInfo {
                trace_id: Some(f.trace_id),
                span_id: Some(f.span_id),
                ..Default::default()
            }),
            ext_info: Some(ExtendedInfo {
                rpc_service: Some(f.service_name),
                request_id: Some(f.request_id as u32),
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

impl From<MysqlInfo> for L7ProtocolSendLog {
    fn from(f: MysqlInfo) -> Self {
        let log = L7ProtocolSendLog {
            version: if f.protocol_version == 0 {
                None
            } else {
                Some(f.protocol_version.to_string())
            },
            row_effect: f.affected_rows as u32,
            req: L7Request {
                req_type: MYSQL_COMMAND_STRS
                    .get(f.command as usize)
                    .unwrap_or(&"")
                    .to_string(),
                resource: f.context,
                ..Default::default()
            },
            resp: L7Response {
                status: f.status,
                code: f.error_code,
                exception: f.error_message,
                ..Default::default()
            },
            ext_info: Some(ExtendedInfo {
                ..Default::default()
            }),
            ..Default::default()
        };
        return log;
    }
}

impl From<PostgreInfo> for L7ProtocolSendLog {
    fn from(p: PostgreInfo) -> L7ProtocolSendLog {
        L7ProtocolSendLog {
            req_len: None,
            resp_len: None,
            row_effect: p.affected_rows as u32,
            req: L7Request {
                req_type: String::from(get_request_str(p.req_type)),
                resource: p.context,
                ..Default::default()
            },
            resp: L7Response {
                status: p.status,
                result: p.result,
                exception: p.error_message,
                ..Default::default()
            },
            ext_info: Some(ExtendedInfo {
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

impl fmt::Display for RedisInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RedisInfo {{ request: {:?}, ",
            str::from_utf8(&self.request).unwrap_or_default()
        )?;
        write!(
            f,
            "request_type: {:?}, ",
            str::from_utf8(&self.request_type).unwrap_or_default()
        )?;
        write!(
            f,
            "response: {:?}, ",
            str::from_utf8(&self.response).unwrap_or_default()
        )?;
        write!(
            f,
            "status: {:?}, ",
            str::from_utf8(&self.status).unwrap_or_default()
        )?;
        write!(
            f,
            "error: {:?} }}",
            str::from_utf8(&self.error).unwrap_or_default()
        )
    }
}

impl From<RedisInfo> for L7ProtocolSendLog {
    fn from(f: RedisInfo) -> Self {
        let log = L7ProtocolSendLog {
            req: L7Request {
                req_type: String::from_utf8_lossy(f.request_type.as_slice()).to_string(),
                resource: String::from_utf8_lossy(f.request.as_slice()).to_string(),
                ..Default::default()
            },
            resp: L7Response {
                status: f.resp_status,
                exception: String::from_utf8_lossy(f.error.as_slice()).to_string(),
                result: String::from_utf8_lossy(f.response.as_slice()).to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        return log;
    }
}

impl From<DnsInfo> for L7ProtocolSendLog {
    fn from(f: DnsInfo) -> Self {
        let req_type = String::from(get_domain_str(f.domain_type as usize));
        let log = L7ProtocolSendLog {
            req: L7Request {
                req_type,
                resource: f.query_name,
                ..Default::default()
            },
            resp: L7Response {
                result: f.answers,
                code: f.status_code,
                status: f.status,
                ..Default::default()
            },
            ext_info: Some(ExtendedInfo {
                request_id: Some(f.trans_id as u32),
                ..Default::default()
            }),
            ..Default::default()
        };

        return log;
    }
}

impl HttpInfo {
    // grpc path: /packageName.Servicename/rcpMethodName
    // return packetName, ServiceName
    fn grpc_package_service_name(&self) -> Option<(String, String)> {
        if !(self.proto == L7Protocol::Grpc) || self.path.len() < 6 {
            return None;
        }

        let idx: Vec<_> = self.path.match_indices("/").collect();
        if idx.len() != 2 {
            return None;
        }
        let (start, end) = (idx[0].0, idx[1].0);
        if let Some((p, _)) = self.path.match_indices(".").next() {
            if p > start && p < end {
                return Some((
                    String::from(&self.path[start + 1..p]),
                    String::from(&self.path[p + 1..end]),
                ));
            }
        }
        None
    }
}

impl From<HttpInfo> for L7ProtocolSendLog {
    fn from(f: HttpInfo) -> Self {
        let is_grpc = f.proto == L7Protocol::Grpc;
        let service_name = if let Some((package, service)) = f.grpc_package_service_name() {
            let svc_name = format!("{}.{}", package, service);
            Some(svc_name)
        } else {
            None
        };

        // grpc protocol special treatment
        let (req_type, resource, domain, endpoint) = if is_grpc {
            // server endpoint = req_type
            (
                String::from("POST"), // grpc method always post, reference https://chromium.googlesource.com/external/github.com/grpc/grpc/+/HEAD/doc/PROTOCOL-HTTP2.md
                service_name.clone().unwrap_or_default(),
                f.host,
                f.path,
            )
        } else {
            (f.method, f.path, f.host, String::new())
        };

        L7ProtocolSendLog {
            req_len: f.req_content_length,
            resp_len: f.resp_content_length,
            version: Some(f.version),
            req: L7Request {
                req_type,
                resource,
                domain,
                endpoint,
            },
            resp: L7Response {
                status: f.status,
                code: f.status_code,
                ..Default::default()
            },
            trace_info: Some(TraceInfo {
                trace_id: Some(f.trace_id),
                span_id: Some(f.span_id),
                ..Default::default()
            }),
            ext_info: Some(ExtendedInfo {
                request_id: f.stream_id,
                x_request_id: Some(f.x_request_id),
                client_ip: Some(f.client_ip),
                user_agent: f.user_agent,
                referer: f.referer,
                rpc_service: service_name,
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

impl From<KrpcInfo> for L7ProtocolSendLog {
    fn from(k: KrpcInfo) -> Self {
        let req_id = Some(k.sequence as u32);
        Self {
            req: L7Request {
                req_type: k.msg_id.to_string(),
                resource: k.serv_id.to_string(),
                endpoint: format!("{}/{}", k.serv_id, k.msg_id),
                ..Default::default()
            },
            resp: L7Response {
                status: k.status,
                code: Some(k.ret_code),
                ..Default::default()
            },
            trace_info: Some(TraceInfo {
                trace_id: Some(k.trace_id),
                span_id: Some(k.span_id),
                ..Default::default()
            }),
            ext_info: Some(ExtendedInfo {
                rpc_service: Some(k.serv_id.to_string()),
                request_id: req_id,
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}
