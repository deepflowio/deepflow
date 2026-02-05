/*
 * Copyright (c) 2025 Yunshan Networks
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

use std::{borrow::Cow, sync::Arc};

use log::trace;

use enterprise_utils::l7::custom_policy::{
    custom_field_policy::{
        enums::{Op, PayloadType, Source},
        Store,
    },
    custom_protocol_policy::ExtraProtocolCharacters,
    enums::TrafficDirection,
};
use public::l7_protocol::{CustomProtocol, L7Log, L7LogAttribute, L7Protocol, LogMessageType};
use public_derive::L7Log;

use crate::{
    common::{
        flow::{L7PerfStats, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParser, L7ProtocolParserInterface, ParseParam},
    },
    flow_generator::{
        protocol_logs::{
            auto_merge_custom_field,
            pb_adapter::{KeyVal, MetricKeyVal},
            set_captured_byte, IpProtocol, L7ResponseStatus,
        },
        Error, Result,
    },
    plugin::{CustomInfo, CustomInfoRequest, CustomInfoResp, CustomInfoTrace},
};

#[derive(Default)]
pub struct CustomPolicyLog {
    perf_stats: Vec<L7PerfStats>,

    policy: Option<ExtraProtocolCharacters>,
    l7_parser: Option<Box<L7ProtocolParser>>,
    biz_protocol: Option<Arc<String>>,

    store: Store,
}

impl L7ProtocolParserInterface for CustomPolicyLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> Option<LogMessageType> {
        if !param.ebpf_type.is_raw_protocol() {
            return None;
        }
        if param.l4_protocol != IpProtocol::TCP {
            return None;
        }

        let (port, direction) = match param.direction {
            PacketDirection::ClientToServer => (param.port_dst, TrafficDirection::REQUEST),
            PacketDirection::ServerToClient => (param.port_src, TrafficDirection::RESPONSE),
        };

        let Some(policies) = param
            .parse_config
            .and_then(|c| c.custom_app.custom_protocol_config.as_ref())
            .and_then(|config| config.select(port))
        else {
            return None;
        };

        for policy in policies {
            let mut parser = if policy.l7_protocol() != L7Protocol::Custom {
                crate::common::l7_protocol_log::get_parser(policy.l7_protocol().into())
            } else {
                None
            };
            if let Some(p) = parser.as_mut() {
                // can only check l7 request now
                if direction == TrafficDirection::RESPONSE
                    || p.check_payload(payload, param).is_none()
                {
                    continue;
                }
            }
            match policy.check_payload(payload, direction) {
                None => continue,
                Some(msg_type) => {
                    trace!("found biz protocol in policy {}", policy.biz_protocol());
                    self.policy = Some(policy.clone());
                    self.l7_parser = parser.map(|p| Box::new(p));
                    self.biz_protocol = Some(Arc::new(policy.biz_protocol().to_string()));
                    return Some(msg_type);
                }
            }
        }

        return None;
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        let Some(config) = param.parse_config else {
            return Err(Error::NoParseConfig);
        };

        let Some(biz_protocol) = self.biz_protocol.as_ref() else {
            return Ok(L7ParseResult::None);
        };

        // check l7 payload on requests
        if param.direction == PacketDirection::ClientToServer {
            if let Some(p) = self.l7_parser.as_mut() {
                if p.check_payload(payload, param).is_none() {
                    return Ok(L7ParseResult::None);
                }
            }
        }
        match self.policy.as_ref() {
            Some(p) if p.check_payload(payload, param.direction.into()).is_some() => (),
            _ => return Ok(L7ParseResult::None),
        }

        let protocol = CustomProtocol::CustomPolicy(biz_protocol.clone());
        let Some(policies) = config.get_custom_field_policies(protocol.into(), param) else {
            return Err(Error::NoParseConfig);
        };

        trace!("apply biz decode policies to {biz_protocol}");
        let mut info = CustomPolicyInfo::default();
        self.perf_stats.clear();
        self.store.clear();
        policies.apply(
            &mut self.store,
            &info,
            param.direction.into(),
            Source::Payload(PayloadType::JSON | PayloadType::XML, payload),
        );

        let mut n_ops = 0;
        for op in self.store.drain_with(policies, &info) {
            match op.op {
                Op::AddMetric(key, value) => {
                    n_ops += 1;
                    info.metrics.push(MetricKeyVal {
                        key: key.to_string(),
                        val: value,
                    });
                }
                Op::SaveHeader(_) | Op::SavePayload(_) => (),
                _ => {
                    n_ops += 1;
                    auto_merge_custom_field(op, &mut info);
                }
            }
        }
        trace!("apply biz decode policies to {biz_protocol} success with {n_ops} ops");
        // at least one tag should be parsed
        if n_ops == 0 {
            return Ok(L7ParseResult::None);
        }

        let mut info = CustomInfo::from((info, param.direction));
        info.msg_type = param.direction.into();
        info.proto_str = biz_protocol.to_string();

        match info.msg_type {
            LogMessageType::Request => {
                info.req_len = Some(payload.len() as u32);
            }
            LogMessageType::Response => {
                info.resp_len = Some(payload.len() as u32);
            }
            _ => {}
        }

        info.set_is_on_blacklist(config);

        if param.parse_perf {
            let mut perf_stat = L7PerfStats::default();
            if info.msg_type == LogMessageType::Response && info.req.endpoint.is_empty() {
                if let Some(endpoint) = info.load_endpoint_from_cache(param, false) {
                    info.req.endpoint = endpoint.to_string();
                }
            }
            if let Some(stats) = info.perf_stats(param) {
                info.rrt = stats.rrt_sum;
                perf_stat.sequential_merge(&stats);
            }
            self.perf_stats.push(perf_stat);
        }

        set_captured_byte!(info, param);
        if param.parse_log {
            Ok(L7ParseResult::Single(L7ProtocolInfo::CustomInfo(info)))
        } else {
            Ok(L7ParseResult::None)
        }
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Custom
    }

    fn perf_stats(&mut self) -> Vec<L7PerfStats> {
        std::mem::take(&mut self.perf_stats)
    }

    fn custom_protocol(&self) -> Option<CustomProtocol> {
        match self.biz_protocol.as_ref() {
            Some(p) => Some(CustomProtocol::CustomPolicy(p.clone())),
            None => None,
        }
    }
}

impl CustomPolicyLog {
    pub fn get(name: Arc<String>) -> CustomPolicyLog {
        CustomPolicyLog {
            biz_protocol: Some(name),
            ..Default::default()
        }
    }
}

#[derive(L7Log, Default, Debug)]
#[l7_log(biz_type.skip = "true")]
#[l7_log(biz_code.skip = "true")]
#[l7_log(biz_scenario.skip = "true")]
pub struct CustomPolicyInfo {
    pub is_request: bool,
    pub version: String,
    pub request_type: String,
    pub request_domain: String,
    pub request_resource: String,
    pub endpoint: String,
    pub request_id: Option<u32>,
    pub response_code: Option<i32>,
    pub response_status: L7ResponseStatus,
    pub response_exception: String,
    pub response_result: String,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub http_proxy_client: Option<String>,
    pub x_request_id: Option<String>,
    pub attributes: Vec<KeyVal>,
    pub metrics: Vec<MetricKeyVal>,
    pub biz_response_code: String,
}

impl L7LogAttribute for CustomPolicyInfo {
    fn add_attribute(&mut self, name: Cow<'_, str>, value: Cow<'_, str>) {
        self.attributes.push(KeyVal {
            key: name.to_string(),
            val: value.to_string(),
        });
    }
}

impl From<(CustomPolicyInfo, PacketDirection)> for CustomInfo {
    fn from((info, direction): (CustomPolicyInfo, PacketDirection)) -> CustomInfo {
        CustomInfo {
            request_id: info.request_id,
            req: CustomInfoRequest {
                version: info.version,
                req_type: info.request_type,
                domain: info.request_domain,
                resource: info.request_resource,
                endpoint: info.endpoint,
            },
            resp: CustomInfoResp {
                status: L7ResponseStatus::from(info.response_status.as_str()),
                code: info.response_code,
                exception: info.response_exception,
                result: info.response_result,
                ..Default::default()
            },
            trace: {
                let mut trace = CustomInfoTrace {
                    trace_ids: match info.trace_id {
                        Some(trace_id) => vec![trace_id],
                        None => Vec::new(),
                    },
                    span_id: info.span_id,
                    http_proxy_client: info.http_proxy_client,
                    ..Default::default()
                };
                if direction == PacketDirection::ClientToServer {
                    trace.x_request_id_0 = info.x_request_id;
                } else {
                    trace.x_request_id_1 = info.x_request_id;
                }
                trace
            },
            attributes: info.attributes,
            metrics: info.metrics,
            biz_response_code: if info.biz_response_code.is_empty() {
                None
            } else {
                Some(info.biz_response_code)
            },
            ..Default::default()
        }
    }
}
