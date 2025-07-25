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

use crate::{
    common::{
        flow::{L7PerfStats, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, ParseParam},
    },
    flow_generator::{
        protocol_logs::{
            pb_adapter::{KeyVal, MetricKeyVal},
            set_captured_byte, IpProtocol, L7ResponseStatus, LogMessageType,
        },
        Error, Result,
    },
    plugin::{CustomInfo, CustomInfoRequest, CustomInfoResp, CustomInfoTrace},
};
use enterprise_utils::l7::plugin::custom_protocol_policy::{CustomPolicyInfo, CustomPolicyParser};
use public::{
    enums::TrafficDirection,
    l7_protocol::{CustomProtocol, L7Protocol, L7ProtocolEnum},
};

#[derive(Default)]
pub struct CustomPolicyLog {
    perf_stats: Option<L7PerfStats>,
    parser: CustomPolicyParser,
    proto_str: String,
    last_is_on_blacklist: bool,
}

impl L7ProtocolParserInterface for CustomPolicyLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if !param.ebpf_type.is_raw_protocol() {
            return false;
        }
        if param.l4_protocol != IpProtocol::TCP {
            return false;
        }
        let Some(config) = param.parse_config else {
            return false;
        };

        if config.custom_protocol_config.protocol_characters.is_empty() {
            return false;
        }

        let (port, direction) = match param.direction {
            PacketDirection::ClientToServer => (param.port_dst, TrafficDirection::Request),
            PacketDirection::ServerToClient => (param.port_src, TrafficDirection::Response),
        };

        match self
            .parser
            .check_payload(payload, &config.custom_protocol_config, direction, port)
        {
            Some(custom_protocol_name) => {
                self.proto_str = custom_protocol_name;
                return true;
            }
            None => {
                return false;
            }
        }
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        let Some(config) = param.parse_config else {
            return Err(Error::NoParseConfig);
        };

        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };

        let custom_protocol =
            L7ProtocolEnum::Custom(CustomProtocol::CustomPolicy(self.proto_str.clone()));

        let (port, direction) = match param.direction {
            PacketDirection::ClientToServer => (param.port_dst, TrafficDirection::Request),
            PacketDirection::ServerToClient => (param.port_src, TrafficDirection::Response),
        };

        let Some(policy) = config
            .l7_log_dynamic
            .extra_field_policies
            .get(&custom_protocol)
        else {
            return Err(Error::NoParseConfig);
        };
        let Some(indices) = policy.indices.find(port) else {
            return Err(Error::NoParseConfig);
        };

        if self
            .parser
            .parse_payload(payload, direction, &policy.policies, indices)
        {
            let mut info = CustomInfo::from((&self.parser.info, param.direction));
            info.msg_type = param.direction.into();
            info.proto_str = self.proto_str.clone();

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
            if !info.is_on_blacklist && !self.last_is_on_blacklist {
                match info.resp.status {
                    L7ResponseStatus::ServerError => {
                        self.perf_stats.as_mut().map(|p| p.inc_resp_err());
                    }
                    _ => (),
                }
                match param.direction {
                    PacketDirection::ClientToServer => {
                        self.perf_stats.as_mut().map(|p| p.inc_req());
                    }
                    PacketDirection::ServerToClient => {
                        self.perf_stats.as_mut().map(|p| p.inc_resp());
                    }
                }
                let endpoint = if info.req.endpoint.is_empty() {
                    None
                } else {
                    Some(info.req.endpoint.clone())
                };
                info.cal_rrt(param, &endpoint).map(|(rrt, endpoint)| {
                    info.rrt = rrt;
                    if info.msg_type == LogMessageType::Response {
                        info.req.endpoint = endpoint.unwrap_or_default();
                    }
                    self.perf_stats.as_mut().map(|p| p.update_rrt(rrt));
                });
            }

            set_captured_byte!(info, param);
            self.last_is_on_blacklist = info.is_on_blacklist;
            if param.parse_log {
                Ok(L7ParseResult::Single(L7ProtocolInfo::CustomInfo(info)))
            } else {
                Ok(L7ParseResult::None)
            }
        } else {
            Err(Error::CustomPolicyParseFail)
        }
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Custom
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }

    fn custom_protocol(&self) -> Option<CustomProtocol> {
        Some(CustomProtocol::CustomPolicy(self.proto_str.clone()))
    }
}

pub fn get_policy_parser(s: String) -> CustomPolicyLog {
    CustomPolicyLog {
        proto_str: s.clone(),
        perf_stats: None,
        last_is_on_blacklist: false,
        parser: CustomPolicyParser::default(),
    }
}

impl From<(&CustomPolicyInfo, PacketDirection)> for CustomInfo {
    fn from(p: (&CustomPolicyInfo, PacketDirection)) -> CustomInfo {
        let (info, direction) = p;
        CustomInfo {
            req: CustomInfoRequest {
                version: info.version.clone(),
                req_type: info.request_type.clone(),
                domain: info.request_domain.clone(),
                resource: info.request_resource.clone(),
                endpoint: info.endpoint.clone(),
            },
            resp: CustomInfoResp {
                status: L7ResponseStatus::from(info.response_status.as_str()),
                code: info.response_code.clone(),
                exception: info.response_exception.clone(),
                result: info.response_result.clone(),
            },
            trace: CustomInfoTrace {
                trace_id: info.trace_id.clone(),
                span_id: info.span_id.clone(),
                http_proxy_client: info.http_proxy_client.clone(),
                x_request_id_0: if direction == PacketDirection::ClientToServer {
                    info.x_request_id.clone()
                } else {
                    None
                },
                x_request_id_1: if direction == PacketDirection::ServerToClient {
                    info.x_request_id.clone()
                } else {
                    None
                },
                ..Default::default()
            },
            attributes: info
                .attributes
                .iter()
                .map(|(k, v)| KeyVal {
                    key: k.clone(),
                    val: v.clone(),
                })
                .collect(),
            metrics: info
                .metrics
                .iter()
                .map(|(k, v)| MetricKeyVal {
                    key: k.clone(),
                    val: v.clone(),
                })
                .collect(),
            ..Default::default()
        }
    }
}
