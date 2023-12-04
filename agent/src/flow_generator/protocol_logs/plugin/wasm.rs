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

use public::l7_protocol::{CustomProtocol, L7Protocol};

use crate::{
    common::{
        flow::{L7PerfStats, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{CheckResult, L7ParseResult, L7ProtocolParserInterface, ParseParam},
    },
    flow_generator::{protocol_logs::L7ResponseStatus, Error, Result},
};

#[derive(Default)]
pub struct WasmLog {
    proto_num: Option<u8>,
    proto_str: String,
    perf_stats: Option<L7PerfStats>,
}

impl L7ProtocolParserInterface for WasmLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> CheckResult {
        let Some(vm) = param.wasm_vm.as_ref() else {
            return CheckResult::Fail;
        };

        let mut vm = vm.borrow_mut();
        let res = vm.on_check_payload(&payload, &param);
        res.map(|(proto_num, proto_str)| {
            self.proto_num = Some(proto_num);
            self.proto_str = proto_str;
        });
        self.proto_num.is_some().into()
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        let Some(vm) = param.wasm_vm.as_ref() else {
            return Err(Error::WasmParseFail);
        };
        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default());
        }
        let mut vm = vm.borrow_mut();

        if let Some(infos) = vm.on_parse_payload(payload, param, self.proto_num.unwrap()) {
            let l7_infos: Vec<L7ProtocolInfo> = infos
                .into_iter()
                .map(|mut i| {
                    i.proto = self.proto_num.unwrap();
                    i.proto_str = self.proto_str.clone();
                    match i.resp.status {
                        L7ResponseStatus::ServerError => {
                            self.perf_stats.as_mut().map(|p| p.inc_resp_err());
                        }
                        L7ResponseStatus::ClientError => {
                            self.perf_stats.as_mut().map(|p| p.inc_req_err());
                        }
                        _ => {}
                    }

                    i.msg_type = param.direction.into();

                    if i.need_merge() {
                        i.cal_rrt_for_multi_merge_log(param).map(|rrt| {
                            i.rrt = rrt;
                        });
                        if i.is_req_end || i.is_resp_end {
                            self.perf_stats.as_mut().map(|p| p.update_rrt(i.rrt));

                            match param.direction {
                                PacketDirection::ClientToServer => {
                                    self.perf_stats.as_mut().map(|p| p.inc_req());
                                }
                                PacketDirection::ServerToClient => {
                                    self.perf_stats.as_mut().map(|p| p.inc_resp());
                                }
                            }
                        }
                    } else {
                        match param.direction {
                            PacketDirection::ClientToServer => {
                                self.perf_stats.as_mut().map(|p| p.inc_req());
                            }
                            PacketDirection::ServerToClient => {
                                self.perf_stats.as_mut().map(|p| p.inc_resp());
                            }
                        }

                        i.cal_rrt(param, None).map(|rrt| {
                            i.rrt = rrt;
                            self.perf_stats.as_mut().map(|p| p.update_rrt(rrt));
                        });
                    }

                    L7ProtocolInfo::CustomInfo(i)
                })
                .collect();
            Ok(L7ParseResult::Multi(l7_infos))
        } else {
            Err(Error::WasmParseFail)
        }
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Custom
    }

    fn custom_protocol(&self) -> Option<CustomProtocol> {
        Some(CustomProtocol::Wasm(
            self.proto_num.unwrap(),
            self.proto_str.clone(),
        ))
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }
}

pub fn get_wasm_parser(p: u8, s: String) -> WasmLog {
    WasmLog {
        proto_num: Some(p),
        proto_str: s,
        perf_stats: None,
    }
}
