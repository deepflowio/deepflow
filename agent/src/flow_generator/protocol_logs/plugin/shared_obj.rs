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

use std::{
    sync::atomic::Ordering,
    time::{SystemTime, UNIX_EPOCH},
};

use log::error;
use public::l7_protocol::{CustomProtocol, L7Protocol};

use crate::{
    common::{
        flow::L7PerfStats,
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, ParseParam},
    },
    flow_generator::{
        protocol_logs::{set_captured_byte, L7ResponseStatus, LogMessageType},
        Error, Result,
    },
    plugin::{
        c_ffi::{c_str_to_string, ParseCtx, ParseInfo, ACTION_CONTINUE, ACTION_ERROR, ACTION_OK},
        CustomInfo,
    },
};

const RESULT_LEN: i32 = 8;

#[derive(Default)]
pub struct SoLog {
    proto_num: Option<u8>,
    proto_str: String,
    perf_stats: Option<L7PerfStats>,
}

impl L7ProtocolParserInterface for SoLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        let so_func_ref = param.so_func.borrow();
        let Some(c_funcs) = &*so_func_ref else {
            return false;
        };
        let ctx = &ParseCtx::from((param, payload));

        for c in c_funcs.iter() {
            let counter = &c.check_payload_counter;

            let start_time = SystemTime::now();
            let start_time = start_time.duration_since(UNIX_EPOCH).unwrap();

            /*
                call the func from so, correctness depends on plugin implementation.

                there is impossible to verify the plugin implemention correctness, so plugin maybe do some UB,
                for eaxmple, modify the payload (due to the payload is not copy but pass the ptr to ctx directly and should
                not be modify, modify the payload is UB).

                the plugin correctness depend on the implementation of the developer
            */
            let res = unsafe { (c.check_payload)(ctx as *const ParseCtx) };

            counter.exe_duration.swap(
                {
                    let end_time = SystemTime::now();
                    let end_time = end_time.duration_since(UNIX_EPOCH).unwrap();
                    // Local timestamp may be modified
                    if end_time > start_time {
                        (end_time - start_time).as_micros() as u64
                    } else {
                        0
                    }
                },
                Ordering::Relaxed,
            );

            if res.proto != 0 {
                self.proto_num = res.proto.into();
                match c_str_to_string(&res.proto_name) {
                    Some(s) => self.proto_str = s,
                    None => {
                        error!("read proto str from so plugin fail");
                        counter.fail_cnt.fetch_add(1, Ordering::Relaxed);
                        return false;
                    }
                }
                return true;
            }
        }
        false
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        let so_func_ref = param.so_func.borrow();
        let Some(c_funcs) = &*so_func_ref else {
            return Err(Error::NoParseConfig);
        };

        let ctx = &mut ParseCtx::from((param, payload));
        ctx.proto = self.proto_num.unwrap();
        let mut resp = [ParseInfo::default(); RESULT_LEN as usize];

        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default());
        }

        for c in c_funcs.iter() {
            let counter = &c.parse_payload_counter;

            let start_time = SystemTime::now();
            let start_time = start_time.duration_since(UNIX_EPOCH).unwrap();

            /*
                call the func from so, correctness depends on plugin implementation

                there is impossible to verify the plugin implemention correctness, so plugin maybe do some UB,
                for example, set the wrong msg_type will make the log take the incorrect data in union.

                the plugin correctness depend on the implementation of the developer
            */
            let res = unsafe {
                (c.parse_payload)(
                    ctx as *const ParseCtx,
                    &mut resp as *mut ParseInfo,
                    RESULT_LEN,
                )
            };

            counter.exe_duration.swap(
                {
                    let end_time = SystemTime::now();
                    let end_time = end_time.duration_since(UNIX_EPOCH).unwrap();
                    // Local timestamp may be modified
                    if end_time > start_time {
                        (end_time - start_time).as_micros() as u64
                    } else {
                        0
                    }
                },
                Ordering::Relaxed,
            );

            match res.action {
                ACTION_OK => {
                    if res.len == 0 {
                        return Ok(L7ParseResult::None);
                    }
                    if res.len > RESULT_LEN {
                        error!(
                            "so plugin {} return large result length {}",
                            c.name, res.len
                        );
                        counter.fail_cnt.fetch_add(1, Ordering::Relaxed);
                        return Err(Error::SoReturnUnexpectVal);
                    }
                    let mut v = vec![];
                    for i in 0..res.len as usize {
                        match CustomInfo::try_from(resp[i]) {
                            Ok(mut info) => {
                                info.proto_str = self.proto_str.clone();
                                info.proto = self.proto_num.unwrap();
                                set_captured_byte!(info, param);
                                match info.msg_type {
                                    LogMessageType::Request => {
                                        self.perf_stats.as_mut().map(|p| p.inc_req());
                                    }
                                    LogMessageType::Response => {
                                        self.perf_stats.as_mut().map(|p| p.inc_resp());
                                    }
                                    _ => unreachable!(),
                                }

                                match info.resp.status {
                                    L7ResponseStatus::ClientError => {
                                        self.perf_stats.as_mut().map(|p| p.inc_req_err());
                                    }
                                    L7ResponseStatus::ServerError => {
                                        self.perf_stats.as_mut().map(|p| p.inc_resp_err());
                                    }
                                    _ => {}
                                }

                                info.cal_rrt(param, None).map(|rrt| {
                                    info.rrt = rrt;
                                    self.perf_stats.as_mut().map(|p| p.update_rrt(rrt));
                                });
                                if res.len == 1 {
                                    return Ok(L7ParseResult::Single(L7ProtocolInfo::CustomInfo(
                                        info,
                                    )));
                                }
                                v.push(L7ProtocolInfo::CustomInfo(info));
                            }
                            Err(e) => {
                                counter.fail_cnt.fetch_add(1, Ordering::Relaxed);
                                error!("so plugin {} convert l7 info fail: {}", c.name, e);
                            }
                        }
                    }
                    return Ok(L7ParseResult::Multi(v));
                }
                ACTION_CONTINUE => continue,
                ACTION_ERROR => {
                    counter.fail_cnt.fetch_add(1, Ordering::Relaxed);
                    return Err(Error::SoParseFail);
                }

                _ => {
                    error!("so plugin {} return unknown action {}", c.name, res.action);
                    counter.fail_cnt.fetch_add(1, Ordering::Relaxed);
                    return Err(Error::SoReturnUnexpectVal);
                }
            }
        }
        Err(Error::SoParseFail)
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Custom
    }

    fn custom_protocol(&self) -> Option<CustomProtocol> {
        Some(CustomProtocol::So(
            self.proto_num.unwrap(),
            self.proto_str.clone(),
        ))
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }
}

pub fn get_so_parser(p: u8, s: String) -> SoLog {
    SoLog {
        proto_num: Some(p),
        proto_str: s,
        perf_stats: None,
    }
}
