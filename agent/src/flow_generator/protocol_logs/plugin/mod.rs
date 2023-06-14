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

use enum_dispatch::enum_dispatch;
use public::l7_protocol::{CustomProtocol, L7Protocol, L7ProtocolEnum, ProtobufRpcProtocol};
use serde::Serialize;
use wasm::WasmLog;

use crate::{
    common::{
        flow::L7PerfStats,
        l7_protocol_info::L7ProtocolInfo,
        l7_protocol_log::{L7ProtocolParser, L7ProtocolParserInterface, ParseParam},
    },
    flow_generator::Result,
};

use self::{custom_wrap::CustomWrapLog, wasm::get_wasm_parser};

pub mod custom_wrap;
pub mod wasm;

#[derive(Debug, Serialize)]
#[enum_dispatch(L7ProtocolParserInterface)]
pub enum CustomLog {
    WasmLog(WasmLog),
}

pub fn get_custom_log_parser(proto: CustomProtocol) -> L7ProtocolParser {
    L7ProtocolParser::Custom(CustomWrapLog {
        parser: Some(match proto {
            CustomProtocol::Wasm(p, s) => CustomLog::WasmLog(get_wasm_parser(p, s)),
        }),
    })
}

#[inline(always)]
fn all_plugin_log_parser() -> [CustomLog; 1] {
    [CustomLog::WasmLog(WasmLog::default())]
}
