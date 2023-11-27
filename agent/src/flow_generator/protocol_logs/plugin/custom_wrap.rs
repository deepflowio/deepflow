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

use public::l7_protocol::L7Protocol;
use serde::Serialize;

use crate::common::l7_protocol_log::{CheckResult, L7ParseResult, L7ProtocolParserInterface};

use super::{all_plugin_log_parser, CustomLog};

#[derive(Default, Debug, Serialize)]
pub struct CustomWrapLog {
    pub(super) parser: Option<CustomLog>,
}

impl L7ProtocolParserInterface for CustomWrapLog {
    fn check_payload(
        &mut self,
        payload: &[u8],
        param: &crate::common::l7_protocol_log::ParseParam,
    ) -> CheckResult {
        for mut p in all_plugin_log_parser().into_iter() {
            if p.check_payload(payload, param) == CheckResult::Ok {
                self.parser = Some(p);
                return CheckResult::Ok;
            }
        }
        CheckResult::Fail
    }

    fn parse_payload(
        &mut self,
        payload: &[u8],
        param: &crate::common::l7_protocol_log::ParseParam,
    ) -> crate::flow_generator::Result<L7ParseResult> {
        self.parser.as_mut().unwrap().parse_payload(payload, param)
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Custom
    }

    fn perf_stats(&mut self) -> Option<crate::common::flow::L7PerfStats> {
        self.parser.as_mut().and_then(|p| p.perf_stats())
    }

    fn reset(&mut self) {
        self.parser.as_mut().unwrap().reset()
    }

    fn custom_protocol(&self) -> Option<public::l7_protocol::CustomProtocol> {
        self.parser.as_ref().unwrap().custom_protocol()
    }
}
