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

#[derive(Default, PartialEq, Debug)]
pub struct OracleParser {
    pub sql: String,
    pub data_id: u8,
    pub call_id: u8,

    // response
    pub ret_code: u16,
    pub affected_rows: Option<u32>,
    pub error_message: String,
}

impl OracleParser {
    pub fn check_payload(&mut self, _: &[u8]) -> bool {
        false
    }

    pub fn parse_payload(&mut self, _: &[u8], _: bool) -> bool {
        unreachable!();
    }
}
