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

use public::l7_protocol::L7Log;
use public_derive::L7Log;

#[derive(L7Log)]
struct TestInfo {
    version: String,
    request_type: String,
    request_domain: String,
    request_resource: String,
    request_id: usize,
    endpoint: String,
    response_code: usize,
    response_status: public::enums::L7ResponseStatus,
    response_exception: String,
    response_result: String,
    trace_id: String,
    span_id: String,
    x_request_id: String,
    http_proxy_client: String,
    biz_type: String,
    biz_code: String,
    biz_scenario: String,
}

fn main() {

}