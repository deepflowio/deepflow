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

use public_derive::L7Log;

#[derive(L7Log)]
#[l7_log(version.skip = "true")]
#[l7_log(request_type.skip = "true")]
#[l7_log(request_domain.skip = "true")]
#[l7_log(request_resource.skip = "true")]
#[l7_log(request_id.skip = "true")]
#[l7_log(response_code.skip = "true")]
#[l7_log(response_status.skip = "true")]
#[l7_log(response_exception.skip = "true")]
#[l7_log(response_result.skip = "true")]
#[l7_log(trace_id.skip = "true")]
#[l7_log(span_id.skip = "true")]
#[l7_log(x_request_id.skip = "true")]
#[l7_log(http_proxy_client.skip = "true")]
#[l7_log(biz_type.skip = "true")]
#[l7_log(biz_code.skip = "true")]
#[l7_log(biz_scenario.skip = "true")]
struct DuplicatedFields {
    #[l7_log(endpoint)]
    endpoint: String,
    #[l7_log(endpoint)]
    endpoint2: String,
}

fn main() {
}