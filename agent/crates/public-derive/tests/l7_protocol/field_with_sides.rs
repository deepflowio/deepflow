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

use public::l7_protocol::{Field, L7Log};
use public_derive::L7Log;

#[derive(L7Log)]
#[l7_log(version.skip = "true")]
#[l7_log(request_type.skip = "true")]
#[l7_log(request_domain.skip = "true")]
#[l7_log(request_resource.skip = "true")]
#[l7_log(endpoint.skip = "true")]
#[l7_log(request_id.skip = "true")]
#[l7_log(response_code.skip = "true")]
#[l7_log(response_status.skip = "true")]
#[l7_log(response_exception.skip = "true")]
#[l7_log(response_result.skip = "true")]
#[l7_log(trace_id.skip = "true")]
#[l7_log(span_id.skip = "true")]
#[l7_log(http_proxy_client.skip = "true")]
#[l7_log(biz_type.skip = "true")]
#[l7_log(biz_code.skip = "true")]
#[l7_log(biz_scenario.skip = "true")]
struct SoloField {
    x_request_id: String,
}

#[derive(L7Log)]
#[l7_log(version.skip = "true")]
#[l7_log(request_type.skip = "true")]
#[l7_log(request_domain.skip = "true")]
#[l7_log(request_resource.skip = "true")]
#[l7_log(endpoint.skip = "true")]
#[l7_log(request_id.skip = "true")]
#[l7_log(response_code.skip = "true")]
#[l7_log(response_status.skip = "true")]
#[l7_log(response_exception.skip = "true")]
#[l7_log(response_result.skip = "true")]
#[l7_log(trace_id.skip = "true")]
#[l7_log(span_id.skip = "true")]
#[l7_log(http_proxy_client.skip = "true")]
#[l7_log(biz_type.skip = "true")]
#[l7_log(biz_code.skip = "true")]
#[l7_log(biz_scenario.skip = "true")]
struct DuetField {
    x_request_id_0: String,
    x_request_id_1: String,
}

fn solo_field() {
    let mut f = SoloField {
        x_request_id: "test".to_string(),
    };
    assert_eq!(f.get_x_request_id(), "test");
    f.set_x_request_id("test2".into());
    assert_eq!(f.get_x_request_id(), "test2");
    f.set_x_request_id_0(10.into());
    assert_eq!(f.get_x_request_id_1(), "10");
    f.set_x_request_id_1(Field::None.into());
    assert_eq!(f.get_x_request_id_0(), "");
    assert_eq!(f.x_request_id, "");
}

fn duet_field() {
    let mut f = DuetField {
        x_request_id_0: "req_id_0".to_string(),
        x_request_id_1: "req_id_1".to_string(),
    };
    assert_eq!(f.get_x_request_id_0(), "req_id_0");
    assert_eq!(f.get_x_request_id_1(), "req_id_1");
    f.set_x_request_id_0("test".into());
    f.set_x_request_id_1("".into());
    assert_eq!(f.get_x_request_id_0(), "test");
    assert_eq!(f.get_x_request_id_1(), "");
    assert_eq!(f.x_request_id_0, "test");
    assert_eq!(f.x_request_id_1, "");
}

fn main() {
    solo_field();
    duet_field();
}