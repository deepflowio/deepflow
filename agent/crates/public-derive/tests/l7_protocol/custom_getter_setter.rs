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

use public::l7_protocol::{Field, FieldSetter, L7Log};
use public_derive::L7Log;

#[derive(L7Log)]
#[l7_log(endpoint.getter = "get_endpoint", endpoint.setter = "set_endpoint")]
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
struct CustomFields {
    switch: u8,
    field0: String,
    field1: String,
}

fn get_endpoint(fields: &CustomFields) -> Field<'_> {
    if fields.switch == 0 {
        Field::from(&fields.field0)
    } else {
        Field::from(&fields.field1)
    }
}

fn set_endpoint(fields: &mut CustomFields, value: FieldSetter<'_>) {
    match value.into_inner() {
        Field::Str(s) => {
            if fields.switch == 0 {
                fields.field0 = s.into_owned();
            } else {
                fields.field1 = s.into_owned();
            }
        }
        _ => (),
    }
}

fn main() {
    let mut fields = CustomFields {
        switch: 0,
        field0: "field0".to_string(),
        field1: "field1".to_string(),
    };
    assert_eq!(fields.get_endpoint(), Field::from("field0"));
    fields.set_endpoint(Field::from("field5").into());
    assert_eq!(fields.get_endpoint(), Field::from("field5"));
    assert_eq!(fields.field0, "field5");
    fields.switch = 1;
    assert_eq!(fields.get_endpoint(), Field::from("field1"));
    fields.set_endpoint(Field::from("field2").into());
    assert_eq!(fields.get_endpoint(), Field::from("field2"));
    assert_eq!(fields.field1, "field2");
}