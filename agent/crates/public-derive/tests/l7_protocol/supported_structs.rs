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

use std::borrow::Cow;

use public::{enums::L7ResponseStatus, l7_protocol::{Field, FieldSetter, L7Log}, types::PrioField};
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
struct StringField {
    endpoint: String,
    endpoint2: usize,
}

fn string_field() {
    let mut f = StringField {
        endpoint: "test".to_string(),
        endpoint2: 10,
    };
    assert_eq!(f.get_endpoint(), "test");
    f.set_endpoint(Field::from("test2").into());
    assert_eq!(f.get_endpoint(), "test2");
    f.set_endpoint(Field::from(10).into());
    assert_eq!(f.get_endpoint(), "10");
    f.set_endpoint(Field::None.into());
    assert_eq!(f.get_endpoint(), "");
}

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
struct OptionStringField {
    #[l7_log(endpoint)]
    path: Option<String>,
    endpoint: usize,
}

fn option_string_field() {
    let mut f = OptionStringField {
        path: Some("test".to_string()),
        endpoint: 10,
    };
    assert_eq!(f.get_endpoint(), "test");
    f.set_endpoint("test2".into());
    assert_eq!(f.get_endpoint(), "test2");
    assert_eq!(f.path, Some("test2".to_string()));
    f.set_endpoint(Field::from(10).into());
    assert_eq!(f.get_endpoint(), "10");
    f.set_endpoint(Field::None.into());
    assert_eq!(f.get_endpoint(), Field::None);
}

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
struct IntField {
    endpoint: String,
    // override endpoint field
    #[l7_log(endpoint)]
    endpoint2: usize,
}

fn int_field() {
    let mut f = IntField {
        endpoint: "test".to_string(),
        endpoint2: 10,
    };
    assert_eq!(f.get_endpoint(), 10);
    f.set_endpoint(Field::from("test2").into());
    assert_eq!(f.get_endpoint(), 0);
    f.set_endpoint(Field::from(20).into());
    assert_eq!(f.get_endpoint(), 20);
    assert_eq!(f.endpoint2, 20);
    f.set_endpoint(Field::from("100").into());
    assert_eq!(f.get_endpoint(), 100);
    f.set_endpoint(Field::None.into());
    assert_eq!(f.get_endpoint(), 0);
}

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
struct OptionIntField {
    #[l7_log(endpoint)]
    id: Option<usize>,
}

fn option_int_field() {
    let mut f = OptionIntField {
        id: Some(10),
    };
    assert_eq!(f.get_endpoint(), 10);
    f.set_endpoint(Field::Int(30).into());
    assert_eq!(f.get_endpoint(), 30);
    assert_eq!(f.id, Some(30));
    f.set_endpoint(Field::Str(Cow::Borrowed("20")).into());
    assert_eq!(f.get_endpoint(), 20);
    f.set_endpoint(Field::None.into());
    assert_eq!(f.get_endpoint(), Field::None);
}

#[derive(L7Log, Default)]
#[l7_log(endpoint.skip = "true")]
struct SkipField {
    endpoint: String,

    // all other fields, not used for testing
    version: String,
    request_type: String,
    request_domain: String,
    request_resource: String,
    request_id: usize,
    response_code: usize,
    response_status: L7ResponseStatus,
    response_exception: String,
    response_result: String,
    trace_id: String,
    span_id: String,
    x_request_id: String,
    http_proxy_client: String,
    biz_type: u8,
    biz_code: String,
    biz_scenario: String,
}

fn skip_field() {
    let mut f = SkipField {
        endpoint: "test".to_string(),
        ..Default::default()
    };
    assert_eq!(f.get_endpoint(), Field::None);
    f.set_endpoint(Field::from("test2").into());
    assert_eq!(f.get_endpoint(), Field::None);
    f.set_endpoint(Field::from(10).into());
    assert_eq!(f.get_endpoint(), Field::None);
    f.set_endpoint(Field::None.into());
    assert_eq!(f.get_endpoint(), Field::None);
}

#[derive(L7Log, Default)]
struct WithPrioField {
    endpoint: PrioField<String>,

    // all other fields, not used for testing
    version: String,
    request_type: String,
    request_domain: String,
    request_resource: String,
    request_id: usize,
    response_code: usize,
    response_status: L7ResponseStatus,
    response_exception: String,
    response_result: String,
    trace_id: String,
    span_id: String,
    x_request_id: String,
    http_proxy_client: String,
    biz_type: u8,
    biz_code: String,
    biz_scenario: String,
}

fn with_prio_field() {
    let mut f = WithPrioField::default();
    assert_eq!(f.get_endpoint(), "");
    f.set_endpoint("abc".into());
    assert_eq!(f.get_endpoint(), "abc");

    // set with low prio
    f.set_endpoint(FieldSetter::new(10, "cba".into()));
    assert_eq!(f.get_endpoint(), "abc");

    // set with high prio
    f.endpoint = PrioField::new(10, "ddd".into());
    assert_eq!(f.get_endpoint(), "ddd");
    f.set_endpoint(FieldSetter::new(9, "cba".into()));
    assert_eq!(f.get_endpoint(), "cba");
}

#[derive(L7Log, Default)]
struct OptionPrioField {
    endpoint: Option<PrioField<String>>,

    // all other fields, not used for testing
    version: String,
    request_type: String,
    request_domain: String,
    request_resource: String,
    request_id: usize,
    response_code: usize,
    response_status: L7ResponseStatus,
    response_exception: String,
    response_result: String,
    trace_id: String,
    span_id: String,
    x_request_id: String,
    http_proxy_client: String,
    biz_type: u8,
    biz_code: String,
    biz_scenario: String,
}

fn option_prio_field() {
    let mut f = OptionPrioField::default();
    assert_eq!(f.get_endpoint(), Field::None);
    f.set_endpoint("abc".into());
    assert_eq!(f.get_endpoint(), "abc");

    // set with low prio
    f.set_endpoint(FieldSetter::new(10, "cba".into()));
    assert_eq!(f.get_endpoint(), "abc");

    // set with high prio
    f.endpoint.replace(PrioField::new(10, "ddd".into()));
    assert_eq!(f.get_endpoint(), "ddd");
    f.set_endpoint(FieldSetter::new(9, "cba".into()));
    assert_eq!(f.get_endpoint(), "cba");
}

fn main() {
    string_field();
    option_string_field();
    int_field();
    option_int_field();
    skip_field();
    with_prio_field();
    option_prio_field();
}