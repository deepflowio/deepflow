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

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod l7_protocol;

/// Usage of derive macro `L7Log`:
///
/// ```ignore
/// // omitting imports
///
/// #[derive(L7Log)]
/// struct MyStruct {
///     version: String,
///     request_type: String,
///     request_domain: String,
///     request_resource: String,
///     request_id: usize,
///     endpoint: String,
///     response_code: usize,
///     response_status: public::enums::L7ResponseStatus,
///     response_exception: String,
///     response_result: String,
///     trace_id: String,
///     span_id: String,
///     x_request_id: String,
///     http_proxy_client: String,
///     biz_type: String,
///     biz_code: String,
///     biz_scenario: String,
/// }
/// ```
///
/// Deriving `L7Log` will automatically generate getters and setters for all fields in `L7Log` trait.
///
/// Field types supported are:
/// - For `response_status`:
///   - L7ResponseStatus
///   - Option<L7ResponseStatus>
/// - For other fields:
///   - String
///   - i8, i16, i32, i64, isize, u8, u16, u32, u64, usize
///   - Option<T> for all previous types
///   - PrioField<T> for all previous types
///   - Option<PrioField<T>> for all previous types
///   - PrioField<Option<T>> for all previous types
///
/// For types that are not in the list, custom getters and setters can be specified as follows:
///
/// ```ignore
/// // omitting imports
///
/// #[derive(L7Log)]
/// #[l7_log(endpoint.getter = "MyStruct::get_endpoint", endpoint.setter = "MyStruct::set_endpoint")]
/// struct MyStruct {
///     endpoint: Endpoint,
/// }
///
/// impl MyStruct {
///     fn get_endpoint(&self) -> Field<'_> {
///         // construct Field from your own data
///     }
///
///     fn set_endpoint(&mut self, field: FieldSetter<'_>) {
///         // set your own data from Field
///     }
/// }
/// ```
///
/// Fields can also be renamed by using `l7_log` attribute.
///
/// ```ignore
/// // omitting imports
///
/// #[derive(L7Log)]
/// struct MyStruct {
///     #[l7_log(response_code)]
///     code: String,
/// }
/// ```
///
/// Fields can be skipped by using `l7_log` attribute.
///
/// ```ignore
/// // omitting imports
///
/// #[derive(L7Log)]
/// #[l7_log(response_code.skip = "true")]
/// struct MyStruct {
/// }
/// ```
///
/// Empty implementations of getters and setters for skipped fields will be generated.
#[proc_macro_derive(L7Log, attributes(l7_log))]
pub fn l7_log_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    l7_protocol::expand_derive(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
