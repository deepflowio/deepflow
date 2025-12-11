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
/// ```rust
/// use public_derive::L7Log;
/// use public::l7_protocol::Field;
///
/// #[derive(L7Log)]
/// #[l7_log(endpoint.getter = "get_endpoint", endpoint.setter = "set_endpoint")]
/// struct MyStruct {
///     #[l7_log(endpoint, setter = "set_endpoint", getter = "get_endpoint")]
///     ep: Field,
/// }
/// ```

#[proc_macro_derive(L7Log, attributes(l7_log))]
pub fn l7_log_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    l7_protocol::expand_derive(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
