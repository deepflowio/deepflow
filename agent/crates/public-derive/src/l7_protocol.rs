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

use std::collections::HashMap;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{parse::ParseStream, parse2, DeriveInput};

const ATTRIBUTE_NAME: &str = "l7_log";

const NATIVE_TAG_RESPONSE_STATUS: &str = "response_status";
const NATIVE_TAG_X_REQUEST_ID: &str = "x_request_id";
const NATIVE_TAG_X_REQUEST_ID_0: &str = "x_request_id_0";
const NATIVE_TAG_X_REQUEST_ID_1: &str = "x_request_id_1";

cfg_if::cfg_if! {
    if #[cfg(not(target_os = "windows"))] {
        use public::l7_protocol::NativeTag;

        fn expected_fields() -> HashMap<&'static str, FieldOptions> {
            let fields = vec![
                NativeTag::Version,
                NativeTag::RequestType,
                NativeTag::RequestDomain,
                NativeTag::RequestResource,
                NativeTag::RequestId,
                NativeTag::Endpoint,
                NativeTag::ResponseCode,
                NativeTag::ResponseStatus,
                NativeTag::ResponseException,
                NativeTag::ResponseResult,
                NativeTag::TraceId,
                NativeTag::SpanId,
                NativeTag::XRequestId,
                NativeTag::XRequestId0,
                NativeTag::XRequestId1,
                NativeTag::HttpProxyClient,
                NativeTag::BizType,
                NativeTag::BizCode,
                NativeTag::BizScenario,
            ];
            HashMap::from_iter(
                fields
                    .into_iter()
                    .map(|field| (field.into(), FieldOptions::default())),
            )
        }
    } else {
        // Using anything in public crate will cause linking error under windows thus should be avoided.
        fn expected_fields() -> HashMap<&'static str, FieldOptions> {
            let fields = vec![
                "version",
                "request_type",
                "request_domain",
                "request_resource",
                "request_id",
                "endpoint",
                "response_code",
                NATIVE_TAG_RESPONSE_STATUS,
                "response_exception",
                "response_result",
                "trace_id",
                "span_id",
                NATIVE_TAG_X_REQUEST_ID,
                NATIVE_TAG_X_REQUEST_ID_0,
                NATIVE_TAG_X_REQUEST_ID_1,
                "http_proxy_client",
                "biz_type",
                "biz_code",
                "biz_scenario",
            ];
            HashMap::from_iter(
                fields
                    .into_iter()
                    .map(|field| (field, FieldOptions::default())),
            )
        }
    }
}

pub fn expand_derive(input: &DeriveInput) -> syn::Result<TokenStream> {
    let mut fields = expected_fields();
    parse_field_options(input, &mut fields)?;
    parse_fields(input, &mut fields)?;

    let xid_0_opts = fields.get(NATIVE_TAG_X_REQUEST_ID_0).unwrap();
    let xid_1_opts = fields.get(NATIVE_TAG_X_REQUEST_ID_1).unwrap();
    if (xid_0_opts.configured() || xid_0_opts.valid())
        && (xid_1_opts.configured() || xid_1_opts.valid())
    {
        let xid_opts = fields.get_mut(NATIVE_TAG_X_REQUEST_ID).unwrap();
        // remove invalid x_request_id if it's not configured
        if !xid_opts.configured() && !xid_opts.valid() {
            xid_opts.skip = true;
        }
    } else {
        // remove not configured or inferred x_request_id_0/1
        for id in [NATIVE_TAG_X_REQUEST_ID_0, NATIVE_TAG_X_REQUEST_ID_1] {
            let xid_opts = fields.get(id).unwrap();
            if !xid_opts.configured() && !xid_opts.valid() {
                fields.remove(id);
            }
        }
    }

    let mut function_impls = TokenStream::new();
    for (key, opts) in fields {
        if !opts.valid() {
            match (opts.getter.is_none(), opts.setter.is_none()) {
                (true, true) => {
                    return Err(syn::Error::new_spanned(
                        input,
                        format!("Missing field: {key}"),
                    ))
                }
                (true, _) => {
                    return Err(syn::Error::new_spanned(
                        input,
                        format!("Missing getter for field: {key}"),
                    ))
                }
                (_, true) => {
                    return Err(syn::Error::new_spanned(
                        input,
                        format!("Missing setter for field: {key}"),
                    ))
                }
                _ => unreachable!(),
            }
        };
        function_impls.extend(generate_impls(key, opts)?);
    }

    let name = &input.ident;
    Ok(quote! {
        impl L7Log for #name {
            #function_impls
        }
    })
}

#[derive(Default)]
struct FieldOptions {
    skip: bool,

    // attributed by l7_log, has higher priority than inferring from field name
    attributed: bool,
    source: Option<syn::Field>,

    getter: Option<syn::Path>,
    setter: Option<syn::Path>,
}

impl FieldOptions {
    fn configured(&self) -> bool {
        self.attributed || self.getter.is_some() || self.setter.is_some()
    }

    fn valid(&self) -> bool {
        self.skip || (self.getter.is_some() && self.setter.is_some()) || self.source.is_some()
    }
}

fn parse_field_options(
    input: &DeriveInput,
    expected_fields: &mut HashMap<&'static str, FieldOptions>,
) -> syn::Result<()> {
    for attr in input.attrs.iter() {
        if !attr.path().is_ident(ATTRIBUTE_NAME) {
            continue;
        }
        let Ok(meta) = attr.meta.require_list() else {
            continue;
        };
        meta.parse_args_with(|input: ParseStream| {
            loop {
                let name: syn::Ident = input.parse()?;
                let name_str = name.to_string();
                let Some(opts) = expected_fields.get_mut(name_str.as_str()) else {
                    return Err(syn::Error::new_spanned(
                        &name,
                        format!("Unknown field: {name}"),
                    ));
                };
                input.parse::<syn::Token![.]>()?;
                let option: syn::Ident = input.parse()?;
                if option != "getter" && option != "setter" && option != "skip" {
                    return Err(syn::Error::new_spanned(
                        &option,
                        format!("Unknown option: {option}"),
                    ));
                }
                input.parse::<syn::Token![=]>()?;
                let value: syn::LitStr = input.parse()?;
                if option == "getter" {
                    if opts.getter.is_some() {
                        return Err(syn::Error::new_spanned(
                            &option,
                            format!("Duplicated option: {option}"),
                        ));
                    }
                    let path = parse2::<syn::Path>(value.value().parse()?)?;
                    opts.getter.replace(path);
                } else if option == "setter" {
                    if opts.setter.is_some() {
                        return Err(syn::Error::new_spanned(
                            &option,
                            format!("Duplicated option: {option}"),
                        ));
                    }
                    let path = parse2::<syn::Path>(value.value().parse()?)?;
                    opts.setter.replace(path);
                } else if option == "skip" {
                    if value.value() == "true" {
                        opts.skip = true;
                    } else if value.value() == "false" {
                        opts.skip = false;
                    } else {
                        return Err(syn::Error::new_spanned(
                            &value,
                            format!("Invalid value for skip: {}", value.value()),
                        ));
                    }
                }
                if input.is_empty() {
                    break;
                }
                input.parse::<syn::Token![,]>()?;
            }
            Ok(())
        })?;
    }
    Ok(())
}

fn parse_fields(
    input: &DeriveInput,
    expected_fields: &mut HashMap<&'static str, FieldOptions>,
) -> syn::Result<()> {
    let data = match &input.data {
        syn::Data::Enum(data) => {
            return Err(syn::Error::new_spanned(
                data.enum_token,
                "Enum is not supported",
            ));
        }
        syn::Data::Union(data) => {
            return Err(syn::Error::new_spanned(
                data.union_token,
                "Union is not supported",
            ));
        }
        syn::Data::Struct(data) => match &data.fields {
            syn::Fields::Named(_) => data,
            syn::Fields::Unnamed(_) => {
                return Err(syn::Error::new_spanned(
                    &data.fields,
                    "Unnamed fields are not supported",
                ));
            }
            syn::Fields::Unit => {
                return Err(syn::Error::new_spanned(
                    &data.fields,
                    "Unit struct is not supported",
                ));
            }
        },
    };
    for field in data.fields.iter() {
        let Some(field_ident) = &field.ident else {
            continue;
        };
        // check attributes first
        for attr in field.attrs.iter() {
            if !attr.path().is_ident(ATTRIBUTE_NAME) {
                continue;
            }
            let meta = attr.meta.require_list()?;
            let ident = meta.parse_args::<syn::Ident>()?;
            let ident_str = ident.to_string();
            let Some(opts) = expected_fields.get_mut(ident_str.as_str()) else {
                return Err(syn::Error::new_spanned(ident, "Unknown field"));
            };
            if opts.attributed || (opts.getter.is_some() && opts.setter.is_some()) {
                return Err(syn::Error::new_spanned(ident, "Duplicated field attribute"));
            }
            opts.attributed = true;
            opts.source = Some(field.clone());
        }
        if let Some(opts) = expected_fields.get_mut(field_ident.to_string().as_str()) {
            if opts.attributed || (opts.getter.is_some() && opts.setter.is_some()) {
                continue;
            }
            opts.source = Some(field.clone());
        }
    }
    Ok(())
}

fn generate_response_status_getter(field: &syn::Ident, is_option: bool) -> TokenStream {
    if is_option {
        quote! {
            self.#field.unwrap_or_default()
        }
    } else {
        quote! {
            self.#field
        }
    }
}

fn generate_response_status_setter(field: &syn::Ident, is_option: bool) -> TokenStream {
    if is_option {
        quote! {
            self.#field.replace(value);
        }
    } else {
        quote! {
            self.#field = value;
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Wrapper {
    Option,
    PrioField,
}

fn generate_getter(field: &syn::Ident, wrappers: &[Wrapper], ty: &str) -> TokenStream {
    if ty == "L7ResponseStatus" {
        // response_status can only have Option wrapper
        return generate_response_status_getter(field, !wrappers.is_empty());
    }
    let mut tokens = TokenStream::new();
    tokens.extend(quote! {
        let field = &self.#field;
    });
    for wrapper in wrappers {
        match wrapper {
            Wrapper::Option => tokens.extend(quote! {
                let Some(field) = field.as_ref() else {
                    return ::public::l7_protocol::Field::None;
                };
            }),
            Wrapper::PrioField => tokens.extend(quote! {
                let field = field.get();
            }),
        }
    }
    if ty == "String" {
        tokens.extend(quote! {
            ::public::l7_protocol::Field::Str(std::borrow::Cow::Borrowed(field))
        });
    } else {
        tokens.extend(quote! {
            ::public::l7_protocol::Field::Int(*field as i64)
        });
    }
    tokens
}

fn generate_setter(field: &syn::Ident, wrappers: &[Wrapper], ty: &str) -> TokenStream {
    if ty == "L7ResponseStatus" {
        // response_status can only have Option wrapper
        return generate_response_status_setter(field, !wrappers.is_empty());
    }
    let get_owned_value = if ty == "String" {
        quote! {
            match value {
                ::public::l7_protocol::Field::Str(s) => s.into_owned(),
                ::public::l7_protocol::Field::Int(i) => i.to_string(),
                ::public::l7_protocol::Field::None => Default::default(),
            }
        }
    } else {
        quote! {
            match value {
                ::public::l7_protocol::Field::Str(s) => s.parse().unwrap_or_default(),
                ::public::l7_protocol::Field::Int(i) => i as _,
                ::public::l7_protocol::Field::None => Default::default(),
            }
        }
    };
    match (wrappers.get(0), wrappers.get(1)) {
        (Some(Wrapper::Option), Some(Wrapper::PrioField)) => quote! {
            let (prio, value) = (value.prio(), value.into_inner());
            if matches!(value, ::public::l7_protocol::Field::None) {
                self.#field = None;
            } else {
                match self.#field.as_mut() {
                    Some(field) => field.set_with(prio, || #get_owned_value),
                    None => self.#field = Some(PrioField::new(prio, #get_owned_value)),
                }
            }
        },
        (Some(Wrapper::PrioField), Some(Wrapper::Option)) => quote! {
            let (prio, value) = (value.prio(), value.into_inner());
            self.#field.set_with(prio, || match value {
                ::public::l7_protocol::Field::None => None,
                _ => Some(#get_owned_value),
            })
        },
        (Some(Wrapper::Option), None) => quote! {
            let value = value.into_inner();
            self.#field = match value {
                ::public::l7_protocol::Field::None => None,
                _ => Some(#get_owned_value),
            };
        },
        (Some(Wrapper::PrioField), None) => quote! {
            let (prio, value) = (value.prio(), value.into_inner());
            self.#field.set_with(prio, || #get_owned_value);
        },
        (None, _) => quote! {
            let value = value.into_inner();
            self.#field = #get_owned_value;
        },
        _ => unreachable!(),
    }
}

fn generate_impls(key: &str, options: FieldOptions) -> syn::Result<TokenStream> {
    let getter_ident = format_ident!("get_{}", key);
    let setter_ident = format_ident!("set_{}", key);

    let (value_type, value_setter_type) = if key == NATIVE_TAG_RESPONSE_STATUS {
        (
            quote!(::public::enums::L7ResponseStatus),
            quote!(::public::enums::L7ResponseStatus),
        )
    } else {
        (
            quote!(::public::l7_protocol::Field<'_>),
            quote!(::public::l7_protocol::FieldSetter<'_>),
        )
    };

    if options.skip {
        return Ok(quote! {
            #[automatically_derived]
            fn #getter_ident(&self) -> #value_type {
                Default::default()
            }
            #[automatically_derived]
            fn #setter_ident(&mut self, _value: #value_setter_type) {
            }
        });
    }

    if let Some((g, s)) = options.getter.as_ref().zip(options.setter.as_ref()) {
        return Ok(quote! {
            #[automatically_derived]
            fn #getter_ident(&self) -> #value_type {
                #g(&self)
            }
            #[automatically_derived]
            fn #setter_ident(&mut self, value: #value_setter_type) {
                #s(self, value)
            }
        });
    }

    let source = options.source.unwrap();
    let (ident, path) = match source.ty {
        syn::Type::Path(syn::TypePath { path, .. }) => (source.ident, path),
        _ => return Err(syn::Error::new_spanned(source.ty, "Unsupported field type")),
    };
    let mut wrappers = vec![];
    let mut path_segment = path.segments.last().unwrap();
    while path_segment.ident == "Option" || path_segment.ident == "PrioField" {
        if path_segment.ident == "Option" {
            wrappers.push(Wrapper::Option);
        } else if path_segment.ident == "PrioField" {
            wrappers.push(Wrapper::PrioField);
        }
        match &path_segment.arguments {
            syn::PathArguments::AngleBracketed(syn::AngleBracketedGenericArguments {
                args,
                ..
            }) => match &args.first() {
                Some(syn::GenericArgument::Type(syn::Type::Path(syn::TypePath {
                    path, ..
                }))) => path_segment = path.segments.last().unwrap(),
                _ => (),
            },
            _ => (),
        }
    }
    if key == NATIVE_TAG_RESPONSE_STATUS {
        // expecting only Option wrapper
        if !wrappers.is_empty() {
            if wrappers.len() != 1 || wrappers[0] != Wrapper::Option {
                return Err(syn::Error::new_spanned(
                    path,
                    "Unsupported response_status field type",
                ));
            }
        }
    } else {
        // can have only two different layers
        if !wrappers.is_empty() {
            if wrappers.len() > 2 || wrappers.get(0) == wrappers.get(1) {
                return Err(syn::Error::new_spanned(path, "Unsupported field type"));
            }
        }
    }

    let inner_type = path_segment.ident.to_string();
    match inner_type.as_str() {
        "String" => (),
        "i8" | "i16" | "i32" | "i64" | "isize" | "u8" | "u16" | "u32" | "u64" | "usize" => (),
        "L7ResponseStatus" if key == NATIVE_TAG_RESPONSE_STATUS => (),
        _ => return Err(syn::Error::new_spanned(path, "Unsupported field type")),
    }
    let field = ident.as_ref().unwrap();

    let getter_impl = match options.getter {
        Some(getter) => quote! {
            #getter(&self)
        },
        None => generate_getter(field, &wrappers, inner_type.as_str()),
    };
    let setter_impl = match options.setter {
        Some(setter) => quote! {
            #setter(self, value);
        },
        None => generate_setter(field, &wrappers, inner_type.as_str()),
    };
    Ok(quote! {
        #[automatically_derived]
        fn #getter_ident(&self) -> #value_type {
            #getter_impl
        }
        #[automatically_derived]
        fn #setter_ident(&mut self, value: #value_setter_type) {
            #setter_impl
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn expand_struct() {
        let input: DeriveInput = syn::parse_quote! {
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
            struct Test {
                endpoint: Option<PrioField<String>>,
            }
        };
        let output = expand_derive(&input).unwrap();
        println!("{}", output);
    }

    #[test]
    fn derive_test() {
        let t = trybuild::TestCases::new();
        t.pass("tests/l7_protocol/all_fields.rs");
        t.pass("tests/l7_protocol/supported_structs.rs");
        t.pass("tests/l7_protocol/custom_getter_setter.rs");
        t.pass("tests/l7_protocol/field_with_sides.rs");

        t.compile_fail("tests/l7_protocol/missing_fields.rs");
        t.compile_fail("tests/l7_protocol/duplicated_fields.rs");
    }
}
