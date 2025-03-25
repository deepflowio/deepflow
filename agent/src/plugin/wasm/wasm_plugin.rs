#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppRequest {
    #[prost(string, optional, tag = "1")]
    pub version: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "2")]
    pub r#type: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "3")]
    pub domain: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "4")]
    pub resource: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "5")]
    pub endpoint: ::core::option::Option<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppResponse {
    #[prost(enumeration = "AppRespStatus", optional, tag = "1")]
    pub status: ::core::option::Option<i32>,
    #[prost(int32, optional, tag = "2")]
    pub code: ::core::option::Option<i32>,
    #[prost(string, optional, tag = "3")]
    pub exception: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "4")]
    pub result: ::core::option::Option<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppTrace {
    #[prost(string, optional, tag = "1")]
    pub trace_id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "2")]
    pub span_id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "3")]
    pub parent_span_id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "4")]
    pub x_request_id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "5")]
    pub http_proxy_client: ::core::option::Option<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeyVal {
    #[prost(string, tag = "1")]
    pub key: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub val: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppInfo {
    #[prost(uint32, optional, tag = "1")]
    pub req_len: ::core::option::Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub resp_len: ::core::option::Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub request_id: ::core::option::Option<u32>,
    #[prost(message, optional, tag = "12")]
    pub trace: ::core::option::Option<AppTrace>,
    #[prost(string, optional, tag = "13")]
    pub protocol_str: ::core::option::Option<::prost::alloc::string::String>,
    /// a null `is_end` means no need for protocol merge
    #[prost(bool, optional, tag = "21")]
    pub is_end: ::core::option::Option<bool>,
    #[prost(message, repeated, tag = "31")]
    pub attributes: ::prost::alloc::vec::Vec<KeyVal>,
    #[prost(uint32, optional, tag = "32")]
    pub biz_type: ::core::option::Option<u32>,
    #[prost(oneof = "app_info::Info", tags = "10, 11")]
    pub info: ::core::option::Option<app_info::Info>,
}
/// Nested message and enum types in `AppInfo`.
pub mod app_info {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Info {
        #[prost(message, tag = "10")]
        Req(super::AppRequest),
        #[prost(message, tag = "11")]
        Resp(super::AppResponse),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NatsMessage {
    #[prost(string, tag = "1")]
    pub subject: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub reply_to: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "3")]
    pub payload: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ZmtpMessage {
    #[prost(bytes = "vec", tag = "2")]
    pub payload: ::prost::alloc::vec::Vec<u8>,
    #[prost(oneof = "zmtp_message::Subscription", tags = "1")]
    pub subscription: ::core::option::Option<zmtp_message::Subscription>,
}
/// Nested message and enum types in `ZmtpMessage`.
pub mod zmtp_message {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Subscription {
        #[prost(string, tag = "1")]
        MatchPattern(::prost::alloc::string::String),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum AppRespStatus {
    RespOk = 0,
    RespTimeout = 2,
    RespServerError = 3,
    RespClientError = 4,
    RespUnknown = 5,
}
impl AppRespStatus {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            AppRespStatus::RespOk => "RESP_OK",
            AppRespStatus::RespTimeout => "RESP_TIMEOUT",
            AppRespStatus::RespServerError => "RESP_SERVER_ERROR",
            AppRespStatus::RespClientError => "RESP_CLIENT_ERROR",
            AppRespStatus::RespUnknown => "RESP_UNKNOWN",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "RESP_OK" => Some(Self::RespOk),
            "RESP_TIMEOUT" => Some(Self::RespTimeout),
            "RESP_SERVER_ERROR" => Some(Self::RespServerError),
            "RESP_CLIENT_ERROR" => Some(Self::RespClientError),
            "RESP_UNKNOWN" => Some(Self::RespUnknown),
            _ => None,
        }
    }
}
