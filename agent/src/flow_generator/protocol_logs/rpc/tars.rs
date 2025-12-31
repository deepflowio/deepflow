/*
 * Copyright (c) 2024 Yunshan Networks
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

use std::{num::NonZeroUsize, str};

use nom::{
    bytes::complete::take,
    number::complete::{be_i16, be_i32, be_i64, be_i8, be_u32, be_u8},
    IResult,
};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::Serialize;

use public::l7_protocol::LogMessageType;

use crate::{
    common::{
        flow::{L7PerfStats, L7Protocol},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, LogCache, ParseParam},
    },
    config::handler::LogParserConfig,
    flow_generator::{
        error::{Error, Result},
        protocol_logs::{
            pb_adapter::{ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response},
            AppProtoHead, L7ResponseStatus,
        },
    },
};

/*
These parameters can be determined from the framework code (Refer to the notes below)
based on the actual value range of some data in the header.
*/
const MIN_BODY_SIZE: usize = 12;
const HEADER_SIZE: usize = 4;
const VERSION_INDEX: usize = 5;
const INITIAL_LEN: usize = 7;

#[derive(Clone, Copy, Debug, Default, TryFromPrimitive, IntoPrimitive, Serialize)]
#[repr(i32)]
enum ErrorCode {
    // Server-side processing is successful
    ServerSuccess = 0,
    // Server-side decoding exception
    ServerDecodeErr = -1,
    // Server-side encoding exception
    ServerEncodeErr = -2,
    // Server-side does not have the function
    ServerNoFuncErr = -3,
    // Server-side does not have the Servant object
    ServerNoServantErr = -4,
    // Server-side gray status is inconsistent
    ServerResetGrid = -5,
    // Server-side queue exceeds the limit
    ServerQueueTimeout = -6,
    // Asynchronous call timeout or Invocation timeout
    AsyncCallOrInvokeTimeout = -7,
    // Proxy connection exception
    ProxyConnectErr = -8,
    // Server-side overload, exceeds queue length
    ServerOverload = -9,
    // Client-side routing is empty, service does not exist or all services are down
    AdapterNull = -10,
    // Client-side invocation by set rule is illegal
    InvokeByInvalidEset = -11,
    // Client-side decoding exception
    ClientDecodeErr = -12,
    // Server-side unknown exception
    #[default]
    ServerUnknownErr = -99,
}

impl From<ErrorCode> for L7ResponseStatus {
    fn from(value: ErrorCode) -> Self {
        match value {
            ErrorCode::ServerSuccess => L7ResponseStatus::Ok,
            ErrorCode::AdapterNull
            | ErrorCode::InvokeByInvalidEset
            | ErrorCode::ClientDecodeErr => L7ResponseStatus::ClientError,
            ErrorCode::ServerDecodeErr
            | ErrorCode::ServerEncodeErr
            | ErrorCode::ServerNoFuncErr
            | ErrorCode::ServerNoServantErr
            | ErrorCode::ServerResetGrid
            | ErrorCode::ServerQueueTimeout
            | ErrorCode::AsyncCallOrInvokeTimeout
            | ErrorCode::ProxyConnectErr
            | ErrorCode::ServerOverload
            | ErrorCode::ServerUnknownErr => L7ResponseStatus::ServerError,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct TarsInfo {
    msg_type: LogMessageType,

    rrt: u64,

    is_tls: bool,

    req_len: u32,
    resp_len: u32,

    pkt_type: u32,
    request_id: u32,
    imsg_type: u32,

    req_service_name: Option<String>,
    req_method_name: Option<String>,

    captured_request_byte: u32,
    captured_response_byte: u32,

    ret: Option<ErrorCode>,

    is_on_blacklist: bool,

    tars_version: u8,

    endpoint: Option<String>,
}

/*
tars reference
-----------------------
1. Basic types and packets of TARS protocols
https://doc.tarsyun.com/#/base/tars-protocol.md

-----------------------
2. For detailed protocol implementation,
   maybe you need to refer to the official framework code,
   and the protocol documentation is not very detailed
https://github.com/TarsCloud

PS:
Framework code discovery is not mentioned in the protocol documentation:
1. The protocol does not have a magic number header
2. The first four bytes of the data packet represent the entire length of the data packet.
3. The string type in the data packet may contain binary data
4. The data type will be compressed and the shortest type will be selected for transmission.
-----------------------
*/

const TYPE_INT8: u8 = 0;
const TYPE_INT16: u8 = 1;
const TYPE_INT32: u8 = 2;
const TYPE_INT64: u8 = 3;
const TYPE_FLOAT: u8 = 4;
const TYPE_DOUBLE: u8 = 5;
const TYPE_STRING1: u8 = 6;
const TYPE_STRING4: u8 = 7;
const TYPE_MAPS: u8 = 8;
const TYPE_LIST: u8 = 9;
const TYPE_STRUCT_BEGIN: u8 = 10;
const TYPE_STRUCT_END: u8 = 11;
const TYPE_ZERO: u8 = 12;
const TYPE_SIMPLE_LIST: u8 = 13;

#[derive(Clone, Copy)]
enum Field<'a> {
    Integer(u8, i64),
    String(u8, &'a str),
    // there are other irrelevant types
}

impl<'a> Field<'a> {
    fn parse(input: &'a [u8]) -> IResult<&'a [u8], Field<'a>> {
        let (input, b) = take(1usize)(input)?;
        let field_type = b[0] & 0x0F;
        let tag = (b[0] >> 4) & 0x0F;

        // tag id larger than 14 is not necessary at the moment
        if tag == 0xF {
            return Err(nom::Err::Failure(nom::error::Error::new(
                b,
                nom::error::ErrorKind::Verify,
            )));
        }

        match field_type {
            TYPE_INT8 => {
                let (input, value) = be_i8(input)?;
                Ok((input, Field::Integer(tag, value as i64)))
            }
            TYPE_INT16 => {
                let (input, value) = be_i16(input)?;
                Ok((input, Field::Integer(tag, value as i64)))
            }
            TYPE_INT32 => {
                let (input, value) = be_i32(input)?;
                Ok((input, Field::Integer(tag, value as i64)))
            }
            TYPE_INT64 => {
                let (input, value) = be_i64(input)?;
                Ok((input, Field::Integer(tag, value as i64)))
            }
            TYPE_STRING1 => {
                let (input, value) = be_u8(input)?;
                let (input, s) = take(value as usize)(input)?;
                match str::from_utf8(s) {
                    Ok(s) => Ok((input, Field::String(tag, s))),
                    Err(_) => Err(nom::Err::Failure(nom::error::Error::new(
                        s,
                        nom::error::ErrorKind::Verify,
                    ))),
                }
            }
            TYPE_STRING4 => {
                let (input, value) = be_u32(input)?;
                let (input, s) = take(value as usize)(input)?;
                match str::from_utf8(s) {
                    Ok(s) => Ok((input, Field::String(tag, s))),
                    Err(_) => Err(nom::Err::Failure(nom::error::Error::new(
                        s,
                        nom::error::ErrorKind::Verify,
                    ))),
                }
            }
            TYPE_ZERO => Ok((input, Field::Integer(tag, 0))),
            _ => Err(nom::Err::Failure(nom::error::Error::new(
                b,
                nom::error::ErrorKind::Verify,
            ))),
        }
    }

    fn tag(&self) -> u8 {
        match self {
            Field::Integer(tag, _) => *tag,
            Field::String(tag, _) => *tag,
        }
    }
}

/*
The parsing rules are:
1. The current field gets tag and type based on the header of the data type.(use ByteParser)
2. Get data.
3. Do the same for the next field.

The meaning of parameters in some codes:
head_x: Data header of the xth field
data_x: The actual data of the xth field

Since the value range of the first few fields is limited,
it may not be necessary to distinguish all shaping types.
For details, please refer to the protocol document and actual framework code.
*/

impl TarsInfo {
    fn generate_endpoint(&self) -> Option<String> {
        format!(
            "{}/{}",
            self.req_service_name.as_ref()?,
            self.req_method_name.as_ref()?
        )
        .into()
    }

    fn parse<'a>(payload: &'a [u8]) -> IResult<&'a [u8], TarsInfo> {
        let (input, total_len) = be_u32(payload)?;
        if total_len as usize > payload.len() {
            return Err(nom::Err::Incomplete(nom::Needed::Size(
                NonZeroUsize::new(total_len as usize).unwrap(),
            )));
        }

        let (mut input, ver) = Field::parse(input)?;
        let ver = match ver {
            // only support version 1 and 3
            Field::Integer(1, v) if v == 1 || v == 3 => v,
            _ => {
                return Err(nom::Err::Failure(nom::error::Error::new(
                    payload,
                    nom::error::ErrorKind::Verify,
                )))
            }
        };

        /*
           we only care about field 2-6 in tars packets

           request fields:
               struct RequestPacket
               {
                   1  require short        iVersion;         //版本号
                   2  optional byte        cPacketType;      //包类型
                   3  optional int         iMessageType;     //消息类型
                   4  require int          iRequestId;       //请求ID
                   5  require string       sServantName;     //servant名字
                   6  require string       sFuncName;        //函数名称
                   7  require vector<byte> sBuffer;          //二进制buffer
                   8  optional int         iTimeout;         //超时时间（毫秒）
                   9  optional map<string, string> context;  //业务上下文
                   10 optional map<string, string> status;   //框架协议上下文
               };

           response fields:
               struct ResponsePacket
               {
                   1 require short         iVersion;       //版本号
                   2 optional byte         cPacketType;    //包类型
                   3 require int           iRequestId;     //请求ID
                   4 optional int          iMessageType;   //消息类型
                   5 optional int          iRet;           //返回值
                   6 require vector<byte>  sBuffer;        //二进制流
                   7 optional map<string, string> status;  //协议上下文
                   8 optional string       sResultDesc;    //结果描述
               };
        */
        let mut fields = [None; 5]; // field 2-6

        // assume tag is in ascending order
        loop {
            let Ok((next, field)) = Field::parse(input) else {
                break;
            };
            let tag = field.tag() as usize;
            match tag {
                2..=6 => fields[tag - 2] = Some(field),
                _ => break,
            }
            input = next;
        }

        let mut info = TarsInfo {
            tars_version: ver as u8,
            ..Default::default()
        };
        if let Some(Field::Integer(tag, value)) = fields[0] {
            assert_eq!(tag, 2);
            info.pkt_type = value as u32;
        }
        // if field 5 exists and is a string, then it's tars request
        match fields[3] {
            Some(Field::String(tag, _)) => {
                assert_eq!(tag, 5);

                info.msg_type = LogMessageType::Request;
                info.req_len = total_len;
                info.captured_request_byte = payload.len() as u32;
                if let Some(Field::Integer(tag, value)) = fields[1] {
                    assert_eq!(tag, 3);
                    info.imsg_type = value as u32;
                }
                if let Some(Field::Integer(tag, value)) = fields[2] {
                    assert_eq!(tag, 4);
                    info.request_id = value as u32;
                }
                if let Some(Field::String(tag, value)) = fields[3] {
                    assert_eq!(tag, 5);
                    info.req_service_name = Some(value.to_string());
                }
                if let Some(Field::String(tag, value)) = fields[4] {
                    assert_eq!(tag, 6);
                    info.req_method_name = Some(value.to_string());
                }
                info.endpoint = info.generate_endpoint();
            }
            _ => {
                info.msg_type = LogMessageType::Response;
                info.resp_len = total_len;
                info.captured_response_byte = payload.len() as u32;

                if let Some(Field::Integer(tag, value)) = fields[1] {
                    assert_eq!(tag, 3);
                    info.request_id = value as u32;
                }
                if let Some(Field::Integer(tag, value)) = fields[2] {
                    assert_eq!(tag, 4);
                    info.imsg_type = value as u32;
                }
                if let Some(Field::Integer(tag, value)) = fields[3] {
                    assert_eq!(tag, 5);
                    info.ret = Some(ErrorCode::try_from(value as i32).unwrap_or_default());
                }
            }
        }
        Ok((input, info))
    }

    fn merge(&mut self, other: &mut Self) {
        if other.is_on_blacklist {
            self.is_on_blacklist = other.is_on_blacklist;
        }
        match other.msg_type {
            LogMessageType::Request => {
                self.req_len = other.req_len;
                self.request_id = other.request_id;
                self.captured_request_byte = other.captured_request_byte;
            }
            LogMessageType::Response => {
                self.resp_len = other.resp_len;
                self.captured_response_byte = other.captured_response_byte;
                self.ret = other.ret;
            }
            _ => {}
        }
    }

    fn set_is_on_blacklist(&mut self, config: &LogParserConfig) {
        if let Some(t) = config.l7_log_blacklist_trie.get(&L7Protocol::Tars) {
            self.is_on_blacklist = self
                .req_method_name
                .as_ref()
                .map(|p| t.request_type.is_on_blacklist(p))
                .unwrap_or_default()
                || self
                    .req_service_name
                    .as_ref()
                    .map(|p| t.request_resource.is_on_blacklist(p))
                    .unwrap_or_default()
                || self
                    .endpoint
                    .as_ref()
                    .map(|p| t.endpoint.is_on_blacklist(p))
                    .unwrap_or_default();
        }
    }
}

#[derive(Default)]
pub struct TarsLog {
    info: TarsInfo,
    perf_stats: Option<L7PerfStats>,
}

impl L7ProtocolParserInterface for TarsLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> Option<LogMessageType> {
        if !param.ebpf_type.is_raw_protocol() {
            return None;
        }
        if TarsInfo::parse(payload).is_ok() {
            Some(LogMessageType::Request)
        } else {
            None
        }
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        if self.perf_stats.is_none() {
            self.perf_stats = Some(L7PerfStats::default())
        };
        let mut info = match TarsInfo::parse(payload) {
            Ok((_, info)) => info,
            Err(e) => {
                return Err(Error::L7LogParseFailed {
                    proto: L7Protocol::Tars,
                    reason: format!("parser has error: {e:?}").into(),
                });
            }
        };
        if let Some(config) = param.parse_config {
            info.set_is_on_blacklist(config);
        }
        if let Some(perf_stats) = self.perf_stats.as_mut() {
            if info.msg_type == LogMessageType::Response {
                if let Some(endpoint) = info.load_endpoint_from_cache(param, false) {
                    info.endpoint = Some(endpoint.to_string());
                }
            }
            if let Some(stats) = info.perf_stats(param) {
                info.rrt = stats.rrt_sum;
                perf_stats.sequential_merge(&stats);
            }
        }
        if param.parse_log {
            Ok(L7ParseResult::Single(L7ProtocolInfo::TarsInfo(info)))
        } else {
            Ok(L7ParseResult::None)
        }
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Tars
    }

    fn reset(&mut self) {
        let mut s = Self::default();
        s.perf_stats = self.perf_stats.take();
        *self = s;
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }
}

impl From<TarsInfo> for L7ProtocolSendLog {
    fn from(info: TarsInfo) -> Self {
        let log = L7ProtocolSendLog {
            req_len: info.req_len.into(),
            resp_len: info.resp_len.into(),
            req: L7Request {
                req_type: info.req_method_name.unwrap_or_default(),
                resource: info.req_service_name.unwrap_or_default(),
                endpoint: info.endpoint.unwrap_or_default(),
                ..Default::default()
            },
            resp: L7Response {
                code: info.ret.map(|r| r.into()),
                status: match info.ret {
                    Some(r) => r.into(),
                    None => L7ResponseStatus::Unknown,
                },
                ..Default::default()
            },
            ext_info: Some(ExtendedInfo {
                request_id: Some(info.request_id),
                ..Default::default()
            }),
            version: info.tars_version.to_string().into(),
            captured_request_byte: info.captured_request_byte,
            captured_response_byte: info.captured_response_byte,
            ..Default::default()
        };
        return log;
    }
}

impl From<&TarsInfo> for LogCache {
    fn from(info: &TarsInfo) -> Self {
        LogCache {
            msg_type: info.msg_type,
            resp_status: info.ret.map(|r| r.into()).unwrap_or_default(),
            on_blacklist: info.is_on_blacklist,
            endpoint: info.get_endpoint(),
            ..Default::default()
        }
    }
}

impl L7ProtocolInfoInterface for TarsInfo {
    fn session_id(&self) -> Option<u32> {
        None
    }

    fn is_tls(&self) -> bool {
        self.is_tls
    }

    fn is_on_blacklist(&self) -> bool {
        self.is_on_blacklist
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::Tars,
            msg_type: self.msg_type,
            rrt: 0,
        })
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::TarsInfo(other) = other {
            self.merge(other);
        }
        Ok(())
    }

    fn get_endpoint(&self) -> Option<String> {
        self.endpoint.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, fmt::Write, fs, path::Path, rc::Rc};

    use serde_json;

    use super::*;

    use crate::{
        common::{flow::PacketDirection, l7_protocol_log::L7PerfCache, MetaPacket},
        config::handler::{L7LogDynamicConfigBuilder, LogParserConfig, TraceType},
        flow_generator::L7_RRT_CACHE_CAPACITY,
        utils::test::Capture,
    };

    const FILE_DIR: &str = "resources/test/flow_generator/tars";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name));
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let mut packets = capture.collect::<Vec<_>>();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut output: String = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
        let mut tars = TarsLog::default();
        for packet in packets.iter_mut() {
            packet.lookup_key.direction = if packet.lookup_key.dst_port == first_dst_port {
                PacketDirection::ClientToServer
            } else {
                PacketDirection::ServerToClient
            };
            let payload = match packet.get_l4_payload() {
                Some(p) => p,
                None => continue,
            };
            let param = &mut ParseParam::new(
                packet as &MetaPacket,
                log_cache.clone(),
                Default::default(),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Default::default(),
                true,
                true,
            );
            param.set_captured_byte(payload.len());

            let config = L7LogDynamicConfigBuilder {
                proxy_client: vec![],
                x_request_id: vec![],
                trace_types: vec![TraceType::Sw8, TraceType::TraceParent],
                span_types: vec![TraceType::Sw8, TraceType::TraceParent],
                ..Default::default()
            };
            let parse_config = &LogParserConfig {
                l7_log_dynamic: config.into(),
                ..Default::default()
            };

            param.set_log_parser_config(parse_config);

            if tars.check_payload(payload, param).is_none() {
                output.push_str("not tars\n");
                continue;
            }

            let info = tars.parse_payload(payload, param);
            if let Ok(info) = info {
                match info {
                    L7ParseResult::Single(s) => {
                        let _ = write!(&mut output, "{}\n", serde_json::to_string(&s).unwrap());
                    }
                    L7ParseResult::Multi(m) => {
                        for i in m {
                            let _ = write!(&mut output, "{}\n", serde_json::to_string(&i).unwrap());
                        }
                    }
                    L7ParseResult::None => {
                        output.push_str("None\n");
                    }
                }
            } else {
                let _ = write!(
                    &mut output,
                    "{}\n",
                    serde_json::to_string(&TarsInfo::default()).unwrap()
                );
            }
        }

        output
    }

    #[test]
    fn check() {
        let files = vec![("tars-echo.pcap", "tars-echo.result")];
        for item in files.iter() {
            let expected = fs::read_to_string(&Path::new(FILE_DIR).join(item.1)).unwrap();
            let output = run(item.0);

            if output != expected {
                let output_path = Path::new("actual.txt");
                fs::write(&output_path, &output).unwrap();
                assert!(
                    output == expected,
                    "output different from expected {}, written to {:?}",
                    item.1,
                    output_path
                );
            }
        }
    }

    #[test]
    fn truncated() {
        assert!(TarsInfo::parse(&[0xde, 0xad, 0xbe, 0xef]).is_err());
    }
}
