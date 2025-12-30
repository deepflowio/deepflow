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

use std::{fmt, mem, str};

use serde::Serialize;

use public::l7_protocol::LogMessageType;

use crate::{
    common::{
        enums::IpProtocol,
        flow::{L7PerfStats, L7Protocol},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, LogCache, ParseParam},
        meta_packet::ApplicationFlags,
    },
    config::handler::LogParserConfig,
    flow_generator::{
        error::{Error, Result},
        protocol_logs::{
            pb_adapter::{L7ProtocolSendLog, L7Request, L7Response},
            AppProtoHead, L7ResponseStatus, PacketDirection,
        },
    },
};

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    // Storage commands
    Set,
    Add,
    Replace,
    Append,
    Prepend,
    Cas,
    // Retrieval commands
    Get,
    Gets,
    Gat,
    Gats,
    // Other commands
    Delete,
    Incr,
    Decr,
    Touch,
    // Meta commands are ignored for the moment
    // Other administrative commands are ignored, like `flush_all`, `cache_memlimit`, `shutdown`, `version`, etc.
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Set => write!(f, "set"),
            Self::Add => write!(f, "add"),
            Self::Replace => write!(f, "replace"),
            Self::Append => write!(f, "append"),
            Self::Prepend => write!(f, "prepend"),
            Self::Cas => write!(f, "cas"),
            Self::Get => write!(f, "get"),
            Self::Gets => write!(f, "gets"),
            Self::Gat => write!(f, "gat"),
            Self::Gats => write!(f, "gats"),
            Self::Delete => write!(f, "delete"),
            Self::Incr => write!(f, "incr"),
            Self::Decr => write!(f, "decr"),
            Self::Touch => write!(f, "touch"),
        }
    }
}

impl TryFrom<&str> for Command {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self> {
        match s {
            "set" => Ok(Self::Set),
            "add" => Ok(Self::Add),
            "replace" => Ok(Self::Replace),
            "append" => Ok(Self::Append),
            "prepend" => Ok(Self::Prepend),
            "cas" => Ok(Self::Cas),
            "get" => Ok(Self::Get),
            "gets" => Ok(Self::Gets),
            "gat" => Ok(Self::Gat),
            "gats" => Ok(Self::Gats),
            "delete" => Ok(Self::Delete),
            "incr" => Ok(Self::Incr),
            "decr" => Ok(Self::Decr),
            "touch" => Ok(Self::Touch),
            _ => Err(Error::L7LogParseFailed {
                proto: L7Protocol::Memcached,
                reason: format!("Unhandled command `{s}`").into(),
            }),
        }
    }
}

impl Command {
    pub fn is_matched(&self, resp: &Response) -> bool {
        match self {
            Self::Set | Self::Add | Self::Replace | Self::Append | Self::Prepend | Self::Cas => {
                match resp {
                    Response::Stored
                    | Response::NotStored
                    | Response::Exists
                    | Response::NotFound => true,
                    _ => false,
                }
            }

            Self::Get | Self::Gets | Self::Gat | Self::Gats => resp == &Response::Value,

            Self::Delete => match resp {
                Response::Deleted | Response::NotFound => true,
                _ => false,
            },

            Self::Incr | Self::Decr => match resp {
                Response::NotFound | Response::RawValue(_) => true,
                _ => false,
            },

            Self::Touch => match resp {
                Response::Touched | Response::NotFound => true,
                _ => false,
            },
        }
    }
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Response {
    // Error strings
    Error, // client command error
    ClientError,
    ServerError,
    // Value with a data block
    Value,
    // empty value
    ValueEnd,
    // Command responses
    Stored,
    NotStored,
    Exists,
    NotFound,
    Deleted,
    Touched,
    // value only, for incr/decr
    RawValue(u64),
}

impl TryFrom<&str> for Response {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self> {
        match s {
            "ERROR" => Ok(Self::Error),
            "CLIENT_ERROR" => Ok(Self::ClientError),
            "SERVER_ERROR" => Ok(Self::ServerError),
            "STORED" => Ok(Self::Stored),
            "NOT_STORED" => Ok(Self::NotStored),
            "EXISTS" => Ok(Self::Exists),
            "NOT_FOUND" => Ok(Self::NotFound),
            "VALUE" => Ok(Self::Value),
            "END" => Ok(Self::ValueEnd),
            "DELETED" => Ok(Self::Deleted),
            "TOUCHED" => Ok(Self::Touched),
            _ => match s.parse::<u64>() {
                Ok(v) => Ok(Self::RawValue(v)),
                Err(_) => Err(Error::L7LogParseFailed {
                    proto: L7Protocol::Memcached,
                    reason: format!("Unhandled response `{s}`").into(),
                }),
            },
        }
    }
}

impl From<&Response> for L7ResponseStatus {
    fn from(resp: &Response) -> Self {
        match resp {
            Response::NotFound => L7ResponseStatus::Unknown,
            Response::ServerError => L7ResponseStatus::ServerError,
            Response::Error | Response::ClientError => L7ResponseStatus::ClientError,
            _ => L7ResponseStatus::Ok,
        }
    }
}

impl Response {
    pub fn is_matched(&self, cmd: &Command) -> bool {
        cmd.is_matched(self)
    }
}

#[derive(Serialize, Debug, Default, Clone)]
pub struct MemcachedInfo {
    pub msg_type: LogMessageType,

    pub captured_request_byte: usize,
    pub captured_response_byte: usize,

    #[serde(rename = "request_type")]
    pub command: Option<Command>,
    #[serde(rename = "request_resource")]
    pub request: String,

    #[serde(rename = "response_status")]
    pub response: Option<Response>,
    #[serde(rename = "response_result")]
    pub result: String,
    #[serde(rename = "response_exception")]
    pub err_msg: String,

    rrt: u64,

    #[serde(skip)]
    is_tls: bool,
    #[serde(skip)]
    is_on_blacklist: bool,
}

impl L7ProtocolInfoInterface for MemcachedInfo {
    fn session_id(&self) -> Option<u32> {
        None
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::MemcachedInfo(other) = other {
            return self.merge(other);
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::Memcached,
            msg_type: self.msg_type,
            rrt: self.rrt,
        })
    }

    fn is_tls(&self) -> bool {
        false
    }

    fn get_request_resource_length(&self) -> usize {
        self.request.len()
    }

    fn is_on_blacklist(&self) -> bool {
        self.is_on_blacklist
    }
}

impl MemcachedInfo {
    fn merge(&mut self, other: &mut Self) -> Result<()> {
        if other.captured_request_byte != 0 {
            self.captured_request_byte = other.captured_request_byte;
        }
        if other.captured_response_byte != 0 {
            self.captured_response_byte = other.captured_response_byte;
        }
        if let Some(cmd) = other.command {
            self.command.replace(cmd);
            mem::swap(&mut self.request, &mut other.request);
        }
        if let Some(resp) = other.response {
            self.response.replace(resp);
            mem::swap(&mut self.result, &mut other.result);
            mem::swap(&mut self.err_msg, &mut other.err_msg);
        }
        self.is_on_blacklist |= other.is_on_blacklist;

        Ok(())
    }

    fn is_on_blacklist(&self, config: &LogParserConfig) -> bool {
        let Some(t) = config.l7_log_blacklist_trie.get(&L7Protocol::Memcached) else {
            return false;
        };

        t.request_resource.is_on_blacklist(&self.request)
            || self
                .command
                .map(|c| t.request_type.is_on_blacklist(&c.to_string()))
                .unwrap_or(false)
    }
}

impl fmt::Display for MemcachedInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MemcachedInfo {{ msg_type: {:?} request: {} req_size: {} result: {} err_msg: {} res_size: {} rtt: {} }}",
            &self.msg_type, &self.request, &self.captured_request_byte, &self.result, &self.err_msg, &self.captured_response_byte, self.rrt,
        )
    }
}

impl From<MemcachedInfo> for L7ProtocolSendLog {
    fn from(f: MemcachedInfo) -> Self {
        let flags = if f.is_tls() {
            ApplicationFlags::TLS.bits()
        } else {
            ApplicationFlags::NONE.bits()
        };

        let mut log = L7ProtocolSendLog {
            captured_request_byte: f.captured_request_byte as u32,
            captured_response_byte: f.captured_response_byte as u32,
            flags,
            ..Default::default()
        };
        if let Some(req_type) = f.command {
            log.req = L7Request {
                req_type: req_type.to_string(),
                resource: f.request.clone(),
                ..Default::default()
            };
        }
        if let Some(resp) = f.response {
            log.resp = L7Response {
                result: f.result,
                status: L7ResponseStatus::from(&resp),
                exception: f.err_msg,
                ..Default::default()
            };
        }
        log
    }
}

impl From<&MemcachedInfo> for LogCache {
    fn from(info: &MemcachedInfo) -> Self {
        LogCache {
            msg_type: info.msg_type,
            resp_status: info
                .response
                .map(|r| L7ResponseStatus::from(&r))
                .unwrap_or_default(),
            on_blacklist: info.is_on_blacklist,
            ..Default::default()
        }
    }
}

#[derive(Default)]
pub struct MemcachedLog {
    perf_stats: Option<L7PerfStats>,
}

impl MemcachedLog {
    fn reset(&mut self) {
        self.perf_stats = None;
    }

    fn parse_commands(mut payload: &[u8]) -> Result<Vec<MemcachedInfo>> {
        let mut mis = vec![];
        while !payload.is_empty() {
            match Self::parse_command_line(payload) {
                Ok((next, info)) => {
                    payload = next;
                    mis.push(info);
                }
                Err(e) => {
                    if mis.is_empty() {
                        return Err(e);
                    } else {
                        return Ok(mis);
                    }
                }
            }
        }
        Ok(mis)
    }

    fn parse_response(payload: &[u8]) -> Result<MemcachedInfo> {
        let Some(eol) = Self::find_next_crlf(payload) else {
            return Err(Error::L7LogParseFailed {
                proto: L7Protocol::Memcached,
                reason: "text line truncated".into(),
            });
        };
        let line = str::from_utf8(&payload[..eol]).map_err(|_| Error::L7LogParseFailed {
            proto: L7Protocol::Memcached,
            reason: "text line is not valid UTF-8".into(),
        })?;

        let mut line_iter = line.split_ascii_whitespace();
        let Some(first) = line_iter.next() else {
            return Err(Error::L7LogParseFailed {
                proto: L7Protocol::Memcached,
                reason: "text line empty".into(),
            });
        };
        let resp = Response::try_from(first)?;
        let mut info = MemcachedInfo {
            msg_type: LogMessageType::Response,
            response: Some(resp),
            result: line.to_string(),
            captured_response_byte: line.len() + Self::CRLF.len(),
            ..Default::default()
        };
        match resp {
            Response::Error | Response::ClientError | Response::ServerError => {
                match line_iter.next() {
                    Some(msg) if msg.len() != 0 => info.err_msg = msg.to_owned(),
                    _ => (),
                }
            }
            Response::Value => {
                return Self::parse_value_response(line, &payload[eol + Self::CRLF.len()..], info)
            }
            Response::ValueEnd => (),
            Response::Stored
            | Response::NotStored
            | Response::Exists
            | Response::NotFound
            | Response::Deleted
            | Response::Touched
            | Response::RawValue(_) => (),
        }
        Ok(info)
    }

    const CRLF: &'static [u8] = "\r\n".as_bytes();
    const END: &'static [u8] = "END\r\n".as_bytes();

    fn find_next_crlf(payload: &[u8]) -> Option<usize> {
        for (i, window) in payload.windows(Self::CRLF.len()).enumerate() {
            if window == Self::CRLF {
                return Some(i);
            }
        }
        None
    }

    fn parse_command_line(payload: &[u8]) -> Result<(&[u8], MemcachedInfo)> {
        let Some(eol) = Self::find_next_crlf(payload) else {
            return Err(Error::L7LogParseFailed {
                proto: L7Protocol::Memcached,
                reason: "text line truncated".into(),
            });
        };
        let line = str::from_utf8(&payload[..eol]).map_err(|_| Error::L7LogParseFailed {
            proto: L7Protocol::Memcached,
            reason: "text line is not valid UTF-8".into(),
        })?;

        let Some(first) = line.split_ascii_whitespace().next() else {
            return Err(Error::L7LogParseFailed {
                proto: L7Protocol::Memcached,
                reason: "text line empty".into(),
            });
        };
        let command = Command::try_from(first)?;
        match command {
            // storage commands are followed by unstructured data which needs to be consumed
            Command::Set
            | Command::Add
            | Command::Replace
            | Command::Append
            | Command::Prepend
            | Command::Cas => {
                Self::parse_storage_command(command, line, &payload[eol + Self::CRLF.len()..])
            }
            Command::Get | Command::Gets | Command::Gat | Command::Gats => {
                Self::parse_retrieval_command(command, line, &payload[eol + Self::CRLF.len()..])
            }
            _ => Ok((
                &payload[eol + Self::CRLF.len()..],
                MemcachedInfo {
                    msg_type: LogMessageType::Request,
                    command: Some(command),
                    captured_request_byte: line.len() + Self::CRLF.len(),
                    request: line.to_owned(),
                    ..Default::default()
                },
            )),
        }
    }

    fn parse_storage_command<'a>(
        command: Command,
        line: &'a str,
        payload: &'a [u8],
    ) -> Result<(&'a [u8], MemcachedInfo)> {
        // <command name> <key> <flags> <exptime> <bytes> [noreply]\r\n
        // <data block>\r\n
        // or
        // cas <key> <flags> <exptime> <bytes> <cas unique> [noreply]\r\n
        // <data block>\r\n
        let mut splits = line.split_ascii_whitespace();
        let Some(bytes) = splits.nth(4).and_then(|s| s.parse::<usize>().ok()) else {
            return Err(Error::L7LogParseFailed {
                proto: L7Protocol::Memcached,
                reason: format!("invalid <bytes> in storage command: {}", line).into(),
            });
        };

        let next_line = if payload.get(bytes..=bytes + 1) != Some(Self::CRLF) {
            // payload is truncated, just ignore everything after this line
            payload.len()
        } else {
            bytes + Self::CRLF.len()
        };

        Ok((
            &payload[next_line..],
            MemcachedInfo {
                msg_type: LogMessageType::Request,
                command: Some(command),
                captured_request_byte: line.len() + Self::CRLF.len() + next_line,
                request: line.to_owned(),
                ..Default::default()
            },
        ))
    }

    fn parse_retrieval_command<'a>(
        command: Command,
        line: &'a str,
        payload: &'a [u8],
    ) -> Result<(&'a [u8], MemcachedInfo)> {
        // get <key>*\r\n
        // gets <key>*\r\n
        // gat <exptime> <key>*\r\n
        // gats <exptime> <key>*\r\n

        // TODO: match with response
        Ok((
            payload,
            MemcachedInfo {
                msg_type: LogMessageType::Request,
                command: Some(command),
                captured_request_byte: line.len() + Self::CRLF.len(),
                request: line.to_owned(),
                ..Default::default()
            },
        ))
    }

    fn parse_value_response(
        line: &str,
        payload: &[u8],
        mut info: MemcachedInfo,
    ) -> Result<MemcachedInfo> {
        // VALUE <key> <flags> <bytes> [<cas unique>]\r\n
        // <data block>\r\n
        //
        // followed by
        // END\r\n
        let mut splits = line.split_ascii_whitespace();
        if splits
            .nth(3)
            .and_then(|s| s.parse::<usize>().ok())
            .is_none()
        {
            return Err(Error::L7LogParseFailed {
                proto: L7Protocol::Memcached,
                reason: format!("invalid <bytes> in value response: {}", line).into(),
            });
        };

        // not extracting each VALUE, but find the final `END\r\n` to calculate response size
        for (i, window) in payload.windows(Self::END.len()).enumerate().rev() {
            if window == Self::END {
                info.captured_response_byte += i + Self::END.len();
                return Ok(info);
            }
        }

        // payload is truncated
        info.captured_response_byte += payload.len();
        Ok(info)
    }
}

impl L7ProtocolParserInterface for MemcachedLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> Option<LogMessageType> {
        if !param.ebpf_type.is_raw_protocol() {
            return None;
        }
        if param.l4_protocol != IpProtocol::TCP {
            return None;
        }

        if MemcachedLog::parse_commands(payload).is_ok() {
            Some(LogMessageType::Request)
        } else {
            None
        }
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };
        let mut on_blacklist = false;
        let mut results = match param.direction {
            PacketDirection::ClientToServer => {
                let cmds = MemcachedLog::parse_commands(payload)?;
                if let Some(conf) = param.parse_config {
                    on_blacklist = cmds.iter().all(|cmd| cmd.is_on_blacklist(conf));
                }
                cmds
            }
            PacketDirection::ServerToClient => {
                let resp = Self::parse_response(payload)?;
                if let Some(conf) = param.parse_config {
                    on_blacklist = resp.is_on_blacklist(conf);
                }
                vec![resp]
            }
        };
        let Some(info) = results.get(0) else {
            return Err(Error::L7LogParseFailed {
                proto: L7Protocol::Memcached,
                reason: "memcached info is empty".into(),
            });
        };
        let mut info_rrt = 0;
        if let Some(perf_stats) = self.perf_stats.as_mut() {
            if let Some(stats) = info.perf_stats(param) {
                info_rrt = stats.rrt_sum;
                perf_stats.sequential_merge(&stats);
            }
        }
        for info in results.iter_mut() {
            info.is_on_blacklist = on_blacklist;
            info.rrt = info_rrt;
        }
        if param.parse_log {
            if results.len() == 1 {
                Ok(L7ParseResult::Single(L7ProtocolInfo::MemcachedInfo(
                    results.into_iter().next().unwrap(),
                )))
            } else {
                Ok(L7ParseResult::Multi(
                    results
                        .into_iter()
                        .map(|r| L7ProtocolInfo::MemcachedInfo(r))
                        .collect(),
                ))
            }
        } else {
            Ok(L7ParseResult::None)
        }
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Memcached
    }

    fn parsable_on_tcp(&self) -> bool {
        true
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::RefCell;
    use std::fmt::Write;
    use std::fs;
    use std::path::Path;
    use std::rc::Rc;

    use crate::{
        common::{flow::PacketDirection, l7_protocol_log::L7PerfCache, MetaPacket},
        flow_generator::L7_RRT_CACHE_CAPACITY,
        utils::test::Capture,
    };

    const FILE_DIR: &str = "resources/test/flow_generator/memcached";

    fn run(name: &str) -> String {
        let pcap_file = Path::new(FILE_DIR).join(name);
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let capture = Capture::load_pcap(pcap_file);
        let mut packets = capture.collect::<Vec<_>>();
        if packets.is_empty() {
            return "".to_string();
        }
        let mut output = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
        let mut memcached = MemcachedLog::default();
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
                true, /*  */
            );
            param.set_captured_byte(payload.len());

            let is_memcached = match packet.lookup_key.direction {
                PacketDirection::ClientToServer => {
                    memcached.check_payload(payload, param).is_some()
                }
                PacketDirection::ServerToClient => MemcachedLog::parse_response(payload).is_ok(),
            };

            match memcached.parse_payload(payload, param) {
                Ok(L7ParseResult::Single(L7ProtocolInfo::MemcachedInfo(info))) => {
                    let _ = write!(&mut output, "{} is_memcached: {}\n", info, is_memcached);
                }
                Ok(L7ParseResult::Multi(m)) => {
                    for info in m {
                        if let L7ProtocolInfo::MemcachedInfo(info) = info {
                            let _ =
                                write!(&mut output, "{} is_memcached: {}\n", info, is_memcached);
                        }
                    }
                }
                Err(e) => {
                    let _ = write!(&mut output, "parse failed {}\n", e);
                }
                _ => (),
            }
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![
            ("memcached.pcap", "memcached.result"),
            ("memcached-userdata.pcap", "memcached-userdata.result"),
        ];

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
}
