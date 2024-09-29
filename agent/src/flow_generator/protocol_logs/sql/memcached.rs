use serde::Serialize;
use std::{fmt, str};

use super::super::{AppProtoHead, L7ResponseStatus, LogMessageType};

use crate::{
    common::{
        enums::IpProtocol,
        flow::{L7PerfStats, L7Protocol},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, ParseParam},
        meta_packet::EbpfFlags,
    },
    flow_generator::{
        error::Result,
        protocol_logs::pb_adapter::{L7ProtocolSendLog, L7Request, L7Response},
    },
};

#[derive(Serialize, Debug, Default, Clone)]
pub struct MemcachedInfo {
    pub msg_type: LogMessageType,

    pub command: String,
    pub size_incr_or_decr: u64,
    pub value: Vec<String>,
    pub brief_rep: String,
    pub key: String,
    pub proto_flag: u32,
    pub exptime: u32,
    pub length: u32,
    pub cas_unique: u32,
    pub noreply: bool,

    pub request: String,
    pub response: String,
    pub resp_status: L7ResponseStatus,

    flag: u8, // TODO: 未知作用
    rrt: u64,
}

impl L7ProtocolInfoInterface for MemcachedInfo {
    fn session_id(&self) -> Option<u32> {
        None
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::MemCachedInfo(other) = other {
            return self.merge(other);
        }
        core::result::Result::Ok(())
        //flow_generator::error::Error
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::MemCached,
            msg_type: self.msg_type,
            rrt: self.rrt,
        })
    }

    fn is_tls(&self) -> bool {
        false
    }
}

impl MemcachedInfo {
    fn merge(&mut self, _other: &mut Self) -> Result<()> {
        // self.response = other.response.clone();
        // self.resp_cas_unique = other.resp_cas_unique.clone();
        // self.resp_data_length = other.resp_data_length.clone();
        // self.resp_status = other.resp_status.clone();
        // self.error = other.error.clone();
        // self.resp_flags = other.resp_flags.clone();
        // self.resp_data_length = other.resp_data_length.clone();

        core::result::Result::Ok(())
    }
}

impl fmt::Display for MemcachedInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "resquest: {:?}", &self.request)?;
        write!(f, "response: {:?}", &self.response)
    }
}

impl From<MemcachedInfo> for L7ProtocolSendLog {
    fn from(f: MemcachedInfo) -> Self {
        let _flags = if f.is_tls() {
            EbpfFlags::TLS.bits()
        } else {
            EbpfFlags::NONE.bits()
        };

        pub mod tmp {
            pub enum Status {
                Ok,
                NotExit,
                Error,
            }
        }
        let mut command = tmp::Status::Ok;
        const STORAGE_COMMANDS_RET: [&str; 3] = ["STORED", "NOT_STORED", "EXISTS"];
        const ERROR_STRING: [&str; 3] = ["ERROR", "CLIENT_ERROR", "SERVER_ERROR "];
        if STORAGE_COMMANDS_RET.contains(&f.response.as_str()) {
            command = tmp::Status::Ok;
        };
        if STORAGE_COMMANDS_RET.contains(&f.response.as_str()) {
            command = tmp::Status::Error;
        };
        if f.response == "NOT_FOUND".to_string() {
            command = tmp::Status::NotExit;
        }
        let log = L7ProtocolSendLog {
            captured_request_byte: f.request.len() as u32,
            captured_response_byte: f.response.len() as u32,
            req: L7Request {
                req_type: f.command.clone(),
                resource: f.request.clone(),

                ..Default::default()
            },
            resp: L7Response {
                result: f.response.clone(),
                status: match command {
                    tmp::Status::Ok => L7ResponseStatus::Ok,
                    tmp::Status::NotExit => L7ResponseStatus::NotExist,
                    tmp::Status::Error => L7ResponseStatus::ClientError,
                    // _ => L7ResponseStatus::ClientError,
                },
                ..Default::default()
            },
            version: None,
            ..Default::default()
        };
        return log;
    }
}

#[derive(Serialize, Default)]
pub struct MemCachedLog {
    info: MemcachedInfo,
    #[serde(skip)]
    perf_stats: Option<L7PerfStats>,
    #[serde(skip)]
    parsed: bool,
}

impl L7ProtocolParserInterface for MemCachedLog {
    fn check_payload(&mut self, _payload: &[u8], param: &ParseParam) -> bool {
        if param.l4_protocol != IpProtocol::TCP {
            return false;
        }
        if param.port_dst == 11211 || param.port_src == 11211 {
            return true;
        }
        false
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        println!("FixMe: {:?}", String::from_utf8(payload.to_vec()).unwrap());
        println!();

        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };
        let mut info = MemcachedInfo::default();
        let get_parse = memcached_parser::parse_get_command(payload);
        let response_parse = memcached_parser::parse_response(payload);
        let parse_store_command = memcached_parser::parse_memcached_command(payload);
        let parse_cas_command = memcached_parser::parse_cas_command(payload);
        let parse_delete_command = memcached_parser::parse_delete_command(payload);
        let parse_incr_command = memcached_parser::parse_incr_decr_command(payload, "incr");
        let parse_decr_command = memcached_parser::parse_incr_decr_command(payload, "decr");
        let parse_touch_command = memcached_parser::parse_touch_command(payload);
        let parse_value = memcached_parser::parse_value_response(payload);

        if let Ok(value_parse) = parse_value {
            info.key = value_parse.0;
            info.proto_flag = value_parse.1;
            let mut v = Vec::new();
            v.push(String::from_utf8(value_parse.2.clone()).unwrap_or("".to_string()));
            info.value = v;
            info.length = value_parse.2.len() as u32;
            info.cas_unique = match value_parse.3 {
                Some(s) => s as u32,
                None => 0,
            };
            if info.cas_unique != 0 {
                info.response = format!(
                    "VALUE {} {} {} {} \r\n {:?} \r\n",
                    info.key.clone(),
                    info.proto_flag.clone(),
                    info.length.clone(),
                    info.cas_unique.clone(),
                    info.value.clone(),
                );
            } else {
                info.response = format!(
                    "VALUE {} {} {} \r\n {:?} \r\n",
                    info.key.clone(),
                    info.proto_flag.clone(),
                    info.length.clone(),
                    info.value.clone(),
                );
            }
            return Ok(L7ParseResult::Single(L7ProtocolInfo::MemCachedInfo(info)));
        }

        if let Ok(touch_command) = parse_touch_command {
            info.command = "touch".to_string();
            info.key = touch_command.0;
            info.exptime = touch_command.1;
            info.noreply = touch_command.2;
            if info.noreply == true {
                info.request = format!(
                    "touch {} {} noreply\r\n",
                    info.key.clone(),
                    info.exptime.clone(),
                )
            } else {
                info.request = format!("touch {} {}\r\n", info.key.clone(), info.exptime.clone(),)
            }
            return Ok(L7ParseResult::Single(L7ProtocolInfo::MemCachedInfo(info)));
        }

        if let Ok(incr_command) = parse_incr_command {
            info.command = "decr".to_string();
            info.key = incr_command.0;
            info.size_incr_or_decr = incr_command.1;
            info.noreply = incr_command.2;
            if info.noreply == true {
                info.request = format!(
                    "incr {} {:?} noreply\r\n",
                    info.key.clone(),
                    info.value.clone()
                )
            } else {
                info.request = format!("incr {} {:?}\r\n", info.key.clone(), info.value.clone())
            }
            return Ok(L7ParseResult::Single(L7ProtocolInfo::MemCachedInfo(info)));
        }

        if let Ok(decr_command) = parse_decr_command {
            info.command = "decr".to_string();
            info.key = decr_command.0;
            info.size_incr_or_decr = decr_command.1;
            info.noreply = decr_command.2;
            if info.noreply == true {
                info.request = format!(
                    "decr {} {:?} noreply\r\n",
                    info.key.clone(),
                    info.value.clone()
                )
            } else {
                info.request = format!("decr {} {:?}\r\n", info.key.clone(), info.value.clone())
            }
            return Ok(L7ParseResult::Single(L7ProtocolInfo::MemCachedInfo(info)));
        }

        if let Ok(delete_command) = parse_delete_command {
            info.command = "delete".to_string();
            info.key = delete_command.0;
            info.noreply = delete_command.1;
            if info.noreply == true {
                info.request = format!("delete {} , noreply\r\n", info.key.clone());
            } else {
                info.request = format!("delete {}\r\n", info.key.clone());
            }
            return Ok(L7ParseResult::Single(L7ProtocolInfo::MemCachedInfo(info)));
        }

        if let Ok(cas_command) = parse_cas_command {
            info.command = "cas".to_string();
            info.key = cas_command.0;
            info.flag = cas_command.1 as u8;
            info.exptime = cas_command.2;
            info.length = cas_command.3 as u32;
            info.cas_unique = cas_command.4 as u32;
            info.noreply = cas_command.5;
            let s = String::from_utf8(cas_command.6).unwrap_or("".to_string()); // value
            let mut v = Vec::new();
            v.push(s);
            info.value = v;
            if info.noreply {
                info.request = format!(
                    "cas {} {} {} {} {} noreply\r\n{:?}",
                    info.key.clone(),
                    info.flag.clone(),
                    info.exptime.clone(),
                    info.length.clone(),
                    info.cas_unique.clone(),
                    info.value.clone(),
                );
            } else {
                info.request = format!(
                    "cas {} {} {} {} {}\r\n{:?}",
                    info.key.clone(),
                    info.flag.clone(),
                    info.exptime.clone(),
                    info.length.clone(),
                    info.cas_unique.clone(),
                    info.value.clone(),
                );
            }
            return Ok(L7ParseResult::Single(L7ProtocolInfo::MemCachedInfo(info)));
        }

        if let Ok(store_command) = parse_store_command {
            match store_command {
                memcached_parser::MemcachedCommand::Set(
                    key,
                    flags,
                    exptime,
                    length,
                    noreply,
                    value,
                ) => {
                    if info.noreply {
                        info.request = format!(
                            "set {} {} {} {} noreply\r\n{:?}\r\n",
                            &key, &flags, &exptime, &length, &value
                        );
                    } else {
                        info.request = format!(
                            "set {} {} {} {}\r\n{:?}\r\n",
                            &key, &flags, &exptime, &length, &value
                        );
                    }
                    info.key = key;
                    info.proto_flag = flags;
                    info.exptime = exptime;
                    info.length = length as u32;
                    info.noreply = noreply;
                    let mut v = Vec::new();
                    v.push(String::from_utf8(value).unwrap_or("".to_string()));
                    info.value = v;
                }
                memcached_parser::MemcachedCommand::Add(
                    key,
                    flags,
                    exptime,
                    length,
                    noreply,
                    value,
                ) => {
                    if info.noreply {
                        info.request = format!(
                            "add {} {} {} {} noreply\r\n{:?}\r\n",
                            &key, &flags, &exptime, &length, &value
                        );
                    } else {
                        info.request = format!(
                            "add {} {} {} {}\r\n{:?}\r\n",
                            &key, &flags, &exptime, &length, &value
                        );
                    }
                    info.key = key;
                    info.proto_flag = flags as u32;
                    info.exptime = exptime;
                    info.length = length as u32;
                    info.noreply = noreply;
                    let mut v = Vec::new();
                    v.push(String::from_utf8(value).unwrap_or("".to_string()));
                    info.value = v;
                }
                memcached_parser::MemcachedCommand::Replace(
                    key,
                    flags,
                    exptime,
                    length,
                    noreply,
                    value,
                ) => {
                    if info.noreply {
                        info.request = format!(
                            "replace {} {} {} {} noreply\r\n{:?}\r\n",
                            &key, &flags, &exptime, &length, &value
                        );
                    } else {
                        info.request = format!(
                            "replace {} {} {} {}\r\n{:?}\r\n",
                            &key, &flags, &exptime, &length, &value
                        );
                    }
                    info.key = key;
                    info.proto_flag = flags;
                    info.exptime = exptime;
                    info.length = length as u32;
                    info.noreply = noreply;
                    let mut v = Vec::new();
                    v.push(String::from_utf8(value).unwrap_or("".to_string()));
                    info.value = v;
                }
                memcached_parser::MemcachedCommand::Append(key, flags, length, noreply, value) => {
                    if info.noreply {
                        info.request = format!(
                            "append {} {} 0 {} noreply\r\n{:?}\r\n",
                            &key, &flags, &length, &value
                        );
                    } else {
                        info.request = format!(
                            "append {} {} 0 {}\r\n{:?}\r\n",
                            &key, &flags, &length, &value
                        );
                    }
                    info.key = key;
                    info.proto_flag = flags;
                    info.exptime = 0;
                    info.length = length as u32;
                    info.noreply = noreply;
                    let mut v = Vec::new();
                    v.push(String::from_utf8(value).unwrap_or("".to_string()));
                    info.value = v;
                }
                memcached_parser::MemcachedCommand::Prepend(key, flags, length, noreply, value) => {
                    if info.noreply {
                        info.request = format!(
                            "prepend {} {} 0 {} noreply\r\n{:?}\r\n",
                            &key, &flags, &length, &value
                        );
                    } else {
                        info.request = format!(
                            "append {} {} 0 {}\r\n{:?}\r\n",
                            &key, &flags, &length, &value
                        );
                    }
                    info.key = key;
                    info.proto_flag = flags;
                    info.exptime = 0;
                    info.length = length as u32;
                    info.noreply = noreply;
                    let mut v = Vec::new();
                    v.push(String::from_utf8(value).unwrap_or("".to_string()));
                    info.value = v;
                }
            }
        }

        if let Ok(values) = get_parse {
            info.value = values;
            info.request = format!("get {:?}", &info.value);
            return Ok(L7ParseResult::Single(L7ProtocolInfo::MemCachedInfo(info)));
        }

        if let Ok(brief_rep) = response_parse {
            match brief_rep {
                memcached_parser::Response::NotStored => {
                    info.brief_rep = String::from("NotStored");
                    info.response = String::from("NotStored");
                }
                memcached_parser::Response::Stored => {
                    info.brief_rep = String::from("Stored");
                    info.response = String::from("Stored");
                }
                memcached_parser::Response::NOTFOUND => {
                    info.brief_rep = String::from("NOTFOUND");
                    info.response = String::from("NOTFOUND");
                }
                memcached_parser::Response::EXISTS => {
                    info.brief_rep = String::from("EXISTS");
                    info.response = String::from("EXISTS");
                }
                memcached_parser::Response::DELETED => {
                    info.brief_rep = String::from("DELETED");
                    info.response = String::from("DELETED");
                }
                memcached_parser::Response::TOUCHED => {
                    info.brief_rep = String::from("TOUCHED");
                    info.response = String::from("TOUCHED");
                }
                memcached_parser::Response::QUIT => {
                    info.brief_rep = String::from("QUIT");
                    info.response = String::from("QUIT");
                }
                memcached_parser::Response::CLIENTERROR => {
                    info.brief_rep = String::from("CLIENTERROR");
                    info.response = String::from("CLIENTERROR");
                }
                memcached_parser::Response::SERVERERROR => {
                    info.brief_rep = String::from("SERVERERROR");
                    info.response = String::from("SERVERERROR");
                }
                memcached_parser::Response::ERROR => {
                    info.brief_rep = String::from("ERROR");
                    info.response = String::from("ERROR");
                }
            }
            return Ok(L7ParseResult::Single(L7ProtocolInfo::MemCachedInfo(info)));
        }

        return Ok(L7ParseResult::Single(L7ProtocolInfo::MemCachedInfo(
            MemcachedInfo::default(),
        )));
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::MemCached
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

mod memcached_parser {
    pub enum MemcachedCommand {
        Set(String, u32, u32, usize, bool, Vec<u8>),
        Add(String, u32, u32, usize, bool, Vec<u8>),
        Replace(String, u32, u32, usize, bool, Vec<u8>),
        Append(String, u32, usize, bool, Vec<u8>),
        Prepend(String, u32, usize, bool, Vec<u8>),
    }

    #[derive(Debug)]
    pub enum Response {
        NotStored,
        Stored,
        NOTFOUND,
        EXISTS,
        DELETED,
        TOUCHED,
        QUIT,
        CLIENTERROR,
        SERVERERROR,
        ERROR,
    }

    //get <key>*\r\n
    pub fn parse_get_command(payload: &[u8]) -> Result<Vec<String>, &'static str> {
        // 尝试将字节数组转换为 UTF-8 字符串
        let s = match std::str::from_utf8(payload) {
            Ok(s) => s,
            Err(_) => return Err("Invalid UTF-8 encoding"),
        };

        // 找到 "get " 的起始位置
        if let Some(start_pos) = s.find("get ") {
            // 从 "get " 开始截取子字符串
            let command_str = &s[start_pos..];

            // 找到命令结束的位置
            if let Some(end_pos) = command_str.find('\n') {
                let full_command = &command_str[..=end_pos];
                if !full_command.ends_with("\r\n") {
                    return Err("Command does not end with \\r\\n");
                }

                // 分割字符串以获取各个部分
                let parts: Vec<&str> = full_command.split_whitespace().collect();
                if parts.len() < 2 {
                    return Err("Incomplete get command");
                }

                // 提取 key 列表
                let keys: Vec<String> = parts[1..parts.len()]
                    .iter()
                    .map(|&k| k.to_string())
                    .collect();

                Ok(keys)
            } else {
                // 如果没有找到换行符，则命令不完整
                Err("Incomplete get command")
            }
        } else {
            Err("No 'get' command found")
        }
    }

    // set add replace append prepend
    pub fn parse_memcached_command(payload: &[u8]) -> Result<MemcachedCommand, &'static str> {
        // 尝试将字节数组转换为 UTF-8 字符串
        let s = match std::str::from_utf8(payload) {
            Ok(s) => s,
            Err(_) => return Err("Invalid UTF-8 encoding"),
        };

        // 定义命令关键字和对应的枚举类型
        let commands = vec![
            (
                "set ",
                MemcachedCommand::Set("".to_string(), 0, 0, 0, false, vec![]),
            ),
            (
                "add ",
                MemcachedCommand::Add("".to_string(), 0, 0, 0, false, vec![]),
            ),
            (
                "replace ",
                MemcachedCommand::Replace("".to_string(), 0, 0, 0, false, vec![]),
            ),
            (
                "append ",
                MemcachedCommand::Append("".to_string(), 0, 0, false, vec![]),
            ),
            (
                "prepend ",
                MemcachedCommand::Prepend("".to_string(), 0, 0, false, vec![]),
            ),
        ];

        for (cmd, cmd_type) in &commands {
            if let Some(start_pos) = s.find(cmd) {
                // 从命令关键字开始截取子字符串
                let command_str = &s[start_pos..];

                // 分割字符串以获取各个部分
                let parts: Vec<&str> = command_str.split_whitespace().collect();
                if parts.len() < 5 {
                    return Err("Incomplete command");
                }

                // 解析 key
                let key = parts[1].to_string();

                // 解析 flags
                let flags = match parts[2].parse::<u32>() {
                    Ok(f) => f,
                    Err(_) => return Err("Invalid flags value"),
                };

                // 解析 exptime（对于 append 和 prepend 可能没有这个字段）
                let exptime = if *cmd == "append " || *cmd == "prepend " {
                    0
                } else {
                    match parts[3].parse::<u32>() {
                        Ok(e) => e,
                        Err(_) => return Err("Invalid exptime value"),
                    }
                };

                // 解析 length
                let length = match parts[if *cmd == "append " || *cmd == "prepend " {
                    2
                } else {
                    4
                }]
                .parse::<usize>()
                {
                    Ok(l) => l,
                    Err(_) => return Err("Invalid length value"),
                };

                // 可选的 noreply 参数
                let noreply = parts.len()
                    > (if *cmd == "append " || *cmd == "prepend " {
                        4
                    } else {
                        6
                    })
                    && parts[parts.len() - 1] == "noreply";

                // 计算从 start_pos 到 value 结束的总长度
                let command_end = start_pos + command_str.find("\r\n").unwrap_or(0) + 2; // 找到第一个 \r\n 的位置并加上 2
                let total_length = command_end + length + 2; // 2 是 \r\n 的长度

                // 确保有足够的数据来匹配指定的长度
                if payload.len() < total_length {
                    return Err("Value length does not match specified length");
                }

                // 提取 value
                let value_start = command_end;
                let value_end = value_start + length;
                let value = &payload[value_start..value_end].to_vec();

                // 根据命令关键字返回相应的枚举类型
                return match cmd_type {
                    MemcachedCommand::Set(_, _, _, _, _, _) => Ok(MemcachedCommand::Set(
                        key,
                        flags,
                        exptime,
                        length,
                        noreply,
                        value.clone(),
                    )),
                    MemcachedCommand::Add(_, _, _, _, _, _) => Ok(MemcachedCommand::Add(
                        key,
                        flags,
                        exptime,
                        length,
                        noreply,
                        value.clone(),
                    )),
                    MemcachedCommand::Replace(_, _, _, _, _, _) => Ok(MemcachedCommand::Replace(
                        key,
                        flags,
                        exptime,
                        length,
                        noreply,
                        value.clone(),
                    )),
                    MemcachedCommand::Append(_, _, _, _, _) => Ok(MemcachedCommand::Append(
                        key,
                        flags,
                        length,
                        noreply,
                        value.clone(),
                    )),
                    MemcachedCommand::Prepend(_, _, _, _, _) => Ok(MemcachedCommand::Prepend(
                        key,
                        flags,
                        length,
                        noreply,
                        value.clone(),
                    )),
                    // _ => unreachable!(),
                };
            }
        }

        Err("No valid command found")
    }

    pub fn parse_cas_command(
        payload: &[u8],
    ) -> Result<(String, u32, u32, usize, u64, bool, Vec<u8>), &'static str> {
        // 尝试将字节数组转换为 UTF-8 字符串
        let s = match std::str::from_utf8(payload) {
            Ok(s) => s,
            Err(_) => return Err("Invalid UTF-8 encoding"),
        };

        // 找到 "cas " 的起始位置
        if let Some(start_pos) = s.find("cas ") {
            // 从 "cas " 开始截取子字符串
            let command_str = &s[start_pos..];

            // 分割字符串以获取各个部分
            let parts: Vec<&str> = command_str.split_whitespace().collect();
            if parts.len() < 7 {
                return Err("Incomplete cas command");
            }

            // 解析 key
            let key = parts[1].to_string();

            // 解析 flags
            let flags = match parts[2].parse::<u32>() {
                Ok(f) => f,
                Err(_) => return Err("Invalid flags value"),
            };

            // 解析 exptime
            let exptime = match parts[3].parse::<u32>() {
                Ok(e) => e,
                Err(_) => return Err("Invalid exptime value"),
            };

            // 解析 length
            let length = match parts[4].parse::<usize>() {
                Ok(l) => l,
                Err(_) => return Err("Invalid length value"),
            };

            // 解析 cas unique
            let cas_unique = match parts[5].parse::<u64>() {
                Ok(c) => c,
                Err(_) => return Err("Invalid cas unique value"),
            };

            // 可选的 noreply 参数
            let noreply = parts.len() > 7 && parts[6] == "noreply";

            // 计算从 start_pos 到 value 结束的总长度
            let command_end = start_pos + command_str.find("\r\n").unwrap_or(0) + 2; // 找到第一个 \r\n 的位置并加上 2
            let total_length = command_end + length + 2; // 2 是 \r\n 的长度

            // 确保有足够的数据来匹配指定的长度
            if payload.len() < total_length {
                return Err("Value length does not match specified length");
            }

            // 提取 value
            let value_start = command_end;
            let value_end = value_start + length;
            let value = payload[value_start..value_end].to_vec();

            Ok((key, flags, exptime, length, cas_unique, noreply, value))
        } else {
            Err("No 'cas' command found")
        }
    }

    /*
    VALUE <key> <flags> <bytes> [<cas unique>]\r\n
    <value>\r\n
    "some text before VALUE mykey 0 5\r\nvalue\r\nEND\r\n"
    */
    pub fn parse_value_response(
        payload: &[u8],
    ) -> Result<(String, u32, Vec<u8>, Option<u64>), &'static str> {
        // 尝试将字节数组转换为 UTF-8 字符串
        let s = match std::str::from_utf8(payload) {
            Ok(s) => s,
            Err(_) => return Err("Invalid UTF-8 encoding"),
        };

        // 查找 "VALUE " 的起始位置
        if let Some(start_pos) = s.find("VALUE ") {
            let value_line = &s[start_pos..];
            let line_end = value_line.find('\n').ok_or("Incomplete VALUE line")?;
            let value_line = &value_line[..line_end];

            // 提取 key, flags, bytes 和可选的 cas unique
            let parts: Vec<&str> = value_line.split_whitespace().collect();

            if parts.len() < 4 {
                return Err("Incomplete VALUE line");
            }

            let key = parts[1].to_string();
            let flags = parts[2].parse::<u32>().map_err(|_| "Invalid flags value")?;
            let bytes = parts[3]
                .parse::<usize>()
                .map_err(|_| "Invalid bytes value")?;
            let cas_unique = if parts.len() > 4 {
                Some(
                    parts[4]
                        .parse::<u64>()
                        .map_err(|_| "Invalid cas unique value")?,
                )
            } else {
                None
            };

            // 计算 value 的起始和结束位置
            let value_start = start_pos + line_end + 1; // 跳过 \r\n
            let value_end = value_start + bytes + 2; // 包括 \r\n

            if value_end > payload.len() {
                return Err("Value length exceeds payload length");
            }

            // 读取值部分，并去除可能的 \r 字符
            let value = payload[value_start..value_end - 2] // 去除末尾的 \r\n
                .iter()
                .filter(|&&b| b != b'\r')
                .cloned()
                .collect::<Vec<u8>>();

            Ok((key, flags, value, cas_unique))
        } else {
            Err("VALUE line not found")
        }
    }

    pub fn parse_delete_command(payload: &[u8]) -> Result<(String, bool), &'static str> {
        // 尝试将字节数组转换为 UTF-8 字符串
        let s = match std::str::from_utf8(payload) {
            Ok(s) => s,
            Err(_) => return Err("Invalid UTF-8 encoding"),
        };

        // 查找 "delete " 的起始位置
        if let Some(start_pos) = s.find("delete ") {
            let delete_line = &s[start_pos..];
            let line_end = delete_line.find('\n').ok_or("Incomplete delete command")?;
            let delete_line = &delete_line[..line_end];

            // 提取 key 和 noreply 参数
            let parts: Vec<&str> = delete_line.split_whitespace().collect();
            if parts.len() < 2 {
                return Err("Incomplete delete command");
            }

            let key = parts[1].to_string();
            let noreply = parts.len() > 2 && parts[2] == "noreply";

            Ok((key, noreply))
        } else {
            Err("delete command not found")
        }
    }

    //incr <key> <value> [noreply]\r\n
    //decr <key> <value> [noreply]\r\n
    pub fn parse_incr_decr_command(
        payload: &[u8],
        command: &str,
    ) -> Result<(String, u64, bool), &'static str> {
        // 尝试将字节数组转换为 UTF-8 字符串
        let s = match std::str::from_utf8(payload) {
            Ok(s) => s,
            Err(_) => return Err("Invalid UTF-8 encoding"),
        };

        // 查找 "command " 的起始位置
        if let Some(start_pos) = s.find(command) {
            let command_line = &s[start_pos..];
            let line_end = command_line.find('\n').ok_or("Incomplete command")?;
            let command_line = &command_line[..line_end];

            // 提取 key, value 和 noreply 参数
            let parts: Vec<&str> = command_line.split_whitespace().collect();
            if parts.len() < 3 {
                return Err("Incomplete command");
            }

            let key = parts[1].to_string();
            let value = parts[2].parse::<u64>().map_err(|_| "Invalid value")?;
            let noreply = parts.len() > 3 && parts[3] == "noreply";

            Ok((key, value, noreply))
        } else {
            Err("command not found")
        }
    }

    //touch <key> <exptime> [noreply]\r\n
    pub fn parse_touch_command(payload: &[u8]) -> Result<(String, u32, bool), &'static str> {
        // 尝试将字节数组转换为 UTF-8 字符串
        let s = match std::str::from_utf8(payload) {
            Ok(s) => s,
            Err(_) => return Err("Invalid UTF-8 encoding"),
        };

        // 查找 "touch " 的起始位置
        if let Some(start_pos) = s.find("touch ") {
            let touch_line = &s[start_pos..];
            let line_end = touch_line.find('\n').ok_or("Incomplete touch command")?;
            let touch_line = &touch_line[..line_end];

            // 提取 key, exptime 和 noreply 参数
            let parts: Vec<&str> = touch_line.split_whitespace().collect();
            if parts.len() < 3 {
                return Err("Incomplete touch command");
            }

            let key = parts[1].to_string();
            let exptime = parts[2]
                .parse::<u32>()
                .map_err(|_| "Invalid exptime value")?;
            let noreply = parts.len() > 3 && parts[3] == "noreply";

            Ok((key, exptime, noreply))
        } else {
            Err("touch command not found")
        }
    }

    // NOT_STORED STORED EXISTS NOT_FOUND DELETED TOUCHED quit CLIENT_ERROR server_ERROR ERROR
    pub fn parse_response(payload: &[u8]) -> Result<Response, &'static str> {
        // 尝试将字节数组转换为 UTF-8 字符串
        let s = match std::str::from_utf8(payload) {
            Ok(s) => s,
            Err(_) => return Err("Invalid UTF-8 encoding"),
        };

        // 查找换行符的位置
        if let Some(line_end) = s.find("\r\n") {
            let response_line = &s[..line_end];
            if let Some(_f1) = response_line.find("NOT_STORED") {
                return core::result::Result::Ok(Response::NotStored);
            }
            if let Some(_f2) = response_line.find("STORED") {
                return core::result::Result::Ok(Response::Stored);
            }
            if let Some(_f3) = response_line.find("EXISTS") {
                return core::result::Result::Ok(Response::EXISTS);
            }
            if let Some(_f4) = response_line.find("NOT_FOUND") {
                return core::result::Result::Ok(Response::NOTFOUND);
            }
            if let Some(_f5) = response_line.find("DELETED") {
                return core::result::Result::Ok(Response::DELETED);
            }
            if let Some(_f6) = response_line.find("TOUCHED") {
                return core::result::Result::Ok(Response::TOUCHED);
            }
            if let Some(_f7) = response_line.find("quit") {
                return core::result::Result::Ok(Response::QUIT);
            }
            if let Some(_f8) = response_line.find("CLIENT_ERROR") {
                return core::result::Result::Ok(Response::CLIENTERROR);
            }
            if let Some(_f8) = response_line.find("SERVER_ERROR ") {
                return core::result::Result::Ok(Response::SERVERERROR);
            }
            if let Some(_f8) = response_line.find("ERROR ") {
                return core::result::Result::Ok(Response::ERROR);
            }
            Err("Not find right result")
        } else {
            Err("Incomplete command")
        }
    }
}

// test log parse

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::rc::Rc;
    use std::{cell::RefCell, fs};

    use super::memcached_parser::*;
    use super::*;
    use crate::flow_generator::protocol_logs::sql::memcached::tests::MemcachedCommand::*;

    use crate::{
        common::{flow::PacketDirection, l7_protocol_log::L7PerfCache, MetaPacket},
        flow_generator::L7_RRT_CACHE_CAPACITY,
        utils::test::Capture,
    };

    const FILE_DIR: &str = "resources/test/flow_generator/memcached";

    fn run(name: &str) -> String {
        let pcap_file = Path::new(FILE_DIR).join(name);
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let capture = Capture::load_pcap(pcap_file, None);
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }
        let mut output: String = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
        let mut memcached = MemCachedLog::default();
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
                PacketDirection::ClientToServer => memcached.check_payload(payload, param),
                PacketDirection::ServerToClient => memcached.check_payload(payload, param),
            };

            let info = if let Ok(i) = memcached.parse_payload(payload, param) {
                match i.unwrap_single() {
                    L7ProtocolInfo::MemCachedInfo(r) => r,
                    _ => unreachable!(),
                }
            } else {
                MemcachedInfo::default()
            };
            output.push_str(&format!("{} is_memcached: {}\n", info, is_memcached));
        }
        output
    }

    // #[test]
    // fn memcached_check() {
    //     //let files = vec!["memcached.pcap"];
    //     //println!("check function run ==");
    //     let output: String = run("memcached.pcap");
    //     println!("check function output :{:?}", output);
    // }

    #[test]
    fn test_valid_set_command() {
        let payload: &[u8] = b"some text before set mykey 0 0 5\r\nvalue\r\n";
        let result = parse_memcached_command(payload);
        assert!(result.is_ok());
        if let Ok(Set(key, flags, exptime, length, noreply, value)) = result {
            assert_eq!(key, "mykey");
            assert_eq!(flags, 0);
            assert_eq!(exptime, 0);
            assert_eq!(length, 5);
            assert!(!noreply);
            assert_eq!(value, b"value".as_ref());
        }
    }

    #[test]
    fn test_valid_add_command() {
        let payload: &[u8] = b"some text before add mykey 0 0 5\r\nvalue\r\n";
        let result = parse_memcached_command(payload);
        assert!(result.is_ok());
        if let Ok(Add(key, flags, exptime, length, noreply, value)) = result {
            assert_eq!(key, "mykey");
            assert_eq!(flags, 0);
            assert_eq!(exptime, 0);
            assert_eq!(length, 5);
            assert!(!noreply);
            assert_eq!(value, b"value".as_ref());
        }
    }

    #[test]
    fn test_valid_cas_command() {
        let payload: &[u8] = b"some text before cas mykey 0 0 5 1234567890\r\nvalue\r\n";
        let result = parse_cas_command(payload);
        assert!(result.is_ok());
        if let Ok((key, flags, exptime, length, cas_unique, noreply, value)) = result {
            assert_eq!(key, "mykey");
            assert_eq!(flags, 0);
            assert_eq!(exptime, 0);
            assert_eq!(length, 5);
            assert_eq!(cas_unique, 1234567890);
            assert!(!noreply);
            assert_eq!(value, b"value".as_ref());
        }
    }

    #[test]
    fn test_valid_single_value_response() {
        let payload: &[u8] = b"some text before VALUE mykey 0 5\r\nvalue\r\nEND\r\n";
        let result = parse_value_response(payload);
        println!("{:?}", result);

        assert!(result.is_ok());
        if let Ok((key, flags, value, cas_unique)) = result {
            assert_eq!(key, "mykey");
            assert_eq!(flags, 0);
            assert_eq!(value, b"value".as_ref().to_vec());
            assert_eq!(cas_unique, None);
        }
    }

    fn test_valid_delete_command() {
        let payload: &[u8] = b"some text before delete mykey\r\n";
        let result = parse_delete_command(payload);
        println!("{:?}", result);

        assert!(result.is_ok());
        if let Ok((key, noreply)) = result {
            assert_eq!(key, "mykey");
            assert!(!noreply);
        }
    }

    #[test]
    fn test_valid_incr_command() {
        let payload: &[u8] = b"some text before incr mykey 10\r\n";
        let result = parse_incr_decr_command(payload, "incr");
        println!("{:?}", result);

        assert!(result.is_ok());
        if let Ok((key, value, noreply)) = result {
            assert_eq!(key, "mykey");
            assert_eq!(value, 10);
            assert!(!noreply);
        }
    }
    #[test]
    fn test_valid_touch_command() {
        let payload: &[u8] = b"some text before touch mykey 60\r\n";
        let result = parse_touch_command(payload);
        println!("{:?}", result);

        assert!(result.is_ok());
        if let Ok((key, exptime, noreply)) = result {
            assert_eq!(key, "mykey");
            assert_eq!(exptime, 60);
            assert!(!noreply);
        }
    }

    #[test]
    fn test_stored_response() {
        let payload: &[u8] = b"some text before STORED\r\n";
        let result = parse_response(payload);
        println!("{:?}", result);

        assert!(result.is_ok());
        if let Ok(response) = result {
            assert!(matches!(response, Response::Stored));
        }
    }
    #[test]
    fn test_valid_get_command() {
        let payload: &[u8] = b"some text before get key1 key2 key3\r\n";
        let result = parse_get_command(payload);
        println!("{:?}", result);
        assert!(result.is_ok());
        if let Ok(keys) = result {
            assert_eq!(keys, vec!["key1", "key2", "key3"]);
        }
    }
}
