/*
 * Copyright (c) 2022 Yunshan Networks
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

use serde::Serialize;

use super::super::{consts::*, value_is_default, AppProtoHead, L7ResponseStatus, LogMessageType};
use super::sql_check::is_mysql;

use crate::{
    common::{
        enums::IpProtocol,
        flow::L7Protocol,
        flow::PacketDirection,
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ProtocolParserInterface, ParseParam},
    },
    flow_generator::{
        error::{Error, Result},
        protocol_logs::pb_adapter::{ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response},
    },
    utils::bytes,
};
use crate::{log_info_merge, parse_common};

#[derive(Serialize, Debug, Default, Clone)]
pub struct MysqlInfo {
    msg_type: LogMessageType,
    #[serde(skip)]
    start_time: u64,
    #[serde(skip)]
    end_time: u64,
    #[serde(skip)]
    is_tls: bool,

    // Server Greeting
    #[serde(rename = "version", skip_serializing_if = "value_is_default")]
    pub protocol_version: u8,
    #[serde(skip)]
    pub server_version: String,
    #[serde(skip)]
    pub server_thread_id: u32,
    // request
    #[serde(rename = "request_type")]
    pub command: u8,
    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub context: String,
    // response
    pub response_code: u8,
    #[serde(skip)]
    pub error_code: Option<i32>,
    #[serde(rename = "sql_affected_rows", skip_serializing_if = "value_is_default")]
    pub affected_rows: u64,
    #[serde(
        rename = "response_execption",
        skip_serializing_if = "value_is_default"
    )]
    pub error_message: String,
    #[serde(rename = "response_status")]
    pub status: L7ResponseStatus,
}

impl L7ProtocolInfoInterface for MysqlInfo {
    fn session_id(&self) -> Option<u32> {
        None
    }

    fn merge_log(&mut self, other: crate::common::l7_protocol_info::L7ProtocolInfo) -> Result<()> {
        log_info_merge!(self, MysqlInfo, other);
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::MySQL,
            msg_type: self.msg_type,
            rrt: self.end_time - self.start_time,
        })
    }

    fn is_tls(&self) -> bool {
        self.is_tls
    }
}

impl MysqlInfo {
    pub fn merge(&mut self, other: Self) {
        if self.protocol_version == 0 {
            self.protocol_version = other.protocol_version
        }
        if self.server_version.is_empty() {
            self.server_version = other.server_version;
        }
        if self.server_thread_id == 0 {
            self.server_thread_id = other.server_thread_id;
        }
        match other.msg_type {
            LogMessageType::Request => {
                self.command = other.command;
                self.context = other.context;
            }
            LogMessageType::Response => {
                self.response_code = other.response_code;
                self.affected_rows = other.affected_rows;
                self.error_message = other.error_message;
                self.status = other.status;
                if self.error_code.is_none() {
                    self.error_code = other.error_code;
                }
            }
            _ => {}
        }
    }

    pub fn get_command_str(&self) -> &'static str {
        let command = [
            "COM_SLEEP",
            "COM_QUIT",
            "COM_INIT_DB",
            "COM_QUERY",
            "COM_FIELD_LIST",
            "COM_CREATE_DB",
            "COM_DROP_DB",
            "COM_REFRESH",
            "COM_SHUTDOWN",
            "COM_STATISTICS",
            "COM_PROCESS_INFO",
            "COM_CONNECT",
            "COM_PROCESS_KILL",
            "COM_DEBUG",
            "COM_PING",
            "COM_TIME",
            "COM_DELAYED_INSERT",
            "COM_CHANGE_USER",
            "COM_BINLOG_DUMP",
            "COM_TABLE_DUMP",
            "COM_CONNECT_OUT",
            "COM_REGISTER_SLAVE",
            "COM_STMT_PREPARE",
            "COM_STMT_EXECUTE",
            "COM_STMT_SEND_LONG_DATA",
            "COM_STMT_CLOSE",
            "COM_STMT_RESET",
            "COM_SET_OPTION",
            "COM_STMT_FETCH",
            "COM_DAEMON",
            "COM_BINLOG_DUMP_GTID",
            "COM_RESET_CONNECTION",
        ];
        match self.command {
            0x00..=0x1f => command[self.command as usize],
            _ => "",
        }
    }
}

impl From<MysqlInfo> for L7ProtocolSendLog {
    fn from(f: MysqlInfo) -> Self {
        let log = L7ProtocolSendLog {
            version: if f.protocol_version == 0 {
                None
            } else {
                Some(f.protocol_version.to_string())
            },
            row_effect: f.affected_rows as u32,
            req: L7Request {
                req_type: String::from(f.get_command_str()),
                resource: f.context,
                ..Default::default()
            },
            resp: L7Response {
                status: f.status,
                code: f.error_code,
                exception: f.error_message,
                ..Default::default()
            },
            ext_info: Some(ExtendedInfo {
                ..Default::default()
            }),
            ..Default::default()
        };
        return log;
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct MysqlLog {
    info: MysqlInfo,
    l7_proto: L7Protocol,
    command: u8,
}

impl L7ProtocolParserInterface for MysqlLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if !param.ebpf_type.is_raw_protocol() {
            return false;
        }
        self.info.is_tls = param.is_tls();
        Self::mysql_check_protocol(payload, param)
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<Vec<L7ProtocolInfo>> {
        parse_common!(self, param);
        self.info.is_tls = param.is_tls();
        self.parse(payload, param.l4_protocol, param.direction, None, None)?;
        Ok(vec![L7ProtocolInfo::MysqlInfo(self.info.clone())])
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::MySQL
    }

    fn reset(&mut self) {
        *self = Self {
            l7_proto: self.l7_proto,
            command: self.command,
            ..Default::default()
        };
    }
}

fn mysql_string(payload: &[u8]) -> String {
    if payload.len() > 2 && payload[0] == 0 && payload[1] == 1 {
        // MYSQL 8.0.26返回字符串前有0x0、0x1，MYSQL 8.0.21版本没有这个问题
        // https://gitlab.yunshan.net/platform/trident/-/merge_requests/2592#note_401425
        String::from_utf8_lossy(&payload[2..]).into_owned()
    } else {
        String::from_utf8_lossy(payload).into_owned()
    }
}

impl MysqlLog {
    fn request_string(&mut self, payload: &[u8]) {
        self.info.context = mysql_string(payload);
    }

    fn reset_logs(&mut self) {
        self.info = MysqlInfo::default();
        self.info.status = L7ResponseStatus::Ok;
        self.info.error_code = None;
    }

    fn greeting(&mut self, payload: &[u8]) -> Result<()> {
        let mut remain = payload.len();
        if remain < PROTOCOL_VERSION_LEN {
            return Err(Error::MysqlLogParseFailed);
        }
        self.info.protocol_version = payload[PROTOCOL_VERSION_OFFSET];
        remain -= PROTOCOL_VERSION_LEN;
        let server_version_pos = payload[SERVER_VERSION_OFFSET..]
            .iter()
            .position(|&x| x == SERVER_VERSION_EOF)
            .unwrap_or_default();
        if server_version_pos <= 0 {
            return Err(Error::MysqlLogParseFailed);
        }
        self.info.server_version = String::from_utf8_lossy(
            &payload[SERVER_VERSION_OFFSET..SERVER_VERSION_OFFSET + server_version_pos],
        )
        .into_owned();
        remain -= server_version_pos as usize;
        if remain < THREAD_ID_LEN {
            return Err(Error::MysqlLogParseFailed);
        }
        let thread_id_offset = THREAD_ID_OFFSET_B + server_version_pos + 1;
        self.info.server_thread_id = bytes::read_u32_le(&payload[thread_id_offset..]);
        self.l7_proto = L7Protocol::MySQL;
        Ok(())
    }

    fn request(&mut self, payload: &[u8]) -> Result<()> {
        if payload.len() < COMMAND_LEN {
            return Err(Error::MysqlLogParseFailed);
        }
        self.info.command = payload[COMMAND_OFFSET];
        self.command = payload[COMMAND_OFFSET];
        match self.info.command {
            COM_QUIT | COM_FIELD_LIST | COM_STMT_EXECUTE | COM_STMT_CLOSE | COM_STMT_FETCH => (),
            COM_INIT_DB | COM_QUERY | COM_STMT_PREPARE => {
                self.request_string(&payload[COMMAND_OFFSET + COMMAND_LEN..]);
            }
            _ => return Err(Error::MysqlLogParseFailed),
        }
        self.l7_proto = L7Protocol::MySQL;
        Ok(())
    }

    fn decode_compress_int(payload: &[u8]) -> u64 {
        let remain = payload.len();
        if remain == 0 {
            return 0;
        }
        let value = payload[0];
        match value {
            INT_FLAGS_2 if remain > INT_BASE_LEN + 2 => {
                bytes::read_u16_le(&payload[INT_BASE_LEN..]) as u64
            }
            INT_FLAGS_3 if remain > INT_BASE_LEN + 3 => {
                bytes::read_u16_le(&payload[INT_BASE_LEN..]) as u64
                    | ((payload[INT_BASE_LEN + 2] as u64) << 16)
            }
            INT_FLAGS_8 if remain > INT_BASE_LEN + 8 => {
                bytes::read_u64_le(&payload[INT_BASE_LEN..])
            }
            _ => value as u64,
        }
    }

    fn set_status(&mut self, status_code: u16) {
        if status_code != 0 {
            if status_code >= 2000 && status_code <= 2999 {
                self.info.status = L7ResponseStatus::ClientError;
            } else {
                self.info.status = L7ResponseStatus::ServerError;
            }
        } else {
            self.info.status = L7ResponseStatus::Ok;
        }
    }

    fn response(&mut self, payload: &[u8]) -> Result<()> {
        let mut remain = payload.len();
        if remain < RESPONSE_CODE_LEN {
            return Err(Error::MysqlLogParseFailed);
        }
        self.info.response_code = payload[RESPONSE_CODE_OFFSET];
        remain -= RESPONSE_CODE_LEN;
        match self.info.response_code {
            MYSQL_RESPONSE_CODE_ERR => {
                if remain > ERROR_CODE_LEN {
                    let code = bytes::read_u16_le(&payload[ERROR_CODE_OFFSET..]);
                    self.info.error_code = Some(code as i32);
                    self.set_status(code);
                    remain -= ERROR_CODE_LEN;
                }
                let error_message_offset =
                    if remain > SQL_STATE_LEN && payload[SQL_STATE_OFFSET] == SQL_STATE_MARKER {
                        SQL_STATE_OFFSET + SQL_STATE_LEN
                    } else {
                        SQL_STATE_OFFSET
                    };
                if error_message_offset < payload.len() {
                    self.info.error_message =
                        String::from_utf8_lossy(&payload[error_message_offset..]).into_owned();
                }
            }
            MYSQL_RESPONSE_CODE_OK => {
                self.info.status = L7ResponseStatus::Ok;
                if self.command == COM_QUERY {
                    self.info.affected_rows =
                        MysqlLog::decode_compress_int(&payload[AFFECTED_ROWS_OFFSET..]);
                }
            }
            _ => (),
        }
        self.command = 0;
        Ok(())
    }

    pub fn mysql_check_protocol(payload: &[u8], param: &ParseParam) -> bool {
        if param.l4_protocol != IpProtocol::Tcp {
            return false;
        }

        let mut header = MysqlHeader::default();
        let offset = header.decode(payload);
        if offset < 0 {
            return false;
        }
        let offset = offset as usize;

        if header.number != 0 || offset + header.length as usize > payload.len() {
            return false;
        }

        let protocol_version_or_query_type = payload[offset];
        match protocol_version_or_query_type {
            COM_QUERY | COM_STMT_PREPARE => {
                let context = mysql_string(&payload[offset + 1..]);
                return context.is_ascii() && is_mysql(&context);
            }
            _ => {}
        }
        false
    }

    fn parse(
        &mut self,
        payload: &[u8],
        proto: IpProtocol,
        direction: PacketDirection,
        _is_req_end: Option<bool>,
        _is_resp_end: Option<bool>,
    ) -> Result<()> {
        if proto != IpProtocol::Tcp {
            return Err(Error::InvalidIpProtocol);
        }
        self.reset_logs();

        let mut header = MysqlHeader::default();
        let offset = header.decode(payload);
        if offset < 0 {
            return Err(Error::MysqlLogParseFailed);
        }
        let offset = offset as usize;
        let msg_type = header
            .check(direction, offset, payload, self.l7_proto)
            .ok_or(Error::MysqlLogParseFailed)?;

        match msg_type {
            LogMessageType::Request => self.request(&payload[offset..])?,
            LogMessageType::Response => self.response(&payload[offset..])?,
            LogMessageType::Other => self.greeting(&payload[offset..])?,
            _ => return Err(Error::MysqlLogParseFailed),
        };
        self.info.msg_type = msg_type;

        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct MysqlHeader {
    length: u32,
    number: u8,
}

impl MysqlHeader {
    pub fn decode(&mut self, payload: &[u8]) -> isize {
        if payload.len() < 5 {
            return -1;
        }
        let len = bytes::read_u32_le(payload) & 0xffffff;
        if payload[HEADER_LEN + RESPONSE_CODE_OFFSET] == MYSQL_RESPONSE_CODE_OK
            || payload[HEADER_LEN + RESPONSE_CODE_OFFSET] == MYSQL_RESPONSE_CODE_ERR
            || payload[HEADER_LEN + RESPONSE_CODE_OFFSET] == MYSQL_RESPONSE_CODE_EOF
            || payload[NUMBER_OFFSET] == 0
        {
            self.length = len;
            self.number = payload[NUMBER_OFFSET];
            return HEADER_LEN as isize;
        }
        let offset = len as usize + HEADER_LEN;
        if offset >= payload.len() {
            return 0;
        }
        let offset = offset as isize;
        offset + self.decode(&payload[offset as usize..])
    }

    pub fn check(
        &self,
        direction: PacketDirection,
        offset: usize,
        payload: &[u8],
        l7_proto: L7Protocol,
    ) -> Option<LogMessageType> {
        if offset >= payload.len() || self.length == 0 {
            return None;
        }
        if self.number != 0 && l7_proto == L7Protocol::Unknown {
            return None;
        }

        match direction {
            PacketDirection::ServerToClient if self.number == 0 => {
                let payload = &payload[offset..];
                if payload.len() < PROTOCOL_VERSION_LEN {
                    return None;
                }
                let protocol_version = payload[PROTOCOL_VERSION_OFFSET];
                let index = payload[SERVER_VERSION_OFFSET..]
                    .iter()
                    .position(|&x| x == SERVER_VERSION_EOF)?;
                if index != 0 && protocol_version == PROTOCOL_VERSION {
                    Some(LogMessageType::Other)
                } else {
                    None
                }
            }
            PacketDirection::ServerToClient => Some(LogMessageType::Response),
            PacketDirection::ClientToServer if self.number == 0 => Some(LogMessageType::Request),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;

    use crate::{
        common::{flow::PacketDirection, MetaPacket},
        utils::test::Capture,
    };

    const FILE_DIR: &str = "resources/test/flow_generator/mysql";

    fn run(name: &str) -> String {
        let pcap_file = Path::new(FILE_DIR).join(name);
        let capture = Capture::load_pcap(pcap_file, Some(1400));
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut mysql = MysqlLog::default();
        let mut output: String = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
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
            let _ = mysql.parse(
                payload,
                packet.lookup_key.proto,
                packet.lookup_key.direction,
                None,
                None,
            );
            let is_mysql =
                MysqlLog::mysql_check_protocol(payload, &ParseParam::from(packet as &MetaPacket));
            output.push_str(&format!("{:?} is_mysql: {}\r\n", mysql.info, is_mysql));
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![
            ("mysql-statement-id.pcap", "mysql-statement-id.result"),
            ("mysql-statement.pcap", "mysql-statement.result"),
            ("mysql.pcap", "mysql.result"),
            ("mysql-error.pcap", "mysql-error.result"),
            ("mysql-table-desc.pcap", "mysql-table-desc.result"),
            ("mysql-table-insert.pcap", "mysql-table-insert.result"),
            ("mysql-table-delete.pcap", "mysql-table-delete.result"),
            ("mysql-table-update.pcap", "mysql-table-update.result"),
            ("mysql-table-select.pcap", "mysql-table-select.result"),
            ("mysql-table-create.pcap", "mysql-table-create.result"),
            ("mysql-table-destroy.pcap", "mysql-table-destroy.result"),
            ("mysql-table-alter.pcap", "mysql-table-alter.result"),
            ("mysql-database.pcap", "mysql-database.result"),
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
