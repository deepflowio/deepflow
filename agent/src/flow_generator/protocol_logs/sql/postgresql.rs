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

use public::{
    bytes::{read_u32_be, read_u64_be},
    l7_protocol::L7Protocol,
};
use serde::Serialize;

use crate::{
    common::{
        flow::PacketDirection,
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ProtocolParserInterface, ParseParam},
    },
    flow_generator::{
        protocol_logs::{
            pb_adapter::{ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response},
            L7ResponseStatus,
        },
        AppProtoHead, Error, LogMessageType, Result,
    },
};

const SSL_REQ: u64 = 34440615471; // 00000008(len) 04d2162f(const 80877103)

#[derive(Debug, Default, Clone, Serialize)]
pub struct PostgreInfo {
    msg_type: LogMessageType,
    start_time: u64,
    end_time: u64,
    is_tls: bool,

    // request
    pub context: String,
    pub req_type: u8,

    // response
    pub resp_type: u8,
    pub response_code: u8,
    pub error_code: Option<i32>,
    pub affected_rows: u64,
    pub error_message: String,
    pub status: L7ResponseStatus,
}

impl L7ProtocolInfoInterface for PostgreInfo {
    fn session_id(&self) -> Option<u32> {
        None
    }

    fn merge_log(&mut self, other: L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::PostgreInfo(pg) = other {
            if pg.start_time < self.start_time {
                self.start_time = pg.start_time;
            }
            if pg.end_time > self.end_time {
                self.end_time = pg.end_time;
            }
            match pg.msg_type {
                LogMessageType::Request => {
                    self.req_type = pg.req_type;
                    self.context = pg.context.clone();
                }
                LogMessageType::Response => {
                    self.resp_type = pg.resp_type;
                    self.response_code = pg.response_code;
                    self.error_code = pg.error_code;
                    self.error_message = pg.error_message;
                    self.status = pg.status;
                    self.affected_rows = pg.affected_rows;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::Postgresql,
            msg_type: self.msg_type,
            rrt: self.end_time - self.start_time,
        })
    }

    fn is_tls(&self) -> bool {
        self.is_tls
    }

    fn skip_send(&self) -> bool {
        false
    }
}

impl From<PostgreInfo> for L7ProtocolSendLog {
    fn from(p: PostgreInfo) -> L7ProtocolSendLog {
        L7ProtocolSendLog {
            req_len: None,
            resp_len: None,
            row_effect: p.affected_rows as u32,
            req: L7Request {
                req_type: String::from(char::from(p.req_type)),
                domain: String::new(),
                resource: p.context,
            },
            resp: L7Response {
                status: p.status,
                code: Some(p.resp_type as i32),
                result: get_response_result(p.resp_type).unwrap_or_default(),
                exception: p.error_message,
            },
            ext_info: Some(ExtendedInfo {
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

#[derive(Default, Debug, Clone, Serialize)]
pub struct PostgresqlLog {
    info: PostgreInfo,
    parsed: bool,
}

impl L7ProtocolParserInterface for PostgresqlLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        self.info.start_time = param.time;
        self.info.end_time = param.time;
        self.set_msg_type(param.direction);
        if self.check_is_ssl_req(payload) {
            return true;
        }

        if self.parse(payload).is_ok() {
            self.parsed = true;
            return true;
        } else {
            return false;
        }
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<Vec<L7ProtocolInfo>> {
        if self.parsed {
            return Ok(vec![L7ProtocolInfo::PostgreInfo(self.info.clone())]);
        }

        if self.check_is_ssl_req(payload) {
            return Ok(vec![]);
        }

        self.info.start_time = param.time;
        self.info.end_time = param.time;
        self.set_msg_type(param.direction);
        self.parse(payload)?;
        Ok(vec![L7ProtocolInfo::PostgreInfo(self.info.clone())])
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Postgresql
    }

    fn reset(&mut self) {
        *self = Self::default();
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }
}

impl PostgresqlLog {
    fn set_msg_type(&mut self, direction: PacketDirection) {
        match direction {
            PacketDirection::ClientToServer => self.info.msg_type = LogMessageType::Request,
            PacketDirection::ServerToClient => self.info.msg_type = LogMessageType::Response,
        }
    }

    /*
    type: 1byte
    len(payload + len):  4byte be
    payload: len - 4 byte
    */

    fn parse(&mut self, payload: &[u8]) -> Result<()> {
        if payload.len() < 5 {
            return Err(Error::L7ProtocolUnknown);
        }

        let typ = payload[0];
        if !check_type(self.info.msg_type, typ) {
            return Err(Error::L7ProtocolUnknown);
        };

        let data_len = read_u32_be(&payload[1..5]);
        if payload.len() - 1 < data_len as usize {
            return Err(Error::L7ProtocolUnknown);
        }

        match self.info.msg_type {
            LogMessageType::Request => {
                self.info.req_type = typ;
                self.info.context = String::from_utf8_lossy(&payload[5..]).to_string();
            }
            LogMessageType::Response => {
                self.info.resp_type = typ;
                match char::from(self.info.resp_type) {
                    'E' => {
                        self.info.status = L7ResponseStatus::Error;
                        /*
                        type: 1B
                        len: 4B
                        Severity: string, end with 0x0
                        Text: string end with 0x0
                        code: string end with 0x0

                        ...

                        */
                        let mut data = &payload[5..];

                        for _ in 0..2 {
                            if let Some(idx) = data.iter().position(|x| *x == 0) {
                                data = &data[idx + 1..];
                            } else {
                                return Ok(());
                            }
                        }
                        if let Some(idx) = data.iter().position(|x| *x == 0) {
                            self.info.error_message =
                                String::from_utf8_lossy(&data[..idx]).to_string();
                        }

                        return Ok(());
                    }
                    'C' => {
                        self.info.status = L7ResponseStatus::Ok;
                        // INSERT xxx xxx0x0 where last xxx is row effect.
                        // DELETE xxx0x0
                        // UPDATE xxx0x0
                        let mut tag = &payload[5..];
                        if let Some(idx) = tag.iter().position(|x| *x == 0x20) {
                            let op = &tag[..idx];
                            tag = &tag[idx + 1..];
                            if op.eq("INSERT".as_bytes()) {
                                if let Some(idx) = tag.iter().position(|x| *x == 0x20) {
                                    tag = &tag[idx + 1..];
                                } else {
                                    return Ok(());
                                }
                            } else {
                                if !(op.eq("DELETE".as_bytes()) || op.eq("UPDATE".as_bytes())) {
                                    return Ok(());
                                }
                            }
                        }

                        if let Some(idx) = tag.iter().position(|x| *x == 0x0) {
                            let row_eff = String::from_utf8_lossy(&tag[..idx]).to_string();
                            self.info.affected_rows = row_eff.parse().unwrap_or(0);
                        }
                    }
                    _ => {
                        self.info.status = L7ResponseStatus::Ok;
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn check_is_ssl_req(&self, payload: &[u8]) -> bool {
        if payload.len() != 8 {
            return false;
        }
        self.info.msg_type == LogMessageType::Request && read_u64_be(payload) == SSL_REQ
    }
}

/*
req:
case 'Q'            simple query
case 'P'            parse
case 'B'            bind
case 'E'            execute
case 'F'            fastpath function call
case 'C'            close
case 'D'            describe
case 'H'            flush
case 'S'            sync
case 'X'            exit
case 'd'            copy data
case 'c'            copy done
case 'f'            copy fail

resp:
case 'C':        command complete
case 'E':        error return
case 'Z':        backend is ready for new query
case 'I':        empty query
case '1':        Parse Complete
case '2':        Bind Complete
case '3':        Close Complete
case 'S':        parameter status
case 'K':        secret key data from the backend
case 'T':        Row Description
case 'n':        No Data
case 'N':        No Data
case 't':        Parameter Description
case 'D':        Data Row
case 'G':        Start Copy In
case 'H':        Start Copy Out
case 'W':        Start Copy Both
case 'd':        Copy Data
case 'c':        Copy Done
case 'R':        Authentication Reques, should ignore
*/

fn check_type(msg_type: LogMessageType, typ: u8) -> bool {
    let c = char::from(typ);
    match msg_type {
        LogMessageType::Request => match c {
            'Q' | 'P' | 'B' | 'E' | 'F' | 'C' | 'D' | 'H' | 'S' | 'X' | 'd' | 'c' | 'f' => {
                return true
            }
            _ => false,
        },
        LogMessageType::Response => match c {
            'C' | 'E' | 'Z' | 'I' | '1' | '2' | '3' | 'S' | 'K' | 'T' | 'n' | 'N' | 't' | 'D'
            | 'G' | 'H' | 'W' | 'd' | 'c' => true,
            _ => false,
        },
        _ => false,
    }
}

fn get_response_result(typ: u8) -> Option<String> {
    return match char::from(typ) {
        'C' => Some(String::from("command complete")),
        'E' => Some(String::from("error return")),
        'Z' => Some(String::from("backend is ready for new query")),
        'I' => Some(String::from("empty query")),
        '1' => Some(String::from("Parse Complete")),
        '2' => Some(String::from("Bind Complete")),
        '3' => Some(String::from("Close Complete")),
        'S' => Some(String::from("parameter status")),
        'K' => Some(String::from("secret key data from the backend")),
        'T' => Some(String::from("Row Description")),
        'n' => Some(String::from("No Data")),
        'N' => Some(String::from("No Data")),
        't' => Some(String::from("Parameter Description")),
        'D' => Some(String::from("Data Row")),
        'G' => Some(String::from("Start Copy In")),
        'H' => Some(String::from("Start Copy Out")),
        'W' => Some(String::from("Start Copy Both")),
        'd' => Some(String::from("Copy Data")),
        'c' => Some(String::from("Copy Done")),
        _ => None,
    };
}
