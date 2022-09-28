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

use public::{bytes::read_u32_be, l7_protocol::L7Protocol};
use serde::Serialize;

use crate::{
    common::{
        ebpf::EbpfType,
        flow::PacketDirection,
        l7_protocol_log::{L7ProtocolLog, L7ProtocolLogInterface, ParseParam},
    },
    flow_generator::{
        protocol_logs::{
            pb_adapter::{ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response},
            L7ResponseStatus,
        },
        AppProtoHead, Error, LogMessageType, Result,
    },
    ignore_ebpf,
};

#[derive(Debug, Default, Clone, Serialize)]
pub struct PostgresInfo {
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

#[derive(Default, Debug, Clone, Serialize)]
pub struct PostgresqlLog {
    info: PostgresInfo,
    msg_type: LogMessageType,
    start_time: u64,
    end_time: u64,
    is_tls: bool,
}

impl L7ProtocolLogInterface for PostgresqlLog {
    fn session_id(&self) -> Option<u32> {
        return None;
    }

    fn merge_log(&mut self, other: L7ProtocolLog) -> Result<()> {
        if let L7ProtocolLog::PostgresLog(pg) = other {
            if pg.start_time < self.start_time {
                self.start_time = pg.start_time;
            }
            if pg.end_time > self.end_time {
                self.end_time = pg.end_time;
            }

            match pg.msg_type {
                LogMessageType::Request => {
                    self.info.req_type = pg.info.req_type;
                    self.info.context = pg.info.context.clone();
                }
                LogMessageType::Response => {
                    self.info.resp_type = pg.info.resp_type;
                    self.info.response_code = pg.info.response_code;
                    self.info.error_code = pg.info.error_code;
                    self.info.error_message = pg.info.error_message;
                    self.info.status = pg.info.status;
                    self.info.affected_rows = pg.info.affected_rows;
                }
                _ => {}
            }
        }
        return Ok(());
    }

    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        ignore_ebpf!(param);
        self.set_msg_type(param.direction);
        return self.parse(payload, true).is_ok();
    }

    fn parse_payload(mut self, payload: &[u8], param: &ParseParam) -> Result<Vec<L7ProtocolLog>> {
        self.start_time = param.time;
        self.end_time = param.time;
        self.set_msg_type(param.direction);
        self.parse(payload, false)?;
        return Ok(vec![L7ProtocolLog::PostgresLog(self)]);
    }

    fn protocol(&self) -> (L7Protocol, &str) {
        return (L7Protocol::Postgresql, "POSTGRESQL");
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        return Some(AppProtoHead {
            proto: L7Protocol::Postgresql,
            msg_type: self.msg_type,
            rrt: self.end_time - self.start_time,
        });
    }

    fn is_tls(&self) -> bool {
        return self.is_tls;
    }

    fn skip_send(&self) -> bool {
        return false;
    }

    fn into_l7_protocol_send_log(self) -> L7ProtocolSendLog {
        return L7ProtocolSendLog {
            req_len: None,
            resp_len: None,
            req: L7Request {
                req_type: String::from(char::from(self.info.req_type)),
                domain: String::new(),
                resource: self.info.context,
            },
            resp: L7Response {
                status: self.info.status,
                code: Some(self.info.resp_type as i32),
                result: self.info.error_message,
                ..Default::default()
            },
            ext_info: Some(ExtendedInfo {
                row_effect: Some(self.info.affected_rows as u32),
                ..Default::default()
            }),
            ..Default::default()
        };
    }

    fn reset_and_copy(&self) -> L7ProtocolLog {
        return L7ProtocolLog::PostgresLog(Self::default());
    }

    fn parse_on_udp(&self) -> bool {
        return false;
    }
}

impl PostgresqlLog {
    fn set_msg_type(&mut self, direction: PacketDirection) {
        match direction {
            PacketDirection::ClientToServer => self.msg_type = LogMessageType::Request,
            PacketDirection::ServerToClient => self.msg_type = LogMessageType::Response,
        }
    }

    /*
    type: 1byte
    len(payload + len):  4byte be
    payload: len - 4 byte
    */

    fn parse(&mut self, payload: &[u8], check_only: bool) -> Result<()> {
        if payload.len() < 5 {
            return Err(Error::L7ProtocolUnknown);
        }
        let typ = payload[0];
        if !check_type(self.msg_type, typ) {
            return Err(Error::L7ProtocolUnknown);
        };

        let data_len = read_u32_be(&payload[1..5]);
        if payload.len() - 1 < data_len as usize {
            return Err(Error::L7ProtocolUnknown);
        }
        if check_only {
            return Ok(());
        }
        match self.msg_type {
            LogMessageType::Request => {
                self.info.req_type = typ;
                self.info.context = String::from_utf8_lossy(&payload[5..]).to_string();
            }
            LogMessageType::Response => {
                self.info.resp_type = typ;
                match char::from(self.info.resp_type) {
                    RESP_ERROR => {
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
                    RESP_COMM_COMPLETE => {
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

        return Ok(());
    }
}

/*
req:
case 'Q':            simple query
case 'P':            parse
case 'B':            bind
case 'E':            execute
case 'F':            fastpath function call
case 'C':            close
case 'D':            describe
case 'H':            flush
case 'S':            sync
case 'X':            exit
case 'd':            copy data
case 'c':            copy done
case 'f':            copy fail

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
case 't':        Parameter Description
case 'D':        Data Row
case 'G':        Start Copy In
case 'H':        Start Copy Out
case 'W':        Start Copy Both
case 'd':        Copy Data
case 'c':        Copy Done
case 'R':        Authentication Reques
*/
const QUERY_SIMPLE_QUERY: char = 'Q';
const QUERY_EXEC: char = 'E';

const RESP_ERROR: char = 'E';
const RESP_COMM_COMPLETE: char = 'C';
const RESP_ROW_DESC: char = 'T';
const RESP_DATA_ROW: char = 'D';

fn check_type(msg_type: LogMessageType, typ: u8) -> bool {
    let c = char::from(typ);
    match msg_type {
        LogMessageType::Request => match c {
            QUERY_SIMPLE_QUERY | QUERY_EXEC => return true,
            _ => return false,
        },
        LogMessageType::Response => match c {
            RESP_ERROR | RESP_COMM_COMPLETE | RESP_ROW_DESC | RESP_DATA_ROW => return true,
            _ => return false,
        },
        _ => return false,
    }
}
