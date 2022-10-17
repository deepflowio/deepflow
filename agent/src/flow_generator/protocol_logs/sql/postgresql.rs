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
    /*
        ignore return this info, default is true.

        with request, parse:
            simple query ('Q')
            prepare statment ('P')

        with response parse
            command complete('C')
            error return ('E')

        when frame not all of these block, it will ignore.

        it use for skip some prepare statement execute and param bind, let the session aggregate match the query and result.

    */
    ignore: bool,

    // request
    pub context: String,
    pub req_type: char,

    // response
    pub resp_type: char,
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
                req_type: String::from(get_request_str(p.req_type)),
                resource: p.context,
                ..Default::default()
            },
            resp: L7Response {
                status: p.status,
                code: p.error_code,
                result: String::from(get_response_result(p.resp_type)),
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
            let r = if self.info.ignore {
                vec![]
            } else {
                vec![L7ProtocolInfo::PostgreInfo(self.info.clone())]
            };
            return Ok(r);
        }

        if self.check_is_ssl_req(payload) {
            return Ok(vec![]);
        }

        self.info.start_time = param.time;
        self.info.end_time = param.time;
        self.set_msg_type(param.direction);
        self.parse(payload)?;

        let r = if self.info.ignore {
            vec![]
        } else {
            vec![L7ProtocolInfo::PostgreInfo(self.info.clone())]
        };
        Ok(r)
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Postgresql
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }
}

impl PostgresqlLog {
    pub fn new() -> Self {
        let mut s = Self::default();
        s.info.ignore = true;
        s
    }

    fn set_msg_type(&mut self, direction: PacketDirection) {
        match direction {
            PacketDirection::ClientToServer => self.info.msg_type = LogMessageType::Request,
            PacketDirection::ServerToClient => self.info.msg_type = LogMessageType::Response,
        }
    }

    fn parse(&mut self, payload: &[u8]) -> Result<()> {
        let mut offset = 0;
        loop {
            if offset >= payload.len() {
                break;
            }
            let sub_payload = &payload[offset..];
            if let Some((tag, len)) = read_block(sub_payload) {
                offset += len + 5; // len(data) + len 4B + tag 1B
                match self.info.msg_type {
                    LogMessageType::Request => self.on_req_block(tag, &sub_payload[5..5 + len])?,
                    LogMessageType::Response => {
                        self.on_resp_block(tag, &sub_payload[5..5 + len])?
                    }

                    _ => {}
                }
            } else {
                break;
            }
        }
        Ok(())
    }

    fn check_is_ssl_req(&self, payload: &[u8]) -> bool {
        payload.len() == 8
            && self.info.msg_type == LogMessageType::Request
            && read_u64_be(payload) == SSL_REQ
    }

    fn on_req_block(&mut self, tag: char, data: &[u8]) -> Result<()> {
        match tag {
            'Q' => {
                self.info.req_type = tag;
                self.info.context = strip_string_end_with_zero(data);
                self.info.ignore = false;
                Ok(())
            }
            'P' => {
                // | statement 2B | query (len -4) B | param 2B |
                let len = data.len();
                if len < 5 {
                    return Err(Error::L7ProtocolUnknown);
                }
                self.info.req_type = tag;
                self.info.context = strip_string_end_with_zero(&data[2..len - 2]);
                self.info.ignore = false;
                Ok(())
            }
            'B' | 'F' | 'C' | 'D' | 'H' | 'S' | 'X' | 'd' | 'c' | 'f' => Ok(()),
            _ => Err(Error::L7ProtocolUnknown),
        }
    }

    fn on_resp_block(&mut self, tag: char, data: &[u8]) -> Result<()> {
        let mut data = data;
        match tag {
            'C' => {
                self.info.status = L7ResponseStatus::Ok;
                self.info.ignore = false;
                self.info.resp_type = tag;

                // INSERT xxx xxx0x0 where last xxx is row effect.
                // DELETE xxx0x0
                // UPDATE xxx0x0
                // SELECT xxx0x0
                if let Some(idx) = data.iter().position(|x| *x == 0x20) {
                    let op = &data[..idx];
                    data = &data[idx + 1..];
                    if op.eq("INSERT".as_bytes()) {
                        if let Some(idx) = data.iter().position(|x| *x == 0x20) {
                            data = &data[idx + 1..];
                        } else {
                            return Ok(());
                        }
                    } else {
                        if !(op.eq("DELETE".as_bytes())
                            || op.eq("UPDATE".as_bytes())
                            || op.eq("SELECT".as_bytes()))
                        {
                            return Ok(());
                        }
                    }
                }

                if let Some(idx) = data.iter().position(|x| *x == 0x0) {
                    let row_eff = String::from_utf8_lossy(&data[..idx]).to_string();
                    self.info.affected_rows = row_eff.parse().unwrap_or(0);
                }

                Ok(())
            }
            'E' => {
                self.info.status = L7ResponseStatus::Error;
                self.info.resp_type = tag;
                self.info.ignore = false;
                /*
                Severity: string end with 0x0
                Text:     string end with 0x0
                code:     string end with 0x0
                message:  string end with 0x0
                ...

                */
                for _ in 0..2 {
                    if let Some(idx) = data.iter().position(|x| *x == 0) {
                        data = &data[idx + 1..];
                    } else {
                        return Ok(());
                    }
                }
                // code, such as `C42601`
                if let Some(idx) = data.iter().position(|x| *x == 0) {
                    if data[0] != b'C' {
                        return Err(Error::L7ProtocolUnknown);
                    }
                    let err_code_str = String::from_utf8_lossy(&data[1..idx]).to_string();
                    self.info.error_code =
                        Some(err_code_str.parse().map_err(|_| Error::L7ProtocolUnknown)?);
                    data = &data[idx + 1..];
                }
                // message, start with "M"
                if let Some(idx) = data.iter().position(|x| *x == 0) {
                    if data[0] != b'M' {
                        return Err(Error::L7ProtocolUnknown);
                    }
                    self.info.error_message = strip_string_end_with_zero(&data[1..idx]);
                }
                Ok(())
            }

            'Z' | 'I' | '1' | '2' | '3' | 'S' | 'K' | 'T' | 'n' | 'N' | 't' | 'D' | 'G' | 'H'
            | 'W' | 'd' | 'c' => Ok(()),
            _ => Err(Error::L7ProtocolUnknown),
        }
    }
}

/*
    type: 1byte
    len(payload + len):  4byte be
    payload: len - 4 byte
    return tag, data length
*/
fn read_block(payload: &[u8]) -> Option<(char, usize)> {
    if payload.len() < 5 {
        return None;
    }
    let tag = char::from(payload[0]);
    let len = read_u32_be(&payload[1..]) as usize;
    if len < 4 || len + 1 > payload.len() {
        return None;
    }
    Some((tag, len - 4))
}

// strip the latest 0x0 in string
fn strip_string_end_with_zero(data: &[u8]) -> String {
    if data.ends_with(&[0]) {
        return String::from_utf8_lossy(&data[..data.len() - 1]).to_string();
    }
    String::from_utf8_lossy(&data[..data.len()]).to_string()
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

const RESP_STR_C: &'static str = "command complete";
const RESP_STR_E: &'static str = "error return";
const RESP_STR_Z: &'static str = "backend is ready for new query";
const RESP_STR_I: &'static str = "empty query";
const RESP_STR_1: &'static str = "Parse Complete";
const RESP_STR_2: &'static str = "Bind Complete";
const RESP_STR_3: &'static str = "Close Complete";
const RESP_STR_S: &'static str = "parameter status";
const RESP_STR_K: &'static str = "secret key data from the backend";
const RESP_STR_T: &'static str = "Row Description";
const RESP_STR_N: &'static str = "No Data";
const RESP_STR_PARAM_DESC: &'static str = "Parameter Description";
const RESP_STR_D: &'static str = "Data Row";
const RESP_STR_G: &'static str = "Start Copy In";
const RESP_STR_H: &'static str = "Start Copy Out";
const RESP_STR_W: &'static str = "Start Copy Both";
const RESP_STR_COPY_DATA: &'static str = "Copy Data";
const RESP_STR_COPY_DONE: &'static str = "Copy Done";

fn get_response_result(typ: char) -> &'static str {
    return match typ {
        'C' => RESP_STR_C,
        'E' => RESP_STR_E,
        'Z' => RESP_STR_Z,
        'I' => RESP_STR_I,
        '1' => RESP_STR_1,
        '2' => RESP_STR_2,
        '3' => RESP_STR_3,
        'S' => RESP_STR_S,
        'K' => RESP_STR_K,
        'T' => RESP_STR_T,
        'n' => RESP_STR_N,
        'N' => RESP_STR_N,
        't' => RESP_STR_PARAM_DESC,
        'D' => RESP_STR_D,
        'G' => RESP_STR_G,
        'H' => RESP_STR_H,
        'W' => RESP_STR_W,
        'd' => RESP_STR_COPY_DATA,
        'c' => RESP_STR_COPY_DONE,
        _ => "",
    };
}

const REQ_STR_Q: &'static str = "simple query";
const REQ_STR_P: &'static str = "parse";
const REQ_STR_B: &'static str = "bind";
const REQ_STR_E: &'static str = "execute";
const REQ_STR_F: &'static str = "fastpath function call";
const REQ_STR_C: &'static str = "close";
const REQ_STR_D: &'static str = "describe";
const REQ_STR_H: &'static str = "flush";
const REQ_STR_S: &'static str = "sync";
const REQ_STR_X: &'static str = "exit";
const REQ_STR_COPY_DATA: &'static str = "copy data";
const REQ_STR_COPY_DONE: &'static str = "copy done";
const REQ_STR_COPY_FAIL: &'static str = "copy fail";

fn get_request_str(typ: char) -> &'static str {
    match typ {
        'Q' => REQ_STR_Q,
        'P' => REQ_STR_P,
        'B' => REQ_STR_B,
        'E' => REQ_STR_E,
        'F' => REQ_STR_F,
        'C' => REQ_STR_C,
        'D' => REQ_STR_D,
        'H' => REQ_STR_H,
        'S' => REQ_STR_S,
        'X' => REQ_STR_X,
        'd' => REQ_STR_COPY_DATA,
        'c' => REQ_STR_COPY_DONE,
        'f' => REQ_STR_COPY_FAIL,
        _ => "",
    }
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use crate::{
        common::{
            l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
            l7_protocol_log::L7ProtocolParserInterface,
            l7_protocol_log::ParseParam, flow::PacketDirection,
        },
        flow_generator::protocol_logs::PostgreInfo,
        flow_generator::protocol_logs::PostgresqlLog,
        utils::test::Capture,
    };

    const FILE_DIR: &str = "resources/test/flow_generator/postgre";
    #[test]
    fn test_postgre() {
        test_simple_query()
    }
    fn test_simple_query() {
        let info = check_and_parse("simple_query.pcap");
        assert_eq!(info.affected_rows, 1);
        assert_eq!(info.req_type, 'Q');
        assert_eq!(info.context.as_str(), "delete  from test;");
        assert_eq!(info.resp_type, 'C');
    }

    fn test_prepare_stmt() {
        let info = check_and_parse("prepare_stat.pcap");
        assert_eq!(info.affected_rows, 0);
        assert_eq!(info.req_type, 'P');
        assert_eq!(
            info.context.as_str(),
            "delete from test where id=$1 returning id"
        );
        assert_eq!(info.resp_type, 'C');
    }

    fn test_error() {
        let info = check_and_parse("error.pcap");
        assert_eq!(info.req_type, 'Q');
        assert_eq!(info.context.as_str(), "asdsdfdsf;");
        assert_eq!(info.resp_type, 'E');
        assert_eq!(
            info.error_message.as_str(),
            "syntax error at or near \"asdsdfdsf\""
        );
    }

    fn check_and_parse(file_name: &str) -> PostgreInfo {
        let pcap_file = Path::new(FILE_DIR).join(file_name);
        let capture = Capture::load_pcap(pcap_file, None);
        let mut p = capture.as_meta_packets();
        p[0].direction= PacketDirection::ClientToServer;
        p[1].direction= PacketDirection::ServerToClient;

        let mut parser = PostgresqlLog::new();
        let req_param = &mut ParseParam::from(&p[0]);
        let req_payload = p[0].get_l4_payload().unwrap();
        assert_eq!((&mut parser).check_payload(req_payload, req_param), true);
        let mut info = (&mut parser).parse_payload(req_payload, req_param).unwrap();
        let mut req = info.swap_remove(0);

        (&mut parser).reset();

        let resp_param = &ParseParam::from(&p[1]);
        let resp_payload = p[1].get_l4_payload().unwrap();
        assert_eq!((&mut parser).check_payload(resp_payload, resp_param), true);
        let resp = (&mut parser)
            .parse_payload(resp_payload, resp_param)
            .unwrap()
            .swap_remove(0);

        req.merge_log(resp).unwrap();
        if let L7ProtocolInfo::PostgreInfo(info) = req {
            return info;
        }
        unreachable!()
    }
}
