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
        flow::{FlowPerfStats, L7PerfStats, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ProtocolParserInterface, ParseParam},
        MetaPacket,
    },
    flow_generator::{
        perf::{L7FlowPerf, PerfStats},
        protocol_logs::{
            pb_adapter::{ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response},
            L7ResponseStatus,
        },
        AppProtoHead, Error, LogMessageType, Result,
    },
};

use super::{
    is_postgresql,
    postgre_convert::{get_code_desc, get_request_str},
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
    pub result: String,
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
                    self.result = pg.result;
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
            proto: L7Protocol::PostgreSQL,
            msg_type: self.msg_type,
            rrt: self.end_time - self.start_time,
        })
    }

    fn is_tls(&self) -> bool {
        self.is_tls
    }

    fn skip_send(&self) -> bool {
        return self.context.is_empty();
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
                result: p.result,
                exception: p.error_message,
                ..Default::default()
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
    perf_stats: Option<PerfStats>,
    parsed: bool,
}

impl L7ProtocolParserInterface for PostgresqlLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        self.info.start_time = param.time;
        self.info.end_time = param.time;
        self.set_msg_type(param.direction);
        self.info.is_tls = param.is_tls();
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
        self.info.is_tls = param.is_tls();
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
        L7Protocol::PostgreSQL
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }
}

impl L7FlowPerf for PostgresqlLog {
    fn parse(&mut self, packet: &MetaPacket, _flow_id: u64) -> Result<()> {
        if let Some(payload) = packet.get_l4_payload() {
            self.parse_payload(payload, &ParseParam::from(packet))?;
        }
        Ok(())
    }

    fn data_updated(&self) -> bool {
        return self.perf_stats.is_some();
    }

    fn copy_and_reset_data(&mut self, _l7_timeout_count: u32) -> FlowPerfStats {
        FlowPerfStats {
            l7_protocol: L7Protocol::PostgreSQL,
            l7: if let Some(perf) = self.perf_stats.take() {
                L7PerfStats {
                    request_count: perf.req_count,
                    response_count: perf.resp_count,
                    rrt_count: perf.rrt_count,
                    rrt_sum: perf.rrt_sum.as_micros() as u64,
                    rrt_max: perf.rrt_max.as_micros() as u32,
                    ..Default::default()
                }
            } else {
                L7PerfStats::default()
            },
            ..Default::default()
        }
    }

    fn app_proto_head(&mut self) -> Option<(AppProtoHead, u16)> {
        if let Some(h) = L7ProtocolInfoInterface::app_proto_head(&self.info) {
            return Some((h, 0));
        }
        None
    }
}

impl PostgresqlLog {
    pub fn new() -> Self {
        let mut s = Self::default();
        s.info.ignore = true;
        s
    }

    fn update_perf(&mut self, req_count: u32, resp_count: u32, req_err: u32, resp_err: u32) {
        if self.perf_stats.is_none() {
            self.perf_stats = Some(PerfStats::default());
        }
        let perf = self.perf_stats.as_mut().unwrap();
        perf.req_count += req_count;
        perf.resp_count += resp_count;
        perf.req_err_count += req_err;
        perf.resp_err_count += resp_err;
    }

    fn set_msg_type(&mut self, direction: PacketDirection) {
        match direction {
            PacketDirection::ClientToServer => self.info.msg_type = LogMessageType::Request,
            PacketDirection::ServerToClient => self.info.msg_type = LogMessageType::Response,
        }
    }

    fn parse(&mut self, payload: &[u8]) -> Result<()> {
        let mut offset = 0;
        // is at lease one validate block in payload, prevent miscalculate to other protocol
        let mut at_lease_one_block = false;
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

                if !at_lease_one_block {
                    at_lease_one_block = true;
                }
            } else {
                break;
            }
        }
        if at_lease_one_block {
            return Ok(());
        }
        Err(Error::L7ProtocolUnknown)
    }

    fn check_is_ssl_req(&self, payload: &[u8]) -> bool {
        payload.len() == 8
            && self.info.msg_type == LogMessageType::Request
            && read_u64_be(payload) == SSL_REQ
    }

    fn on_req_block(&mut self, tag: char, data: &[u8]) -> Result<()> {
        self.update_perf(1, 0, 0, 0);
        match tag {
            'Q' => {
                self.info.req_type = tag;
                self.info.context = strip_string_end_with_zero(data)?;
                if !is_postgresql(&self.info.context) {
                    return Err(Error::L7ProtocolUnknown);
                }
                self.info.ignore = false;
                Ok(())
            }
            'P' => {
                self.info.req_type = tag;
                self.info.ignore = false;

                let mut data = data;

                // | statement str, end with 0x0 | query str, end with 0x0 | param |
                if let Some(idx) = data.iter().position(|x| *x == 0x0) {
                    // skip statement
                    data = &data[idx + 1..];

                    // parse query
                    if let Some(idx) = data.iter().position(|x| *x == 0x0) {
                        self.info.context = String::from_utf8_lossy(&data[..idx]).to_string();
                        if is_postgresql(&self.info.context) {
                            return Ok(());
                        }
                    }
                }
                Err(Error::L7ProtocolUnknown)
            }
            'B' | 'F' | 'C' | 'D' | 'H' | 'S' | 'X' | 'd' | 'c' | 'f' => Ok(()),
            _ => Err(Error::L7ProtocolUnknown),
        }
    }

    fn on_resp_block(&mut self, tag: char, data: &[u8]) -> Result<()> {
        let mut data = data;
        self.update_perf(0, 1, 0, 0);
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
                self.info.status = L7ResponseStatus::ClientError;
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
                    self.info.result = String::from_utf8_lossy(&data[1..idx]).to_string();
                    let (err_desc, status) = get_code_desc(self.info.result.as_str());
                    self.info.error_message = String::from(err_desc);
                    self.info.status = status;
                    match self.info.status {
                        L7ResponseStatus::ClientError => self.update_perf(0, 0, 1, 0),
                        L7ResponseStatus::ServerError => self.update_perf(0, 0, 0, 1),
                        _ => {}
                    }
                    return Ok(());
                }

                Err(Error::L7ProtocolUnknown)
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
// if not end with 0x0, presume it is not pg protocol
fn strip_string_end_with_zero(data: &[u8]) -> Result<String> {
    if data.ends_with(&[0]) {
        return Ok(String::from_utf8_lossy(&data[..data.len() - 1]).to_string());
    }
    Err(Error::L7ProtocolUnknown)
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use crate::{
        common::{
            flow::PacketDirection,
            l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
            l7_protocol_log::L7ProtocolParserInterface,
            l7_protocol_log::ParseParam,
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
        assert_eq!(info.result.as_str(), "42601");
        assert_eq!(info.error_message.as_str(), "syntax_error",);
    }

    fn check_and_parse(file_name: &str) -> PostgreInfo {
        let pcap_file = Path::new(FILE_DIR).join(file_name);
        let capture = Capture::load_pcap(pcap_file, None);
        let mut p = capture.as_meta_packets();
        p[0].direction = PacketDirection::ClientToServer;
        p[1].direction = PacketDirection::ServerToClient;

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
