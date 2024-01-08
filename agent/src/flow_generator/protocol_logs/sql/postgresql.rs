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

use lru::LruCache;
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
    config::handler::LogParserConfig,
    flow_generator::{
        perf::{L7FlowPerf, PerfStats},
        protocol_logs::{
            pb_adapter::{ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response},
            L7ResponseStatus,
        },
        AppProtoHead, Error, LogMessageType, Result,
    },
    perf_impl,
};

use super::{
    super::value_is_default,
    postgre_convert::{get_code_desc, get_request_str},
    sql_check::is_postgresql,
};

const SSL_REQ: u64 = 34440615471; // 00000008(len) 04d2162f(const 80877103)

#[derive(Debug, Default, Clone, Serialize)]
pub struct PostgreInfo {
    msg_type: LogMessageType,
    #[serde(skip)]
    start_time: u64,
    #[serde(skip)]
    end_time: u64,
    #[serde(skip)]
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
    #[serde(skip)]
    ignore: bool,

    // request
    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub context: String,
    #[serde(rename = "request_type", skip_serializing_if = "value_is_default")]
    pub req_type: char,

    // response
    #[serde(skip)]
    pub resp_type: char,

    #[serde(rename = "response_result", skip_serializing_if = "value_is_default")]
    pub result: String,
    #[serde(rename = "sql_affected_rows", skip_serializing_if = "value_is_default")]
    pub affected_rows: u64,
    #[serde(
        rename = "response_execption",
        skip_serializing_if = "value_is_default"
    )]
    pub error_message: String,
    pub status: L7ResponseStatus,
}

impl L7ProtocolInfoInterface for PostgreInfo {
    fn session_id(&self) -> Option<u32> {
        None
    }

    fn merge_log(&mut self, other: L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::PostgreInfo(pg) = other {
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

#[derive(Debug, Serialize)]
pub struct PostgresqlLog {
    info: PostgreInfo,
    perf_stats: Option<PerfStats>,
    // <session_id,(type,time)>, use for calculate perf
    #[serde(skip)]
    previous_log_info: LruCache<u32, (LogMessageType, u64)>,
    parsed: bool,
}

impl Default for PostgresqlLog {
    fn default() -> Self {
        let mut log = Self {
            previous_log_info: LruCache::new(1.try_into().unwrap()),
            info: PostgreInfo::default(),
            perf_stats: None,
            parsed: false,
        };
        log.info.ignore = true;
        log
    }
}

perf_impl!(PostgresqlLog);

impl L7ProtocolParserInterface for PostgresqlLog {
    fn check_payload(
        &mut self,
        _: Option<&LogParserConfig>,
        payload: &[u8],
        param: &ParseParam,
    ) -> bool {
        self.set_msg_type(param.direction);
        self.info.is_tls = param.is_tls();
        if self.check_is_ssl_req(payload) {
            return true;
        }

        if self.parse(payload, param).is_ok() {
            self.parsed = true;
            return true;
        } else {
            return false;
        }
    }

    fn parse_payload(
        &mut self,
        _: Option<&LogParserConfig>,
        payload: &[u8],
        param: &ParseParam,
    ) -> Result<Vec<L7ProtocolInfo>> {
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
        self.parse(payload, param)?;
        self.revert_info_time(param.direction, param.time, param.rrt_timeout);
        Ok(if self.info.ignore {
            vec![]
        } else {
            vec![L7ProtocolInfo::PostgreInfo(self.info.clone())]
        })
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::PostgreSQL
    }

    fn reset(&mut self) {
        if !self.info.ignore {
            self.save_info_time();
        }
        self.info = PostgreInfo::default();
        self.parsed = false;
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }
}

impl L7FlowPerf for PostgresqlLog {
    fn parse(
        &mut self,
        config: Option<&LogParserConfig>,
        packet: &MetaPacket,
        _flow_id: u64,
        _rrt_timeout: usize,
    ) -> Result<()> {
        if let Some(payload) = packet.get_l4_payload() {
            self.parse_payload(config, payload, &ParseParam::from(packet))?;
        }
        Ok(())
    }

    fn data_updated(&self) -> bool {
        return self.perf_stats.is_some();
    }

    fn copy_and_reset_data(&mut self, l7_timeout_count: u32) -> FlowPerfStats {
        FlowPerfStats {
            l7_protocol: L7Protocol::PostgreSQL,
            l7: if let Some(perf) = self.perf_stats.take() {
                L7PerfStats {
                    request_count: perf.req_count,
                    response_count: perf.resp_count,
                    err_client_count: perf.req_err_count,
                    err_server_count: perf.resp_err_count,
                    err_timeout: l7_timeout_count,
                    rrt_count: perf.rrt_count,
                    rrt_sum: perf.rrt_sum.as_micros() as u64,
                    rrt_max: perf.rrt_max.as_micros() as u32,
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
    fn set_msg_type(&mut self, direction: PacketDirection) {
        match direction {
            PacketDirection::ClientToServer => self.info.msg_type = LogMessageType::Request,
            PacketDirection::ServerToClient => self.info.msg_type = LogMessageType::Response,
        }
    }

    fn parse(&mut self, payload: &[u8], param: &ParseParam) -> Result<()> {
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
                    LogMessageType::Request => {
                        self.on_req_block(tag, &sub_payload[5..5 + len], param.time)?
                    }
                    LogMessageType::Response => {
                        self.on_resp_block(tag, &sub_payload[5..5 + len], param.time)?
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

    fn on_req_block(&mut self, tag: char, data: &[u8], time: u64) -> Result<()> {
        match tag {
            'Q' => {
                self.info.req_type = tag;
                self.info.context = strip_string_end_with_zero(data)?;
                self.info.ignore = false;
                self.perf_inc_req(time);
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
                            self.perf_inc_req(time);
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

    fn on_resp_block(&mut self, tag: char, data: &[u8], time: u64) -> Result<()> {
        let mut data = data;
        match tag {
            'C' => {
                self.info.status = L7ResponseStatus::Ok;
                self.info.ignore = false;
                self.info.resp_type = tag;

                // reference https://www.postgresql.org/docs/16/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-COMMANDCOMPLETE
                // INSERT oid rows0x0, where rows is the number of rows inserted.
                // DELETE | UPDATE | SELECT | MERGE | MOVE | FETCH | COPY rows0x0
                // CREATE TABLE
                if let Some(idx) = data.iter().position(|x| *x == 0x20) {
                    let op = &data[..idx];
                    data = &data[idx + 1..];
                    if op.eq("INSERT".as_bytes()) {
                        if let Some(idx) = data.iter().position(|x| *x == 0x20) {
                            data = &data[idx + 1..];
                            if let Some(idx) = data.iter().position(|x| *x == 0x0) {
                                let row_eff = String::from_utf8_lossy(&data[..idx]).to_string();
                                self.info.affected_rows = row_eff.parse().unwrap_or(0);
                            }
                        } else {
                            return Ok(());
                        }
                    } else if op.eq("DELETE".as_bytes())
                        || op.eq("UPDATE".as_bytes())
                        || op.eq("SELECT".as_bytes())
                        || op.eq("MERGE".as_bytes())
                        || op.eq("MOVE".as_bytes())
                        || op.eq("FETCH".as_bytes())
                        || op.eq("COPY".as_bytes())
                    {
                        if let Some(idx) = data.iter().position(|x| *x == 0x0) {
                            let row_eff = String::from_utf8_lossy(&data[..idx]).to_string();
                            self.info.affected_rows = row_eff.parse().unwrap_or(0);
                        }
                    }
                }

                self.perf_inc_resp(time);
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
                        L7ResponseStatus::ClientError => self.perf_inc_req_err(),
                        L7ResponseStatus::ServerError => self.perf_inc_resp_err(),
                        _ => {}
                    }
                    self.perf_inc_resp(time);
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

        let mut parser = PostgresqlLog::default();
        let req_param = &mut ParseParam::from(&p[0]);
        let req_payload = p[0].get_l4_payload().unwrap();
        assert_eq!(
            (&mut parser).check_payload(None, req_payload, req_param),
            true
        );
        let mut info = (&mut parser)
            .parse_payload(None, req_payload, req_param)
            .unwrap();
        let mut req = info.swap_remove(0);

        (&mut parser).reset();

        let resp_param = &ParseParam::from(&p[1]);
        let resp_payload = p[1].get_l4_payload().unwrap();
        assert_eq!(
            (&mut parser).check_payload(None, resp_payload, resp_param),
            true
        );
        let resp = (&mut parser)
            .parse_payload(None, resp_payload, resp_param)
            .unwrap()
            .swap_remove(0);

        req.merge_log(resp).unwrap();
        if let L7ProtocolInfo::PostgreInfo(info) = req {
            return info;
        }
        unreachable!()
    }
}
