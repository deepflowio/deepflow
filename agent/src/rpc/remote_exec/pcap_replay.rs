/*
 * Copyright (c) 2026 Yunshan Networks
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

use std::{
    collections::VecDeque,
    io::{self, Read},
    sync::{Arc, Mutex},
    time::Duration,
};

use log::{debug, trace};
use pcap::Linktype;
use pcap_parser::{
    pcap::LegacyPcapReader, traits::PcapReaderIterator, LegacyPcapBlock, PcapBlockOwned, PcapError,
};
use thiserror::Error;

use public::{
    enums::PacketDirection,
    l7_protocol::{L7ProtocolEnum, LogMessageType},
};

use crate::{
    common::{
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{get_parser, L7ParseResult, L7ProtocolParserInterface, ParseParam},
        meta_packet::{MetaPacket, PcapData},
    },
    config::handler::{FlowConfig, LogParserConfig},
    flow_generator::{
        perf::L7ProtocolChecker,
        protocol_logs::{AppProtoLogsBaseInfo, MetaAppProto},
    },
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("pcap parse error")]
    PcapParseError,
    #[error("unsupported pcap format")]
    UnsupportedPcapFormat,
    #[error("unsupported link type: {0}")]
    UnsupportedLinkType(pcap_parser::Linktype),
    #[error("require more data")]
    RequireMoreData,

    #[error("generate meta packet failed")]
    GenerateMetaPacketFailed,
    #[error("no layer 4 payload to parse")]
    NoPayload,
    #[error("no server port found")]
    NoServerPort,
    #[error("protocol inference no match")]
    ProtocolInferenceNoMatch,
    #[error("l7 log parse failed")]
    LogParseFailed,
    #[error("get parser failed")]
    GetParserFailed,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Default, Clone)]
struct SharedBuffer {
    // this type needs to be send because it's part of responder
    // so Mutex is used instead of RefCell
    chunks: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl Read for SharedBuffer {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut chunks = self.chunks.lock().unwrap();
        trace!(
            "try to read at most {} bytes from {} chunks",
            buf.len(),
            chunks.len()
        );
        let mut written = 0;
        while let Some(first) = chunks.front_mut() {
            if first.len() + written > buf.len() {
                let n = buf.len() - written;
                trace!("read {n}/{} bytes from chunk", first.len());
                buf[written..].copy_from_slice(&first[..n]);
                first.drain(..n);
                trace!("total {} bytes read", buf.len());
                return Ok(buf.len());
            }
            let n = first.len();
            trace!("read {n}/{n} bytes from chunk");
            buf[written..written + n].copy_from_slice(first);
            written += n;
            chunks.pop_front();
            if written == buf.len() {
                trace!("total {} bytes read", buf.len());
                return Ok(buf.len());
            }
        }
        trace!("total {written} bytes read");
        Ok(written)
    }
}

impl SharedBuffer {
    pub fn new(chunk: Vec<u8>) -> Self {
        Self {
            chunks: Arc::new(Mutex::new(VecDeque::from(vec![chunk]))),
        }
    }

    pub fn push_chunk(&self, chunk: Vec<u8>) {
        trace!("pushed {} bytes to buffer", chunk.len());
        self.chunks.lock().unwrap().push_back(chunk);
    }

    pub fn is_empty(&self) -> bool {
        let chunks = self.chunks.lock().unwrap();
        chunks.is_empty() || chunks.front().unwrap().is_empty()
    }
}

struct StreamingParser {
    parser: LegacyPcapReader<SharedBuffer>,
}

impl StreamingParser {
    const DEFAULT_BUFFER_SIZE: usize = 128 * 1024;

    pub fn new(input: SharedBuffer) -> Result<Self> {
        let parser = match LegacyPcapReader::new(Self::DEFAULT_BUFFER_SIZE, input) {
            Ok(parser) => parser,
            Err(e) => {
                debug!("failed to create pcap parser: {e:?}");
                return Err(Error::PcapParseError);
            }
        };
        Ok(Self { parser })
    }

    pub fn next(&mut self) -> Result<(usize, PcapBlockOwned<'_>), PcapError<&[u8]>> {
        self.parser.next()
    }

    pub fn consume(&mut self, offset: usize) {
        self.parser.consume(offset);
    }

    pub fn refill(&mut self) -> Result<(), PcapError<&[u8]>> {
        self.parser.refill()
    }
}

struct ApplicationParser {
    protocol_checker: Option<L7ProtocolChecker>,

    l7_protocol: Option<L7ProtocolEnum>,
    server_port: Option<u16>,
}

impl Default for ApplicationParser {
    fn default() -> Self {
        Self {
            protocol_checker: None,
            l7_protocol: None,
            server_port: None,
        }
    }
}

impl ApplicationParser {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<()> {
        let checker = self.protocol_checker.as_ref().unwrap();
        // check both directions
        let rev_param = param.reversed();
        for p in [param, &rev_param] {
            for protocol in checker.possible_protocols(p.l4_protocol.into(), p.port_dst) {
                let Some(mut parser) = get_parser((*protocol).into()) else {
                    continue;
                };
                trace!("check {protocol:?} on server port {}", p.port_dst);
                match parser.check_payload(payload, p) {
                    Some(LogMessageType::Request) => {
                        debug!("{protocol:?} identified on server port {}", p.port_dst);
                        self.l7_protocol = Some((*protocol).into());
                        self.server_port = Some(p.port_dst);
                        return Ok(());
                    }
                    Some(LogMessageType::Response) => {
                        debug!("{protocol:?} identified on server port {}", p.port_src);
                        self.l7_protocol = Some((*protocol).into());
                        self.server_port = Some(p.port_src);
                        return Ok(());
                    }
                    _ => (),
                }
            }
        }
        Err(Error::ProtocolInferenceNoMatch)
    }

    fn generate_meta_app_proto(
        meta_packet: &MetaPacket,
        direction: PacketDirection,
        l7_info: L7ProtocolInfo,
    ) -> MetaAppProto {
        MetaAppProto {
            base_info: AppProtoLogsBaseInfo {
                start_time: meta_packet.lookup_key.timestamp,
                end_time: meta_packet.lookup_key.timestamp,
                ip_src: meta_packet.lookup_key.src_ip,
                ip_dst: meta_packet.lookup_key.dst_ip,
                port_src: meta_packet.lookup_key.src_port,
                port_dst: meta_packet.lookup_key.dst_port,
                protocol: meta_packet.lookup_key.proto,
                biz_type: l7_info.get_biz_type(),
                head: l7_info.app_proto_head().unwrap_or_default(),
                ..Default::default()
            },
            direction_score: 0,
            direction,
            l7_info,
        }
    }

    pub fn parse(
        &mut self,
        cached: &mut VecDeque<MetaAppProto>,
        config: &Config,
        mut meta_packet: MetaPacket,
    ) -> Result<usize> {
        if let Some(server_port) = self.server_port {
            if meta_packet.lookup_key.src_port == server_port {
                meta_packet.lookup_key.direction = PacketDirection::ServerToClient;
            } else if meta_packet.lookup_key.dst_port == server_port {
                meta_packet.lookup_key.direction = PacketDirection::ClientToServer;
            } else {
                return Err(Error::NoServerPort);
            }
        }

        let mut parse_param = ParseParam::new(
            &meta_packet,
            None,
            Default::default(),
            #[cfg(unix)]
            Default::default(),
            true,
            true,
        );
        parse_param.set_log_parser_config(config.log_parser_config);
        let payload = match meta_packet.get_l4_payload() {
            Some(payload) => payload,
            None => return Err(Error::NoPayload),
        };
        parse_param.set_buf_size(config.flow_config.l7_log_packet_size as usize);
        parse_param.set_captured_byte(payload.len());

        if self.l7_protocol.is_none() {
            if self.protocol_checker.is_none() {
                self.protocol_checker = Some(L7ProtocolChecker::from(config.flow_config));
            }
            self.check_payload(payload, &parse_param)?;
        }
        // need to correct direction on first pass after identifying protocol
        match parse_param.direction {
            PacketDirection::ClientToServer
                if parse_param.port_dst != self.server_port.unwrap() =>
            {
                parse_param = parse_param.reversed();
            }
            PacketDirection::ServerToClient
                if parse_param.port_src != self.server_port.unwrap() =>
            {
                parse_param = parse_param.reversed();
            }
            _ => (),
        }
        let Some(mut l7_parser) = get_parser(self.l7_protocol.clone().unwrap()) else {
            return Err(Error::GetParserFailed);
        };
        match l7_parser.parse_payload(payload, &parse_param) {
            Ok(L7ParseResult::None) => Ok(0),
            Ok(L7ParseResult::Single(log)) => {
                cached.push_back(Self::generate_meta_app_proto(
                    &meta_packet,
                    parse_param.direction,
                    log,
                ));
                Ok(1)
            }
            Ok(L7ParseResult::Multi(logs)) => {
                let n = logs.len();
                for log in logs {
                    cached.push_back(Self::generate_meta_app_proto(
                        &meta_packet,
                        parse_param.direction,
                        log,
                    ));
                }
                Ok(n)
            }
            Err(e) => {
                debug!("l7 log parse failed: {e:?}");
                Err(Error::LogParseFailed)
            }
        }
    }
}

pub struct Config<'a> {
    pub flow_config: &'a FlowConfig,
    pub log_parser_config: &'a LogParserConfig,
}

pub struct Replayer {
    input: SharedBuffer,
    pcap_parser: StreamingParser,
    app_parser: ApplicationParser,

    // return one item per call to `next`
    cached: VecDeque<MetaAppProto>,

    link_type: Option<Linktype>,

    read_packet_count: usize,
    parsed_log_count: usize,
}

impl Replayer {
    pub fn new(data: Vec<u8>) -> Result<Self> {
        let input = SharedBuffer::new(data);
        let pcap_parser = StreamingParser::new(input.clone())?;
        Ok(Self {
            input,
            pcap_parser,
            app_parser: ApplicationParser::default(),
            cached: VecDeque::new(),
            link_type: None,
            read_packet_count: 0,
            parsed_log_count: 0,
        })
    }

    pub fn push_chunk(&self, chunk: Vec<u8>) {
        self.input.push_chunk(chunk);
    }

    fn generate_meta_packet<'a>(
        link_type: Linktype,
        block: LegacyPcapBlock<'a>,
    ) -> Result<MetaPacket<'a>> {
        let pcap_data = PcapData {
            link_type,
            timestamp: Duration::new(block.ts_sec as u64, block.ts_usec as u32 * 1000),
            data: block.data,
        };
        match MetaPacket::try_from(pcap_data) {
            Ok(meta) => Ok(meta),
            Err(e) => {
                trace!("failed to generate meta packet: {e:?}");
                Err(Error::GenerateMetaPacketFailed)
            }
        }
    }

    // can return None before EOF
    // need to check incoming data to determine if EOF
    pub fn next(&mut self, config: &Config) -> Result<Option<MetaAppProto>> {
        if let Some(log) = self.cached.pop_front() {
            return Ok(Some(log));
        }
        let mut refilled = false;
        loop {
            let (offset, block) = match self.pcap_parser.next() {
                Ok((offset, block)) => (offset, block),
                Err(PcapError::Eof) => return Ok(None),
                Err(PcapError::UnexpectedEof | PcapError::Incomplete(_)) => {
                    if !refilled && !self.input.is_empty() {
                        // refill and try again
                        refilled = true;
                        match self.pcap_parser.refill() {
                            Ok(_) => continue,
                            Err(e) => {
                                debug!("failed to refill pcap parser: {e:?}");
                                return Err(Error::PcapParseError);
                            }
                        }
                    }
                    trace!("require more data to continue parsing");
                    return Err(Error::RequireMoreData);
                }
                Err(e) => {
                    debug!("failed to parse packet: {e:?}");
                    return Err(Error::PcapParseError);
                }
            };
            let block = match block {
                PcapBlockOwned::Legacy(block) => {
                    self.read_packet_count += 1;
                    block
                }
                PcapBlockOwned::LegacyHeader(header) => {
                    self.link_type = Some(match header.network {
                        pcap_parser::Linktype::ETHERNET => Linktype::ETHERNET,
                        pcap_parser::Linktype::LINUX_SLL => Linktype::LINUX_SLL,
                        pcap_parser::Linktype::LINUX_SLL2 => Linktype::LINUX_SLL2,
                        _ => return Err(Error::UnsupportedLinkType(header.network)),
                    });
                    self.pcap_parser.consume(offset);
                    continue;
                }
                PcapBlockOwned::NG(_) => {
                    debug!("unsupported pcapng format");
                    self.pcap_parser.consume(offset);
                    return Err(Error::UnsupportedPcapFormat);
                }
            };
            let packet_id = self.read_packet_count;
            trace!("parsing packet #{packet_id}");
            let Some(link_type) = self.link_type else {
                debug!("no link type found in pcap header");
                return Err(Error::PcapParseError);
            };
            let meta_packet = match Self::generate_meta_packet(link_type, block) {
                Ok(meta) => meta,
                Err(e) => {
                    debug!("failed to generate meta packet for packet #{packet_id}: {e:?}");
                    continue;
                }
            };
            let result = self.app_parser.parse(&mut self.cached, config, meta_packet);
            self.pcap_parser.consume(offset);

            match result {
                Ok(n) if n == 0 => {
                    trace!("parsed packet #{packet_id} ended without producing any log");
                    continue;
                }
                Ok(n) => {
                    self.parsed_log_count += n;
                    if n == 1 {
                        debug!(
                            "parsed packet #{packet_id} into log #{}: {:?}",
                            self.parsed_log_count,
                            self.cached
                                .iter()
                                .map(|log| &log.l7_info)
                                .collect::<Vec<_>>(),
                        );
                    } else {
                        debug!(
                            "parsed packet #{packet_id} into logs #{}-{}: {:?}",
                            self.parsed_log_count + 1 - n,
                            self.parsed_log_count,
                            self.cached
                                .iter()
                                .map(|log| &log.l7_info)
                                .collect::<Vec<_>>(),
                        );
                    }
                    return Ok(self.cached.pop_front());
                }
                Err(e) => debug!("parse log from packet #{packet_id} failed: {e:?}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{fs::File, path::Path};

    use rand::Rng;

    use crate::{config::UserConfig, flow_generator::protocol_logs::pb_adapter::L7ProtocolSendLog};

    const PCAP_BASE_PATH: &str = "resources/test/flow_generator";

    #[test]
    fn iterate_pcap() {
        let file = Path::new(PCAP_BASE_PATH).join("http.pcap");
        let mut fp = File::open(file).unwrap();
        // use small prime chunk size to test StreamingParser logic
        let mut buffer = [0; 97];

        assert_eq!(fp.read(&mut buffer).unwrap(), 97);
        let input = SharedBuffer::new(buffer.to_vec());
        let mut parser = StreamingParser::new(input.clone()).unwrap();

        while let Ok(n) = fp.read(&mut buffer) {
            if n == 0 {
                break;
            }
            input.push_chunk(buffer[..n].to_vec());
        }

        let mut has_header = false;
        let mut n_packets = 0;
        loop {
            match parser.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::Legacy(_) => n_packets += 1,
                        PcapBlockOwned::LegacyHeader(_) => has_header = true,
                        _ => (),
                    }
                    parser.consume(offset);
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::UnexpectedEof | PcapError::Incomplete(_)) => {
                    parser.refill().unwrap();
                    continue;
                }
                Err(e) => panic!("unexpected error: {e:?}"),
            }
        }

        assert!(has_header);
        assert_eq!(n_packets, 13);
    }

    #[test]
    fn parse_pcap() {
        let file = Path::new(PCAP_BASE_PATH).join("http/httpv1.pcap");
        let mut fp = File::open(file).unwrap();
        let mut first_chunk = vec![0; 199];
        fp.read_exact(&mut first_chunk).unwrap();

        let mut replayer = Replayer::new(first_chunk).unwrap();
        let flow_config = FlowConfig::from(&UserConfig::default());
        let log_parser_config = LogParserConfig::default();
        let config = Config {
            flow_config: &flow_config,
            log_parser_config: &log_parser_config,
        };
        loop {
            if let Err(e) = replayer.next(&config) {
                assert!(matches!(e, Error::RequireMoreData));
                break;
            }
        }

        let mut buffer = [0; 256];
        loop {
            // read random number of bytes from fp
            let n = rand::thread_rng().gen_range(1..=256);
            let read = fp.read(&mut buffer[..n]).unwrap();
            if read == 0 {
                break;
            }
            replayer.push_chunk(buffer[..read].to_vec());
        }

        let mut result = vec![];
        while let Ok(Some(log)) = replayer.next(&config) {
            result.push(log);
        }
        assert_eq!(result.len(), 2);
        let results: Vec<L7ProtocolSendLog> =
            result.into_iter().map(|log| log.l7_info.into()).collect();
        assert_eq!(results[0].req.req_type, "POST");
        assert_eq!(results[1].resp.code, Some(200));
    }
}
