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

use std::{
    fmt,
    fs::File,
    io::{self, BufRead, BufReader},
    net::IpAddr,
    path::Path,
    sync::{atomic::AtomicI64, Arc},
    time::Duration,
};

use nom::IResult;
use pcap::{self, Linktype};

use public::{
    buffer::BatchedBox,
    debug::QueueDebugger,
    proto::agent::AgentType,
    queue::{self, Receiver},
};

use crate::{
    common::{
        flow::L7Stats,
        meta_packet::{MetaPacket, PcapData},
        TaggedFlow,
    },
    config::{FlowConfig, UserConfig},
    flow_generator::{flow_map::FlowMap, AppProto, FlowTimeout, TcpTimeout},
    policy::Policy,
    utils::stats,
};

cfg_if::cfg_if! {
    if #[cfg(feature = "libtrace")] {
        use std::mem::MaybeUninit;

        use chrono::NaiveDateTime;

        use public::l7_protocol::L7Protocol;

        use crate::ebpf;
    }
}

pub fn load_packets<P: AsRef<Path>>(path: P) -> Vec<MetaPacket<'static>> {
    let path = path.as_ref();
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("pcap") => Capture::load_pcap(path).collect(),
        #[cfg(feature = "libtrace")]
        Some("log") => EbpfDataDump::open(path).unwrap().collect(),
        _ => panic!("unsupported file {}", path.display()),
    }
}

pub struct Capture {
    cap: pcap::Capture<pcap::Offline>,
    dl_type: Linktype,
}

impl Capture {
    pub fn load_pcap<P: AsRef<Path>>(path: P) -> Self {
        let cap = pcap::Capture::from_file(path).unwrap();
        let dl_type = cap.get_datalink();
        Self { cap, dl_type }
    }
}

impl Iterator for Capture {
    type Item = MetaPacket<'static>;

    fn next(&mut self) -> Option<Self::Item> {
        self.cap.next_packet().ok().and_then(|packet| {
            let pcap_data = PcapData {
                link_type: self.dl_type,
                timestamp: Duration::new(
                    packet.header.ts.tv_sec as u64,
                    packet.header.ts.tv_usec as u32 * 1000,
                ),
                data: packet.data,
            };
            MetaPacket::try_from(pcap_data).ok().map(|p| p.into_owned())
        })
    }
}

impl From<Capture> for Vec<Vec<u8>> {
    fn from(mut c: Capture) -> Self {
        let mut vec = Vec::new();
        while let Ok(p) = c.cap.next_packet() {
            vec.push(p.data.to_vec());
        }
        vec
    }
}

#[cfg(feature = "libtrace")]
pub struct EbpfDataDump {
    reader: BufReader<File>,
    buf: String,
    lineno: usize,
}

#[cfg(feature = "libtrace")]
impl EbpfDataDump {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let reader = BufReader::new(File::open(path)?);
        Ok(Self {
            reader,
            buf: String::new(),
            lineno: 1,
        })
    }

    unsafe fn meta_packet(lines: &str) -> IResult<&str, MetaPacket<'static>> {
        use nom::{
            bytes::complete::{is_not, tag, take_until},
            character::complete::{char, digit1, hex_digit1, space0, space1},
            multi::{count, many0},
            sequence::{delimited, pair, preceded, separated_pair, tuple},
        };

        let mut data = MaybeUninit::<ebpf::SK_BPF_DATA>::zeroed().assume_init();

        let (input, raw_data) = lines.split_once('\n').unwrap();

        let input = count(pair(is_not(" "), space1), 5)(input)?.0;

        let (input, l7_proto_str) = delimited(char('<'), is_not(">"), char('>'))(input)?;
        let l7_proto = L7Protocol::try_from(l7_proto_str).unwrap();
        data.l7_protocol_hint = l7_proto as u16;

        let (input, direction) = preceded(tag(" DIR "), is_not(" "))(input)?;
        match direction {
            "out" => data.direction = ebpf::SOCK_DIR_SND,
            "in" => data.direction = ebpf::SOCK_DIR_RCV,
            _ => panic!("invalid direction: {}", direction),
        }

        let (input, msg_type) = preceded(
            tag(" TYPE "),
            preceded(is_not("("), delimited(char('('), digit1, char(')'))),
        )(input)?;
        data.msg_type = msg_type.parse().unwrap();

        let (input, pid) = preceded(tag(" PID "), digit1)(input)?;
        data.process_id = pid.parse().unwrap();

        let (input, thread_id) = preceded(tag(" THREAD_ID "), digit1)(input)?;
        data.thread_id = thread_id.parse().unwrap();

        let (input, coroutine_id) = preceded(tag(" COROUTINE_ID "), digit1)(input)?;
        data.coroutine_id = coroutine_id.parse().unwrap();

        let (input, fd) = preceded(tag(" FD "), digit1)(input)?;
        data.fd = fd.parse().unwrap();

        let (input, role) = preceded(tag(" ROLE "), is_not(" "))(input)?;
        match role {
            "client" => data.socket_role = 1,
            "server" => data.socket_role = 2,
            _ => data.socket_role = 0,
        }

        let (input, container_id) = preceded(tag(" CONTAINER_ID "), is_not(" "))(input)?;
        match container_id {
            "null" => (),
            _ => {
                let len = container_id.len().min(data.container_id.len());
                data.container_id[..len].copy_from_slice(&container_id.as_bytes()[..len]);
            }
        }

        let (input, source) = preceded(tag(" SOURCE "), digit1)(input)?;
        data.source = source.parse().unwrap();

        let (input, comm) = preceded(tag(" COMM "), is_not(" "))(input)?;
        let len = comm.len().min(data.process_kname.len());
        data.process_kname[..len].copy_from_slice(&comm.as_bytes()[..len]);

        let (input, (proto, _, (src_sockaddr, dst_sockaddr))) = preceded(
            char(' '),
            tuple((
                is_not(" "),
                space1,
                separated_pair(is_not(" "), tag(" > "), is_not(" ")),
            )),
        )(input)?;
        let (src_ip, src_port) = {
            let (ip, port) = src_sockaddr.rsplit_once('.').unwrap();
            (ip.parse::<IpAddr>().unwrap(), port.parse::<u16>().unwrap())
        };
        let (dst_ip, dst_port) = {
            let (ip, port) = dst_sockaddr.rsplit_once('.').unwrap();
            (ip.parse::<IpAddr>().unwrap(), port.parse::<u16>().unwrap())
        };
        match proto {
            "TCP" => data.tuple.protocol = 6,
            "UDP" => data.tuple.protocol = 17,
            _ => (),
        }
        match (src_ip, dst_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                data.tuple.addr_len = 4;
                data.tuple.laddr[..4].copy_from_slice(&src.octets());
                data.tuple.raddr[..4].copy_from_slice(&dst.octets());
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                data.tuple.addr_len = 16;
                data.tuple.laddr[..16].copy_from_slice(&src.octets());
                data.tuple.raddr[..16].copy_from_slice(&dst.octets());
            }
            _ => (),
        }
        data.tuple.lport = src_port;
        data.tuple.rport = dst_port;

        let (input, cap_len) = preceded(tag(" LEN "), digit1)(input)?;
        data.cap_len = cap_len.parse().unwrap();

        let (input, syscall_len) = preceded(tag(" SYSCALL_LEN "), digit1)(input)?;
        data.syscall_len = syscall_len.parse().unwrap();

        let (input, socket_id) = preceded(tag(" SOCKET_ID "), digit1)(input)?;
        data.socket_id = socket_id.parse().unwrap();

        let (input, syscall_trace_id_call) = preceded(tag(" TRACE_ID "), digit1)(input)?;
        data.syscall_trace_id_call = syscall_trace_id_call.parse().unwrap();

        let (input, tcp_seq) = preceded(tag(" TCP_SEQ "), digit1)(input)?;
        data.tcp_seq = tcp_seq.parse().unwrap();

        let (input, cap_seq) = preceded(tag(" DATA_SEQ "), digit1)(input)?;
        data.cap_seq = cap_seq.parse().unwrap();

        let (input, is_tls) = preceded(tag(" TLS "), is_not(" "))(input)?;
        match is_tls {
            "true" => data.is_tls = true,
            "false" => data.is_tls = false,
            _ => (),
        }

        let tz = chrono::FixedOffset::east_opt(8 * 3600).unwrap();

        let (input, syscall_time) =
            preceded(tag(" SyscallTime "), take_until(" SyscallMonoTime"))(input)?;
        let parsed = NaiveDateTime::parse_from_str(&syscall_time, "%Y-%m-%d %H:%M:%S%.6f")
            .unwrap()
            .and_local_timezone(tz)
            .unwrap();
        data.timestamp = parsed.timestamp_nanos_opt().unwrap() as u64;

        let input = take_until(" CapTime")(input)?.0;

        let (input, cap_time) = preceded(tag(" CapTime "), take_until(" CapMonoTime"))(input)?;
        let parsed = NaiveDateTime::parse_from_str(&cap_time, "%Y-%m-%d %H:%M:%S%.6f")
            .unwrap()
            .and_local_timezone(tz)
            .unwrap();
        data.cap_timestamp = parsed.timestamp_nanos_opt().unwrap() as u64;

        let raw_data: Vec<&str> =
            many0(delimited(space0, hex_digit1, take_until(" ")))(raw_data)?.1;
        let raw_data = raw_data
            .into_iter()
            .map(|b| u8::from_str_radix(b, 16).unwrap())
            .collect::<Vec<_>>();
        data.cap_data = raw_data.as_ptr() as *mut libc::c_char;

        unsafe {
            // SAFETY: MetaPacket holds 'static raw data
            let meta_packet = MetaPacket::from_ebpf(&mut data).unwrap();
            Ok((input, meta_packet))
        }
    }

    fn parse_next(&mut self) -> io::Result<Option<MetaPacket<'static>>> {
        self.buf.clear();
        self.reader.read_line(&mut self.buf)?;
        if self.reader.read_line(&mut self.buf)? == 0 {
            return Ok(None);
        }

        unsafe {
            match Self::meta_packet(self.buf.as_str()) {
                Ok((_, meta_packet)) => {
                    self.lineno += 2;
                    Ok(Some(meta_packet))
                }
                Err(e) => panic!(
                    "Error parsing ebpf data dump line {}-{}: {e}",
                    self.lineno,
                    self.lineno + 1
                ),
            }
        }
    }
}

#[cfg(feature = "libtrace")]
impl Iterator for EbpfDataDump {
    type Item = MetaPacket<'static>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Ok(Some(packet)) = self.parse_next() {
            return Some(packet);
        }
        None
    }
}

pub struct WrappedDebugStruct<'a, 'b: 'a>(fmt::DebugStruct<'a, 'b>);

impl<'a, 'b> From<fmt::DebugStruct<'a, 'b>> for WrappedDebugStruct<'a, 'b> {
    fn from(ds: fmt::DebugStruct<'a, 'b>) -> Self {
        Self(ds)
    }
}

impl<'a, 'b: 'a> WrappedDebugStruct<'a, 'b> {
    pub fn field_skip_default<F>(
        &mut self,
        field: &str,
        value: &F,
    ) -> &mut WrappedDebugStruct<'a, 'b>
    where
        F: fmt::Debug + Default + PartialEq,
    {
        if value != &F::default() {
            self.0.field(field, value);
        }
        self
    }

    pub fn field<F>(&mut self, field: &str, value: &F) -> &mut WrappedDebugStruct<'a, 'b>
    where
        F: fmt::Debug,
    {
        self.0.field(field, value);
        self
    }

    pub fn finish(&mut self) -> fmt::Result {
        self.0.finish()
    }
}

pub struct FlowMapTester {
    pub config: FlowConfig,
    pub flow_map: FlowMap,

    pub flow_output: Option<Receiver<Arc<BatchedBox<TaggedFlow>>>>,
    pub l7_stats_output: Option<Receiver<BatchedBox<L7Stats>>>,
    pub app_proto_log_output: Option<Receiver<AppProto>>,
    pub packet_sequence_output: Option<Receiver<Box<packet_sequence_block::PacketSequenceBlock>>>,
}

impl Drop for FlowMapTester {
    fn drop(&mut self) {
        println!("dropping FlowMapTester");
    }
}

pub struct FlowMapTesterBuilder {
    pub config: FlowConfig,
}

impl FlowMapTesterBuilder {
    pub fn new(agent_type: AgentType) -> Self {
        let mut config = FlowConfig {
            agent_type,
            collector_enabled: true,
            l4_performance_enabled: true,
            l7_metrics_enabled: true,
            app_proto_log_enabled: true,
            ignore_idc_vlan: false,
            flow_timeout: TcpTimeout::default().into(),
            ..(&UserConfig::standalone_default()).into()
        };
        config.l7_log_tap_types[0] = true;

        Self { config }
    }

    pub fn with_config(config: FlowConfig) -> Self {
        Self { config }
    }

    pub fn flow_timeout(&mut self, flow_timeout: Option<FlowTimeout>) -> &mut Self {
        if let Some(flow_timeout) = flow_timeout {
            self.config.flow_timeout = flow_timeout.into();
        } else {
            self.config.flow_timeout = TcpTimeout::default().into();
        }
        self
    }

    pub fn ignore_idc_vlan(&mut self, ignore_idc_vlan: bool) -> &mut Self {
        self.config.ignore_idc_vlan = ignore_idc_vlan;
        self
    }

    pub fn build(self) -> FlowMapTester {
        let (_, mut policy_getter) = Policy::new(1, 0, 1 << 10, 1 << 14, false, false);
        policy_getter.disable();

        let queue_debugger = QueueDebugger::new();
        let (output_queue_sender, output_queue_receiver, _) =
            queue::bounded_with_debug(256, "", &queue_debugger);
        let (l7_stats_output_queue_sender, l7_stats_output_receiver, _) =
            queue::bounded_with_debug(256, "", &queue_debugger);
        let (app_proto_log_queue, app_proto_log_receiver, _) =
            queue::bounded_with_debug(256, "", &queue_debugger);
        let (packet_sequence_queue, packet_sequence_receiver, _) =
            queue::bounded_with_debug(256, "", &queue_debugger);
        let flow_map = FlowMap::new(
            0,
            Some(output_queue_sender),
            l7_stats_output_queue_sender,
            policy_getter,
            app_proto_log_queue,
            Arc::new(AtomicI64::new(0)),
            &self.config,
            Some(packet_sequence_queue), // Enterprise Edition Feature: packet-sequence
            Arc::new(stats::Collector::new("", Arc::new(AtomicI64::new(0)))),
            false,
        );

        FlowMapTester {
            config: self.config,
            flow_map,

            flow_output: Some(output_queue_receiver),
            l7_stats_output: Some(l7_stats_output_receiver),
            app_proto_log_output: Some(app_proto_log_receiver),
            packet_sequence_output: Some(packet_sequence_receiver),
        }
    }
}
