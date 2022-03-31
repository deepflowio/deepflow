use log::debug;
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::{Arc, Mutex};
use std::thread;

use super::{Error, Result};

use crate::common::enums::PacketDirection;
use crate::common::flow::L7Protocol;
use crate::common::meta_packet::MetaPacket;
use crate::ebpf;
use crate::flow_generator::{
    AppProtoLogsBaseInfo, AppProtoLogsData, AppProtoLogsInfo, DnsLog, DubboLog, HttpLog, KafkaLog,
    L7LogParse, MysqlLog, RedisLog,
};
use crate::utils::queue::{bounded, Receiver, Sender};

type LoggerItem = (L7Protocol, Box<dyn L7LogParse>);

pub struct EbpfCollector {
    receiver: Arc<Mutex<Receiver<Box<MetaPacket<'static>>>>>,

    output: Sender<Box<AppProtoLogsData>>,
}

static mut SWITCH: bool = false;
static mut SENDER: Option<Sender<Box<MetaPacket>>> = None;

impl EbpfCollector {
    extern "C" fn callback(sd: *mut ebpf::SK_BPF_DATA) {
        unsafe {
            if !SWITCH || SENDER.is_none() {
                return;
            }
            let mut packet = MetaPacket::empty();
            packet.update_from_ebpf(sd);
            let _ = SENDER.as_mut().unwrap().send(Box::new(packet));
        }
    }

    pub fn new(output: Sender<Box<AppProtoLogsData>>, log_path: &str) -> Result<Self> {
        unsafe {
            SWITCH = false;

            let log_file = CString::new(log_path.as_bytes())
                .unwrap()
                .as_c_str()
                .as_ptr();

            if ebpf::bpf_tracer_init(log_file, false) != 0 {
                return Err(Error::EbpfInitError);
            }
            let (s, r, _) = bounded::<Box<MetaPacket>>(1024);
            SENDER = Some(s);
            let e = EbpfCollector {
                receiver: Arc::new(Mutex::new(r)),
                output,
            };

            if ebpf::running_socket_tracer(
                Self::callback, /* 回调接口 rust -> C */
                1,              /* 工作线程数，是指用户态有多少线程参与数据处理 */
                128,            /* 内核共享内存占用的页框数量, 值为2的次幂。用于perf数据传递 */
                65536,          /* 环形缓存队列大小，值为2的次幂。e.g: 2,4,8,16,32,64,128 */
                524288, /* 设置用于socket追踪的hash表项最大值，取决于实际场景中并发请求数量 */
                524288, /* 设置用于线程追踪会话的hash表项最大值，SK_BPF_DATA结构的syscall_trace_id_session关联这个哈希表 */
                520000, /* socket map表项进行清理的最大阈值，当前map的表项数量超过这个值进行map清理操作 */
            ) != 0
            {
                return Err(Error::EbpfRunningError);
            }

            ebpf::bpf_tracer_finish();
            return Ok(e);
        }
    }

    pub fn get_ebpf_stats(&self) -> Result<ebpf::SK_TRACE_STATS> {
        unsafe { Ok(ebpf::socket_tracer_stats()) }
    }

    pub fn start(&mut self) {
        unsafe { SWITCH = true }
        let receiver = Arc::clone(&self.receiver);
        let output = self.output.clone();

        thread::spawn(move || {
            fn parse(
                log_parser: &mut HashMap<L7Protocol, Box<dyn L7LogParse>>,
                packet: &Box<MetaPacket>,
            ) -> Result<L7Protocol> {
                if let Some(parser) = log_parser.get_mut(&packet.l7_protocol) {
                    if let Ok(_) = parser.parse(
                        packet.raw_from_ebpf.as_ref(),
                        packet.lookup_key.proto,
                        PacketDirection::ClientToServer,
                    ) {
                        return Ok(packet.l7_protocol);
                    }
                    return Err(Error::EbpfL7ParseError);
                }

                for (k, v) in log_parser.iter_mut() {
                    if let Ok(_) = v.parse(
                        packet.raw_from_ebpf.as_ref(),
                        packet.lookup_key.proto,
                        PacketDirection::ClientToServer,
                    ) {
                        return Ok(*k);
                    }
                }

                return Err(Error::EbpfL7ParseError);
            }

            fn get_info(
                log_parser: &mut HashMap<L7Protocol, Box<dyn L7LogParse>>,
                l7_protocol: L7Protocol,
            ) -> Result<AppProtoLogsInfo> {
                if let Some(parser) = log_parser.get(&l7_protocol) {
                    return Ok(parser.info());
                }
                return Err(Error::EbpfL7ParseError);
            }

            let mut parser: HashMap<L7Protocol, Box<dyn L7LogParse>> = HashMap::new();
            let receiver = receiver.lock().unwrap();
            parser.insert(L7Protocol::Dns, Box::new(DnsLog::default()));
            parser.insert(L7Protocol::Http1, Box::new(HttpLog::default()));
            parser.insert(L7Protocol::Http2, Box::new(HttpLog::default()));
            parser.insert(L7Protocol::Mysql, Box::new(MysqlLog::default()));
            parser.insert(L7Protocol::Redis, Box::new(RedisLog::default()));
            parser.insert(L7Protocol::Kafka, Box::new(KafkaLog::default()));
            parser.insert(L7Protocol::Dubbo, Box::new(DubboLog::default()));
            while unsafe { SWITCH } {
                let packet = receiver.recv(None);
                if packet.is_err() {
                    continue;
                }
                let packet = packet.as_ref().unwrap();

                if let Ok(l7_protocol) = parse(&mut parser, packet) {
                    if let Ok(info) = get_info(&mut parser, l7_protocol) {
                        let base = AppProtoLogsBaseInfo::from(packet);
                        let data = AppProtoLogsData {
                            base_info: base,
                            special_info: info,
                        };

                        debug!("ebpf app log: {}", data);
                        let _ = output.send(Box::new(data));
                    }
                }
            }
        });
    }

    pub fn stop(&self) {
        unsafe { SWITCH = false }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_ebpf_collector() {}
}
