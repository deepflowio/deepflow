use std::collections::HashMap;
use std::ffi::CString;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use arc_swap::access::Access;
use log::{debug, info, warn};
use lru::LruCache;

use super::{Error, Result};
use crate::common::flow::L7Protocol;
use crate::common::meta_packet::MetaPacket;
use crate::config::handler::EbpfAccess;
use crate::ebpf;
use crate::flow_generator::{
    AppProtoHead, AppProtoLogsBaseInfo, AppProtoLogsData, AppProtoLogsInfo, DnsLog, DubboLog,
    HttpLog, KafkaLog, L7LogParse, LogMessageType, MysqlLog, RedisLog, Result as LogResult,
};
use crate::policy::PolicyGetter;
use crate::sender::SendItem;
use crate::utils::{
    queue::{bounded, DebugSender, Receiver, Sender},
    stats::{Countable, Counter, CounterType, CounterValue},
};

type LoggerItem = (L7Protocol, Box<dyn L7LogParse>);

struct SessionAggr {
    maps: [Option<HashMap<u64, AppProtoLogsData>>; 16],
    start_time: u64, // 秒级时间
    cache_count: u64,
    last_flush_time: u64, // 秒级时间
    slot_count: u64,

    output: DebugSender<SendItem>,
}

impl SessionAggr {
    // 尽力而为的聚合默认120秒(AppProtoLogs.aggr*SLOT_WIDTH)内的请求和响应
    const SLOT_WIDTH: u64 = 60; // 每个slot存60秒
    const SLOT_CACHED_COUNT: u64 = 100000; // 每个slot平均缓存的FLOW数

    pub fn new(l7_log_session_timeout: Duration, output: DebugSender<SendItem>) -> Self {
        let solt_count = l7_log_session_timeout.as_secs() / Self::SLOT_WIDTH;
        let slot_count = solt_count.min(16).max(1) as usize;
        Self {
            slot_count: slot_count as u64,
            output,
            start_time: 0,
            cache_count: 0,
            last_flush_time: 0,
            maps: [
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
            ],
        }
    }

    fn send(&self, log: AppProtoLogsData) {
        debug!("ebpf_collector out: {}", log);
        let _ = self.output.send(SendItem::L7FlowLog(log));
    }

    fn flush(&mut self, count: u64) -> u64 {
        let n = count.min(self.slot_count);
        for i in 0..n as usize {
            let mut map = self.maps[i].take().unwrap();
            for (_, log) in map.drain() {
                self.send(log);
            }
            self.maps[i].replace(map);
        }

        if n != self.slot_count {
            for i in n..self.slot_count {
                let temp_back = self.maps[i as usize].take().unwrap();
                let temp_front = self.maps[(i - n) as usize].take().unwrap();
                self.maps[(i - n) as usize].replace(temp_back);
                self.maps[i as usize].replace(temp_front);
            }
        }
        self.start_time += count * Self::SLOT_WIDTH;

        self.slot_count - 1
    }

    fn slot_handle(&mut self, log: AppProtoLogsData, slot_index: usize, key: u64, ttl: usize) {
        let map = self.maps[slot_index as usize].as_mut().unwrap();

        match log.base_info.head.msg_type {
            LogMessageType::Request => {
                let value = map.get(&key);
                if value.is_none() {
                    // 防止缓存过多的log
                    if self.cache_count >= self.slot_count * Self::SLOT_CACHED_COUNT {
                        self.send(log);
                        return;
                    }

                    map.insert(key, log);
                    self.cache_count += 1;
                    return;
                }
                // 对于HTTPV1, requestID总为0, 连续出现多个request时，response匹配最后一个request为session
                let item = value.unwrap().clone();
                map.insert(key, log);
                self.send(item);
            }
            LogMessageType::Response => {
                let item = map.get(&key);
                if item.is_none() {
                    if ttl > 0 && slot_index != 0 {
                        // 相应和请求可能不在同一个时间槽里，这里继续查询小的时间槽
                        self.slot_handle(log, slot_index - 1, key, ttl - 1);
                    } else {
                        self.send(log);
                    }
                    return;
                }
                let mut item = item.unwrap().clone();
                map.remove(&key);

                let rrt = if log.base_info.start_time > item.base_info.start_time {
                    log.base_info.start_time - item.base_info.start_time
                } else {
                    Duration::ZERO
                };
                item.session_merge(log);
                item.base_info.head.rrt = rrt.as_micros() as u64;
                self.send(item);
            }
            _ => {}
        }
    }

    fn handle(&mut self, log: AppProtoLogsData) {
        let solt_time = log.base_info.start_time.as_secs();
        if solt_time < self.start_time {
            return;
        }
        if self.start_time == 0 {
            self.start_time = solt_time / Self::SLOT_WIDTH * Self::SLOT_WIDTH;
        }

        let mut slot_index = (solt_time - self.start_time) / Self::SLOT_WIDTH;
        if slot_index >= self.slot_count {
            slot_index = self.flush(slot_index - self.slot_count + 1);
        }

        let key = log.flow_session_id();
        self.slot_handle(log, slot_index as usize, key, 1);
    }
}

struct FlowItem {
    last_policy: u64, // 秒级
    other_l3_epc: i32,

    parser: Box<dyn L7LogParse>,
}

impl FlowItem {
    const POLICY_INTERVAL: u64 = 10;

    fn parse(&mut self, packet: &MetaPacket) -> LogResult<AppProtoHead> {
        self.parser.parse(
            packet.raw_from_ebpf.as_ref(),
            packet.lookup_key.proto,
            packet.direction,
        )
    }

    fn get_info(&mut self) -> AppProtoLogsInfo {
        self.parser.info()
    }

    fn handle(
        &mut self,
        packet: &MetaPacket,
        mut policy_getter: PolicyGetter,
        local_epc: i32,
        vtap_id: u16,
    ) -> Option<AppProtoLogsData> {
        // 策略查询
        let key = &packet.lookup_key;
        if key.timestamp.as_secs() > self.last_policy + Self::POLICY_INTERVAL {
            self.last_policy = key.timestamp.as_secs();
            if key.l2_end_0 {
                self.other_l3_epc =
                    policy_getter.lookup_all_by_epc(key.src_ip, key.dst_ip, local_epc, 0);
            } else {
                self.other_l3_epc =
                    policy_getter.lookup_all_by_epc(key.src_ip, key.dst_ip, 0, local_epc);
            }
        }

        // 应用解析
        if let Ok(head) = self.parse(packet) {
            // 获取日志信息
            let info = self.get_info();
            let base = AppProtoLogsBaseInfo::from_ebpf(
                &packet,
                head,
                vtap_id,
                local_epc,
                self.other_l3_epc,
            );
            return Some(AppProtoLogsData {
                base_info: base,
                special_info: info,
            });
        }
        return None;
    }
}

pub struct EbpfCounter {
    rx: u64,
    tx: u64,
    unknown_protocol: u64,
}

impl EbpfCounter {
    fn reset(&mut self) {
        self.rx = 0;
        self.tx = 0;
        self.unknown_protocol = 0;
    }
}

pub struct SyncEbpfCounter {
    counter: *mut EbpfCounter,
}

impl SyncEbpfCounter {
    fn counter(&self) -> &mut EbpfCounter {
        unsafe { &mut *self.counter }
    }
}

unsafe impl Send for SyncEbpfCounter {}
unsafe impl Sync for SyncEbpfCounter {}

impl Countable for SyncEbpfCounter {
    fn get_counters(&self) -> Vec<Counter> {
        let (rx, tx, unknow) = (
            self.counter().rx,
            self.counter().tx,
            self.counter().unknown_protocol,
        );
        self.counter().reset();
        vec![
            ("in", CounterType::Counted, CounterValue::Unsigned(rx)),
            ("out", CounterType::Counted, CounterValue::Unsigned(tx)),
            (
                "unknown_protocol",
                CounterType::Counted,
                CounterValue::Unsigned(unknow),
            ),
        ]
    }
    // EbpfCollector不会重复创建，这里都是false
    fn closed(&self) -> bool {
        false
    }
}

pub struct EbpfCollector {
    receiver: Arc<Receiver<MetaPacket<'static>>>,

    // 策略查询
    policy_getter: PolicyGetter,

    // GRPC配置
    config: EbpfAccess,

    thread_handle: Option<JoinHandle<()>>,

    output: DebugSender<SendItem>,

    counter: EbpfCounter,
}

static mut SWITCH: bool = false;
static mut SENDER: Option<Sender<MetaPacket>> = None;
static mut CAPTURE_SIZE: usize = ebpf::CAP_LEN_MAX as usize;

impl EbpfCollector {
    const FLOW_MAP_SIZE: usize = 1 << 14;

    extern "C" fn callback(sd: *mut ebpf::SK_BPF_DATA) {
        unsafe {
            if !SWITCH || SENDER.is_none() {
                return;
            }
            debug!("ebpf collector in:\n{}", *sd);

            let packet = MetaPacket::from_ebpf(sd, CAPTURE_SIZE);
            if packet.is_err() {
                warn!("meta packet parse from ebpf error: {}", packet.unwrap_err());
                return;
            }
            let _ = SENDER.as_mut().unwrap().send(packet.unwrap());
        }
    }

    fn update_capture_size(capture_size: usize) {
        unsafe {
            if CAPTURE_SIZE != capture_size {
                info!(
                    "ebpf collector capture size change from {} to {}.",
                    CAPTURE_SIZE, capture_size
                );
                CAPTURE_SIZE = capture_size
            }
        }
    }

    pub fn new(
        config: EbpfAccess,
        policy_getter: PolicyGetter,
        output: DebugSender<SendItem>,
    ) -> Result<Box<Self>> {
        unsafe {
            SWITCH = false;
            let log_file = &config.load().log_path;
            let log_file = if !log_file.is_empty() {
                CString::new(log_file.as_bytes())
                    .unwrap()
                    .as_c_str()
                    .as_ptr()
            } else {
                std::ptr::null()
            };
            Self::update_capture_size(config.load().l7_log_packet_size);

            if ebpf::bpf_tracer_init(log_file, true) != 0 {
                return Err(Error::EbpfInitError);
            }
            let (s, r, _) = bounded::<MetaPacket>(1024);
            SENDER = Some(s);
            let e = EbpfCollector {
                receiver: Arc::new(r),
                output,
                policy_getter,
                config,
                thread_handle: None,
                counter: EbpfCounter {
                    rx: 0,
                    tx: 0,
                    unknown_protocol: 0,
                },
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
            info!("ebpf collector init.");
            return Ok(Box::new(e));
        }
    }

    pub fn get_sync_counter(&self) -> SyncEbpfCounter {
        SyncEbpfCounter {
            counter: &self.counter as *const EbpfCounter as *mut EbpfCounter,
        }
    }

    pub fn get_ebpf_stats(&self) -> Result<ebpf::SK_TRACE_STATS> {
        unsafe { Ok(ebpf::socket_tracer_stats()) }
    }

    pub fn start(&mut self) {
        unsafe {
            if SWITCH {
                info!("ebpf collector started");
                return;
            }
            SWITCH = true;
        }
        let receiver = self.receiver.clone();
        let policy_getter = self.policy_getter;
        let config = self.config.clone();

        let mut aggr = SessionAggr::new(config.load().l7_log_session_timeout, self.output.clone());
        let mut flow_map: LruCache<u64, FlowItem> = LruCache::new(Self::FLOW_MAP_SIZE);
        let sync_counter = self.get_sync_counter();

        self.thread_handle = Some(thread::spawn(move || {
            while unsafe { SWITCH } {
                let packet = receiver.recv(Some(Duration::from_millis(1)));
                if packet.is_err() {
                    continue;
                }
                sync_counter.counter().rx += 1;
                let packet = packet.as_ref().unwrap();
                if packet.l7_protocol == L7Protocol::Unknown {
                    sync_counter.counter().unknown_protocol += 1;
                    // 未知协议不处理
                    continue;
                }
                // 流聚合
                let mut flow_item = flow_map.get_mut(&packet.socket_id);
                if flow_item.is_none() {
                    flow_map.put(
                        packet.socket_id,
                        FlowItem {
                            last_policy: 0,
                            parser: get_parser(packet.l7_protocol),
                            other_l3_epc: 0,
                        },
                    );
                    flow_item = flow_map.get_mut(&packet.socket_id);
                }
                let flow_item = flow_item.unwrap();

                let config = config.load();
                if let Some(data) =
                    flow_item.handle(packet, policy_getter, config.epc_id as i32, config.vtap_id)
                {
                    // 应用日志聚合
                    debug!("\n{}", data);
                    aggr.handle(data);
                    sync_counter.counter().tx += 1;
                }
                Self::update_capture_size(config.l7_log_packet_size);
            }

            fn get_parser(protocol: L7Protocol) -> Box<dyn L7LogParse> {
                match protocol {
                    L7Protocol::Dns => Box::from(DnsLog::default()),
                    L7Protocol::Http1 => Box::from(HttpLog::default()),
                    L7Protocol::Http2 => Box::from(HttpLog::default()),
                    L7Protocol::Mysql => Box::from(MysqlLog::default()),
                    L7Protocol::Redis => Box::from(RedisLog::default()),
                    L7Protocol::Kafka => Box::from(KafkaLog::default()),
                    L7Protocol::Dubbo => Box::from(DubboLog::default()),
                    _ => panic!("get_parser unknown protocol."),
                }
            }
        }));
        debug!("ebpf collector starting ebpf-kernel.");
        unsafe {
            while ebpf::tracer_start() != 0 {
                debug!("tracer_start() error, sleep 1s retry.");
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        info!("ebpf collector started");
    }

    pub fn stop(&mut self) {
        unsafe {
            if !SWITCH {
                info!("ebpf collector stopped.");
                return;
            }
            SWITCH = false;
            info!("ebpf collector stopping thread.");
            if let Some(handler) = self.thread_handle.take() {
                let _ = handler.join();
            }
            info!("ebpf collector stopping ebpf-kernel.");
            ebpf::tracer_stop();
            info!("ebpf collector stopped.");
        }
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn test_ebpf_collector() {}
}
