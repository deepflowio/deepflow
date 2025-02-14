use std::{
    collections::{HashMap, HashSet},
    ffi::CString,
    sync::{
        atomic::{AtomicBool, AtomicI64, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use arc_swap::access::Access;
use log::{debug, error, info, trace, warn};
use public::{
    buffer::Allocator,
    counter::Countable,
    debug::QueueDebugger,
    netns::{self, NsFile},
    proto::{common::TridentType, trident::IfMacSource},
    queue::{self, bounded_with_debug, DebugSender},
    utils::net::{links_by_name_regex, Link, MacAddr},
    LeakyBucket,
};
use regex::Regex;

use super::{
    base_dispatcher::{BaseDispatcherListener, TapInterfaceWhitelist},
    BaseDispatcher, BpfOptions, DispatcherBuilder, DispatcherConfig, LocalModeDispatcher, Options,
    Packet, PacketCounter, RecvEngine, TapMode,
};
use crate::{
    config::handler::DispatcherAccess,
    exception::ExceptionHandler,
    flow_generator::{flow_map::Config, FlowMap},
    rpc::get_timestamp,
    utils::stats::QueueStats,
};

const PACKET_BATCH_SIZE: usize = 64;
const SETNS_RETRIES: usize = 3;

pub struct LocalMultinsModeDispatcher {
    base: BaseDispatcher,

    receiver_manager: Option<JoinHandle<()>>,
}

impl LocalMultinsModeDispatcher {
    pub fn new(base: BaseDispatcher) -> Self {
        Self {
            base,
            receiver_manager: None,
        }
    }

    pub fn run(&mut self) {
        info!("Start local multi-namespace dispatcher");

        let base = &mut self.base.is;

        let config = base.dispatcher_config.load();

        let id = base.id;
        let name = "0.1-raw-packet-to-flow-generator";
        let (packet_input, packet_output, counter) =
            bounded_with_debug(config.raw_packet_queue_size, name, &base.queue_debugger);
        base.stats.register_countable(
            &QueueStats { id, module: name },
            Countable::Owned(Box::new(counter)),
        );

        let bpf_controls = Arc::new(Mutex::new(HashMap::new()));

        let dm = ReceiverManager {
            pause: base.pause.clone(),
            terminated: base.terminated.clone(),
            config: base.dispatcher_config.clone(),
            options: base.options.clone(),
            bpf_options: base.bpf_options.clone(),
            queue_debugger: base.queue_debugger.clone(),
            leaky_bucket: base.leaky_bucket.clone(),
            exception_handler: base.exception_handler.clone(),
            counter: base.counter.clone(),
            ntp_diff: base.ntp_diff.clone(),
            bpf_controls: bpf_controls.clone(),
            output: packet_input,
        };
        self.receiver_manager.replace(
            thread::Builder::new()
                .name("pkt-rcv-manager".to_owned())
                .spawn(dm.run())
                .unwrap(),
        );

        let mut flow_map = FlowMap::new(
            base.id as u32,
            base.flow_output_queue.clone(),
            base.l7_stats_output_queue.clone(),
            base.policy_getter,
            base.log_output_queue.clone(),
            base.ntp_diff.clone(),
            &base.flow_map_config.load(),
            Some(base.packet_sequence_output_queue.clone()), // Enterprise Edition Feature: packet-sequence
            base.stats.clone(),
            false, // !from_ebpf
        );

        let tunnel_type_trim_bitmap = base.tunnel_type_trim_bitmap.clone();
        let mut batch = Vec::with_capacity(PACKET_BATCH_SIZE);
        let mut tap_interface_whitelists: HashMap<u64, TapInterfaceWhitelist> = HashMap::new();

        super::set_cpu_affinity(&base.options);
        while !base.terminated.load(Ordering::Relaxed) {
            let config = Config {
                flow: &base.flow_map_config.load(),
                log_parser: &base.log_parse_config.load(),
                collector: &base.collector_config.load(),
                ebpf: None,
            };

            if base.reset_whitelist.swap(false, Ordering::Relaxed) {
                tap_interface_whitelists.clear();
                for (_, bpf_control) in bpf_controls.lock().unwrap().iter() {
                    bpf_control.tap_whitelist.lock().unwrap().clear();
                    bpf_control.need_update.store(true, Ordering::Relaxed);
                }
            }

            match packet_output.recv_all(&mut batch, Some(Duration::from_secs(1))) {
                Ok(_) => {}
                Err(queue::Error::Timeout) => {
                    flow_map.inject_flush_ticker(&config, Duration::ZERO);
                    let need_update_bpf = base.need_update_bpf.swap(false, Ordering::Relaxed);
                    let mut bpf_controls = bpf_controls.lock().unwrap();
                    tap_interface_whitelists.retain(|inode, whitelist| {
                        let ns = NsFile::Proc(*inode);
                        match bpf_controls.get_mut(&ns) {
                            Some(ctrl) => {
                                if whitelist.next_sync(Duration::ZERO) || need_update_bpf {
                                    *ctrl.tap_whitelist.lock().unwrap() =
                                        whitelist.as_set().clone();
                                    ctrl.need_update.store(true, Ordering::Relaxed);
                                }
                                true
                            }
                            None => false,
                        }
                    });
                    continue;
                }
                Err(queue::Error::Terminated(..)) => break,
                Err(queue::Error::BatchTooLarge(_)) => unreachable!(),
            }

            if base.pause.load(Ordering::Relaxed) {
                batch.clear();
                continue;
            }

            let mut last_timestamp = None;
            for mut packet in batch.drain(..) {
                let Some(meta_packet) = LocalModeDispatcher::process_packet(
                    base,
                    &config,
                    &mut flow_map,
                    tunnel_type_trim_bitmap,
                    &mut packet.timestamp,
                    (packet.ns_ino as u64) << 32 | (packet.if_index as u64),
                    &mut packet.raw,
                ) else {
                    continue;
                };

                if let Some(policy) = meta_packet.policy_data.as_ref() {
                    if policy.acl_id > 0 {
                        let whitelist = tap_interface_whitelists
                            .entry(packet.ns_ino as u64)
                            .or_default();
                        if !whitelist.has(packet.if_index as usize) {
                            // 如果匹配策略则认为需要拷贝整个包
                            whitelist.add(packet.if_index as usize);
                        }
                    }
                }
                last_timestamp = Some(meta_packet.lookup_key.timestamp);
            }
            if let Some(ts) = last_timestamp {
                let need_update_bpf = base.need_update_bpf.swap(false, Ordering::Relaxed);
                let mut bpf_controls = bpf_controls.lock().unwrap();
                tap_interface_whitelists.retain(|inode, whitelist| {
                    let ns = NsFile::Proc(*inode);
                    match bpf_controls.get_mut(&ns) {
                        Some(ctrl) => {
                            if whitelist.next_sync(ts.into()) || need_update_bpf {
                                *ctrl.tap_whitelist.lock().unwrap() = whitelist.as_set().clone();
                                ctrl.need_update.store(true, Ordering::Relaxed);
                            }
                            true
                        }
                        None => false,
                    }
                });
            }
        }
        info!("Stopping local multi-namespace dispatcher");
        info!("Wait for receiver manager to stop");
        self.receiver_manager.take().unwrap().join().unwrap();
        info!("Local multi-namespace dispatcher stopped");
    }

    pub(super) fn listener(&self) -> LocalMultinsModeDispatcherListener {
        LocalMultinsModeDispatcherListener::new(
            self.base.listener(),
            &self.base.is.dispatcher_config.load(),
        )
    }
}

#[derive(Debug)]
enum ExitStatus {
    Normal,

    InitFailed,
    UpdateFailed,

    NoTapInterfaces,
}

struct BpfControl {
    need_update: AtomicBool,
    // no packet truncation for tap interfaces in the whitelist
    tap_whitelist: Mutex<HashSet<usize>>,
}

struct PktReceiver {
    pause: Arc<AtomicBool>,
    terminated: Arc<AtomicBool>,
    netns: NsFile,

    config: DispatcherAccess,
    options: Arc<Mutex<Options>>,
    bpf_options: Arc<Mutex<BpfOptions>>,
    queue_debugger: Arc<QueueDebugger>,

    leaky_bucket: Arc<LeakyBucket>,
    exception_handler: ExceptionHandler,
    counter: Arc<PacketCounter>,
    ntp_diff: Arc<AtomicI64>,

    bpf_control: Arc<BpfControl>,

    output: DebugSender<Packet>,
}

impl PktReceiver {
    fn check_and_update_bpf(
        is_root: bool,
        log_prefix: &str,
        ctrl: &BpfControl,
        engine: &mut RecvEngine,
        config: &DispatcherConfig,
        options: &Mutex<Options>,
        bpf_options: &Mutex<BpfOptions>,
    ) -> Option<ExitStatus> {
        let if_regex = if is_root {
            &config.tap_interface_regex
        } else {
            &config.inner_tap_interface_regex
        };
        let links = match links_by_name_regex(if_regex) {
            Ok(links) => links,
            Err(e) => {
                warn!("{log_prefix} failed to get links: {e}");
                return Some(ExitStatus::NoTapInterfaces);
            }
        };
        if links.is_empty() {
            info!("{log_prefix} no tap interfaces found, stop receiving thread");
            return Some(ExitStatus::NoTapInterfaces);
        }

        let options = options.lock().unwrap();
        let bpf_options = bpf_options.lock().unwrap();
        if let Err(e) = engine.set_bpf(
            bpf_options.get_bpf_instructions(
                &links,
                &ctrl.tap_whitelist.lock().unwrap(),
                options.snap_len,
            ),
            &CString::new(bpf_options.get_bpf_syntax()).unwrap(),
        ) {
            warn!(
                "{log_prefix} set_bpf failed with tap_interfaces count {}: {e}",
                links.len()
            );
            return Some(ExitStatus::UpdateFailed);
        }
        None
    }

    fn run(self) -> impl FnOnce() -> ExitStatus {
        move || {
            super::set_cpu_affinity(&self.options);

            let ns_ino = self.netns.get_inode().unwrap() as u32;
            let log_prefix = format!("pkt-rcv({}):", self.netns);
            // try to setns a few times because this can fail when process terminates
            for i in 1..=SETNS_RETRIES {
                let e = match self.netns.open_and_setns() {
                    Ok(_) => break,
                    Err(e) => {
                        debug!("{log_prefix} setns failed {i} time(s): {e}");
                        e
                    }
                };
                if i == SETNS_RETRIES {
                    info!("{log_prefix} setns failed, unable to start receiver: {e}");
                    return ExitStatus::InitFailed;
                }
                thread::sleep(Duration::from_secs(1));
            }

            let cfg = self.config.load();
            let if_regex = match self.netns {
                NsFile::Root => &cfg.tap_interface_regex,
                _ => &cfg.inner_tap_interface_regex,
            };
            let links = match links_by_name_regex(if_regex) {
                Ok(links) => links,
                Err(e) => {
                    warn!("{log_prefix} failed to get links: {e}");
                    return ExitStatus::NoTapInterfaces;
                }
            };
            if links.is_empty() {
                info!("{log_prefix} no tap interfaces found, stop receiving thread");
                return ExitStatus::NoTapInterfaces;
            }

            let mut engine = match DispatcherBuilder::get_engine(
                &Some(links),
                &None,
                TapMode::Local,
                &self.options,
                &self.queue_debugger,
            ) {
                Ok(engine) => engine,
                Err(e) => {
                    warn!("{log_prefix} get_engine failed, stop receiving thread: {e}");
                    return ExitStatus::InitFailed;
                }
            };
            if let Err(e) = engine.init() {
                warn!("{log_prefix} recv_engine init error, stop receiving thread: {e}");
                return ExitStatus::InitFailed;
            }

            let mut prev_timestamp = get_timestamp(self.ntp_diff.load(Ordering::Relaxed));

            let mut batch = Vec::with_capacity(PACKET_BATCH_SIZE);
            let mut allocator = Allocator::new(cfg.raw_packet_buffer_block_size);

            info!("{log_prefix} started packet receive");
            while !self.terminated.load(Ordering::Relaxed) {
                unsafe {
                    // SAFTY:
                    //     Memory in `recved` will be released before the next call to recv.
                    //     It will be copied before sending into the queue.
                    let recved = BaseDispatcher::recv(
                        &mut engine,
                        &self.leaky_bucket,
                        &self.exception_handler,
                        &mut prev_timestamp,
                        &self.counter,
                        &self.ntp_diff,
                    );
                    if recved.is_none() || batch.len() >= PACKET_BATCH_SIZE {
                        if let Err(e) = self.output.send_all(&mut batch) {
                            debug!("{log_prefix} sender failed: {e}");
                            batch.clear();
                        }
                    }

                    let Some((ref packet, timestamp)) = recved else {
                        drop(recved);
                        if self.bpf_control.need_update.swap(false, Ordering::Relaxed) {
                            Self::check_and_update_bpf(
                                self.netns == NsFile::Root,
                                &log_prefix,
                                &self.bpf_control,
                                &mut engine,
                                &cfg,
                                &self.options,
                                &self.bpf_options,
                            );
                        }
                        continue;
                    };

                    if self.pause.load(Ordering::Relaxed) {
                        continue;
                    }

                    self.counter.rx.fetch_add(1, Ordering::Relaxed);
                    self.counter
                        .rx_bytes
                        .fetch_add(packet.capture_length as u64, Ordering::Relaxed);

                    let buffer = allocator.allocate_with(&packet.data);
                    let info = Packet {
                        timestamp,
                        raw: buffer,
                        original_length: packet.capture_length as u32,
                        raw_length: packet.data.len() as u32,
                        if_index: packet.if_index,
                        ns_ino,
                    };
                    batch.push(info);

                    drop(recved);
                    if self.bpf_control.need_update.swap(false, Ordering::Relaxed) {
                        Self::check_and_update_bpf(
                            self.netns == NsFile::Root,
                            &log_prefix,
                            &self.bpf_control,
                            &mut engine,
                            &cfg,
                            &self.options,
                            &self.bpf_options,
                        );
                    }
                }
            }

            info!("{log_prefix} stopped packet receive");
            ExitStatus::Normal
        }
    }
}

struct PktReceiverHandle {
    terminated: Arc<AtomicBool>,
    join_handle: Option<JoinHandle<ExitStatus>>,
}

struct ReceiverManager {
    pause: Arc<AtomicBool>,
    terminated: Arc<AtomicBool>,

    config: DispatcherAccess,
    options: Arc<Mutex<Options>>,
    bpf_options: Arc<Mutex<BpfOptions>>,
    queue_debugger: Arc<QueueDebugger>,

    bpf_controls: Arc<Mutex<HashMap<NsFile, Arc<BpfControl>>>>,

    leaky_bucket: Arc<LeakyBucket>,
    exception_handler: ExceptionHandler,
    counter: Arc<PacketCounter>,
    ntp_diff: Arc<AtomicI64>,

    output: DebugSender<Packet>,
}

impl ReceiverManager {
    // find all namespaces that has a interface that
    // - matches the regex
    // - has its peer interface in root namespace
    // - not in root namespace
    // and extract their inode numbers in sorted order
    fn find_tap_namespaces(re: &Regex) -> netns::Result<Vec<NsFile>> {
        let interfaces = netns::interfaces_linked_with(&vec![NsFile::Root])?
            .remove(&NsFile::Root)
            .unwrap_or_default();
        let root_inode = NsFile::Root.get_inode()?;
        let mut inodes: Vec<NsFile> = interfaces
            .into_iter()
            .filter_map(|info| {
                // filter out interfaces whose peer is in root namespace
                if info.ns_inode == root_inode || !re.is_match(&info.name) {
                    return None;
                }
                Some(NsFile::Proc(info.ns_inode))
            })
            .collect();
        inodes.sort_unstable();
        inodes.dedup();
        debug!("Found tap namespaces: {inodes:?}");
        Ok(inodes)
    }

    const INTERVAL_SECS: u8 = 16;

    fn run(self) -> impl FnOnce() -> () {
        move || {
            super::set_cpu_affinity(&self.options);

            info!("Receiver manager started");

            let mut loop_count = 0;
            let mut zombie_threads = vec![];
            let mut receiver_threads: HashMap<NsFile, PktReceiverHandle> = HashMap::new();
            while !self.terminated.load(Ordering::Relaxed) {
                loop_count = (loop_count + 1) % Self::INTERVAL_SECS;
                if loop_count != 1 {
                    // actual interval is (INTERVAL_SECS - 1) to make this simple and less error prone
                    // no delay on the first loop
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }

                // check if pkt receiver threads are running
                let mut bpf_controls = self.bpf_controls.lock().unwrap();
                receiver_threads.retain(|ns, handle| {
                    if handle.join_handle.as_ref().unwrap().is_finished() {
                        match handle.join_handle.take().unwrap().join() {
                            Ok(status) => debug!("PktReceiver for {ns} is finished {status:?}"),
                            Err(e) => {
                                warn!("PktReceiver for {ns} is finished but join error: {e:?}")
                            }
                        }
                        bpf_controls.remove(ns);
                        false
                    } else {
                        true
                    }
                });
                drop(bpf_controls);

                // check if zombies are finished
                zombie_threads.retain_mut(
                    |(ns, handle): &mut (NsFile, Option<JoinHandle<ExitStatus>>)| {
                        if handle.as_ref().unwrap().is_finished() {
                            match handle.take().unwrap().join() {
                                Ok(status) => debug!("PktReceiver for {ns} is finished {status:?}"),
                                Err(e) => {
                                    warn!("PktReceiver for {ns} is finished but join error: {e:?}")
                                }
                            }
                            false
                        } else {
                            debug!("PktReceiver for {ns} is terminated but not finished");
                            true
                        }
                    },
                );

                let config = self.config.load();
                let re = match Regex::new(&config.inner_tap_interface_regex) {
                    Ok(re) => re,
                    Err(e) => {
                        error!(
                            "Failed to compile inner tap interface regex /{}/: {e}",
                            config.inner_tap_interface_regex
                        );
                        continue;
                    }
                };
                let mut new_namespaces = match Self::find_tap_namespaces(&re) {
                    Ok(namespaces) => namespaces,
                    Err(e) => {
                        error!("Failed to find tap namespaces: {e}");
                        continue;
                    }
                };
                match netns::links_by_name_regex_in_netns(
                    &config.tap_interface_regex,
                    &NsFile::Root,
                ) {
                    Err(e) => warn!(
                        "get interfaces by name regex in {:?} failed: {}",
                        NsFile::Root,
                        e
                    ),
                    Ok(links) if links.is_empty() => {
                        warn!(
                            "tap-interface-regex({}) do not match any interface in {:?}",
                            config.tap_interface_regex,
                            NsFile::Root,
                        );
                    }
                    _ => new_namespaces.push(NsFile::Root),
                }
                trace!("Found {} tap namespaces", new_namespaces.len());
                for ns in new_namespaces.iter() {
                    if receiver_threads.contains_key(ns) {
                        trace!("PktReceiver is running in {ns}");
                        continue;
                    }
                    let terminated = Arc::new(AtomicBool::new(false));
                    let bpf_control = Arc::new(BpfControl {
                        need_update: AtomicBool::new(false),
                        tap_whitelist: Mutex::new(HashSet::new()),
                    });
                    let receiver = PktReceiver {
                        pause: self.pause.clone(),
                        terminated: terminated.clone(),
                        netns: ns.clone(),
                        config: self.config.clone(),
                        options: self.options.clone(),
                        bpf_options: self.bpf_options.clone(),
                        queue_debugger: self.queue_debugger.clone(),
                        leaky_bucket: self.leaky_bucket.clone(),
                        exception_handler: self.exception_handler.clone(),
                        counter: self.counter.clone(),
                        ntp_diff: self.ntp_diff.clone(),
                        bpf_control: bpf_control.clone(),
                        output: self.output.clone(),
                    };
                    let join_handle = thread::Builder::new()
                        .name(format!("pr-{ns}"))
                        .spawn(receiver.run())
                        .unwrap();
                    self.bpf_controls
                        .lock()
                        .unwrap()
                        .insert(ns.clone(), bpf_control);
                    receiver_threads.insert(
                        ns.clone(),
                        PktReceiverHandle {
                            terminated,
                            join_handle: Some(join_handle),
                        },
                    );
                }
                trace!("Receiver threads numbers: {}", receiver_threads.len());

                if receiver_threads.len() == new_namespaces.len() {
                    // all namespaces have a pkt receiver thread running
                    continue;
                }

                // if a net namespace cannot be reached from all process namespace,
                // that is, not accessbile from any /proc/$pid/ns/net files,
                // its packet receiver will be terminated
                //
                // notice that agent still have access to the net namespace,
                // but the namespace file resides in /proc/agent/task/$tid/ns/net
                // so agent itself will not block this action
                let proc_cache = match netns::get_proc_cache() {
                    Ok(cache) => cache,
                    Err(e) => {
                        debug!("Failed to get proc cache: {e}");
                        continue;
                    }
                };
                let mut bpf_controls = self.bpf_controls.lock().unwrap();
                receiver_threads.retain(|ns, handle| {
                    let terminated = match ns.get_inode() {
                        Ok(inode) => !proc_cache.contains_key(&inode),
                        _ => true,
                    };
                    if terminated {
                        handle.terminated.store(true, Ordering::Relaxed);
                        let h = handle.join_handle.take().unwrap();
                        if h.is_finished() {
                            match h.join() {
                                Ok(status) => debug!("PktReceiver for {ns} is finished {status:?}"),
                                Err(e) => {
                                    warn!("PktReceiver for {ns} is finished but join error: {e:?}")
                                }
                            }
                        } else {
                            zombie_threads.push((ns.clone(), Some(h)));
                        }
                        bpf_controls.remove(ns);
                    }
                    !terminated
                });
            }

            info!(
                "Receiver manager stopping {} PktReceivers",
                receiver_threads.len()
            );
            for (_, handle) in receiver_threads.iter() {
                handle.terminated.store(true, Ordering::Relaxed);
            }
            receiver_threads
                .retain(|_, handle| !handle.join_handle.as_ref().unwrap().is_finished());
            info!(
                "Waiting for {} PktReceivers to stop",
                receiver_threads.len()
            );
            for (_, mut handle) in receiver_threads.into_iter() {
                let _ = handle.join_handle.take().unwrap().join();
            }

            info!("Receiver manager stopped");
        }
    }
}

#[derive(Clone)]
pub struct LocalMultinsModeDispatcherListener {
    pub(super) base: BaseDispatcherListener,

    tap_interface_regex: String,
    inner_tap_interface_regex: String,
}

impl LocalMultinsModeDispatcherListener {
    pub(super) fn new(base: BaseDispatcherListener, config: &DispatcherConfig) -> Self {
        Self {
            base,
            tap_interface_regex: config.tap_interface_regex.clone(),
            inner_tap_interface_regex: config.inner_tap_interface_regex.clone(),
        }
    }

    pub fn netns(&self) -> &public::netns::NsFile {
        &self.base.netns
    }

    pub(super) fn on_config_change(&mut self, config: &DispatcherConfig) {
        self.base.on_config_change(config);
        self.tap_interface_regex = config.tap_interface_regex.clone();
        self.inner_tap_interface_regex = config.inner_tap_interface_regex.clone();
    }

    pub fn on_vm_change(&self, _: &[MacAddr]) {}

    pub fn id(&self) -> usize {
        return self.base.id;
    }

    pub fn flow_acl_change(&self) {
        // Start capturing traffic after resource information is distributed
        self.base.pause.store(false, Ordering::Relaxed);
        self.base.reset_whitelist.store(true, Ordering::Relaxed);
    }

    pub fn on_tap_interface_change(
        &self,
        _: &[Link],
        _: IfMacSource,
        _: TridentType,
        _: &Vec<u64>,
    ) {
        let (mut keys, mut macs) = (vec![], vec![]);

        trace!(
            "tap_interface_regex = /{}/, inner_tap_interface_regex = /{}/",
            self.tap_interface_regex,
            self.inner_tap_interface_regex
        );

        match netns::links_by_name_regex_in_netns(&self.tap_interface_regex, &NsFile::Root) {
            Err(e) => {
                warn!(
                    "get interfaces by name regex in {:?} failed: {e}",
                    NsFile::Root
                );
            }
            Ok(mut links) => {
                if links.is_empty() {
                    warn!(
                        "tap-interface-regex({}) do not match any interface in {:?}",
                        self.tap_interface_regex,
                        NsFile::Root,
                    );
                } else {
                    debug!(
                        "tap interfaces in namespace {:?}: {:?}",
                        NsFile::Root,
                        links
                    );
                    links.sort_by_key(|link| link.if_index);
                    for link in links {
                        keys.push(link.if_index as u64);
                        macs.push(link.mac_addr);
                    }
                }
            }
        }

        let Ok(inner_regex) = Regex::new(&self.inner_tap_interface_regex) else {
            warn!(
                "Failed to compile inner tap interface regex /{}/",
                self.inner_tap_interface_regex
            );
            return;
        };
        let interfaces = match netns::interfaces_linked_with(&vec![NsFile::Root]) {
            Ok(mut interfaces) => interfaces.remove(&NsFile::Root).unwrap_or_default(),
            Err(e) => {
                warn!("Failed to get interfaces with peer in root namespace: {e}");
                return;
            }
        };
        let root_inode = NsFile::Root.get_inode().unwrap();
        let mut inodes: Vec<u64> = interfaces
            .into_iter()
            .filter_map(|info| {
                // filter out interfaces whose peer is in root namespace
                if info.ns_inode == root_inode || !inner_regex.is_match(&info.name) {
                    return None;
                }
                Some(info.ns_inode)
            })
            .collect();
        inodes.sort_unstable();
        inodes.dedup();
        debug!("Found tap namespaces: {inodes:?}");

        'outer: for inode in inodes {
            let ns_file = NsFile::Proc(inode);
            for i in 1..=SETNS_RETRIES {
                let e = match ns_file.open_and_setns() {
                    Ok(_) => break,
                    Err(e) => {
                        debug!("setns failed {i} time(s): {e}");
                        e
                    }
                };
                if i == SETNS_RETRIES {
                    info!("setns failed, unable to find links in namespace {ns_file}: {e}");
                    continue 'outer;
                }
                thread::sleep(Duration::from_millis(100));
            }
            let mut links = match links_by_name_regex(inner_regex.as_str()) {
                Ok(links) => links,
                Err(e) => {
                    warn!("Failed to find links in namespace {ns_file}: {e}");
                    continue;
                }
            };
            if links.is_empty() {
                debug!("No links found in namespace {ns_file}");
                continue;
            }
            links.sort_by_key(|link| link.if_index);
            for link in links {
                keys.push(link.if_index as u64 | inode << 32);
                macs.push(link.mac_addr);
            }
        }
        let _ = netns::reset_netns();

        self.base.on_vm_change(&keys, &macs);
    }
}
