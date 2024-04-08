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
    collections::{HashMap, HashSet},
    fmt,
    io::prelude::*,
    mem,
    ops::Deref,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
    thread,
    time::{Duration, SystemTime},
};

use arc_swap::access::Access;
use flate2::{write::ZlibEncoder, Compression};
use k8s_openapi::apimachinery::pkg::version::Info;
use kube::{Client, Config};
use log::{debug, error, info, log_enabled, warn, Level};
use parking_lot::RwLock;
use tokio::{runtime::Runtime, task::JoinHandle};

use super::{
    k8s_events::BoxedKubernetesEvent,
    resource_watcher::{
        default_resources, supported_resources, GenericResourceWatcher, GroupVersion, Resource,
        Watcher, WatcherConfig,
    },
};
use crate::{
    config::{handler::PlatformAccess, KubernetesResourceConfig},
    error::{Error, Result},
    exception::ExceptionHandler,
    platform::kubernetes::resource_watcher::ResourceWatcherFactory,
    rpc::Session,
    trident::AgentId,
    utils::{
        environment::{running_in_container, running_in_only_watch_k8s_mode},
        stats,
    },
};
use public::{
    proto::{
        common::KubernetesApiInfo,
        trident::{Exception, KubernetesApiSyncRequest},
    },
    queue::DebugSender,
};

/*
 * K8s API同步功能
 *     启动时首先为不同的k8s API分别创建一个Watcher进行查询，
 *     APIWatcher每隔interval（默认1分钟）查看每一个Watcher
 *     是否有更新：如有，将全部Watcher数据打包，发送给triso；
 *     否则，发送一个内容为空的心跳数据。发送心跳数据后，得到
 *     triso回复消息的版本号与当前版本不一致，说明triso没收到
 *     最新数据，此时进行一次全量同步。
 */

const PB_VERSION_INFO: &str = "*version.Info";

struct Context {
    config: PlatformAccess,
    runtime: Arc<Runtime>,
    version: AtomicU64,
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
struct WatcherKey {
    name: &'static str,
    group: &'static str,
}

impl fmt::Display for WatcherKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.group, self.name)
    }
}

pub struct ApiWatcher {
    context: Arc<Context>,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
    running: Arc<Mutex<bool>>,
    timer: Arc<Condvar>,
    watchers: Arc<Mutex<HashMap<WatcherKey, GenericResourceWatcher>>>,
    err_msgs: Arc<Mutex<Vec<String>>>,
    apiserver_version: Arc<Mutex<Info>>,
    session: Arc<Session>,
    exception_handler: ExceptionHandler,
    stats_collector: Arc<stats::Collector>,
    agent_id: Arc<RwLock<AgentId>>,
    k8s_events_sender: Arc<Mutex<Option<DebugSender<BoxedKubernetesEvent>>>>,
}

impl ApiWatcher {
    pub fn new(
        runtime: Arc<Runtime>,
        config: PlatformAccess,
        agent_id: Arc<RwLock<AgentId>>,
        session: Arc<Session>,
        exception_handler: ExceptionHandler,
        stats_collector: Arc<stats::Collector>,
    ) -> Self {
        Self {
            context: Arc::new(Context {
                config,
                version: AtomicU64::new(
                    SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                ),
                runtime,
            }),
            thread: Mutex::new(None),
            session,
            timer: Arc::new(Condvar::new()),
            running: Arc::new(Mutex::new(false)),
            agent_id,
            apiserver_version: Arc::new(Mutex::new(Info::default())),
            err_msgs: Arc::new(Mutex::new(vec![])),
            watchers: Arc::new(Mutex::new(HashMap::new())),
            exception_handler,
            stats_collector,
            k8s_events_sender: Arc::new(Mutex::new(None)),
        }
    }

    pub fn set_k8s_events_sender(&self, k8s_events_sender: DebugSender<BoxedKubernetesEvent>) {
        self.k8s_events_sender
            .lock()
            .unwrap()
            .replace(k8s_events_sender);
    }

    // 直接拿对应的entries
    pub fn get_watcher_entries(&self, resource_name: impl AsRef<str>) -> Option<Vec<Vec<u8>>> {
        if !*self.running.lock().unwrap() {
            debug!("ApiWatcher isn't running");
            return None;
        }

        let mut entries = vec![];
        let watchers = self.watchers.lock().unwrap();
        for (k, v) in watchers.iter() {
            if k.name == resource_name.as_ref() {
                entries.append(&mut v.entries())
            }
        }
        if entries.is_empty() {
            None
        } else {
            Some(entries)
        }
    }

    pub fn get_server_version(&self) -> Option<String> {
        let info = self.apiserver_version.lock().unwrap();
        serde_json::to_string(info.deref()).ok()
    }

    pub fn notify_stop(&self) -> Option<thread::JoinHandle<()>> {
        {
            let mut running_guard = self.running.lock().unwrap();
            if !*running_guard {
                debug!("ApiWatcher has already stopped");
                return None;
            }
            *running_guard = false;
        }
        self.timer.notify_one();

        self.thread.lock().unwrap().take()
    }

    // 停止 api watcher, 支持睡眠唤醒
    pub fn stop(&self) {
        {
            let mut running_guard = self.running.lock().unwrap();
            if !*running_guard {
                debug!("ApiWatcher has already stopped");
                return;
            }
            *running_guard = false;
        }
        self.timer.notify_one();

        if let Some(handle) = self.thread.lock().unwrap().take() {
            let _ = handle.join();
        }
    }

    pub fn start(&self) {
        if self.context.config.load().kubernetes_cluster_id.is_empty() {
            info!("ApiWatcher failed to start because kubernetes-cluster-id is empty");
            return;
        }

        if (!self.context.config.load().kubernetes_api_enabled && !running_in_only_watch_k8s_mode())
            || !running_in_container()
        {
            return;
        }

        {
            let mut running_guard = self.running.lock().unwrap();
            if *running_guard {
                debug!("ApiWatcher has already running");
                return;
            }
            *running_guard = true;
        }
        let context = self.context.clone();
        let session = self.session.clone();
        let timer = self.timer.clone();
        let running = self.running.clone();
        let agent_id = self.agent_id.clone();
        let apiserver_version = self.apiserver_version.clone();
        let err_msgs = self.err_msgs.clone();
        let watchers = self.watchers.clone();
        let exception_handler = self.exception_handler.clone();
        let stats_collector = self.stats_collector.clone();
        let k8s_events_sender = self.k8s_events_sender.clone();

        let handle = thread::Builder::new()
            .name("kubernetes-api-watcher".to_owned())
            .spawn(move || {
                Self::run(
                    context,
                    session,
                    timer,
                    running,
                    apiserver_version,
                    err_msgs,
                    watchers,
                    exception_handler,
                    stats_collector,
                    agent_id,
                    k8s_events_sender,
                )
            })
            .unwrap();
        self.thread.lock().unwrap().replace(handle);
    }

    async fn discover_resources(
        client: &Client,
        resource_config: &Vec<KubernetesResourceConfig>,
        err_msgs: &Arc<Mutex<Vec<String>>>,
    ) -> Result<Vec<Resource>> {
        let mut resources = default_resources();
        debug!("default resources are {:?}", resources);
        let supported_resources = supported_resources();

        let mut disabled_resources = HashSet::new();
        for r in resource_config {
            if r.disabled {
                debug!("resource {} disabled", r.name);
                disabled_resources.insert(r.name.clone());
            }
        }
        let mut overridden_resources = HashSet::new();
        for r in resource_config {
            if disabled_resources.contains(&r.name) {
                continue;
            }
            debug!("resource {} overridden", r.name);
            overridden_resources.insert(r.name.clone());
        }

        // remove disabled or overridden entries
        resources.retain(|r| {
            !(disabled_resources.contains(&r.name as &str)
                || overridden_resources.contains(&r.name as &str))
        });

        // add overridden entries
        for r in resource_config {
            if r.disabled {
                continue;
            }
            let Some(index) = supported_resources
                .iter()
                .position(|sr| &sr.name == &r.name)
            else {
                warn!("resource {} not supported", r.name);
                continue;
            };
            let sr = &supported_resources[index];
            if r.group == "" && r.version == "" {
                resources.push(sr.clone());
                continue;
            }
            if r.version == "" {
                let gv = sr
                    .group_versions
                    .iter()
                    .filter_map(|gv| {
                        if &gv.group == &r.group {
                            Some(*gv)
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                if gv.is_empty() {
                    warn!("resource {} in group {} not supported", r.name, r.group);
                } else {
                    resources.push(Resource {
                        group_versions: gv,
                        ..sr.clone()
                    });
                }
                continue;
            }
            let Some(index) = sr
                .group_versions
                .iter()
                .position(|gv| &gv.group == &r.group && &gv.version == &r.version)
            else {
                warn!(
                    "resource {} in group {}/{} not supported",
                    r.name, r.group, r.version
                );
                continue;
            };
            resources.push(Resource {
                selected_gv: Some(sr.group_versions[index]),
                ..sr.clone()
            });
        }
        debug!("overridden resources are {:?}", resources);

        // only support core/v1
        let core_version = "v1";
        let api_versions = client
            .list_core_api_versions()
            .await
            .map_err(|e| Error::KubernetesApiWatcher(format!("{}", e)))?;
        if !api_versions.versions.contains(&core_version.to_owned()) {
            return Err(Error::KubernetesApiWatcher(format!(
                "core api versions {:?} does not contain \"v1\"",
                api_versions.versions
            )));
        }
        let core_resources = client
            .list_core_api_resources(core_version)
            .await
            .map_err(|e| Error::KubernetesApiWatcher(format!("{}", e)))?;
        for api_resource in core_resources.resources {
            let Some(index) = resources.iter().position(|r| {
                &r.name == &api_resource.name
                    && r.group_versions.iter().any(|gv| gv.group == "core")
            }) else {
                continue;
            };
            debug!(
                "found {} api in group core/{}",
                api_resource.name, core_version
            );
            resources[index].selected_gv = Some(GroupVersion {
                group: "core",
                version: core_version,
            });
        }

        let interested_groups: HashSet<&'static str> = resources
            .iter()
            .filter(|r| r.selected_gv.is_none())
            .flat_map(|r| r.group_versions.iter().map(|gv| gv.group))
            .collect();
        debug!("search for api in groups {:?}", interested_groups);
        match client.list_api_groups().await {
            Ok(api_groups) => {
                for group in api_groups.groups {
                    if !interested_groups.contains(&group.name as &str) {
                        debug!("skipped group {}", group.name);
                        continue;
                    }
                    let interested_versions: HashSet<&'static str> = resources
                        .iter()
                        .filter(|r| r.selected_gv.is_none())
                        .flat_map(|r| {
                            r.group_versions.iter().filter_map(|gv| {
                                if gv.group == &group.name {
                                    Some(gv.version)
                                } else {
                                    None
                                }
                            })
                        })
                        .collect();
                    debug!(
                        "search for api in group {} versions {:?}",
                        group.name, interested_versions
                    );
                    for version in group.versions {
                        if !interested_versions.contains(&version.version as &str) {
                            debug!("skipped invalid version {}", version.version);
                            continue;
                        }
                        let mut api_resources = client
                            .list_api_group_resources(&version.group_version)
                            .await;
                        if api_resources.is_err() {
                            debug!(
                                "failed to get api resources from {}: {}",
                                version.group_version,
                                api_resources.unwrap_err()
                            );
                            // try one more time
                            api_resources = client
                                .list_api_group_resources(&version.group_version)
                                .await;
                            if api_resources.is_err() {
                                continue;
                            }
                        }
                        debug!("start to get api resources from {}", version.group_version);

                        for api_resource in api_resources.unwrap().resources {
                            let resource_name = api_resource.name;
                            let Some(index) = resources.iter().position(|r| {
                                &r.name == &resource_name
                                    && r.group_versions.iter().any(|gv| gv.group == &group.name)
                            }) else {
                                continue;
                            };
                            let Some(gv_index) =
                                resources[index].group_versions.iter().position(|gv| {
                                    gv.group == &group.name && gv.version == &version.version
                                })
                            else {
                                debug!(
                                    "skipped {} api in group {} with other version",
                                    resource_name, version.group_version
                                );
                                continue;
                            };
                            let resource = &mut resources[index];
                            let gv = &resource.group_versions[gv_index];
                            debug!(
                                "found {} api in group {}",
                                resource_name, version.group_version
                            );
                            if resource.selected_gv.is_none() {
                                resource.selected_gv = Some(*gv);
                            } else {
                                let selected = &resource.selected_gv.as_ref().unwrap();
                                if &gv != selected {
                                    // must exist
                                    let prev_index = resource
                                        .group_versions
                                        .iter()
                                        .position(|g| &g == selected)
                                        .unwrap();
                                    // prior
                                    if gv_index < prev_index {
                                        debug!("use more suitable {} api in {}", resource_name, gv);
                                        resource.selected_gv = Some(*gv);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(err) => {
                // 检查支持的api列表，如果查不到就用默认的
                let err_msg = format!("get server resources failed: {}, use defaults", err);
                warn!("{}", err_msg);
                err_msgs.lock().unwrap().push(err_msg);
            }
        }

        // check required resources
        for r in resources.iter_mut() {
            if r.selected_gv.is_none() {
                warn!("resource {} not found, use defaults", r.name);
                r.selected_gv = Some(r.group_versions[0]);
            }
        }

        for r in resources.iter() {
            info!(
                "will query resource {} from {}",
                r.name,
                r.selected_gv.unwrap()
            );
        }

        Ok(resources)
    }

    async fn set_up(
        resource_config: &Vec<KubernetesResourceConfig>,
        runtime: &Runtime,
        apiserver_version: &Arc<Mutex<Info>>,
        err_msgs: &Arc<Mutex<Vec<String>>>,
        namespace: Option<&str>,
        stats_collector: &stats::Collector,
        watcher_config: &WatcherConfig,
    ) -> Result<(
        HashMap<WatcherKey, GenericResourceWatcher>,
        Vec<JoinHandle<()>>,
    )> {
        let mut config = Config::infer().await.map_err(|e| {
            Error::KubernetesApiWatcher(format!("failed to infer kubernetes config: {}", e))
        })?;
        config.accept_invalid_certs = true;
        info!("api server url is: {}", config.cluster_url);
        let client = match Client::try_from(config) {
            Ok(c) => c,
            Err(e) => {
                let err_msg = format!("failed to create kubernetes client: {}", e);
                return Err(Error::KubernetesApiWatcher(err_msg));
            }
        };

        match client.apiserver_version().await {
            Ok(info) => {
                *apiserver_version.lock().unwrap() = info;
            }
            Err(err) => {
                let err_msg = format!("failed to get server version: {}", err);
                return Err(Error::KubernetesApiWatcher(err_msg));
            }
        }

        let resources = match Self::discover_resources(&client, resource_config, err_msgs).await {
            Ok(r) => r,
            Err(e) => {
                return Err(Error::KubernetesApiWatcher(e.to_string()));
            }
        };

        let (mut watchers, mut task_handles) = (HashMap::new(), vec![]);
        let watcher_factory = ResourceWatcherFactory::new(client.clone(), runtime.handle().clone());
        for r in resources {
            let key = WatcherKey {
                name: r.name,
                group: r.selected_gv.as_ref().unwrap().group,
            };
            if let Some(watcher) =
                watcher_factory.new_watcher(r, namespace, stats_collector, watcher_config)
            {
                watchers.insert(key, watcher);
            }
        }
        for watcher in watchers.values() {
            if let Some(handle) = watcher.start() {
                task_handles.push(handle);
            }
        }
        Ok((watchers, task_handles))
    }

    fn debug_k8s_request(request: &KubernetesApiSyncRequest, full_sync: bool) {
        let mut map = HashMap::new();
        for entry in request.entries.iter() {
            *map.entry(entry.r#type().to_string()).or_insert(0) += 1;
        }
        let resource_summary = map
            .into_iter()
            .map(|(k, v)| format!("resource: {} len: {}", k, v))
            .collect::<Vec<_>>();
        if full_sync {
            debug!("full sync: {:?}", resource_summary);
        } else {
            debug!("incremental sync {:?}", resource_summary);
        }
    }

    fn process(
        context: &Arc<Context>,
        apiserver_version: &Arc<Mutex<Info>>,
        session: &Arc<Session>,
        err_msgs: &Arc<Mutex<Vec<String>>>,
        watcher_versions: &mut HashMap<WatcherKey, u64>,
        resource_watchers: &Arc<Mutex<HashMap<WatcherKey, GenericResourceWatcher>>>,
        exception_handler: &ExceptionHandler,
        agent_id: &Arc<RwLock<AgentId>>,
        k8s_events_sender: &Arc<Mutex<Option<DebugSender<BoxedKubernetesEvent>>>>,
    ) {
        let version = &context.version;
        // 将缓存的entry 上报，如果没有则跳过
        let mut has_update = false;
        let mut updated_versions = vec![];
        {
            let mut err_msgs_guard = err_msgs.lock().unwrap();
            let resource_watchers_guard = resource_watchers.lock().unwrap();
            for (resource, watcher_version) in watcher_versions.iter_mut() {
                if let Some(watcher) = resource_watchers_guard.get(resource) {
                    if !watcher.ready() {
                        err_msgs_guard.push(format!("{} watcher is not ready", resource));
                        if let Some(msg) = watcher.error() {
                            err_msgs_guard.push(msg);
                        }
                        continue;
                    }

                    let new_version = watcher.version();
                    if new_version != *watcher_version {
                        updated_versions.push(format!(
                            "{}: v{} -> v{}",
                            resource, watcher_version, new_version
                        ));
                        *watcher_version = new_version;
                        has_update = true;
                    }

                    if let Some(msg) = watcher.error() {
                        err_msgs_guard.push(msg);
                    }
                }
            }
        }

        let mut total_entries = vec![];
        let mut pb_version = Some(version.load(Ordering::SeqCst));
        if has_update {
            version.fetch_add(1, Ordering::SeqCst);
            info!(
                "version updated to {} ({})",
                version.load(Ordering::SeqCst),
                updated_versions.join("; ")
            );
            pb_version = Some(version.load(Ordering::SeqCst));
            if let Some(i) =
                Self::parse_apiserver_version(apiserver_version.lock().unwrap().deref())
            {
                total_entries.push(i);
            }
            let resource_watchers_guard = resource_watchers.lock().unwrap();
            for watcher in resource_watchers_guard.values() {
                let kind = watcher.pb_name();
                if kind == "*v1.Events" {
                    let mut events = watcher.events();
                    if events.is_empty() {
                        continue;
                    }
                    let mut k8s_events_sender_guard = k8s_events_sender.lock().unwrap();
                    if let Some(s) = k8s_events_sender_guard.as_mut() {
                        if let Err(e) = s.send_all(&mut events) {
                            warn!("send k8s events failed: {:?}", e);
                        }
                    }
                    continue;
                }
                for entry in watcher.entries() {
                    total_entries.push(KubernetesApiInfo {
                        r#type: Some(kind.to_owned()),
                        compressed_info: Some(entry),
                        info: None,
                    });
                }
            }
        }
        let mut msg = {
            let config_guard = context.config.load();
            let id = agent_id.read();
            KubernetesApiSyncRequest {
                cluster_id: Some(config_guard.kubernetes_cluster_id.to_string()),
                version: pb_version,
                vtap_id: Some(config_guard.vtap_id as u32),
                source_ip: Some(id.ip.to_string()),
                team_id: Some(id.team_id.clone()),
                error_msg: Some(
                    err_msgs
                        .lock()
                        .unwrap()
                        .drain(..)
                        .collect::<Vec<_>>()
                        .as_slice()
                        .join(";"),
                ),
                entries: total_entries,
            }
        };

        if log_enabled!(Level::Debug) {
            Self::debug_k8s_request(&msg, false);
        }

        match context
            .runtime
            .block_on(session.grpc_kubernetes_api_sync_with_statsd(msg.clone()))
        {
            Ok(resp) => {
                if has_update {
                    // 已经发过全量了，不用管返回
                    // 等待下一次timeout
                    return;
                }
                let resp = resp.into_inner();
                if resp.version() == version.load(Ordering::SeqCst) {
                    // 接收端返回之前的version，如果相等，不需要全量同步
                    return;
                }
            }
            Err(e) => {
                let err = format!("kubernetes_api_sync grpc call failed: {}", e);
                exception_handler.set(Exception::ControllerSocketError);
                error!("{}", err);
                err_msgs.lock().unwrap().push(err);
                return;
            }
        }

        // 发送一次全量
        let mut total_entries = vec![];

        if let Some(i) = Self::parse_apiserver_version(apiserver_version.lock().unwrap().deref()) {
            total_entries.push(i);
        }
        let resource_watchers_guard = resource_watchers.lock().unwrap();
        for watcher in resource_watchers_guard.values() {
            let kind = watcher.pb_name();
            for entry in watcher.entries() {
                total_entries.push(KubernetesApiInfo {
                    r#type: Some(kind.to_owned()),
                    compressed_info: Some(entry),
                    info: None,
                });
            }
        }
        drop(resource_watchers_guard);

        msg.entries = total_entries;

        if log_enabled!(Level::Debug) {
            Self::debug_k8s_request(&msg, true);
        }

        if let Err(e) = context
            .runtime
            .block_on(session.grpc_kubernetes_api_sync_with_statsd(msg))
        {
            let err = format!("kubernetes_api_sync grpc call failed: {}", e);
            exception_handler.set(Exception::ControllerSocketError);
            error!("{}", err);
            err_msgs.lock().unwrap().push(err);
        }
    }

    fn parse_apiserver_version(info: &Info) -> Option<KubernetesApiInfo> {
        serde_json::to_vec(info).ok().map(|info| KubernetesApiInfo {
            //FIXME：没找到好方法拿到 Info 的 type,先写死
            r#type: Some(PB_VERSION_INFO.to_string()),
            compressed_info: {
                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(info.as_slice()).unwrap();
                encoder.reset(vec![]).ok()
            },
            info: None,
        })
    }

    fn run(
        context: Arc<Context>,
        session: Arc<Session>,
        timer: Arc<Condvar>,
        running: Arc<Mutex<bool>>,
        apiserver_version: Arc<Mutex<Info>>,
        err_msgs: Arc<Mutex<Vec<String>>>,
        watchers: Arc<Mutex<HashMap<WatcherKey, GenericResourceWatcher>>>,
        exception_handler: ExceptionHandler,
        stats_collector: Arc<stats::Collector>,
        agent_id: Arc<RwLock<AgentId>>,
        k8s_events_sender: Arc<Mutex<Option<DebugSender<BoxedKubernetesEvent>>>>,
    ) {
        info!("kubernetes api watcher starting");

        let config = context.config.load();

        let namespace = config.namespace.clone();
        let ns = namespace.as_ref().map(|ns| ns.as_str());
        let watcher_config = WatcherConfig {
            list_limit: config.kubernetes_api_list_limit,
            list_interval: config.kubernetes_api_list_interval,
            max_memory: config.max_memory,
        };

        let (resource_watchers, task_handles) = loop {
            match context.runtime.block_on(Self::set_up(
                &context.config.load().kubernetes_resources,
                &context.runtime,
                &apiserver_version,
                &err_msgs,
                ns,
                &stats_collector,
                &watcher_config,
            )) {
                Ok(r) => break r,
                Err(e) => {
                    warn!("{}", e);
                    let msg = {
                        let config_guard = context.config.load();
                        let id = agent_id.read();
                        KubernetesApiSyncRequest {
                            cluster_id: Some(config_guard.kubernetes_cluster_id.to_string()),
                            version: Some(context.version.load(Ordering::SeqCst)),
                            vtap_id: Some(config_guard.vtap_id as u32),
                            source_ip: Some(id.ip.to_string()),
                            team_id: Some(id.team_id.clone()),
                            error_msg: Some(e.to_string()),
                            entries: vec![],
                        }
                    };
                    if let Err(e) = context
                        .runtime
                        .block_on(session.grpc_kubernetes_api_sync_with_statsd(msg))
                    {
                        debug!("kubernetes_api_sync grpc call failed: {}", e);
                    }
                }
            }

            // 等待下一次timeout
            if Self::ready_stop(&running, &timer, context.config.load().sync_interval) {
                info!("kubernetes api watcher stopping");
                // tear down
                *watchers.lock().unwrap() = HashMap::new();
                return;
            }
        };
        info!("kubernetes api watcher running");

        let mut watcher_versions = HashMap::new();
        for resource in resource_watchers.keys() {
            watcher_versions.insert(resource.clone(), 0);
        }

        *watchers.lock().unwrap() = resource_watchers;
        let resource_watchers = watchers.clone();

        let sync_interval = context.config.load().sync_interval;

        // send info as soon as node first queried
        const INIT_WAIT_INTERVAL: Duration = Duration::from_secs(5);
        let mut wait_count = 0;
        while !Self::ready_stop(&running, &timer, INIT_WAIT_INTERVAL) {
            let ws = resource_watchers.lock().unwrap();
            let ready = ws.iter().all(|(n, v)| {
                let r = v.ready();
                if !r {
                    debug!("{} watcher is not ready yet", n);
                }
                r
            });
            if !ready {
                wait_count += 1;
                if wait_count >= sync_interval.as_secs() / INIT_WAIT_INTERVAL.as_secs() {
                    break;
                }
                continue;
            }
            mem::drop(ws);
            Self::process(
                &context,
                &apiserver_version,
                &session,
                &err_msgs,
                &mut watcher_versions,
                &resource_watchers,
                &exception_handler,
                &agent_id,
                &k8s_events_sender,
            );
            break;
        }

        // 等一等watcher，第一个tick再上报
        while !Self::ready_stop(&running, &timer, sync_interval) {
            Self::process(
                &context,
                &apiserver_version,
                &session,
                &err_msgs,
                &mut watcher_versions,
                &resource_watchers,
                &exception_handler,
                &agent_id,
                &k8s_events_sender,
            );
        }
        info!("kubernetes api watcher stopping");
        // 终止要监看的resource watcher 协程
        for handle in task_handles {
            handle.abort();
        }
        // tear down
        *watchers.lock().unwrap() = HashMap::new();
    }

    fn ready_stop(running: &Arc<Mutex<bool>>, timer: &Arc<Condvar>, interval: Duration) -> bool {
        let guard = running.lock().unwrap();
        if !*guard {
            return true;
        }
        let (guard, _) = timer.wait_timeout(guard, interval).unwrap();
        if !*guard {
            return true;
        }
        false
    }
}
