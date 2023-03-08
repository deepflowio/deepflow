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

use std::{
    collections::HashMap,
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
use tokio::{runtime::Runtime, task::JoinHandle};

use super::resource_watcher::{GenericResourceWatcher, Watcher, WatcherConfig};
use crate::{
    config::{handler::PlatformAccess, IngressFlavour},
    error::{Error, Result},
    exception::ExceptionHandler,
    platform::kubernetes::resource_watcher::ResourceWatcherFactory,
    rpc::Session,
    utils::{
        environment::{running_in_container, running_in_only_watch_k8s_mode},
        stats,
    },
};
use public::proto::{
    common::KubernetesApiInfo,
    trident::{Exception, KubernetesApiSyncRequest},
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

const RESOURCES: [&str; 10] = [
    "nodes",
    "namespaces",
    "services",
    "deployments",
    "pods",
    "statefulsets",
    "daemonsets",
    "replicationcontrollers",
    "replicasets",
    "ingresses",
];

/*
    PB_RESOURCES 和 PB_INGRESS 用于打包发送k8s信息填写的资源类型，控制器根据类型作为key进行存储, 因为Route/Ingress 可以用Ingress一起表示，
    所以所有Ingress统一用*v1.Ingress。go里可以通过类型反射获取，然后控制器约定为key，rust还没好的方法获取，所以先手动填写，以后更新
*/
const PB_RESOURCES: [&str; 10] = [
    "*v1.Node",
    "*v1.Namespace",
    "*v1.Service",
    "*v1.Deployment",
    "*v1.Pod",
    "*v1.StatefulSet",
    "*v1.DaemonSet",
    "*v1.ReplicationController",
    "*v1.ReplicaSet",
    "*v1.Ingress",
];
const PB_INGRESS: &str = "*v1.Ingress";
const PB_VERSION_INFO: &str = "*version.Info";

struct Context {
    config: PlatformAccess,
    runtime: Arc<Runtime>,
    version: AtomicU64,
}

pub struct ApiWatcher {
    context: Arc<Context>,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
    running: Arc<Mutex<bool>>,
    timer: Arc<Condvar>,
    watchers: Arc<Mutex<HashMap<String, GenericResourceWatcher>>>,
    err_msgs: Arc<Mutex<Vec<String>>>,
    apiserver_version: Arc<Mutex<Info>>,
    session: Arc<Session>,
    exception_handler: ExceptionHandler,
    stats_collector: Arc<stats::Collector>,
}

impl ApiWatcher {
    pub fn new(
        runtime: Arc<Runtime>,
        config: PlatformAccess,
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
            apiserver_version: Arc::new(Mutex::new(Info::default())),
            err_msgs: Arc::new(Mutex::new(vec![])),
            watchers: Arc::new(Mutex::new(HashMap::new())),
            exception_handler,
            stats_collector,
        }
    }

    // 直接拿对应的entries
    pub fn get_watcher_entries(&self, resource_name: impl AsRef<str>) -> Option<Vec<Vec<u8>>> {
        if !*self.running.lock().unwrap() {
            debug!("ApiWatcher isn't running");
            return None;
        }

        self.watchers
            .lock()
            .unwrap()
            .get(resource_name.as_ref())
            .map(|watcher| watcher.entries())
    }

    pub fn get_server_version(&self) -> Option<String> {
        let info = self.apiserver_version.lock().unwrap();
        serde_json::to_string(info.deref()).ok()
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
        let apiserver_version = self.apiserver_version.clone();
        let err_msgs = self.err_msgs.clone();
        let watchers = self.watchers.clone();
        let exception_handler = self.exception_handler.clone();
        let stats_collector = self.stats_collector.clone();

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
                )
            })
            .unwrap();
        self.thread.lock().unwrap().replace(handle);
    }

    async fn set_up(
        is_openshift_route: bool,
        runtime: &Runtime,
        apiserver_version: &Arc<Mutex<Info>>,
        err_msgs: &Arc<Mutex<Vec<String>>>,
        namespace: Option<&str>,
        stats_collector: &stats::Collector,
        watcher_config: &WatcherConfig,
    ) -> Result<(HashMap<String, GenericResourceWatcher>, Vec<JoinHandle<()>>)> {
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

        let api_version = client
            .list_core_api_versions()
            .await
            .map_err(|e| Error::KubernetesApiWatcher(format!("{}", e)))?;

        let (mut watchers, mut task_handles) = (HashMap::new(), vec![]);
        let watcher_factory = ResourceWatcherFactory::new(client.clone(), runtime.handle().clone());
        let mut ingress_groups = vec![];
        for version in api_version.versions {
            let core_resources = client
                .list_core_api_resources(&version)
                .await
                .map_err(|e| Error::KubernetesApiWatcher(format!("{}", e)))?;
            debug!("start to get api resources from {}", version);
            for api_resource in core_resources.resources {
                let resource_name = api_resource.name;
                if !RESOURCES.iter().any(|&r| r == resource_name) {
                    continue;
                }
                info!(
                    "found {} api in group core/{}",
                    resource_name.as_str(),
                    version
                );
                if resource_name != RESOURCES[RESOURCES.len() - 1] {
                    let index = RESOURCES.iter().position(|&r| r == resource_name).unwrap();
                    if let Some(watcher) = watcher_factory.new_watcher(
                        RESOURCES[index],
                        PB_RESOURCES[index],
                        namespace,
                        stats_collector,
                        watcher_config,
                    ) {
                        watchers.insert(resource_name, watcher);
                    }
                }
            }
        }

        match client.list_api_groups().await {
            Ok(api_groups) => {
                for group in api_groups.groups {
                    let version = match group
                        .preferred_version
                        .as_ref()
                        .or_else(|| group.versions.first())
                    {
                        Some(v) => v,
                        None => {
                            continue;
                        }
                    };
                    let mut api_resources = client
                        .list_api_group_resources(version.group_version.as_str())
                        .await;
                    if api_resources.is_err() {
                        debug!(
                            "failed to get api resources from {}: {}",
                            version.group_version.as_str(),
                            api_resources.unwrap_err()
                        );
                        // try one more time
                        api_resources = client
                            .list_api_group_resources(version.group_version.as_str())
                            .await;
                        if api_resources.is_err() {
                            continue;
                        }
                    }
                    debug!(
                        "start to get api resources from {}",
                        version.group_version.as_str()
                    );

                    for api_resource in api_resources.unwrap().resources {
                        let resource_name = api_resource.name;
                        if watchers.contains_key(&resource_name) {
                            debug!(
                                "found another {} api in group {}, skipped",
                                resource_name.as_str(),
                                version.group_version.as_str()
                            );
                            continue;
                        }

                        let Some(index) = RESOURCES.iter().position(|&r| r == resource_name) else {
                            continue;
                        };
                        info!(
                            "found {} api in group {}",
                            resource_name.as_str(),
                            version.group_version.as_str()
                        );

                        if resource_name == "ingresses" {
                            ingress_groups.push(version.group_version.clone());
                        } else if let Some(watcher) = watcher_factory.new_watcher(
                            RESOURCES[index],
                            PB_RESOURCES[index],
                            namespace,
                            stats_collector,
                            watcher_config,
                        ) {
                            watchers.insert(resource_name, watcher);
                        }
                    }
                }
                let ingress_watcher = if is_openshift_route {
                    watcher_factory.new_watcher(
                        "routes",
                        PB_INGRESS,
                        namespace,
                        stats_collector,
                        watcher_config,
                    )
                } else if ingress_groups
                    .iter()
                    .any(|g| g.as_str() == "networking.k8s.io/v1")
                {
                    watcher_factory.new_watcher(
                        "v1ingresses",
                        PB_INGRESS,
                        namespace,
                        stats_collector,
                        watcher_config,
                    )
                } else if ingress_groups
                    .iter()
                    .any(|g| g.as_str() == "networking.k8s.io/v1beta1")
                {
                    watcher_factory.new_watcher(
                        "v1beta1ingresses",
                        PB_INGRESS,
                        namespace,
                        stats_collector,
                        watcher_config,
                    )
                } else if ingress_groups
                    .iter()
                    .any(|g| g.as_str() == "extensions/v1beta1")
                {
                    watcher_factory.new_watcher(
                        "extv1beta1ingresses",
                        PB_INGRESS,
                        namespace,
                        stats_collector,
                        watcher_config,
                    )
                } else {
                    None
                };
                if let Some(watcher) = ingress_watcher {
                    // ingresses 排最后
                    watchers.insert(String::from(RESOURCES[RESOURCES.len() - 1]), watcher);
                }

                {
                    let mut err_msgs_lock = err_msgs.lock().unwrap();
                    for &resource in RESOURCES[..RESOURCES.len() - 1].iter() {
                        if !watchers.contains_key(resource) {
                            let err_msg = format!("resource {} api not available", resource);
                            warn!("{}", err_msg);
                            err_msgs_lock.push(err_msg);
                        }
                    }
                    if !watchers.contains_key(RESOURCES[RESOURCES.len() - 1]) {
                        let err_msg = if is_openshift_route {
                            String::from("resource routes api not available")
                        } else {
                            format!(
                                "resource {} api not available",
                                RESOURCES[RESOURCES.len() - 1]
                            )
                        };
                        warn!("{}", err_msg);
                        err_msgs_lock.push(err_msg);
                    }
                }

                for watcher in watchers.values() {
                    if let Some(handle) = watcher.start() {
                        task_handles.push(handle);
                    }
                }

                Ok((watchers, task_handles))
            }
            Err(err) => {
                // 检查支持的api列表，如果查不到就用默认的
                let err_msg = format!("get server resources failed: {}, use defaults", err);
                warn!("{}", err_msg);
                err_msgs.lock().unwrap().push(err_msg);

                for (index, &resource) in RESOURCES.iter().enumerate() {
                    if watchers.contains_key(resource) {
                        continue;
                    }
                    if let Some(watcher) = watcher_factory.new_watcher(
                        resource,
                        PB_RESOURCES[index],
                        namespace,
                        stats_collector,
                        watcher_config,
                    ) {
                        if let Some(handle) = watcher.start() {
                            task_handles.push(handle);
                        }
                        watchers.insert(String::from(resource), watcher);
                    }
                }

                let ingress_watcher = if is_openshift_route {
                    watcher_factory.new_watcher(
                        "routes",
                        PB_INGRESS,
                        namespace,
                        stats_collector,
                        watcher_config,
                    )
                } else {
                    watcher_factory.new_watcher(
                        "v1ingresses",
                        PB_INGRESS,
                        namespace,
                        stats_collector,
                        watcher_config,
                    )
                };

                if let Some(watcher) = ingress_watcher {
                    if let Some(handle) = watcher.start() {
                        task_handles.push(handle);
                    }
                    watchers.insert(String::from("ingresses"), watcher);
                }

                Ok((watchers, task_handles))
            }
        }
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
        watcher_versions: &mut HashMap<String, u64>,
        resource_watchers: &Arc<Mutex<HashMap<String, GenericResourceWatcher>>>,
        exception_handler: &ExceptionHandler,
    ) {
        let version = &context.version;
        // 将缓存的entry 上报，如果没有则跳过
        let mut has_update = false;
        {
            let mut err_msgs_guard = err_msgs.lock().unwrap();
            let resource_watchers_guard = resource_watchers.lock().unwrap();
            for (resource, watcher_version) in watcher_versions.iter_mut() {
                if let Some(watcher) = resource_watchers_guard.get(resource) {
                    let new_version = watcher.version();
                    if new_version != *watcher_version {
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
            info!("version updated to {}", version.load(Ordering::SeqCst));
            pb_version = Some(version.load(Ordering::SeqCst));
            if let Some(i) =
                Self::parse_apiserver_version(apiserver_version.lock().unwrap().deref())
            {
                total_entries.push(i);
            }
            let resource_watchers_guard = resource_watchers.lock().unwrap();
            for watcher in resource_watchers_guard.values() {
                let kind = watcher.kind();
                for entry in watcher.entries() {
                    total_entries.push(KubernetesApiInfo {
                        r#type: Some(kind.clone()),
                        compressed_info: Some(entry),
                        info: None,
                    });
                }
            }
        }
        let mut msg = {
            let config_guard = context.config.load();
            KubernetesApiSyncRequest {
                cluster_id: Some(config_guard.kubernetes_cluster_id.to_string()),
                version: pb_version,
                vtap_id: Some(config_guard.vtap_id as u32),
                source_ip: Some(config_guard.source_ip.to_string()),
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
            let kind = watcher.kind();
            for entry in watcher.entries() {
                total_entries.push(KubernetesApiInfo {
                    r#type: Some(kind.clone()),
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
        watchers: Arc<Mutex<HashMap<String, GenericResourceWatcher>>>,
        exception_handler: ExceptionHandler,
        stats_collector: Arc<stats::Collector>,
    ) {
        info!("kubernetes api watcher starting");

        let config = context.config.load();

        let namespace = config.namespace.clone();
        let ns = namespace.as_ref().map(|ns| ns.as_str());
        let watcher_config = WatcherConfig {
            list_limit: config.kubernetes_api_list_limit,
            list_interval: config.kubernetes_api_list_interval,
        };

        let (resource_watchers, task_handles) = loop {
            match context.runtime.block_on(Self::set_up(
                context.config.load().ingress_flavour == IngressFlavour::Openshift,
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
                    let config_guard = context.config.load();
                    let msg = KubernetesApiSyncRequest {
                        cluster_id: Some(config_guard.kubernetes_cluster_id.to_string()),
                        version: Some(context.version.load(Ordering::SeqCst)),
                        vtap_id: Some(config_guard.vtap_id as u32),
                        source_ip: Some(config_guard.source_ip.to_string()),
                        error_msg: Some(e.to_string()),
                        entries: vec![],
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
            if !ws.get("nodes").map(|w| w.ready()).unwrap_or(false) {
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
