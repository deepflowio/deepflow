use std::{
    collections::HashMap,
    net::IpAddr,
    ops::Deref,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
    thread,
    time::Duration,
};

use k8s_openapi::apimachinery::pkg::version::Info;
use kube::Client;
use log::{debug, info, warn};
use tokio::{runtime::Handle, task::JoinHandle};

use super::resource_watcher::{GenericResourceWatcher, Watcher};
use crate::{
    error::{Error, Result},
    platform::kubernetes::resource_watcher::ResourceWatcherFactory,
    proto::trident::{
        self, KubernetesApiInfo, KubernetesApiSyncRequest, KubernetesApiSyncResponse,
    },
    rpc::Session,
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

struct Context {
    runtime: Handle,
    is_openshift_route: bool,
    interval: Duration,
    vtap_id: AtomicU32,
    version: AtomicU64,
    cluster_id: String,
    ctrl_ip: IpAddr,
}

struct ApiWatcher {
    context: Arc<Context>,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
    running: Arc<Mutex<bool>>,
    timer: Arc<Condvar>,
    watchers: Arc<Mutex<HashMap<String, GenericResourceWatcher>>>,
    err_msgs: Arc<Mutex<Vec<String>>>,
    apiserver_version: Arc<Mutex<Info>>,
    session: Arc<Session>,
}

impl ApiWatcher {
    pub fn new(
        ctrl_ip: IpAddr,
        cluster_id: String,
        is_openshift_route: bool,
        interval: Duration,
        runtime: Handle,
        session: Arc<Session>,
    ) -> Self {
        Self {
            context: Arc::new(Context {
                ctrl_ip,
                cluster_id,
                is_openshift_route,
                vtap_id: AtomicU32::new(0),
                interval,
                version: AtomicU64::new(0),
                runtime,
            }),
            thread: Mutex::new(None),
            session,
            timer: Arc::new(Condvar::new()),
            running: Arc::new(Mutex::new(false)),
            apiserver_version: Arc::new(Mutex::new(Info::default())),
            err_msgs: Arc::new(Mutex::new(vec![])),
            watchers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn set_vtap_id(&self, vtap_id: u32) {
        self.context.vtap_id.store(vtap_id, Ordering::SeqCst);
    }

    // 直接拿对应的entries
    pub fn get_watcher_entries(&self, resource_name: &str) -> Option<Vec<String>> {
        if !*self.running.lock().unwrap() {
            debug!("ApiWatcher isn't running");
            return None;
        }

        self.watchers
            .lock()
            .unwrap()
            .get(resource_name)
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
        if self.context.cluster_id.is_empty() {
            info!("ApiWatcher failed to start because kubernetes-cluster-id is empty");
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

        let handle = thread::spawn(move || {
            Self::run(
                context,
                session,
                timer,
                running,
                apiserver_version,
                err_msgs,
                watchers,
            )
        });
        self.thread.lock().unwrap().replace(handle);
    }

    async fn set_up(
        is_openshift_route: bool,
        runtime: &Handle,
        apiserver_version: &Arc<Mutex<Info>>,
        err_msgs: &Arc<Mutex<Vec<String>>>,
    ) -> Result<(HashMap<String, GenericResourceWatcher>, Vec<JoinHandle<()>>)> {
        let client = match Client::try_default().await {
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

        match client.list_api_groups().await {
            Ok(api_groups) => {
                let mut watchers = HashMap::new();
                let mut ingress_groups = vec![];

                let watcher_factory = ResourceWatcherFactory::new(client.clone(), runtime.clone());

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
                        if !RESOURCES.iter().any(|&r| r == resource_name) {
                            continue;
                        }
                        if version.group_version.as_str().contains('/') {
                            info!(
                                "found {} api in group {}",
                                resource_name.as_str(),
                                version.group_version.as_str()
                            );
                        } else {
                            info!(
                                "found {} api in group core/{}",
                                resource_name.as_str(),
                                version.group_version.as_str()
                            );
                        }
                        if resource_name != RESOURCES[RESOURCES.len() - 1] {
                            let index = RESOURCES.iter().position(|&r| r == resource_name).unwrap();
                            if let Some(watcher) = watcher_factory.new_watcher(RESOURCES[index]) {
                                watchers.insert(resource_name, watcher);
                            }
                            continue;
                        }
                        ingress_groups.push(version.group_version.clone());
                    }
                }
                let ingress_watcher = if is_openshift_route {
                    watcher_factory.new_watcher("routes")
                } else if ingress_groups
                    .iter()
                    .any(|g| g.as_str() == "networking.k8s.io/v1")
                {
                    watcher_factory.new_watcher("v1ingresses")
                } else if ingress_groups
                    .iter()
                    .any(|g| g.as_str() == "networking.k8s.io/v1beta1")
                {
                    watcher_factory.new_watcher("v1beta1ingresses")
                } else if ingress_groups
                    .iter()
                    .any(|g| g.as_str() == "extensions/v1beta1")
                {
                    watcher_factory.new_watcher("extv1beta1ingresses")
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

                let mut task_handles = vec![];
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

                let (mut watchers, mut task_handles) = (HashMap::new(), vec![]);
                let watcher_factory = ResourceWatcherFactory::new(client.clone(), runtime.clone());
                for resource in RESOURCES {
                    if let Some(watcher) = watcher_factory.new_watcher(resource) {
                        if let Some(handle) = watcher.start() {
                            task_handles.push(handle);
                        }
                        watchers.insert(String::from(resource), watcher);
                    }
                }

                let ingress_watcher = if is_openshift_route {
                    watcher_factory.new_watcher("routes")
                } else {
                    watcher_factory.new_watcher("v1ingresses")
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

    fn process(
        context: &Arc<Context>,
        apiserver_version: &Arc<Mutex<Info>>,
        ctrl_ip: &IpAddr,
        session: &Arc<Session>,
        version: &AtomicU64,
        err_msgs: &Arc<Mutex<Vec<String>>>,
        cluster_id: &str,
        vtap_id: &AtomicU32,
        watcher_versions: &mut HashMap<String, u64>,
        resource_watchers: &Arc<Mutex<HashMap<String, GenericResourceWatcher>>>,
    ) {
        // 将缓存的entry 上报，如果没有则跳过
        let mut has_update = false;
        {
            let mut err_msgs_guard = err_msgs.lock().unwrap();
            let resource_watchers_guard = resource_watchers.lock().unwrap();
            for (resource, version) in watcher_versions.iter_mut() {
                if let Some(watcher) = resource_watchers_guard.get(resource) {
                    let new_version = watcher.version();
                    if new_version != *version {
                        *version = new_version;
                        has_update = true;
                    }

                    if let Some(msg) = watcher.error() {
                        err_msgs_guard.push(msg);
                    }
                }
            }
        }

        let mut total_entries = vec![];
        let mut pb_version = None;
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
                total_entries.append(&mut watcher.pb_entries());
            }
        }
        let mut msg = KubernetesApiSyncRequest {
            cluster_id: Some(cluster_id.to_string()),
            version: pb_version,
            vtap_id: Some(vtap_id.load(Ordering::SeqCst)),
            source_ip: Some(ctrl_ip.to_string()),
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
        };

        match context
            .runtime
            .block_on(Self::kubernetes_api_sync(session, msg.clone()))
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
                let err = format!("KubernetesAPISync failed: {}", e);
                warn!("{}", err);
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
            total_entries.append(&mut watcher.pb_entries());
        }
        drop(resource_watchers_guard);

        msg.entries = total_entries;

        if let Err(e) = context
            .runtime
            .block_on(Self::kubernetes_api_sync(session, msg))
        {
            let err = format!("KubernetesAPISync failed: {}", e);
            warn!("{}", err);
            err_msgs.lock().unwrap().push(err);
        }
    }

    async fn kubernetes_api_sync(
        session: &Arc<Session>,
        req: KubernetesApiSyncRequest,
    ) -> Result<tonic::Response<KubernetesApiSyncResponse>, tonic::Status> {
        session.update_current_server().await;
        let client = session
            .get_client()
            .ok_or(tonic::Status::not_found("rpc client not connected"))?;

        let mut client = trident::synchronizer_client::SynchronizerClient::new(client);
        client.kubernetes_api_sync(req).await
    }

    fn parse_apiserver_version(info: &Info) -> Option<KubernetesApiInfo> {
        serde_json::to_string(info)
            .ok()
            .map(|info| KubernetesApiInfo {
                //FIXME：没找到好方法拿到 Info 的 type,先写死
                r#type: Some("Info".to_string()),
                compressed_info: Some(info.into_bytes()),
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
    ) {
        info!("kubernetes api watcher starting");

        let (resource_watchers, task_handles) = loop {
            match context.runtime.block_on(Self::set_up(
                context.is_openshift_route,
                &context.runtime,
                &apiserver_version,
                &err_msgs,
            )) {
                Ok(r) => break r,
                Err(e) => {
                    warn!("{}", e);
                    let msg = KubernetesApiSyncRequest {
                        cluster_id: Some(context.cluster_id.to_string()),
                        version: Some(context.version.load(Ordering::SeqCst)),
                        vtap_id: Some(context.vtap_id.load(Ordering::SeqCst)),
                        source_ip: Some(context.ctrl_ip.to_string()),
                        error_msg: Some(e.to_string()),
                        entries: vec![],
                    };
                    if let Err(e) = context
                        .runtime
                        .block_on(Self::kubernetes_api_sync(&session, msg))
                    {
                        debug!("report error: {}", e);
                    }
                }
            }

            // 等待下一次timeout
            if Self::wait_timeout(&running, &timer, context.interval) {
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

        // 等一等watcher，第一个tick再上报
        while Self::wait_timeout(&running, &timer, context.interval) {
            Self::process(
                &context,
                &apiserver_version,
                &context.ctrl_ip,
                &session,
                &context.version,
                &err_msgs,
                context.cluster_id.as_str(),
                &context.vtap_id,
                &mut watcher_versions,
                &resource_watchers,
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

    fn wait_timeout(running: &Arc<Mutex<bool>>, timer: &Arc<Condvar>, interval: Duration) -> bool {
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
