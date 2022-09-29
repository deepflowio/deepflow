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
    fmt::Debug,
    io::{self, Write},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime},
};

use enum_dispatch::enum_dispatch;
use flate2::{write::ZlibEncoder, Compression};
use futures::{StreamExt, TryStreamExt};
use k8s_openapi::{
    api::{
        apps::v1::{
            DaemonSet, DaemonSetSpec, Deployment, DeploymentSpec, ReplicaSet, ReplicaSetSpec,
            StatefulSet, StatefulSetSpec,
        },
        core::v1::{
            Namespace, Node, NodeSpec, NodeStatus, Pod, PodStatus, ReplicationController,
            ReplicationControllerSpec, Service, ServiceSpec,
        },
        extensions, networking,
    },
    apimachinery::pkg::apis::meta::v1::ObjectMeta,
    Metadata,
};
use kube::{
    api::ListParams,
    runtime::{self, watcher::Event},
    Api, Client, Resource,
};
use log::{debug, info, warn};
use openshift_openapi::api::route::v1::Route;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use tokio::{runtime::Handle, sync::Mutex, task::JoinHandle, time};

const LIST_INTERVAL: Duration = Duration::from_secs(600);
const REFRESH_INTERVAL: Duration = Duration::from_secs(3600);
const MAX_EVENT_COUNT: u16 = 1024;

#[derive(Default)]
struct EventCounter {
    applied: u16,
    deleted: u16,
    restarted: u16,
}

#[enum_dispatch]
pub trait Watcher {
    fn start(&self) -> Option<JoinHandle<()>>;
    fn error(&self) -> Option<String>;
    fn entries(&self) -> Vec<Vec<u8>>;
    fn kind(&self) -> String;
    fn version(&self) -> u64;
}

#[enum_dispatch(Watcher)]
#[derive(Clone)]
pub enum GenericResourceWatcher {
    Node(ResourceWatcher<Node>),
    Namespace(ResourceWatcher<Namespace>),
    Service(ResourceWatcher<Service>),
    Deployment(ResourceWatcher<Deployment>),
    Pod(ResourceWatcher<Pod>),
    StatefulSet(ResourceWatcher<StatefulSet>),
    DaemonSet(ResourceWatcher<DaemonSet>),
    ReplicationController(ResourceWatcher<ReplicationController>),
    ReplicaSet(ResourceWatcher<ReplicaSet>),
    V1Ingress(ResourceWatcher<networking::v1::Ingress>),
    V1beta1Ingress(ResourceWatcher<networking::v1beta1::Ingress>),
    ExtV1beta1Ingress(ResourceWatcher<extensions::v1beta1::Ingress>),
    Route(ResourceWatcher<Route>),
}

// 发生错误，需要重新构造实例
#[derive(Clone)]
pub struct ResourceWatcher<K> {
    api: Api<K>,
    entries: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    err_msg: Arc<Mutex<Option<String>>>,
    kind: &'static str,
    version: Arc<AtomicU64>,
    runtime: Handle,
}

impl<K> Watcher for ResourceWatcher<K>
where
    K: Clone + Debug + DeserializeOwned + Resource + Serialize + Trimmable,
    K: Metadata<Ty = ObjectMeta>,
{
    fn start(&self) -> Option<JoinHandle<()>> {
        let entries = self.entries.clone();
        let version = self.version.clone();
        let kind = self.kind;
        let err_msg = self.err_msg.clone();

        let api = self.api.clone();

        let handle = self
            .runtime
            .spawn(Self::process(entries, version, api, kind, err_msg));

        info!("{} watcher started", self.kind);
        Some(handle)
    }

    fn version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }

    fn error(&self) -> Option<String> {
        self.err_msg.blocking_lock().take()
    }

    fn kind(&self) -> String {
        self.kind.to_string()
    }

    fn entries(&self) -> Vec<Vec<u8>> {
        self.entries
            .blocking_lock()
            .values()
            .map(Clone::clone)
            .collect::<Vec<_>>()
    }
}

impl<K> ResourceWatcher<K>
where
    K: Clone + Debug + DeserializeOwned + Resource + Serialize + Trimmable,
    K: Metadata<Ty = ObjectMeta>,
{
    pub fn new(api: Api<K>, kind: &'static str, runtime: Handle) -> Self {
        Self {
            api,
            entries: Arc::new(Mutex::new(HashMap::new())),
            version: Arc::new(AtomicU64::new(0)),
            kind,
            err_msg: Arc::new(Mutex::new(None)),
            runtime,
        }
    }

    async fn process(
        entries: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        version: Arc<AtomicU64>,
        api: Api<K>,
        kind: &'static str,
        err_msg: Arc<Mutex<Option<String>>>,
    ) {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        Self::get_list_entry(&mut encoder, &entries, &version, kind, &api, &err_msg).await;

        let mut ticker = time::interval(LIST_INTERVAL);

        let mut stream = runtime::watcher(api.clone(), ListParams::default()).boxed();

        let mut last_update = SystemTime::now();
        let mut last_refresh = SystemTime::now();

        let mut event_counter = EventCounter::default();

        loop {
            // 当 `select!` 执行的时候， 多个通道有待处理的消息，只有一个通道有一个值弹出。所有其他通道保持不变，
            // 它们的消息保留在这些通道中，直到下一次循环迭代。没有消息丢失。
            // select 和 tokio::spawn 一起用的话，因为tokio runtime 调度 spawn 的task 可能与select 调度是
            // 同时运行在不同操作系统线程select 用于在单个task下多路复用 async futures
            tokio::select! {
                maybe_event = stream.try_next() => {
                    Self::resolve_event(
                        &mut encoder,
                        maybe_event,
                        &mut last_update,
                        &entries,
                        &version,
                        kind,
                        &err_msg,
                        &mut event_counter
                    ).await;
                }
                _ = ticker.tick() => {
                    if last_update.elapsed().unwrap() < LIST_INTERVAL
                        && last_refresh.elapsed().unwrap() < REFRESH_INTERVAL
                    {
                        continue;
                    }

                    last_update = SystemTime::now();
                    last_refresh = SystemTime::now();
                    Self::get_list_entry(&mut encoder, &entries, &version, kind, &api, &err_msg).await;
                }
            }
        }
    }

    async fn get_list_entry(
        encoder: &mut ZlibEncoder<Vec<u8>>,
        entries: &Arc<Mutex<HashMap<String, Vec<u8>>>>,
        version: &Arc<AtomicU64>,
        kind: &str,
        api: &Api<K>,
        err_msg: &Arc<Mutex<Option<String>>>,
    ) {
        match api.list(&ListParams::default()).await {
            Ok(object_list) => {
                info!(
                    "k8s {} watcher list entry.len={}",
                    kind,
                    object_list.items.len()
                );
                // 检查内存和List API查询结果是否一致
                {
                    let entries_lock = entries.lock().await;
                    if object_list.items.len() == entries_lock.len() {
                        let mut identical = true;
                        for object in object_list.items.iter() {
                            match object.meta().uid.as_ref() {
                                Some(uid) if entries_lock.contains_key(uid) => (),
                                _ => {
                                    identical = false;
                                    break;
                                }
                            }
                        }
                        if identical {
                            return;
                        }
                    }
                }

                debug!("reload {} data", kind);

                let mut new_entries = HashMap::new();

                for object in object_list {
                    if object.meta().uid.as_ref().is_none() {
                        continue;
                    }
                    let mut trim_object = object.trim();
                    match serde_json::to_vec(&trim_object) {
                        Ok(serialized_object) => {
                            let compressed_object =
                                match Self::compress_entry(encoder, serialized_object.as_slice()) {
                                    Ok(c) => c,
                                    Err(e) => {
                                        warn!(
                                        "failed to compress {} resource with UID({}) error: {} ",
                                        kind,
                                        trim_object.meta().uid.as_ref().unwrap(),
                                        e
                                    );
                                        continue;
                                    }
                                };
                            new_entries.insert(
                                trim_object.meta_mut().uid.take().unwrap(),
                                compressed_object,
                            );
                        }
                        Err(e) => warn!(
                            "failed serialized resource {} UID({}) to json Err: {}",
                            kind,
                            trim_object.meta().uid.as_ref().unwrap(),
                            e
                        ),
                    }
                }

                if !new_entries.is_empty() {
                    *entries.lock().await = new_entries;
                    version.fetch_add(1, Ordering::SeqCst);
                }
            }
            Err(err) => {
                let msg = format!("{} watcher list failed: {}", kind, err);
                warn!("{}", msg);
                err_msg.lock().await.replace(msg);
            }
        }
    }

    async fn resolve_event(
        encoder: &mut ZlibEncoder<Vec<u8>>,
        maybe_event: Result<Option<Event<K>>, runtime::watcher::Error>,
        last_update: &mut SystemTime,
        entries: &Arc<Mutex<HashMap<String, Vec<u8>>>>,
        version: &Arc<AtomicU64>,
        kind: &str,
        err_msg: &Arc<Mutex<Option<String>>>,
        event_counter: &mut EventCounter,
    ) {
        match maybe_event {
            Ok(Some(event)) => {
                match event {
                    Event::Applied(object) => {
                        event_counter.applied += 1;
                        Self::insert_object(encoder, object, entries, version, kind).await;
                    }
                    Event::Deleted(mut object) => {
                        if let Some(uid) = object.meta_mut().uid.take() {
                            event_counter.deleted += 1;
                            // 只有删除时检查是否需要更新版本号，其余消息直接更新map内容
                            if entries.lock().await.remove(&uid).is_some() {
                                version.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                    // 按照语义重启后应该拿改key对应最新的state，所以只取restart的最后一个
                    // restarted 存储的是某个key对应的object在重启过程中不同状态
                    Event::Restarted(mut objects) => {
                        if let Some(object) = objects.pop() {
                            event_counter.restarted += 1;
                            Self::insert_object(encoder, object, entries, version, kind).await;
                        }
                    }
                }
                if event_counter.applied >= MAX_EVENT_COUNT {
                    info!(
                        "k8s {} watcher has {} applied events",
                        kind, event_counter.applied
                    );
                    event_counter.applied = 0;
                } else if event_counter.deleted >= MAX_EVENT_COUNT {
                    info!(
                        "k8s {} watcher has {} deleted events",
                        kind, event_counter.deleted
                    );
                    event_counter.deleted = 0;
                } else if event_counter.restarted >= MAX_EVENT_COUNT {
                    info!(
                        "k8s {} watcher has {} restarted events",
                        kind, event_counter.restarted
                    );
                    event_counter.restarted = 0;
                }
                *last_update = SystemTime::now();
            }
            Ok(None) => (),
            Err(err) => {
                // 因为watcher 链接中断会有自动重连, 错误附在事件上,存储对应报错信息
                debug!("{} watcher retry watch", kind);
                match err {
                    runtime::watcher::Error::WatchStartFailed(_) => {
                        let msg = format!("{} watcher watch failed: {}", kind, err);
                        warn!("{}", msg);
                        err_msg.lock().await.replace(msg);
                    }
                    // 正常的超时
                    runtime::watcher::Error::WatchError(err_res)
                        if err_res.message.contains("RST_STREAM") =>
                    {
                        debug!("{} watcher timeout retry watch", kind)
                    }
                    runtime::watcher::Error::TooManyObjects
                    | runtime::watcher::Error::WatchError(_)
                    | runtime::watcher::Error::InitialListFailed(_)
                    | runtime::watcher::Error::WatchFailed(_) => {
                        let msg = format!("{} watcher watch failed: {}", kind, err);
                        warn!("{}", msg);
                        err_msg.lock().await.replace(msg);
                    }
                }
            }
        }
    }

    async fn insert_object(
        encoder: &mut ZlibEncoder<Vec<u8>>,
        object: K,
        entries: &Arc<Mutex<HashMap<String, Vec<u8>>>>,
        version: &Arc<AtomicU64>,
        kind: &str,
    ) {
        let uid = object.meta().uid.clone();
        if let Some(uid) = uid {
            let trim_object = object.trim();
            let serialized_object = serde_json::to_vec(&trim_object);
            match serialized_object {
                Ok(serobj) => {
                    let compressed_object = match Self::compress_entry(encoder, serobj.as_slice()) {
                        Ok(c) => c,
                        Err(e) => {
                            warn!(
                                "failed to compress {} resource with UID({}) error: {} ",
                                kind,
                                trim_object.meta().uid.as_ref().unwrap(),
                                e
                            );
                            return;
                        }
                    };
                    entries.lock().await.insert(uid, compressed_object);
                    version.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) => debug!(
                    "failed serialized resource {} UID({}) to json Err: {}",
                    kind, uid, e
                ),
            }
        }
    }

    fn compress_entry(encoder: &mut ZlibEncoder<Vec<u8>>, entry: &[u8]) -> io::Result<Vec<u8>> {
        encoder.write_all(entry)?;
        encoder.reset(vec![])
    }
}

pub trait Trimmable: 'static + Send {
    fn trim(self) -> Self;
}

impl Trimmable for Pod {
    fn trim(mut self) -> Self {
        let mut trim_pod = Pod::default();
        trim_pod.metadata = ObjectMeta {
            uid: self.metadata.uid.take(),
            name: self.metadata.name.take(),
            namespace: self.metadata.namespace.take(),
            owner_references: self.metadata.owner_references.take(),
            creation_timestamp: self.metadata.creation_timestamp.take(),
            labels: self.metadata.labels.take(),
            ..Default::default()
        };
        if let Some(pod_status) = self.status.take() {
            trim_pod.status = Some(PodStatus {
                host_ip: pod_status.host_ip,
                conditions: pod_status.conditions,
                pod_ip: pod_status.pod_ip,
                ..Default::default()
            });
        }
        trim_pod
    }
}

impl Trimmable for Node {
    fn trim(mut self) -> Self {
        let mut trim_node = Node::default();
        trim_node.metadata = ObjectMeta {
            uid: self.metadata.uid.take(),
            name: self.metadata.name.take(),
            labels: self.metadata.labels.take(),
            ..Default::default()
        };

        if let Some(node_status) = self.status.take() {
            trim_node.status = Some(NodeStatus {
                addresses: node_status.addresses,
                conditions: node_status.conditions,
                capacity: node_status.capacity,
                ..Default::default()
            });
        }
        if let Some(node_spec) = self.spec.take() {
            trim_node.spec = Some(NodeSpec {
                pod_cidr: node_spec.pod_cidr,
                ..Default::default()
            });
        }
        trim_node
    }
}

impl Trimmable for ReplicaSet {
    fn trim(mut self) -> Self {
        let mut trim_rs = ReplicaSet::default();
        trim_rs.metadata = ObjectMeta {
            uid: self.metadata.uid.take(),
            name: self.metadata.name.take(),
            namespace: self.metadata.namespace.take(),
            owner_references: self.metadata.owner_references.take(),
            labels: self.metadata.labels.take(),
            ..Default::default()
        };

        if let Some(rs_spec) = self.spec.take() {
            trim_rs.spec = Some(ReplicaSetSpec {
                replicas: rs_spec.replicas,
                selector: rs_spec.selector,
                ..Default::default()
            });
        }

        trim_rs
    }
}

impl Trimmable for ReplicationController {
    fn trim(mut self) -> Self {
        let mut trim_rc = ReplicationController::default();
        trim_rc.metadata = ObjectMeta {
            uid: self.metadata.uid.take(),
            name: self.metadata.name.take(),
            namespace: self.metadata.namespace.take(),
            ..Default::default()
        };

        if let Some(rc_spec) = self.spec.take() {
            trim_rc.spec = Some(ReplicationControllerSpec {
                replicas: rc_spec.replicas,
                selector: rc_spec.selector,
                template: rc_spec.template,
                ..Default::default()
            });
        }

        trim_rc
    }
}

impl Trimmable for networking::v1::Ingress {
    fn trim(mut self) -> Self {
        self.metadata = ObjectMeta {
            uid: self.metadata.uid.take(),
            name: self.metadata.name.take(),
            namespace: self.metadata.namespace.take(),
            ..Default::default()
        };
        self.status = None;
        self
    }
}

impl Trimmable for networking::v1beta1::Ingress {
    fn trim(mut self) -> Self {
        self.metadata = ObjectMeta {
            uid: self.metadata.uid.take(),
            name: self.metadata.name.take(),
            namespace: self.metadata.namespace.take(),
            ..Default::default()
        };
        self.status = None;
        self
    }
}

impl Trimmable for extensions::v1beta1::Ingress {
    fn trim(mut self) -> Self {
        self.metadata = ObjectMeta {
            uid: self.metadata.uid.take(),
            name: self.metadata.name.take(),
            namespace: self.metadata.namespace.take(),
            ..Default::default()
        };
        self.status = None;
        self
    }
}

impl Trimmable for Route {
    fn trim(mut self) -> Self {
        self.metadata = ObjectMeta {
            uid: self.metadata.uid.take(),
            name: self.metadata.name.take(),
            namespace: self.metadata.namespace.take(),
            ..Default::default()
        };
        self.status = Default::default();
        self
    }
}

impl Trimmable for DaemonSet {
    fn trim(mut self) -> Self {
        let mut trim_ds = DaemonSet::default();
        trim_ds.metadata = ObjectMeta {
            uid: self.metadata.uid.take(),
            name: self.metadata.name.take(),
            namespace: self.metadata.namespace.take(),
            labels: self.metadata.labels.take(),
            ..Default::default()
        };
        if let Some(ds_spec) = self.spec.take() {
            trim_ds.spec = Some(DaemonSetSpec {
                selector: ds_spec.selector,
                template: ds_spec.template,
                ..Default::default()
            })
        }

        trim_ds
    }
}

impl Trimmable for StatefulSet {
    fn trim(mut self) -> Self {
        let mut trim_st = StatefulSet::default();
        trim_st.metadata = ObjectMeta {
            uid: self.metadata.uid.take(),
            name: self.metadata.name.take(),
            namespace: self.metadata.namespace.take(),
            labels: self.metadata.labels.take(),
            ..Default::default()
        };

        if let Some(st_spec) = self.spec.take() {
            trim_st.spec = Some(StatefulSetSpec {
                replicas: st_spec.replicas,
                selector: st_spec.selector,
                template: st_spec.template,
                ..Default::default()
            })
        }
        trim_st
    }
}

impl Trimmable for Deployment {
    fn trim(mut self) -> Self {
        let mut trim_de = Deployment::default();
        trim_de.metadata = ObjectMeta {
            uid: self.metadata.uid.take(),
            name: self.metadata.name.take(),
            namespace: self.metadata.namespace.take(),
            labels: self.metadata.labels.take(),
            ..Default::default()
        };

        if let Some(de_spec) = self.spec.take() {
            trim_de.spec = Some(DeploymentSpec {
                replicas: de_spec.replicas,
                selector: de_spec.selector,
                template: de_spec.template,
                ..Default::default()
            });
        }

        trim_de
    }
}

impl Trimmable for Service {
    fn trim(mut self) -> Self {
        let mut trim_svc = Service::default();
        trim_svc.metadata = ObjectMeta {
            uid: self.metadata.uid.take(),
            name: self.metadata.name.take(),
            namespace: self.metadata.namespace.take(),
            annotations: self.metadata.annotations.take(),
            ..Default::default()
        };

        if let Some(svc_spec) = self.spec.take() {
            trim_svc.spec = Some(ServiceSpec {
                selector: svc_spec.selector,
                type_: svc_spec.type_,
                cluster_ip: svc_spec.cluster_ip,
                ports: svc_spec.ports,
                ..Default::default()
            });
        }
        trim_svc
    }
}

impl Trimmable for Namespace {
    fn trim(mut self) -> Self {
        let mut trim_ns = Namespace::default();
        trim_ns.metadata = ObjectMeta {
            uid: self.metadata.uid.take(),
            name: self.metadata.name.take(),
            ..Default::default()
        };
        trim_ns
    }
}

pub struct ResourceWatcherFactory {
    client: Client,
    runtime: Handle,
}

impl ResourceWatcherFactory {
    pub fn new(client: Client, runtime: Handle) -> Self {
        Self { client, runtime }
    }

    pub fn new_watcher(
        &self,
        resource: &'static str,
        kind: &'static str,
        namespace: Option<&str>,
    ) -> Option<GenericResourceWatcher> {
        match resource {
            // 特定namespace不支持Node/Namespace资源
            "nodes" => Some(GenericResourceWatcher::Node(ResourceWatcher::new(
                Api::all(self.client.clone()),
                kind,
                self.runtime.clone(),
            ))),
            "namespaces" => Some(GenericResourceWatcher::Namespace(ResourceWatcher::new(
                Api::all(self.client.clone()),
                kind,
                self.runtime.clone(),
            ))),
            "services" => Some(GenericResourceWatcher::Service(ResourceWatcher::new(
                match namespace {
                    Some(namespace) => Api::namespaced(self.client.clone(), namespace),
                    None => Api::all(self.client.clone()),
                },
                kind,
                self.runtime.clone(),
            ))),
            "deployments" => Some(GenericResourceWatcher::Deployment(ResourceWatcher::new(
                match namespace {
                    Some(namespace) => Api::namespaced(self.client.clone(), namespace),
                    None => Api::all(self.client.clone()),
                },
                kind,
                self.runtime.clone(),
            ))),
            "pods" => Some(GenericResourceWatcher::Pod(ResourceWatcher::new(
                match namespace {
                    Some(namespace) => Api::namespaced(self.client.clone(), namespace),
                    None => Api::all(self.client.clone()),
                },
                kind,
                self.runtime.clone(),
            ))),
            "statefulsets" => Some(GenericResourceWatcher::StatefulSet(ResourceWatcher::new(
                match namespace {
                    Some(namespace) => Api::namespaced(self.client.clone(), namespace),
                    None => Api::all(self.client.clone()),
                },
                kind,
                self.runtime.clone(),
            ))),
            "daemonsets" => Some(GenericResourceWatcher::DaemonSet(ResourceWatcher::new(
                match namespace {
                    Some(namespace) => Api::namespaced(self.client.clone(), namespace),
                    None => Api::all(self.client.clone()),
                },
                kind,
                self.runtime.clone(),
            ))),
            "replicationcontrollers" => Some(GenericResourceWatcher::ReplicationController(
                ResourceWatcher::new(
                    match namespace {
                        Some(namespace) => Api::namespaced(self.client.clone(), namespace),
                        None => Api::all(self.client.clone()),
                    },
                    kind,
                    self.runtime.clone(),
                ),
            )),
            "replicasets" => Some(GenericResourceWatcher::ReplicaSet(ResourceWatcher::new(
                match namespace {
                    Some(namespace) => Api::namespaced(self.client.clone(), namespace),
                    None => Api::all(self.client.clone()),
                },
                kind,
                self.runtime.clone(),
            ))),
            "v1ingresses" => Some(GenericResourceWatcher::V1Ingress(ResourceWatcher::new(
                match namespace {
                    Some(namespace) => Api::namespaced(self.client.clone(), namespace),
                    None => Api::all(self.client.clone()),
                },
                kind,
                self.runtime.clone(),
            ))),
            "v1beta1ingresses" => Some(GenericResourceWatcher::V1beta1Ingress(
                ResourceWatcher::new(
                    match namespace {
                        Some(namespace) => Api::namespaced(self.client.clone(), namespace),
                        None => Api::all(self.client.clone()),
                    },
                    kind,
                    self.runtime.clone(),
                ),
            )),
            "extv1beta1ingresses" => Some(GenericResourceWatcher::ExtV1beta1Ingress(
                ResourceWatcher::new(
                    match namespace {
                        Some(namespace) => Api::namespaced(self.client.clone(), namespace),
                        None => Api::all(self.client.clone()),
                    },
                    kind,
                    self.runtime.clone(),
                ),
            )),
            "routes" => Some(GenericResourceWatcher::Route(ResourceWatcher::new(
                match namespace {
                    Some(namespace) => Api::namespaced(self.client.clone(), namespace),
                    None => Api::all(self.client.clone()),
                },
                kind,
                self.runtime.clone(),
            ))),
            _ => None,
        }
    }
}
