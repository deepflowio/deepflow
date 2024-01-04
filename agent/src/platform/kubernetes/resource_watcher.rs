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
    collections::{hash_map::Entry, HashMap},
    fmt::{self, Debug},
    io::{self, Write},
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
        Arc, Weak,
    },
    time::{Duration, Instant, SystemTime},
};

use enum_dispatch::enum_dispatch;
use flate2::{write::ZlibEncoder, Compression};
use futures::StreamExt;
use k8s_openapi::{
    api::{
        apps::v1::{
            DaemonSet, DaemonSetSpec, Deployment, DeploymentSpec, ReplicaSet, ReplicaSetSpec,
            StatefulSet, StatefulSetSpec,
        },
        core::v1::{
            Container, ContainerStatus, Namespace, Node, NodeSpec, NodeStatus, Pod, PodSpec,
            PodStatus, ReplicationController, ReplicationControllerSpec, Service, ServiceSpec,
        },
        extensions, networking,
    },
    apimachinery::pkg::apis::meta::v1::ObjectMeta,
};
use kube::{
    api::{ListParams, WatchEvent},
    error::ErrorResponse,
    Api, Client, Error as ClientErr, Resource as KubeResource, ResourceExt,
};
use log::{debug, info, trace, warn};
use openshift_openapi::api::route::v1::Route;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use tokio::{runtime::Handle, sync::Mutex, task::JoinHandle, time};

use super::crd::{
    calico::IpPool,
    kruise::{CloneSet, StatefulSet as KruiseStatefulSet},
    pingan::ServiceRule,
};
use crate::utils::stats::{
    self, Countable, Counter, CounterType, CounterValue, RefCountable, StatsOption,
};

const REFRESH_INTERVAL: Duration = Duration::from_secs(3600);
const SLEEP_INTERVAL: Duration = Duration::from_secs(5);
const SPIN_INTERVAL: Duration = Duration::from_millis(100);
const HTTP_FORBIDDEN: u16 = 403;
const HTTP_GONE: u16 = 410;

#[enum_dispatch]
pub trait Watcher {
    fn start(&self) -> Option<JoinHandle<()>>;
    fn error(&self) -> Option<String>;
    fn entries(&self) -> Vec<Vec<u8>>;
    fn pb_name(&self) -> &str;
    fn version(&self) -> u64;
    fn ready(&self) -> bool;
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

    // CRDs
    ServiceRule(ResourceWatcher<ServiceRule>),
    CloneSet(ResourceWatcher<CloneSet>),
    KruiseStatefulSet(ResourceWatcher<KruiseStatefulSet>),
    IpPool(ResourceWatcher<IpPool>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupVersion {
    pub group: &'static str,
    pub version: &'static str,
}

impl fmt::Display for GroupVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.group, self.version)
    }
}

#[derive(Clone, Debug)]
pub struct Resource {
    pub name: &'static str,
    pub pb_name: &'static str,
    // supported group versions ordered by priority
    pub group_versions: Vec<GroupVersion>,
    // group version to use
    pub selected_gv: Option<GroupVersion>,
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.selected_gv {
            Some(gv) => write!(f, "{}/{}", gv, self.name),
            None => write!(f, "{}: {:?}", self.name, self.group_versions),
        }
    }
}

pub fn default_resources() -> Vec<Resource> {
    vec![
        Resource {
            name: "namespaces",
            pb_name: "*v1.Namespace",
            group_versions: vec![GroupVersion {
                group: "core",
                version: "v1",
            }],
            selected_gv: None,
        },
        Resource {
            name: "nodes",
            pb_name: "*v1.Node",
            group_versions: vec![GroupVersion {
                group: "core",
                version: "v1",
            }],
            selected_gv: None,
        },
        Resource {
            name: "pods",
            pb_name: "*v1.Pod",
            group_versions: vec![GroupVersion {
                group: "core",
                version: "v1",
            }],
            selected_gv: None,
        },
        Resource {
            name: "replicationcontrollers",
            pb_name: "*v1.ReplicationController",
            group_versions: vec![GroupVersion {
                group: "core",
                version: "v1",
            }],
            selected_gv: None,
        },
        Resource {
            name: "services",
            pb_name: "*v1.Service",
            group_versions: vec![GroupVersion {
                group: "core",
                version: "v1",
            }],
            selected_gv: None,
        },
        Resource {
            name: "daemonsets",
            pb_name: "*v1.DaemonSet",
            group_versions: vec![GroupVersion {
                group: "apps",
                version: "v1",
            }],
            selected_gv: None,
        },
        Resource {
            name: "deployments",
            pb_name: "*v1.Deployment",
            group_versions: vec![GroupVersion {
                group: "apps",
                version: "v1",
            }],
            selected_gv: None,
        },
        Resource {
            name: "replicasets",
            pb_name: "*v1.ReplicaSet",
            group_versions: vec![GroupVersion {
                group: "apps",
                version: "v1",
            }],
            selected_gv: None,
        },
        Resource {
            name: "statefulsets",
            pb_name: "*v1.StatefulSet",
            group_versions: vec![GroupVersion {
                group: "apps",
                version: "v1",
            }],
            selected_gv: None,
        },
        Resource {
            name: "ingresses",
            pb_name: "*v1.Ingress",
            group_versions: vec![
                GroupVersion {
                    group: "networking.k8s.io",
                    version: "v1",
                },
                GroupVersion {
                    group: "networking.k8s.io",
                    version: "v1beta1",
                },
                GroupVersion {
                    group: "extensions",
                    version: "v1beta1",
                },
            ],
            selected_gv: None,
        },
    ]
}

pub fn supported_resources() -> Vec<Resource> {
    vec![
        Resource {
            name: "namespaces",
            pb_name: "*v1.Namespace",
            group_versions: vec![GroupVersion {
                group: "core",
                version: "v1",
            }],
            selected_gv: None,
        },
        Resource {
            name: "nodes",
            pb_name: "*v1.Node",
            group_versions: vec![GroupVersion {
                group: "core",
                version: "v1",
            }],
            selected_gv: None,
        },
        Resource {
            name: "pods",
            pb_name: "*v1.Pod",
            group_versions: vec![GroupVersion {
                group: "core",
                version: "v1",
            }],
            selected_gv: None,
        },
        Resource {
            name: "replicationcontrollers",
            pb_name: "*v1.ReplicationController",
            group_versions: vec![GroupVersion {
                group: "core",
                version: "v1",
            }],
            selected_gv: None,
        },
        Resource {
            name: "services",
            pb_name: "*v1.Service",
            group_versions: vec![GroupVersion {
                group: "core",
                version: "v1",
            }],
            selected_gv: None,
        },
        Resource {
            name: "daemonsets",
            pb_name: "*v1.DaemonSet",
            group_versions: vec![GroupVersion {
                group: "apps",
                version: "v1",
            }],
            selected_gv: None,
        },
        Resource {
            name: "deployments",
            pb_name: "*v1.Deployment",
            group_versions: vec![GroupVersion {
                group: "apps",
                version: "v1",
            }],
            selected_gv: None,
        },
        Resource {
            name: "replicasets",
            pb_name: "*v1.ReplicaSet",
            group_versions: vec![GroupVersion {
                group: "apps",
                version: "v1",
            }],
            selected_gv: None,
        },
        Resource {
            name: "statefulsets",
            pb_name: "*v1.StatefulSet",
            group_versions: vec![
                GroupVersion {
                    group: "apps",
                    version: "v1",
                },
                GroupVersion {
                    group: "apps.kruise.io",
                    version: "v1beta1",
                },
            ],
            selected_gv: None,
        },
        Resource {
            name: "ingresses",
            pb_name: "*v1.Ingress",
            group_versions: vec![
                GroupVersion {
                    group: "networking.k8s.io",
                    version: "v1",
                },
                GroupVersion {
                    group: "networking.k8s.io",
                    version: "v1beta1",
                },
                GroupVersion {
                    group: "extensions",
                    version: "v1beta1",
                },
            ],
            selected_gv: None,
        },
        Resource {
            name: "routes",
            pb_name: "*v1.Ingress",
            group_versions: vec![GroupVersion {
                group: "route.openshift.io",
                version: "v1",
            }],
            selected_gv: None,
        },
        Resource {
            name: "servicerules",
            pb_name: "*v1.ServiceRule",
            group_versions: vec![GroupVersion {
                group: "crd.pingan.org",
                version: "v1alpha1",
            }],
            selected_gv: None,
        },
        Resource {
            name: "clonesets",
            pb_name: "*v1.CloneSet",
            group_versions: vec![GroupVersion {
                group: "apps.kruise.io",
                version: "v1alpha1",
            }],
            selected_gv: None,
        },
        Resource {
            name: "ippools",
            pb_name: "*v1.IPPool",
            group_versions: vec![GroupVersion {
                group: "crd.projectcalico.org",
                version: "v1",
            }],
            selected_gv: None,
        },
    ]
}

#[derive(Default)]
pub struct WatcherCounter {
    list_count: AtomicU32,
    list_length: AtomicU32,
    list_cost_time_sum: AtomicU64, // ns
    list_error: AtomicU32,
    watch_applied: AtomicU32,
    watch_deleted: AtomicU32,
    watch_restarted: AtomicU32,
}

impl RefCountable for WatcherCounter {
    fn get_counters(&self) -> Vec<Counter> {
        let list_count = self.list_count.swap(0, Ordering::Relaxed);
        let list_avg_cost_time = self
            .list_cost_time_sum
            .swap(0, Ordering::Relaxed)
            .checked_div(list_count as u64)
            .unwrap_or_default();
        let list_avg_length = self
            .list_length
            .swap(0, Ordering::Relaxed)
            .checked_div(list_count)
            .unwrap_or_default();
        vec![
            (
                "list_avg_length",
                CounterType::Gauged,
                CounterValue::Unsigned(list_avg_length as u64),
            ),
            (
                "list_avg_cost_time",
                CounterType::Counted,
                CounterValue::Unsigned(list_avg_cost_time),
            ),
            (
                "list_error",
                CounterType::Gauged,
                CounterValue::Unsigned(self.list_error.swap(0, Ordering::Relaxed) as u64),
            ),
            (
                "watch_applied",
                CounterType::Gauged,
                CounterValue::Unsigned(self.watch_applied.swap(0, Ordering::Relaxed) as u64),
            ),
            (
                "watch_deleted",
                CounterType::Gauged,
                CounterValue::Unsigned(self.watch_deleted.swap(0, Ordering::Relaxed) as u64),
            ),
            (
                "watch_restarted",
                CounterType::Gauged,
                CounterValue::Unsigned(self.watch_restarted.swap(0, Ordering::Relaxed) as u64),
            ),
        ]
    }
}

#[derive(Clone)]
pub struct WatcherConfig {
    pub list_limit: u32,
    pub list_interval: Duration,
    pub max_memory: u64,
}

// 发生错误，需要重新构造实例
#[derive(Clone)]
pub struct ResourceWatcher<K> {
    api: Api<K>,
    entries: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    err_msg: Arc<Mutex<Option<String>>>,
    kind: Resource,
    version: Arc<AtomicU64>,
    runtime: Handle,
    ready: Arc<AtomicBool>,
    stats_counter: Arc<WatcherCounter>,
    config: WatcherConfig,

    listing: Arc<AtomicBool>,
}

struct Context<K> {
    entries: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    version: Arc<AtomicU64>,
    api: Api<K>,
    kind: Resource,
    err_msg: Arc<Mutex<Option<String>>>,
    ready: Arc<AtomicBool>,
    stats_counter: Arc<WatcherCounter>,
    config: WatcherConfig,
    resource_version: Option<String>,

    listing: Arc<AtomicBool>,
}

impl<K> Watcher for ResourceWatcher<K>
where
    K: Clone + Debug + DeserializeOwned + KubeResource + Serialize + Trimmable,
{
    fn start(&self) -> Option<JoinHandle<()>> {
        let ctx = Context {
            entries: self.entries.clone(),
            version: self.version.clone(),
            kind: self.kind.clone(),
            err_msg: self.err_msg.clone(),
            ready: self.ready.clone(),
            api: self.api.clone(),
            stats_counter: self.stats_counter.clone(),
            config: self.config.clone(),
            resource_version: None,
            listing: self.listing.clone(),
        };

        let handle = self.runtime.spawn(Self::process(ctx));
        info!("{} watcher started", self.kind);
        Some(handle)
    }

    fn version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }

    fn error(&self) -> Option<String> {
        self.err_msg.blocking_lock().take()
    }

    fn pb_name(&self) -> &str {
        self.kind.pb_name
    }

    fn entries(&self) -> Vec<Vec<u8>> {
        self.entries
            .blocking_lock()
            .values()
            .map(Clone::clone)
            .collect::<Vec<_>>()
    }

    fn ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }
}

impl<K> ResourceWatcher<K>
where
    K: Clone + Debug + DeserializeOwned + KubeResource + Serialize + Trimmable,
{
    pub fn new(
        api: Api<K>,
        kind: Resource,
        runtime: Handle,
        config: &WatcherConfig,
        listing: Arc<AtomicBool>,
    ) -> Self {
        Self {
            api,
            entries: Arc::new(Mutex::new(HashMap::new())),
            version: Arc::new(AtomicU64::new(0)),
            kind,
            err_msg: Arc::new(Mutex::new(None)),
            runtime,
            ready: Default::default(),
            stats_counter: Default::default(),
            config: config.clone(),
            listing,
        }
    }

    // returns true if re-listing is required
    async fn watch(ctx: &mut Context<K>, encoder: &mut ZlibEncoder<Vec<u8>>) -> bool {
        loop {
            let mut stream = match ctx
                .api
                .watch(
                    &ListParams::default(),
                    ctx.resource_version
                        .as_ref()
                        .map(|s| s as &str)
                        .unwrap_or(""),
                )
                .await
            {
                Ok(s) => s.boxed(),
                Err(e) => {
                    warn!("{} watch failed: {:?}", ctx.kind, e);
                    return false;
                }
            };
            while let Some(ev) = stream.next().await {
                match ev {
                    Ok(event) => {
                        match &event {
                            WatchEvent::Added(o)
                            | WatchEvent::Modified(o)
                            | WatchEvent::Deleted(o) => {
                                if let Some(version) = o.resource_version() {
                                    if version != "" {
                                        ctx.resource_version.replace(version);
                                    }
                                }
                            }
                            WatchEvent::Bookmark(_) => continue,
                            WatchEvent::Error(e) => {
                                if e.code == HTTP_FORBIDDEN {
                                    warn!("{} watch error: {:?}", ctx.kind, e);
                                } else {
                                    debug!("{} watch error: {:?}", ctx.kind, e);
                                }
                                return e.code == HTTP_GONE;
                            }
                        }
                        // handles add/modify/delete
                        Self::resolve_event(&ctx, encoder, event).await;
                    }
                    Err(e) => {
                        if std::matches!(
                            e,
                            ClientErr::Api(ErrorResponse {
                                code: HTTP_FORBIDDEN,
                                ..
                            })
                        ) {
                            warn!("{} watch error: {:?}", ctx.kind, e);
                        } else {
                            debug!("{} watch error: {:?}", ctx.kind, e);
                        }
                        return false;
                    }
                }
            }
            // recreate watcher and resume watching
            debug!("{} watch resuming", ctx.kind);
        }
    }

    async fn process(mut ctx: Context<K>) {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        while !Self::serialized_get_list_entry(&mut ctx, &mut encoder).await {
            time::sleep(SLEEP_INTERVAL).await;
        }
        ctx.ready.store(true, Ordering::Relaxed);
        info!("{} watcher initial list ready", ctx.kind);

        let mut last_update = SystemTime::now();

        info!("{} watcher start watching", ctx.kind);
        loop {
            let need_relist = Self::watch(&mut ctx, &mut encoder).await;
            time::sleep(SLEEP_INTERVAL).await;
            let now = SystemTime::now();
            // list and rewatch
            if need_relist
                || now < last_update
                || last_update.elapsed().unwrap() >= ctx.config.list_interval
            {
                debug!("{} watcher relisting", ctx.kind);
                Self::full_sync(&mut ctx, &mut encoder).await;
                last_update = now;
            }
        }
    }

    async fn full_sync(ctx: &mut Context<K>, encoder: &mut ZlibEncoder<Vec<u8>>) {
        let now = Instant::now();
        Self::serialized_get_list_entry(ctx, encoder).await;
        ctx.stats_counter
            .list_cost_time_sum
            .fetch_add(now.elapsed().as_nanos() as u64, Ordering::Relaxed);
        ctx.stats_counter.list_count.fetch_add(1, Ordering::Relaxed);
    }

    async fn serialized_get_list_entry(
        ctx: &mut Context<K>,
        encoder: &mut ZlibEncoder<Vec<u8>>,
    ) -> bool {
        while let Err(_) =
            ctx.listing
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        {
            time::sleep(SPIN_INTERVAL).await;
        }
        let r = Self::get_list_entry(ctx, encoder).await;
        ctx.listing.store(false, Ordering::SeqCst);
        r
    }

    // calling list on multiple resources simultaneously may consume a lot of memory
    // use serialized_get_list_entry to avoid oom
    async fn get_list_entry(ctx: &mut Context<K>, encoder: &mut ZlibEncoder<Vec<u8>>) -> bool {
        info!(
            "list {} entries with limit {}",
            ctx.kind, ctx.config.list_limit,
        );
        let mut all_entries = HashMap::new();
        let mut total_count = 0;
        let mut total_bytes = 0;
        let mut params = ListParams::default().limit(ctx.config.list_limit);
        loop {
            trace!("{} list with {:?}", ctx.kind, params);
            match ctx.api.list(&params).await {
                Ok(mut object_list) => {
                    total_count += object_list.items.len();
                    if ctx.resource_version.is_some()
                        && ctx.resource_version == object_list.metadata.resource_version
                    {
                        debug!("skip {} list with same resource version", ctx.kind);
                        ctx.stats_counter
                            .list_length
                            .fetch_add(total_count as u32, Ordering::Relaxed);
                        return true;
                    }
                    debug!(
                        "{} list returns {} entries, {} remaining",
                        ctx.kind,
                        object_list.items.len(),
                        object_list
                            .metadata
                            .remaining_item_count
                            .unwrap_or_default()
                    );

                    for object in object_list.items {
                        if object.meta().uid.as_ref().is_none() {
                            continue;
                        }
                        let mut trim_object = object.trim();
                        match serde_json::to_vec(&trim_object) {
                            Ok(serialized_object) => {
                                let compressed_object = match Self::compress_entry(
                                    encoder,
                                    serialized_object.as_slice(),
                                ) {
                                    Ok(c) => c,
                                    Err(e) => {
                                        warn!(
                                            "failed to compress {} resource with UID({}) error: {} ",
                                            ctx.kind,
                                            trim_object.meta().uid.as_ref().unwrap(),
                                            e
                                        );
                                        continue;
                                    }
                                };
                                total_bytes += compressed_object.len();
                                all_entries.insert(
                                    trim_object.meta_mut().uid.take().unwrap(),
                                    compressed_object,
                                );
                            }
                            Err(e) => warn!(
                                "failed serialized resource {} UID({}) to json Err: {}",
                                ctx.kind,
                                trim_object.meta().uid.as_ref().unwrap(),
                                e
                            ),
                        }
                    }

                    match object_list.metadata.continue_.as_ref().map(String::as_str) {
                        // sometimes k8s api return Some("") instead of None even if
                        // there is no more entries
                        None | Some("") => {
                            info!(
                                "list {} returned {} entries in {}B",
                                ctx.kind, total_count, total_bytes
                            );
                            if !all_entries.is_empty() {
                                *ctx.entries.lock().await = all_entries;
                                ctx.version.fetch_add(1, Ordering::SeqCst);
                            }
                            ctx.resource_version = object_list.metadata.resource_version.take();
                            ctx.stats_counter
                                .list_length
                                .fetch_add(total_count as u32, Ordering::Relaxed);
                            return true;
                        }
                        _ => (),
                    }
                    params.continue_token = object_list.metadata.continue_.take();
                }
                Err(err) => {
                    ctx.stats_counter.list_error.fetch_add(1, Ordering::Relaxed);
                    let msg = format!("{} watcher list failed: {}", ctx.kind, err);
                    warn!("{}", msg);
                    ctx.err_msg.lock().await.replace(msg);
                    return false;
                }
            }
        }
    }

    async fn resolve_event(
        ctx: &Context<K>,
        encoder: &mut ZlibEncoder<Vec<u8>>,
        event: WatchEvent<K>,
    ) {
        match event {
            WatchEvent::Added(object) | WatchEvent::Modified(object) => {
                Self::insert_object(encoder, object, &ctx.entries, &ctx.version, &ctx.kind).await;
                ctx.stats_counter
                    .watch_applied
                    .fetch_add(1, Ordering::Relaxed);
            }
            WatchEvent::Deleted(mut object) => {
                if let Some(uid) = object.meta_mut().uid.take() {
                    // 只有删除时检查是否需要更新版本号，其余消息直接更新map内容
                    if ctx.entries.lock().await.remove(&uid).is_some() {
                        ctx.version.fetch_add(1, Ordering::SeqCst);
                    }
                    ctx.stats_counter
                        .watch_deleted
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            WatchEvent::Bookmark(_) | WatchEvent::Error(_) => unreachable!(),
        }
    }

    async fn insert_object(
        encoder: &mut ZlibEncoder<Vec<u8>>,
        object: K,
        entries: &Arc<Mutex<HashMap<String, Vec<u8>>>>,
        version: &Arc<AtomicU64>,
        kind: &Resource,
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
                    let mut entries = entries.lock().await;
                    match entries.entry(uid) {
                        Entry::Occupied(o) if o.get() == &compressed_object => return,
                        Entry::Occupied(mut o) => {
                            o.insert(compressed_object);
                        }
                        Entry::Vacant(o) => {
                            o.insert(compressed_object);
                        }
                    }
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
            annotations: self.metadata.annotations.take(),
            ..Default::default()
        };
        if let Some(spec) = self.spec.take() {
            trim_pod.spec = Some(PodSpec {
                containers: spec
                    .containers
                    .into_iter()
                    .map(|mut c| Container {
                        name: c.name,
                        env: c.env.take(),
                        ..Default::default()
                    })
                    .collect(),
                node_name: spec.node_name,
                ..Default::default()
            });
        }
        if let Some(pod_status) = self.status.take() {
            trim_pod.status = Some(PodStatus {
                host_ip: pod_status.host_ip,
                conditions: pod_status.conditions,
                container_statuses: pod_status.container_statuses.map(|cs| {
                    cs.into_iter()
                        .map(|mut s| ContainerStatus {
                            container_id: s.container_id.take(),
                            ..Default::default()
                        })
                        .collect()
                }),
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
            labels: self.metadata.labels.take(),
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

    // serialize list operation
    listing: Arc<AtomicBool>,
}

impl ResourceWatcherFactory {
    pub fn new(client: Client, runtime: Handle) -> Self {
        Self {
            client,
            runtime,
            listing: Default::default(),
        }
    }

    fn new_watcher_inner<K>(
        &self,
        kind: Resource,
        stats_collector: &stats::Collector,
        namespace: Option<&str>,
        config: &WatcherConfig,
    ) -> ResourceWatcher<K>
    where
        K: Clone + Debug + DeserializeOwned + KubeResource + Serialize + Trimmable,
        <K as KubeResource>::DynamicType: Default,
    {
        let watcher = ResourceWatcher::new(
            match namespace {
                Some(namespace) => Api::namespaced(self.client.clone(), namespace),
                None => Api::all(self.client.clone()),
            },
            kind,
            self.runtime.clone(),
            config,
            self.listing.clone(),
        );
        stats_collector.register_countable(
            "resource_watcher",
            Countable::Ref(Arc::downgrade(&watcher.stats_counter) as Weak<dyn RefCountable>),
            vec![StatsOption::Tag("kind", watcher.kind.to_string())],
        );
        watcher
    }

    pub fn new_watcher(
        &self,
        resource: Resource,
        namespace: Option<&str>,
        stats_collector: &stats::Collector,
        config: &WatcherConfig,
    ) -> Option<GenericResourceWatcher> {
        let watcher = match resource.name {
            // 特定namespace不支持Node/Namespace资源
            "nodes" => GenericResourceWatcher::Node(self.new_watcher_inner(
                resource,
                stats_collector,
                None,
                config,
            )),
            "namespaces" => GenericResourceWatcher::Namespace(self.new_watcher_inner(
                resource,
                stats_collector,
                None,
                config,
            )),
            "services" => GenericResourceWatcher::Service(self.new_watcher_inner(
                resource,
                stats_collector,
                namespace,
                config,
            )),
            "deployments" => GenericResourceWatcher::Deployment(self.new_watcher_inner(
                resource,
                stats_collector,
                namespace,
                config,
            )),
            "pods" => GenericResourceWatcher::Pod(self.new_watcher_inner(
                resource,
                stats_collector,
                namespace,
                config,
            )),
            "statefulsets" => match resource.selected_gv.as_ref().unwrap() {
                GroupVersion {
                    group: "apps.kruise.io",
                    version: "v1beta1",
                } => GenericResourceWatcher::KruiseStatefulSet(self.new_watcher_inner(
                    resource,
                    stats_collector,
                    namespace,
                    config,
                )),
                GroupVersion {
                    group: "apps",
                    version: "v1",
                } => GenericResourceWatcher::StatefulSet(self.new_watcher_inner(
                    resource,
                    stats_collector,
                    namespace,
                    config,
                )),
                _ => {
                    warn!(
                        "unsupported resource {} group version {}",
                        resource.name,
                        resource.selected_gv.as_ref().unwrap()
                    );
                    return None;
                }
            },
            "daemonsets" => GenericResourceWatcher::DaemonSet(self.new_watcher_inner(
                resource,
                stats_collector,
                namespace,
                config,
            )),
            "replicationcontrollers" => GenericResourceWatcher::ReplicationController(
                self.new_watcher_inner(resource, stats_collector, namespace, config),
            ),
            "replicasets" => GenericResourceWatcher::ReplicaSet(self.new_watcher_inner(
                resource,
                stats_collector,
                namespace,
                config,
            )),
            "ingresses" => match resource.selected_gv.as_ref().unwrap() {
                GroupVersion {
                    group: "networking.k8s.io",
                    version: "v1",
                } => GenericResourceWatcher::V1Ingress(self.new_watcher_inner(
                    resource,
                    stats_collector,
                    namespace,
                    config,
                )),
                GroupVersion {
                    group: "networking.k8s.io",
                    version: "v1beta1",
                } => GenericResourceWatcher::V1beta1Ingress(self.new_watcher_inner(
                    resource,
                    stats_collector,
                    namespace,
                    config,
                )),
                GroupVersion {
                    group: "extensions",
                    version: "v1beta1",
                } => GenericResourceWatcher::ExtV1beta1Ingress(self.new_watcher_inner(
                    resource,
                    stats_collector,
                    namespace,
                    config,
                )),
                _ => {
                    warn!(
                        "unsupported resource {} group version {}",
                        resource.name,
                        resource.selected_gv.as_ref().unwrap()
                    );
                    return None;
                }
            },
            "routes" => GenericResourceWatcher::Route(self.new_watcher_inner(
                resource,
                stats_collector,
                namespace,
                config,
            )),
            "servicerules" => GenericResourceWatcher::ServiceRule(self.new_watcher_inner(
                resource,
                stats_collector,
                namespace,
                config,
            )),
            "clonesets" => GenericResourceWatcher::CloneSet(self.new_watcher_inner(
                resource,
                stats_collector,
                namespace,
                config,
            )),
            "ippools" => GenericResourceWatcher::IpPool(self.new_watcher_inner(
                resource,
                stats_collector,
                namespace,
                config,
            )),
            _ => {
                warn!("unsupported resource {}", resource.name);
                return None;
            }
        };

        Some(watcher)
    }
}
