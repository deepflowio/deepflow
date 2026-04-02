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
    borrow::Cow,
    collections::HashMap,
    convert::Infallible,
    panic::Location,
    sync::{
        atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicU8, Ordering},
        Arc, Weak,
    },
    time::Instant,
};

use hyper::{
    header::CONTENT_TYPE,
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server, StatusCode,
};
use log::{debug, error, info, trace, warn};
use parking_lot::Mutex;
use serde::Serialize;
use tokio::{runtime::Runtime, sync::oneshot, task::JoinHandle};

use crate::trident::VersionInfo;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[repr(u8)]
pub enum LivenessEvent {
    #[default]
    None = 0,
    Pause = 1,
    Heartbeat = 2,
}

impl LivenessEvent {
    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(LivenessEvent::Pause),
            2 => Some(LivenessEvent::Heartbeat),
            _ => None,
        }
    }
}

const EMPTY_VERSION_INFO: &'static VersionInfo = &VersionInfo {
    name: "",
    branch: "",
    commit_id: "",
    rev_count: "",
    compiler: "",
    compile_time: "",
    revision: "",
};

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ComponentId {
    pub module: &'static str,
    pub id: u32,
}

impl ComponentId {
    pub const fn new(module: &'static str, id: u32) -> Self {
        Self { module, id }
    }
}

#[derive(Clone, Debug)]
pub struct ComponentSpec {
    pub id: ComponentId,
    pub display_name: Cow<'static, str>,
    pub required: bool,
    pub timeout_ms: u64,
}

impl Default for ComponentSpec {
    fn default() -> Self {
        Self {
            id: ComponentId::default(),
            display_name: Cow::Borrowed(""),
            required: true,
            timeout_ms: 0,
        }
    }
}

struct ComponentState {
    id: ComponentId,
    display_name: Cow<'static, str>,
    required: bool,
    timeout_ms: AtomicU64,
    // Monotonically increasing generation distinguishes a fresh registration from a stale handle
    // that still exists briefly during component restart/recreation.
    generation: u64,
    running: AtomicBool,
    last_heartbeat_mono_ms: AtomicU64,
    last_event: AtomicU8,
    // Stores the latest callsite observed through #[track_caller] on heartbeat/pause.
    last_location: AtomicPtr<Location<'static>>,
}

impl ComponentState {
    fn new(spec: ComponentSpec, generation: u64) -> Self {
        Self {
            id: spec.id,
            display_name: spec.display_name,
            required: spec.required,
            timeout_ms: AtomicU64::new(spec.timeout_ms),
            generation,
            running: AtomicBool::new(false),
            last_heartbeat_mono_ms: AtomicU64::new(u64::MAX),
            last_event: AtomicU8::new(LivenessEvent::None as u8),
            last_location: AtomicPtr::new(std::ptr::null_mut()),
        }
    }

    fn snapshot(&self, now_mono_ms: u64) -> ComponentSnapshot {
        let last_heartbeat_mono_ms = self.last_heartbeat_mono_ms.load(Ordering::Relaxed);
        let last_event = LivenessEvent::from_u8(self.last_event.load(Ordering::Relaxed));
        let location_ptr = self.last_location.load(Ordering::Relaxed);
        let last_location = if location_ptr.is_null() {
            None
        } else {
            // The pointer always originates from &'static Location::caller()
            Some(unsafe { &*location_ptr })
        };
        ComponentSnapshot {
            module: self.id.module,
            id: self.id.id,
            display_name: self.display_name.clone(),
            running: self.running.load(Ordering::Relaxed),
            required: self.required,
            timeout_ms: self.timeout_ms.load(Ordering::Relaxed),
            last_heartbeat_ago_ms: if last_heartbeat_mono_ms == u64::MAX {
                None
            } else {
                Some(now_mono_ms.saturating_sub(last_heartbeat_mono_ms))
            },
            last_event,
            last_location: last_location.map(|loc| SourceLocation {
                file: loc.file(),
                line: loc.line(),
            }),
        }
    }
}

struct RegistryInner {
    started_at: Instant,
    version: &'static VersionInfo,
    next_generation: AtomicU64,
    components: Mutex<HashMap<ComponentId, Arc<ComponentState>>>,
}

impl RegistryInner {
    fn mono_ms(&self) -> u64 {
        self.started_at.elapsed().as_millis().min(u64::MAX as u128) as u64
    }

    fn deregister(&self, id: ComponentId, generation: u64) {
        let mut components = self.components.lock();
        let should_remove = components
            .get(&id)
            .map(|state| state.generation == generation)
            .unwrap_or(false);
        if should_remove {
            trace!(
                "liveness deregistered component: module={} id={} generation={}",
                id.module,
                id.id,
                generation
            );
            components.remove(&id);
        } else {
            trace!(
                "liveness ignored stale deregistration: module={} id={} generation={}",
                id.module,
                id.id,
                generation
            );
        }
    }
}

#[derive(Clone)]
pub struct LivenessRegistry {
    inner: Arc<RegistryInner>,
}

impl Default for LivenessRegistry {
    fn default() -> Self {
        Self::new(EMPTY_VERSION_INFO)
    }
}

impl LivenessRegistry {
    pub fn new(version_info: &'static VersionInfo) -> Self {
        Self {
            inner: Arc::new(RegistryInner {
                started_at: Instant::now(),
                version: version_info,
                next_generation: AtomicU64::new(1),
                components: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn register(&self, spec: ComponentSpec) -> LivenessHandle {
        let generation = self.inner.next_generation.fetch_add(1, Ordering::Relaxed);
        let component_id = spec.id;
        let display_name = spec.display_name.clone();
        let required = spec.required;
        let timeout_ms = spec.timeout_ms;
        let state = Arc::new(ComponentState::new(spec, generation));
        let mut components = self.inner.components.lock();
        if let Some(old) = components.insert(component_id, state.clone()) {
            warn!(
                "liveness component re-registered: module={} id={} old_display_name={} new_display_name={}",
                component_id.module, component_id.id, old.display_name, display_name
            );
        }
        debug!(
            "liveness registered component: module={} id={} display_name={} generation={} required={} timeout_ms={}",
            component_id.module,
            component_id.id,
            display_name,
            generation,
            required,
            timeout_ms
        );
        LivenessHandle(Some(Arc::new(HandleInner {
            registry: Arc::downgrade(&self.inner),
            state,
        })))
    }

    pub fn report(&self) -> LivenessReport {
        let now_mono_ms = self.inner.mono_ms();
        let mut components = self
            .inner
            .components
            .lock()
            .values()
            .map(|state| state.snapshot(now_mono_ms))
            .collect::<Vec<_>>();
        components.sort_by(|a, b| (&a.module, a.id).cmp(&(&b.module, b.id)));
        let failed_components = components
            .iter()
            .filter(|component| {
                component.running
                    && component.required
                    && component
                        .last_heartbeat_ago_ms
                        .map(|elapsed| elapsed > component.timeout_ms)
                        .unwrap_or(true)
            })
            .cloned()
            .collect::<Vec<_>>();
        if !failed_components.is_empty() {
            debug!(
                "liveness report detected {} failed component(s)",
                failed_components.len()
            );
        }
        LivenessReport {
            status: if failed_components.is_empty() {
                "ok"
            } else {
                "fail"
            },
            version: self.inner.version,
            uptime_ms: now_mono_ms,
            failed_components,
            components,
        }
    }
}

pub fn register(registry: Option<&LivenessRegistry>, spec: ComponentSpec) -> LivenessHandle {
    registry
        .map(|registry| registry.register(spec))
        .unwrap_or_else(LivenessHandle::disabled)
}

#[derive(Clone, Default)]
pub struct LivenessHandle(Option<Arc<HandleInner>>);

struct HandleInner {
    registry: Weak<RegistryInner>,
    state: Arc<ComponentState>,
}

impl HandleInner {
    // Every state transition funnels through this helper so the report always carries
    // a consistent (event, timestamp, callsite) tuple.
    fn update(
        &self,
        running: Option<bool>,
        event: LivenessEvent,
        location: Option<&'static Location<'static>>,
    ) {
        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        let now_mono_ms = registry.mono_ms();
        if let Some(running) = running {
            self.state.running.store(running, Ordering::Relaxed);
        }
        self.state
            .last_heartbeat_mono_ms
            .store(now_mono_ms, Ordering::Relaxed);
        self.state.last_event.store(event as u8, Ordering::Relaxed);
        self.state.last_location.store(
            location
                .map(|loc| loc as *const Location<'static> as *mut Location<'static>)
                .unwrap_or(std::ptr::null_mut()),
            Ordering::Relaxed,
        );
        trace!(
            "liveness update: module={} id={} event={:?} running={:?}",
            self.state.id.module,
            self.state.id.id,
            event,
            running
        );
    }
}

impl Drop for HandleInner {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.deregister(self.state.id, self.state.generation);
        }
    }
}

impl LivenessHandle {
    pub fn disabled() -> Self {
        Self(None)
    }

    #[track_caller]
    pub fn heartbeat(&self) {
        if let Some(inner) = self.0.as_ref() {
            // The first heartbeat implicitly marks the component as running, which keeps
            // long-lived loops and short-lived worker threads on the same API.
            inner.update(
                Some(true),
                LivenessEvent::Heartbeat,
                Some(Location::caller()),
            );
        }
    }

    #[track_caller]
    pub fn pause(&self) {
        if let Some(inner) = self.0.as_ref() {
            inner.update(Some(false), LivenessEvent::Pause, Some(Location::caller()));
        }
    }

    pub fn set_timeout_ms(&self, timeout_ms: u64) {
        if let Some(inner) = self.0.as_ref() {
            inner.state.timeout_ms.store(timeout_ms, Ordering::Relaxed);
            trace!(
                "liveness timeout updated: module={} id={} timeout_ms={}",
                inner.state.id.module,
                inner.state.id.id,
                timeout_ms
            );
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SourceLocation {
    pub file: &'static str,
    pub line: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ComponentSnapshot {
    pub module: &'static str,
    pub id: u32,
    pub display_name: Cow<'static, str>,
    pub running: bool,
    pub required: bool,
    pub timeout_ms: u64,
    pub last_heartbeat_ago_ms: Option<u64>,
    pub last_event: Option<LivenessEvent>,
    pub last_location: Option<SourceLocation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LivenessReport {
    pub status: &'static str,
    pub version: &'static VersionInfo,
    pub uptime_ms: u64,
    pub failed_components: Vec<ComponentSnapshot>,
    pub components: Vec<ComponentSnapshot>,
}

pub struct LivenessServer {
    runtime: Arc<Runtime>,
    registry: LivenessRegistry,
    port: u16,
    running: AtomicBool,
    task: Mutex<Option<JoinHandle<()>>>,
    shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
}

impl LivenessServer {
    pub fn new(runtime: Arc<Runtime>, registry: LivenessRegistry, port: u16) -> Self {
        Self {
            runtime,
            registry,
            port,
            running: AtomicBool::new(false),
            task: Mutex::new(None),
            shutdown_tx: Mutex::new(None),
        }
    }

    pub fn start(&self) -> Result<(), hyper::Error> {
        if self.running.swap(true, Ordering::Relaxed) {
            return Ok(());
        }

        let _runtime_guard = self.runtime.enter();
        let addr = ([0, 0, 0, 0], self.port).into();
        let server_builder = match Server::try_bind(&addr) {
            Ok(builder) => builder,
            Err(e) => {
                self.running.store(false, Ordering::Relaxed);
                return Err(e);
            }
        };
        let registry = self.registry.clone();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        *self.shutdown_tx.lock() = Some(shutdown_tx);
        self.task.lock().replace(self.runtime.spawn(async move {
            let service = make_service_fn(move |_| {
                let registry = registry.clone();
                async move {
                    Ok::<_, Infallible>(service_fn(move |req| {
                        let registry = registry.clone();
                        async move { Ok::<_, Infallible>(Self::handle_request(registry, req)) }
                    }))
                }
            });

            info!("liveness probe listening on http://{addr}/livez");
            let server = server_builder.serve(service).with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            });
            if let Err(e) = server.await {
                error!("liveness probe server error: {e}");
            }
        }));
        Ok(())
    }

    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            return;
        }

        if let Some(tx) = self.shutdown_tx.lock().take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.lock().take() {
            let _ = self.runtime.block_on(task);
        }
    }

    fn handle_request(registry: LivenessRegistry, req: Request<Body>) -> Response<Body> {
        match (req.method(), req.uri().path()) {
            (&Method::GET, "/livez") => {
                let report = registry.report();
                let status = if report.status == "ok" {
                    StatusCode::OK
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                };
                match serde_json::to_vec(&report) {
                    Ok(body) => Response::builder()
                        .status(status)
                        .header(CONTENT_TYPE, "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                    Err(e) => Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from(format!(
                            r#"{{"status":"fail","error":"serialize liveness report failed: {e}"}}"#
                        )))
                        .unwrap(),
                }
            }
            _ => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Not Found"))
                .unwrap(),
        }
    }
}

impl Drop for LivenessServer {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use hyper::{body::to_bytes, Client, StatusCode};
    use serde_json::Value;

    use super::*;

    const TEST_VERSION_INFO: &VersionInfo = &VersionInfo {
        name: "deepflow-agent-ce",
        branch: "test",
        commit_id: "deadbeef",
        rev_count: "1",
        compiler: "",
        compile_time: "now",
        revision: "test 1-deadbeef",
    };

    #[test]
    fn duplicate_registration_replaces_state() {
        let registry = LivenessRegistry::new(TEST_VERSION_INFO);
        let first = registry.register(ComponentSpec {
            id: ComponentId::new("test", 1),
            display_name: "first".into(),
            timeout_ms: 1000,
            ..Default::default()
        });
        first.heartbeat();

        let second = registry.register(ComponentSpec {
            id: ComponentId::new("test", 1),
            display_name: "second".into(),
            timeout_ms: 2000,
            ..Default::default()
        });
        second.heartbeat();
        drop(first);

        let report = registry.report();
        assert_eq!(report.components.len(), 1);
        assert_eq!(report.components[0].display_name, "second");
        assert_eq!(report.components[0].timeout_ms, 2000);
    }

    #[test]
    fn handle_drop_deregisters_component() {
        let registry = LivenessRegistry::new(TEST_VERSION_INFO);
        let handle = registry.register(ComponentSpec {
            id: ComponentId::new("test", 2),
            display_name: "test".into(),
            timeout_ms: 1000,
            ..Default::default()
        });
        handle.heartbeat();
        assert_eq!(registry.report().components.len(), 1);

        drop(handle);

        assert!(registry.report().components.is_empty());
    }

    #[test]
    fn stopped_component_does_not_fail_liveness() {
        let registry = LivenessRegistry::new(TEST_VERSION_INFO);
        let handle = registry.register(ComponentSpec {
            id: ComponentId::new("test", 3),
            display_name: "test".into(),
            timeout_ms: 0,
            ..Default::default()
        });
        handle.heartbeat();
        handle.pause();

        let report = registry.report();
        assert_eq!(report.status, "ok");
        assert!(!report.components[0].running);
    }

    #[test]
    fn http_server_returns_liveness_report() {
        let runtime = Arc::new(Runtime::new().unwrap());
        let registry = LivenessRegistry::new(TEST_VERSION_INFO);
        let handle = registry.register(ComponentSpec {
            id: ComponentId::new("test", 4),
            display_name: "test".into(),
            timeout_ms: 60_000,
            ..Default::default()
        });
        handle.heartbeat();
        assert_eq!(registry.report().status, "ok");

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let server = LivenessServer::new(runtime.clone(), registry.clone(), port);
        server.start().unwrap();

        let client = Client::new();
        let response = runtime.block_on(async move {
            client
                .get(format!("http://127.0.0.1:{port}/livez").parse().unwrap())
                .await
                .unwrap()
        });
        assert_eq!(response.status(), StatusCode::OK);
        let body = runtime.block_on(async { to_bytes(response.into_body()).await.unwrap() });
        let report: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(report["status"], "ok");
        assert_eq!(report["version"]["commit_id"], "deadbeef");
        assert_eq!(report["components"].as_array().unwrap().len(), 1);
    }
}
