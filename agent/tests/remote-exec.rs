/*
 * Copyright (c) 2026 Yunshan Networks
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
    fs::File,
    io::{ErrorKind, Read},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};

use log::trace;
use md5::{Digest, Md5};
use parking_lot::RwLock;
use prost::Message;
use rand::Rng;
use tokio::{runtime::Runtime, sync::mpsc, task::JoinHandle};
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt};
use tonic::{transport::Server as TonicServer, Request, Response, Status, Streaming};

use deepflow_agent::{
    config::{config::Config, handler::ConfigHandler},
    exception::ExceptionHandler,
    rpc::{Executor, Session, DEFAULT_TIMEOUT},
    trident::AgentId,
    utils::{environment::get_ctrl_ip_and_mac, hasher::md5_to_string, stats},
};

use public::{
    bytes::read_u32_be,
    proto::{
        agent::{
            self,
            synchronizer_server::{Synchronizer, SynchronizerServer},
        },
        flow_log,
    },
    utils::net::IpMacPair,
};

struct ServiceImpl {
    pcap_path: PathBuf,
    result_tx: mpsc::Sender<Option<flow_log::AppProtoLogsData>>,
}

#[tonic::async_trait]
impl Synchronizer for ServiceImpl {
    type PushStream = Streaming<agent::SyncResponse>;
    type UpgradeStream = Streaming<agent::UpgradeResponse>;
    type PluginStream = Streaming<agent::PluginResponse>;
    type RemoteExecuteStream =
        Pin<Box<dyn Stream<Item = Result<agent::RemoteExecRequest, Status>> + Send>>;

    async fn sync(
        &self,
        _request: Request<agent::SyncRequest>,
    ) -> Result<Response<agent::SyncResponse>, Status> {
        unimplemented!()
    }

    async fn push(
        &self,
        _request: Request<agent::SyncRequest>,
    ) -> Result<Response<Self::PushStream>, Status> {
        unimplemented!()
    }

    async fn upgrade(
        &self,
        _request: Request<agent::UpgradeRequest>,
    ) -> Result<Response<Self::UpgradeStream>, Status> {
        unimplemented!()
    }

    async fn query(
        &self,
        _request: Request<agent::NtpRequest>,
    ) -> Result<Response<agent::NtpResponse>, Status> {
        unimplemented!()
    }

    async fn plugin(
        &self,
        _request: Request<agent::PluginRequest>,
    ) -> Result<Response<Self::PluginStream>, Status> {
        unimplemented!()
    }

    async fn get_kubernetes_cluster_id(
        &self,
        _request: Request<agent::KubernetesClusterIdRequest>,
    ) -> Result<Response<agent::KubernetesClusterIdResponse>, Status> {
        unimplemented!()
    }

    async fn genesis_sync(
        &self,
        _request: Request<agent::GenesisSyncRequest>,
    ) -> Result<Response<agent::GenesisSyncResponse>, Status> {
        unimplemented!()
    }

    async fn kubernetes_api_sync(
        &self,
        _request: Request<agent::KubernetesApiSyncRequest>,
    ) -> Result<Response<agent::KubernetesApiSyncResponse>, Status> {
        unimplemented!()
    }

    async fn gpid_sync(
        &self,
        _request: Request<agent::GpidSyncRequest>,
    ) -> Result<Response<agent::GpidSyncResponse>, Status> {
        unimplemented!()
    }

    async fn share_gpid_local_data(
        &self,
        _request: Request<agent::ShareGpidSyncRequests>,
    ) -> Result<Response<agent::ShareGpidSyncRequests>, Status> {
        unimplemented!()
    }

    async fn remote_execute(
        &self,
        request: Request<tonic::Streaming<agent::RemoteExecResponse>>,
    ) -> Result<Response<Self::RemoteExecuteStream>, Status> {
        let mut istream = request.into_inner();
        let (tx, rx) = mpsc::channel(128);
        let mut pcap_sent = false;
        let pcap_path = self.pcap_path.clone();
        let result_tx = self.result_tx.clone();

        tokio::spawn(async move {
            let mut decode_buffer = vec![];
            let mut digest = Md5::new();
            let mut complete = false;
            while let Some(result) = istream.next().await {
                let Ok(resp) = result else {
                    break;
                };
                if resp.command_result.is_none() {
                    if pcap_sent {
                        tx.send(Ok(agent::RemoteExecRequest::default()))
                            .await
                            .unwrap();
                    } else {
                        pcap_sent = true;
                        Self::send_pcap(pcap_path.as_path(), &tx).await;
                    }
                    continue;
                }
                let data = resp.command_result.unwrap();
                trace!(
                    "received content length {}",
                    data.content.as_ref().map(|c| c.len()).unwrap_or(0)
                );
                match data.content {
                    Some(content) if !content.is_empty() => {
                        digest.update(&content[..]);
                        decode_buffer.extend(content);
                    }
                    _ => (),
                }
                if let Some(md5) = data.md5 {
                    assert_eq!(md5_to_string(&mut digest), md5);
                    complete = true;
                }
                Self::handle_l7_log(&mut decode_buffer, &result_tx).await;
                if complete {
                    result_tx.send(None).await.unwrap();
                    break;
                }
            }
        });

        let ostream = ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(ostream) as Self::RemoteExecuteStream))
    }
}

impl ServiceImpl {
    async fn send_pcap(
        pcap_path: &Path,
        tx: &mpsc::Sender<Result<agent::RemoteExecRequest, Status>>,
    ) {
        let mut fp = File::open(pcap_path).unwrap();
        let mut md5 = Md5::new();
        let mut buffer = [0; 1024];
        loop {
            let n = rand::thread_rng().gen_range(1..=1024);
            let read = match fp.read(&mut buffer[..n]) {
                Ok(read) => read,
                Err(e) if e.kind() == ErrorKind::Interrupted => {
                    continue;
                }
                Err(e) => panic!("unexpected read error: {:?}", e),
            };
            if read > 0 {
                md5.update(&buffer[..read]);
            }
            trace!("sending {read} bytes pcap chunk");
            tx.send(Ok(agent::RemoteExecRequest {
                request_id: Some(42),
                batch_len: Some(1024),
                exec_type: Some(agent::ExecutionType::DryReplayPcap.into()),
                command_data: Some(agent::DataChunk {
                    content: Some(buffer[..read].to_vec()),
                    md5: if read == 0 || read < n {
                        Some(md5_to_string(&mut md5))
                    } else {
                        None
                    },
                    ..Default::default()
                }),
                ..Default::default()
            }))
            .await
            .unwrap();

            if read == 0 || read < n {
                break;
            }
        }
    }

    async fn handle_l7_log(
        buffer: &mut Vec<u8>,
        result_tx: &mpsc::Sender<Option<flow_log::AppProtoLogsData>>,
    ) {
        loop {
            let Some(length) = buffer.get(..4) else {
                return;
            };
            let length = read_u32_be(length) as usize;
            if 4 + length > buffer.len() {
                return;
            }
            trace!("received {length} bytes l7 log");

            let l7_log = flow_log::AppProtoLogsData::decode(&buffer[4..4 + length]).unwrap();

            trace!("l7 log: {:?}", l7_log);
            result_tx.send(Some(l7_log)).await.unwrap();

            buffer.drain(..4 + length);
        }
    }
}

struct TestHandle {
    rt: Arc<Runtime>,
    config: Config,

    executor: Option<Executor>,
    server_handle: Option<JoinHandle<()>>,

    pcap_path: PathBuf,
    result_tx: mpsc::Sender<Option<flow_log::AppProtoLogsData>>,
}

impl TestHandle {
    pub fn start_server(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let server_ip: IpAddr = self.config.controller_ips[0].parse().unwrap();
        let addr = SocketAddr::from((server_ip, self.config.controller_port));
        let service_impl = ServiceImpl {
            pcap_path: self.pcap_path.clone(),
            result_tx: self.result_tx.clone(),
        };
        let srv = self.rt.spawn(async move {
            TonicServer::builder()
                .add_service(SynchronizerServer::new(service_impl))
                .serve(addr)
                .await
                .unwrap();
        });
        self.server_handle = Some(srv);
        Ok(())
    }

    pub fn start_executor(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let exc = ExceptionHandler::default();
        let stats_collector = Arc::new(stats::Collector::new("localhost", Default::default()));
        let session = Arc::new(Session::new(
            self.config.controller_port,
            0,
            DEFAULT_TIMEOUT,
            "".to_owned(),
            self.config.controller_ips.clone(),
            exc.clone(),
            &stats_collector,
        ));

        let agent_id = Arc::new(RwLock::new(AgentId {
            ipmac: IpMacPair::default(),
            team_id: "example-team".to_owned(),
            group_id: "example-group".to_owned(),
        }));

        let server_ip = self.config.controller_ips[0].parse().unwrap();
        let (ctrl_ip, ctrl_mac) = get_ctrl_ip_and_mac(&server_ip).unwrap();
        let config_handler = ConfigHandler::new(self.config.clone(), ctrl_ip, ctrl_mac);

        let executor = Executor::new(
            agent_id,
            session.clone(),
            self.rt.clone(),
            exc,
            config_handler.flow(),
            config_handler.log_parser(),
        );
        self.rt.block_on(async move {
            session.update_current_server().await;
        });
        executor.start();
        self.executor = Some(executor);
        Ok(())
    }
}

#[test]
fn dry_replay_pcap() {
    let (result_tx, mut result_rx) = mpsc::channel(128);
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap(),
    );
    let mut handle = TestHandle {
        rt: rt.clone(),
        config: Config {
            controller_ips: vec!["127.0.0.1".to_owned()],
            controller_port: 34000,
            ..Default::default()
        },
        executor: None,
        server_handle: None,
        pcap_path: PathBuf::from("resources/test/flow_generator/http/sw8.pcap"),
        result_tx,
    };
    handle.start_server().unwrap();
    handle.start_executor().unwrap();
    let results = rt.block_on(async move {
        let mut results = vec![];
        while let Some(result) = result_rx.recv().await {
            match result {
                None => break,
                Some(result) => results.push(result),
            }
        }
        results
    });
    assert_eq!(results.len(), 6);
    assert_eq!(
        results[0]
            .base
            .as_ref()
            .unwrap()
            .head
            .as_ref()
            .unwrap()
            .proto,
        public::l7_protocol::L7Protocol::Http1 as u32
    );
    assert_eq!(
        results[1]
            .base
            .as_ref()
            .unwrap()
            .head
            .as_ref()
            .unwrap()
            .msg_type,
        public::l7_protocol::LogMessageType::Response as u32
    );
    assert_eq!(results[2].req.as_ref().unwrap().endpoint, "/createOrder");
    assert_eq!(results[3].resp.as_ref().unwrap().code, 200);
    assert_eq!(
        results[4].trace_info.as_ref().unwrap().trace_ids[0],
        "3912196de0cf41f4bab8a8a8108fc3a8.56.16294441349520027"
    );
    assert_eq!(results[5].base.as_ref().unwrap().port_src, 20880);
}
