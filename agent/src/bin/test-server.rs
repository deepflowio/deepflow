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

use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fs, io};

use clap::Parser;
use tonic::{codec::Streaming, transport::Server, Request, Response, Status};

use deepflow_agent::config::UserConfig;
use public::proto::agent::*;

#[derive(Debug, Default, Clone, PartialEq, clap::ValueEnum)]
enum Detail {
    #[default]
    None,
    All,
    Sync,
    Push,
    Upgrade,
    Query,
    GenesisSync,
    KubernetesApiSync,
    GpidSync,
    ShareGpidLocalData,
    Plugin,
    RemoteExecute,
    GetKubernetesClusterId,
}

#[derive(Parser, Debug, Default)]
pub struct Config {
    /// Specify agent config file location
    #[clap(
        short = 'f',
        visible_short_alias = 'c',
        long,
        default_value = "./agent-config.yaml"
    )]
    agent_config_path: String,
    /// Specify agent dynamic config file location(use UserConfig.global.common)
    #[clap(short = 'd', long, default_value = "./agent-dynamic-config.yaml")]
    agent_dynamiconfig_path: String,
    /// Agent dynamic config update interval, setting 0 will not be updated
    #[clap(short = 'i', long, default_value_t = 0)]
    agent_config_update_interval: u64,
    /// Displays the details of the agent information
    #[clap(short = 's', long, value_enum, default_value_t = Detail::None)]
    detail: Detail,
}

#[derive(Debug, Default)]
pub struct TestServer {
    config: Config,

    agent_config: Arc<RwLock<UserConfig>>,
    agent_config_yaml: Arc<RwLock<String>>,
    last_update_config: Arc<RwLock<Duration>>,
}

impl TestServer {
    fn update_agent_config(&self) {
        let mut config = self.agent_config.write().unwrap();
        let mut config_yaml = self.agent_config_yaml.write().unwrap();

        let contents = fs::read_to_string(&self.config.agent_config_path)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Agent config error {} with path {}",
                        e.to_string(),
                        self.config.agent_config_path
                    ),
                )
            })
            .unwrap();
        *config = serde_yaml::from_str(contents.as_str())
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Agent config error {} with contents {}",
                        e.to_string(),
                        contents
                    ),
                )
            })
            .unwrap();
        *config_yaml = contents;
        let contents = fs::read_to_string(&self.config.agent_dynamiconfig_path)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Agent dynamic config error {} with path {}",
                        e.to_string(),
                        self.config.agent_config_path
                    ),
                )
            })
            .unwrap();
        config.global.common.update(
            serde_yaml::from_str(contents.as_str())
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "Agent dynamic config error {} with contents {}",
                            e.to_string(),
                            contents
                        ),
                    )
                })
                .unwrap(),
        );
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        println!("Config update at {:?}", now);
        *self.last_update_config.write().unwrap() = now;
    }

    fn check_agent_config(&self) {
        if self.config.agent_config_update_interval == 0 {
            return;
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let last = *self.last_update_config.read().unwrap();
        let timeout = Duration::from_secs(self.config.agent_config_update_interval);

        if now - last >= timeout {
            self.update_agent_config();
        }
    }

    fn set_config(&mut self, config: Config) {
        self.config = config;

        self.update_agent_config();
    }

    fn do_show_detail(&self, detail: Detail) -> bool {
        self.config.detail == detail || self.config.detail == Detail::All
    }

    fn generate_sync_response(&self, revision: Option<String>) -> SyncResponse {
        let config = self.agent_config.read().unwrap();
        let common = &config.global.common;
        SyncResponse {
            status: Some(0),
            user_config: Some(self.agent_config_yaml.read().unwrap().clone()),
            revision,
            self_update_url: None,
            version_platform_data: Some(self.last_update_config.read().unwrap().as_secs()),
            version_acls: Some(self.last_update_config.read().unwrap().as_secs()),
            version_groups: Some(self.last_update_config.read().unwrap().as_secs()),
            containers: vec![],
            local_segments: vec![],
            remote_segments: vec![],
            platform_data: None,
            flow_acls: None,
            groups: None,
            capture_network_types: vec![],
            skip_interface: vec![],
            dynamic_config: Some(DynamicConfig {
                kubernetes_api_enabled: Some(common.kubernetes_api_enabled),
                enabled: Some(common.enabled),
                region_id: Some(common.region_id),
                pod_cluster_id: Some(common.pod_cluster_id),
                vpc_id: Some(common.vpc_id),
                agent_id: Some(common.agent_id),
                team_id: Some(common.team_id),
                organize_id: Some(common.organize_id),
                agent_type: Some(common.agent_type.into()),
                secret_key: Some(common.secret_key.clone()),
                hostname: Some("testsrv-agent-01".to_string()),
                group_id: None,
            }),
        }
    }
}

#[tonic::async_trait]
impl synchronizer_server::Synchronizer for TestServer {
    type PushStream = Streaming<SyncResponse>;
    type UpgradeStream = Streaming<UpgradeResponse>;
    type PluginStream = Streaming<PluginResponse>;
    type RemoteExecuteStream = Streaming<RemoteExecRequest>;

    async fn sync(&self, request: Request<SyncRequest>) -> Result<Response<SyncResponse>, Status> {
        self.check_agent_config();

        let sync_request = request.get_ref();
        let version = sync_request.revision.clone();
        if self.do_show_detail(Detail::Sync) {
            println!("sync: {:?}", sync_request);
        }

        Ok(Response::new(self.generate_sync_response(version)))
    }

    async fn push(
        &self,
        request: Request<SyncRequest>,
    ) -> Result<Response<Self::PushStream>, Status> {
        self.check_agent_config();

        let sync_request = request.get_ref();
        if self.do_show_detail(Detail::Push) {
            println!("push: {:?}", sync_request);
        }

        Err(Status::unimplemented("server not support."))
    }

    async fn upgrade(
        &self,
        request: Request<UpgradeRequest>,
    ) -> Result<Response<Self::UpgradeStream>, Status> {
        self.check_agent_config();

        let upgrade_request = request.get_ref();
        if self.do_show_detail(Detail::Upgrade) {
            println!("upgrade: {:?}", upgrade_request);
        }

        Err(Status::unimplemented("server not support."))
    }

    async fn query(&self, request: Request<NtpRequest>) -> Result<Response<NtpResponse>, Status> {
        self.check_agent_config();

        let ntp_request = request.get_ref();
        if self.do_show_detail(Detail::Query) {
            println!("query: {:?}", ntp_request);
        }

        Err(Status::unimplemented("server not support."))
    }

    async fn genesis_sync(
        &self,
        request: Request<GenesisSyncRequest>,
    ) -> Result<Response<GenesisSyncResponse>, Status> {
        self.check_agent_config();

        let genesis_request = request.get_ref();
        let version = genesis_request.version.clone();
        if self.do_show_detail(Detail::GenesisSync) {
            println!("genesis_sync: {:?}", genesis_request);
        }

        Ok(Response::new(GenesisSyncResponse { version }))
    }

    async fn kubernetes_api_sync(
        &self,
        request: Request<KubernetesApiSyncRequest>,
    ) -> Result<Response<KubernetesApiSyncResponse>, Status> {
        self.check_agent_config();

        let k8s_api_request = request.get_ref();
        let version = k8s_api_request.version.clone();
        if self.do_show_detail(Detail::KubernetesApiSync) {
            println!("kubernetes_api_sync: {:?}", k8s_api_request);
        }

        Ok(Response::new(KubernetesApiSyncResponse { version }))
    }

    async fn gpid_sync(
        &self,
        request: Request<GpidSyncRequest>,
    ) -> Result<Response<GpidSyncResponse>, Status> {
        self.check_agent_config();

        let gpid_request = request.get_ref();
        if self.do_show_detail(Detail::GpidSync) {
            println!("gpid_sync: {:?}", gpid_request);
        }

        Err(Status::unimplemented("server not support."))
    }

    async fn share_gpid_local_data(
        &self,
        request: Request<ShareGpidSyncRequests>,
    ) -> Result<Response<ShareGpidSyncRequests>, Status> {
        self.check_agent_config();

        let gpid_request = request.get_ref();
        if self.do_show_detail(Detail::ShareGpidLocalData) {
            println!("share_gpid_local_data: {:?}", gpid_request);
        }

        Err(Status::unimplemented("server not support."))
    }

    async fn plugin(
        &self,
        request: Request<PluginRequest>,
    ) -> Result<Response<Self::PluginStream>, Status> {
        self.check_agent_config();

        let request = request.get_ref();
        if self.do_show_detail(Detail::Plugin) {
            println!("plugin: {:?}", request);
        }

        // loop {
        //     yield_now().await
        // }

        Err(Status::unimplemented("server not support."))
    }

    async fn remote_execute(
        &self,
        request: Request<Streaming<RemoteExecResponse>>,
    ) -> Result<Response<Self::RemoteExecuteStream>, Status> {
        self.check_agent_config();

        let request = request.get_ref();
        if self.do_show_detail(Detail::RemoteExecute) {
            println!("remote_execute: {:?}", request);
        }

        // loop {
        //     yield_now().await
        // }

        Err(Status::unimplemented("server not support."))
    }

    async fn get_kubernetes_cluster_id(
        &self,
        request: Request<KubernetesClusterIdRequest>,
    ) -> Result<Response<KubernetesClusterIdResponse>, Status> {
        self.check_agent_config();

        let request = request.get_ref();
        if self.do_show_detail(Detail::GetKubernetesClusterId) {
            println!("get_kubernetes_cluster_id: {:?}", request);
        }

        Ok(Response::new(KubernetesClusterIdResponse {
            error_msg: None,
            cluster_id: None,
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "0.0.0.0:30035".parse()?;
    let mut server = TestServer::default();
    let config = Config::parse();

    server.set_config(config);

    println!("Server listening on {}", addr);
    Server::builder()
        .add_service(synchronizer_server::SynchronizerServer::new(server))
        .serve(addr)
        .await?;

    Ok(())
}
