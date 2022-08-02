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

use std::fs;
use std::io;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use log::{error, info, warn};
use md5::{Digest, Md5};
use serde::Deserialize;
use thiserror::Error;
use tokio::runtime::Runtime;

use crate::common::decapsulate::TunnelType;
use crate::common::{
    enums::TapType, DEFAULT_LOG_FILE, L7_PROTOCOL_INFERENCE_MAX_FAIL_COUNT,
    L7_PROTOCOL_INFERENCE_TTL,
};
use crate::proto::{
    common,
    trident::{self, KubernetesClusterIdRequest},
};
use crate::rpc::Session;

const K8S_CA_CRT_PATH: &str = "/run/secrets/kubernetes.io/serviceaccount/ca.crt";
const MINUTE: Duration = Duration::from_secs(60);

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("controller-ips is empty")]
    ControllerIpsEmpty,
    #[error("controller-ips invalid")]
    ControllerIpsInvalid,
    #[error("runtime config invalid: {0}")]
    RuntimeConfigInvalid(String),
    #[error("yaml config invalid: {0}")]
    YamlConfigInvalid(String),
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default, rename_all = "kebab-case")]
pub struct Config {
    pub controller_ips: Vec<String>,
    pub controller_port: u16,
    pub controller_tls_port: u16,
    pub controller_cert_file_prefix: String,
    pub log_file: String,
    pub kubernetes_cluster_id: String,
    pub vtap_group_id_request: String,
    pub controller_domain_name: Vec<String>,
}

impl Config {
    pub fn load_from_file<T: AsRef<Path>>(path: T) -> Result<Self, ConfigError> {
        let contents =
            fs::read_to_string(path).map_err(|e| ConfigError::YamlConfigInvalid(e.to_string()))?;
        Self::load(&contents)
    }

    pub fn load<C: AsRef<str>>(contents: C) -> Result<Self, ConfigError> {
        let contents = contents.as_ref();
        if contents.len() == 0 {
            // parsing empty string leads to EOF error
            Ok(Self::default())
        } else {
            let mut cfg: Self = serde_yaml::from_str(contents)
                .map_err(|e| ConfigError::YamlConfigInvalid(e.to_string()))?;

            for i in 0..cfg.controller_ips.len() {
                if cfg.controller_ips[i].parse::<IpAddr>().is_err() {
                    let ip = resolve_domain(&cfg.controller_ips[i]);
                    if ip.is_none() {
                        return Err(ConfigError::ControllerIpsInvalid);
                    }

                    cfg.controller_domain_name
                        .push(cfg.controller_ips[i].clone());
                    cfg.controller_ips[i] = ip.unwrap();
                }
            }

            Ok(cfg)
        }
    }

    // 目的是为了k8s采集器configmap中不配置k8s-cluster-id也能实现注册。
    // 如果agent在容器中运行且ConfigMap中kubernetes-cluster-id为空,
    // 调用GetKubernetesClusterID RPC，获取cluster-id, 如果RPC调用失败，sleep 1分钟后再次调用，直到成功
    // ======================================================================================================
    // The purpose is to enable registration without configuring k8s-cluster-id in the k8s collector configmap.
    // If agent is running in container and the kubernetes-cluster-id in the
    // ConfigMap is empty, Call GetKubernetesClusterID RPC to get the cluster-id, if the RPC call fails, call it again
    // after 1 minute of sleep until it succeeds
    pub fn get_k8s_cluster_id(session: &Session) -> String {
        let ca_md5 = loop {
            match fs::read_to_string(K8S_CA_CRT_PATH) {
                Ok(c) => {
                    break Some(
                        Md5::digest(c.as_bytes())
                            .into_iter()
                            .fold(String::new(), |s, c| s + &format!("{:02x}", c)),
                    );
                }
                Err(e) => {
                    error!(
                        "get kubernetes_cluster_id error: failed to read {} error: {}",
                        K8S_CA_CRT_PATH, e
                    );
                    thread::sleep(MINUTE);
                }
            }
        };
        let runtime = Runtime::new().unwrap();
        runtime.block_on(async {
            loop {
                session.update_current_server().await;
                let client = match session.get_client() {
                    Some(c) => c,
                    None => {
                        session.set_request_failed(true);
                        warn!("rpc client not connected");
                        tokio::time::sleep(MINUTE).await;
                        continue;
                    }
                };
                let mut client = trident::synchronizer_client::SynchronizerClient::new(client);
                let request = KubernetesClusterIdRequest {
                    ca_md5: ca_md5.clone(),
                };

                match client.get_kubernetes_cluster_id(request).await {
                    Ok(response) => {
                        let cluster_id_response = response.into_inner();
                        if !cluster_id_response.error_msg().is_empty() {
                            error!(
                                "failed to get kubernetes_cluster_id from server error: {}",
                                cluster_id_response.error_msg()
                            );
                            tokio::time::sleep(MINUTE).await;
                            continue;
                        }
                        match cluster_id_response.cluster_id {
                            Some(id) => {
                                if id.is_empty() {
                                    error!("call get_kubernetes_cluster_id return cluster_id is empty string");
                                    tokio::time::sleep(MINUTE).await;
                                    continue;
                                }
                                info!("set kubernetes_cluster_id to {}", id);
                                return id;
                            }
                            None => {
                                error!("call get_kubernetes_cluster_id return response is none")
                            }
                        }
                    }
                    Err(e) => error!("failed to call get_kubernetes_cluster_id error: {}", e),
                }
                tokio::time::sleep(MINUTE).await;
            }
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            controller_ips: vec![],
            controller_port: 30035,
            controller_tls_port: 30135,
            controller_cert_file_prefix: "".into(),
            log_file: DEFAULT_LOG_FILE.into(),
            kubernetes_cluster_id: "".into(),
            vtap_group_id_request: "".into(),
            controller_domain_name: vec![],
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct YamlConfig {
    #[serde(with = "LevelDef")]
    pub log_level: log::Level,
    pub profiler: bool,
    #[serde(alias = "afpacket-blocks-enabled")]
    pub af_packet_blocks_enabled: bool,
    #[serde(alias = "afpacket-blocks")]
    pub af_packet_blocks: usize,
    pub enable_debug_stats: bool,
    pub analyzer_dedup_disabled: bool,
    pub default_tap_type: u32,
    pub debug_listen_port: u16,
    pub enable_qos_bypass: bool,
    pub fast_path_map_size: usize,
    pub first_path_level: u32,
    pub src_interfaces: Vec<String>,
    #[serde(with = "TapModeDef")]
    pub tap_mode: trident::TapMode,
    pub mirror_traffic_pcp: u16,
    pub vtap_group_id_request: String,
    pub pcap: PcapConfig,
    pub flow: FlowGeneratorConfig,
    pub flow_queue_size: usize,
    pub quadruple_queue_size: usize,
    pub analyzer_queue_size: usize,
    #[serde(rename = "ovs-dpdk-enable")]
    pub ovs_dpdk_enabled: bool,
    pub dpdk_pmd_core_id: u32,
    pub dpdk_ring_port: String,
    pub xflow_collector: XflowGeneratorConfig,
    pub vxlan_port: u16,
    pub collector_sender_queue_size: usize,
    pub collector_sender_queue_count: usize,
    pub flow_sender_queue_size: usize,
    pub flow_sender_queue_count: usize,
    #[serde(with = "humantime_serde")]
    pub second_flow_extra_delay: Duration,
    #[serde(with = "humantime_serde")]
    pub packet_delay: Duration,
    pub triple: TripleMapConfig,
    pub kubernetes_poller_type: KubernetesPollerType,
    pub decap_erspan: bool,
    pub analyzer_ip: String,
    pub ingress_flavour: IngressFlavour,
    pub grpc_buffer_size: usize,
    #[serde(with = "humantime_serde")]
    pub l7_log_session_aggr_timeout: Duration,
    pub tap_mac_script: String,
    pub cloud_gateway_traffic: bool,
    pub ebpf_log_file: String,
    pub kubernetes_namespace: String,
    pub external_metrics_sender_queue_size: usize,
    pub l7_protocol_inference_max_fail_count: usize,
    pub l7_protocol_inference_ttl: usize,
    pub packet_sequence_block_size: usize, // Enterprise Edition Feature: packet-sequence
    pub packet_sequence_queue_size: usize, // Enterprise Edition Feature: packet-sequence
    pub packet_sequence_queue_count: usize, // Enterprise Edition Feature: packet-sequence
    pub packet_sequence_flag: u8,          // Enterprise Edition Feature: packet-sequence
}

impl YamlConfig {
    pub fn load_from_file<T: AsRef<Path>>(path: T) -> Result<Self, io::Error> {
        let contents = fs::read_to_string(path)?;
        Self::load(&contents)
    }

    pub fn load<C: AsRef<str>>(contents: C) -> Result<Self, io::Error> {
        let contents = contents.as_ref();
        let mut c = if contents.len() == 0 {
            // parsing empty string leads to EOF error
            Self::default()
        } else {
            serde_yaml::from_str(contents)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?
        };

        if c.pcap.queue_size < 1 << 16 {
            c.pcap.queue_size = 1 << 16;
        }
        if c.pcap.queue_count < 1 || c.pcap.queue_count > 16 {
            c.pcap.queue_count = 1;
        } else {
            c.pcap.queue_count = c.pcap.queue_count.next_power_of_two();
        }
        if c.flow.flush_interval < Duration::from_secs(1)
            || c.flow.flush_interval > Duration::from_secs(10)
        {
            c.flow.flush_interval = Duration::from_secs(1);
        }
        if c.flow_queue_size < 1 << 16 {
            c.flow_queue_size = 1 << 16;
        }
        if c.quadruple_queue_size < 1 << 18 {
            c.quadruple_queue_size = 1 << 18;
        }
        if c.analyzer_queue_size < 1 << 17 {
            c.analyzer_queue_size = 1 << 17;
        }
        if c.collector_sender_queue_size == 0 {
            c.collector_sender_queue_size = if c.tap_mode == trident::TapMode::Analyzer {
                8 << 20
            } else {
                1 << 16
            }
        }
        if c.flow_sender_queue_size == 0 {
            c.flow_sender_queue_size = if c.tap_mode == trident::TapMode::Analyzer {
                8 << 20
            } else {
                1 << 16
            }
        }
        if c.packet_delay < Duration::from_secs(1) || c.packet_delay > Duration::from_secs(10) {
            c.packet_delay = Duration::from_secs(1);
        }
        if c.first_path_level < 1 || c.first_path_level > 16 {
            c.first_path_level = 8;
        }

        // L7Log Session timeout must more than or equal 10s to keep window
        if c.l7_log_session_aggr_timeout.as_secs() < 10 {
            c.l7_log_session_aggr_timeout = Duration::from_secs(10);
        }

        if c.external_metrics_sender_queue_size == 0 {
            c.external_metrics_sender_queue_size = 1 << 12;
        }

        if c.l7_protocol_inference_max_fail_count == 0 {
            c.l7_protocol_inference_max_fail_count = L7_PROTOCOL_INFERENCE_MAX_FAIL_COUNT;
        }

        if c.l7_protocol_inference_ttl == 0 {
            c.l7_protocol_inference_ttl = L7_PROTOCOL_INFERENCE_TTL;
        }

        // Enterprise Edition Feature: packet-sequence
        if c.packet_sequence_block_size <= 0 || c.packet_sequence_block_size >= 1024 {
            c.packet_sequence_block_size = 64;
        }

        // Enterprise Edition Feature: packet-sequence
        if c.packet_sequence_queue_size == 0 {
            if c.tap_mode == trident::TapMode::Analyzer {
                c.packet_sequence_queue_size = 8 << 20;
            } else {
                c.packet_sequence_queue_size = 1 << 16;
            }
        }

        // Enterprise Edition Feature: packet-sequence
        if c.packet_sequence_queue_count == 0 {
            c.packet_sequence_queue_count = 1;
        }

        if let Err(e) = c.validate() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, e.to_string()));
        }
        Ok(c)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        Ok(())
    }
}

impl Default for YamlConfig {
    fn default() -> Self {
        Self {
            log_level: log::Level::Info,
            profiler: false,
            af_packet_blocks_enabled: false,
            af_packet_blocks: 0,
            enable_debug_stats: false,
            analyzer_dedup_disabled: false,
            default_tap_type: 3,
            debug_listen_port: 0,
            enable_qos_bypass: false,
            fast_path_map_size: 1 << 14,
            first_path_level: 0,
            src_interfaces: vec![],
            tap_mode: trident::TapMode::Local,
            mirror_traffic_pcp: 0,
            vtap_group_id_request: "".into(),
            pcap: Default::default(),
            flow: Default::default(),
            flow_queue_size: 65536,
            quadruple_queue_size: 262144,
            analyzer_queue_size: 131072,
            ovs_dpdk_enabled: false,
            dpdk_pmd_core_id: 0,
            dpdk_ring_port: "dpdkr0".into(),
            xflow_collector: Default::default(),
            vxlan_port: 4789,
            // default size changes according to tap_mode
            collector_sender_queue_size: 0,
            collector_sender_queue_count: 1,
            // default size changes according to tap_mode
            flow_sender_queue_size: 0,
            flow_sender_queue_count: 1,
            second_flow_extra_delay: Duration::from_secs(0),
            packet_delay: Duration::from_secs(1),
            triple: Default::default(),
            kubernetes_poller_type: KubernetesPollerType::Adaptive,
            decap_erspan: false,
            analyzer_ip: "".into(),
            ingress_flavour: IngressFlavour::Kubernetes,
            grpc_buffer_size: 5,
            l7_log_session_aggr_timeout: Duration::from_secs(120),
            tap_mac_script: "".into(),
            cloud_gateway_traffic: false,
            ebpf_log_file: "".into(),
            kubernetes_namespace: "".into(),
            external_metrics_sender_queue_size: 0,
            l7_protocol_inference_max_fail_count: L7_PROTOCOL_INFERENCE_MAX_FAIL_COUNT,
            l7_protocol_inference_ttl: L7_PROTOCOL_INFERENCE_TTL,
            packet_sequence_block_size: 64, // Enterprise Edition Feature: packet-sequence
            packet_sequence_queue_size: 0,  // Enterprise Edition Feature: packet-sequence
            packet_sequence_queue_count: 1, // Enterprise Edition Feature: packet-sequence
            packet_sequence_flag: 0,        // Enterprise Edition Feature: packet-sequence
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(remote = "log::Level", rename_all = "kebab-case")]
enum LevelDef {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(remote = "trident::TapMode")]
enum TapModeDef {
    #[serde(rename = "0")]
    Local,
    #[serde(rename = "1")]
    Mirror,
    #[serde(rename = "2")]
    Analyzer,
    #[serde(rename = "3")]
    Decap,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct PortConfig {
    pub analyzer_port: u16,
    pub proxy_controller_port: u16,
}

impl Default for PortConfig {
    fn default() -> Self {
        let config = trident::Config {
            ..Default::default()
        };
        PortConfig {
            analyzer_port: config.analyzer_port.unwrap() as u16,
            proxy_controller_port: config.proxy_controller_port.unwrap() as u16,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct PcapConfig {
    pub enabled: bool,
    pub queue_size: u32,
    pub queue_count: u32,
    pub tcpip_checksum: bool,
    pub block_size_kb: u32,
    pub max_concurrent_files: u32,
    pub max_file_size_mb: u32,
    pub max_directory_size_gb: u32,
    pub disk_free_space_margin_gb: u32,
    #[serde(with = "humantime_serde")]
    pub max_file_period: Duration,
    pub file_directory: PathBuf,
    pub server_port: u32,
}

impl Default for PcapConfig {
    fn default() -> Self {
        PcapConfig {
            enabled: false,
            queue_size: 65536,
            queue_count: 1,
            tcpip_checksum: false,
            block_size_kb: 64,
            max_concurrent_files: 5000,
            max_file_size_mb: 250,
            max_directory_size_gb: 100,
            disk_free_space_margin_gb: 10,
            max_file_period: Duration::from_secs(300),
            file_directory: "/var/lib/pcap".into(),
            server_port: 20205,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct FlowGeneratorConfig {
    // tcp timeout config
    #[serde(with = "humantime_serde")]
    pub established_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub closing_rst_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub others_timeout: Duration,

    #[serde(rename = "flow-slots-size")]
    pub hash_slots: u32,
    #[serde(rename = "flow-count-limit")]
    pub capacity: u32,
    #[serde(with = "humantime_serde")]
    pub flush_interval: Duration,
    #[serde(rename = "flow-sender-throttle")]
    pub sender_throttle: u32,
    #[serde(rename = "flow-aggr-queue-size")]
    pub aggr_queue_size: u32,

    pub ignore_tor_mac: bool,
    pub ignore_l2_end: bool,
}

impl Default for FlowGeneratorConfig {
    fn default() -> Self {
        FlowGeneratorConfig {
            established_timeout: Duration::from_secs(300),
            closing_rst_timeout: Duration::from_secs(35),
            others_timeout: Duration::from_secs(5),

            hash_slots: 131072,
            capacity: 1048576,
            flush_interval: Duration::from_secs(1),
            sender_throttle: 1024,
            aggr_queue_size: 65535,

            ignore_tor_mac: false,
            ignore_l2_end: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct XflowGeneratorConfig {
    pub sflow_ports: Vec<String>,
    pub netflow_ports: Vec<String>,
}

impl Default for XflowGeneratorConfig {
    fn default() -> Self {
        XflowGeneratorConfig {
            sflow_ports: vec!["6343".into()],
            netflow_ports: vec!["2055".into()],
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct TripleMapConfig {
    #[serde(rename = "flow-slots-size")]
    pub hash_slots: u32,
    pub capacity: u32,
}

impl Default for TripleMapConfig {
    fn default() -> Self {
        TripleMapConfig {
            hash_slots: 65536,
            capacity: 1048576,
        }
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
pub enum KubernetesPollerType {
    Adaptive,
    Active,
    Passive,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum IngressFlavour {
    Kubernetes,
    Openshift,
}

#[derive(Debug)]
pub struct RuntimeConfig {
    pub enabled: bool,
    pub max_cpus: u32,
    pub max_memory: u64,
    pub sync_interval: Duration,
    pub stats_interval: Duration,
    pub global_pps_threshold: u64,
    pub tap_interface_regex: String,
    pub host: String,
    pub rsyslog_enabled: bool,
    pub output_vlan: u16,
    pub mtu: u32,
    pub npb_bps_threshold: u64,
    pub collector_enabled: bool,
    pub l4_log_store_tap_types: [bool; 256],
    pub app_proto_log_enabled: bool,
    pub l7_log_store_tap_types: [bool; 256],
    pub packet_header_enabled: bool,
    pub platform_enabled: bool,
    pub server_tx_bandwidth_threshold: u64,
    pub bandwidth_probe_interval: Duration,
    pub npb_vlan_mode: trident::VlanMode,
    pub npb_dedup_enabled: bool,
    pub if_mac_source: trident::IfMacSource,
    pub vtap_flow_1s_enabled: bool,
    pub debug_enabled: bool,
    pub log_threshold: u32,
    pub log_level: log::Level,
    pub analyzer_ip: String,
    pub analyzer_port: u16,
    pub max_escape: Duration,
    pub proxy_controller_ip: String,
    pub proxy_controller_port: u16,
    pub epc_id: u32,
    pub vtap_id: u16,
    pub collector_socket_type: trident::SocketType,
    pub compressor_socket_type: trident::SocketType,
    pub npb_socket_type: trident::SocketType,
    pub trident_type: common::TridentType,
    pub capture_packet_size: u32,
    pub inactive_server_port_enabled: bool,
    pub inactive_ip_enabled: bool,
    pub libvirt_xml_path: String,
    pub l7_log_packet_size: u32,
    pub l4_log_collect_nps_threshold: u64,
    pub l7_log_collect_nps_threshold: u64,
    pub l7_metrics_enabled: bool,
    pub decap_types: Vec<TunnelType>,
    pub http_log_proxy_client: String,
    pub http_log_trace_id: String,
    pub http_log_span_id: String,
    pub http_log_x_request_id: String,
    pub region_id: u32,
    pub pod_cluster_id: u32,
    pub log_retention: u32,
    pub capture_socket_type: trident::CaptureSocketType,
    pub process_threshold: u32,
    pub thread_threshold: u32,
    pub capture_bpf: String,
    pub l4_performance_enabled: bool,
    pub kubernetes_api_enabled: bool,
    pub ntp_enabled: bool,
    pub sys_free_memory_limit: u32,
    pub log_file_size: u32,
    pub external_agent_http_proxy_enabled: bool,
    pub external_agent_http_proxy_port: u16,
    // TODO: expand and remove
    pub yaml_config: YamlConfig,
}

impl RuntimeConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.sync_interval < Duration::from_secs(1)
            || self.sync_interval > Duration::from_secs(60 * 60)
        {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "sync-interval {:?} not in [1s, 1h]",
                self.sync_interval
            )));
        }
        if self.stats_interval < Duration::from_secs(1)
            || self.stats_interval > Duration::from_secs(60 * 60)
        {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "stats-interval {:?} not in [1s, 1h]",
                self.stats_interval
            )));
        }

        // 虽然RFC 791里最低MTU是68，但是此时compressor会崩溃，
        // 所以MTU最低限定到200以确保deepflow-agent能够成功运行
        if self.mtu < 200 {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "MTU({}) specified smaller than 200",
                self.mtu
            )));
        }

        if self.output_vlan > 4095 {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "output-vlan({}) out of range (0-4095)",
                self.output_vlan
            )));
        }

        if self.analyzer_ip.parse::<IpAddr>().is_err() || self.analyzer_ip == "0.0.0.0" {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "analyzer-ip({}) invalid",
                self.analyzer_ip
            )));
        }

        if self.analyzer_port == 0 {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "analyzer-port({}) invalid",
                self.analyzer_port
            )));
        }

        if regex::Regex::new(&self.tap_interface_regex).is_err() {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "malformed tap-interface-regex({})",
                self.tap_interface_regex
            )));
        }

        if self.max_escape < Duration::from_secs(600)
            || self.max_escape > Duration::from_secs(30 * 24 * 60 * 60)
        {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "max-escape-seconds {:?} not in [600s, 30d]",
                self.max_escape
            )));
        }

        if !self.proxy_controller_ip.is_empty()
            && (self.proxy_controller_ip == "0.0.0.0"
                || self.proxy_controller_ip.parse::<IpAddr>().is_err())
        {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "proxy-controller-ip({}) invalid",
                self.proxy_controller_ip
            )));
        }

        if self.proxy_controller_port == 0 {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "proxy-controller-port({}) invalid",
                self.proxy_controller_port
            )));
        }

        if self.capture_packet_size > 65535 || self.capture_packet_size < 128 {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "capture packet size {} not in [128, 65535]",
                self.capture_packet_size
            )));
        }

        if self.collector_socket_type == trident::SocketType::RawUdp {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "invalid collector_socket_type {:?}",
                self.collector_socket_type
            )));
        }

        if self.npb_socket_type == trident::SocketType::Tcp {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "invalid npb_socket_type {:?}",
                self.npb_socket_type
            )));
        }

        Ok(())
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        trident::Config::default().try_into().unwrap()
    }
}

impl TryFrom<trident::Config> for RuntimeConfig {
    type Error = io::Error;

    fn try_from(mut conf: trident::Config) -> Result<Self, io::Error> {
        let rc = Self {
            enabled: conf.enabled(),
            max_cpus: conf.max_cpus(),
            max_memory: (conf.max_memory() as u64) << 20,
            sync_interval: Duration::from_secs(conf.sync_interval() as u64),
            stats_interval: Duration::from_secs(conf.stats_interval() as u64),
            global_pps_threshold: conf.global_pps_threshold(),
            tap_interface_regex: conf.tap_interface_regex().to_owned(),
            host: conf.host().to_owned(),
            rsyslog_enabled: conf.rsyslog_enabled(),
            output_vlan: (conf.output_vlan() & 0xFFFFFFFF) as u16,
            mtu: conf.mtu(),
            npb_bps_threshold: conf.npb_bps_threshold(),
            collector_enabled: conf.collector_enabled(),
            l4_log_store_tap_types: {
                let mut tap_types = [false; 256];
                for t in conf.l4_log_tap_types.drain(..) {
                    if t >= u16::from(TapType::Max) as u32 {
                        warn!("invalid tap type: {}", t);
                    } else {
                        tap_types[t as usize] = true;
                    }
                }
                tap_types
            },
            packet_header_enabled: conf.packet_header_enabled(),
            platform_enabled: conf.platform_enabled(),
            server_tx_bandwidth_threshold: conf.server_tx_bandwidth_threshold(),
            bandwidth_probe_interval: Duration::from_secs(conf.bandwidth_probe_interval()),
            npb_vlan_mode: conf.npb_vlan_mode(),
            npb_dedup_enabled: conf.npb_dedup_enabled(),
            if_mac_source: conf.if_mac_source(),
            vtap_flow_1s_enabled: conf.vtap_flow_1s_enabled(),
            debug_enabled: conf.debug_enabled(),
            log_threshold: conf.log_threshold(),
            log_level: match conf.log_level().to_lowercase().as_str() {
                "error" => log::Level::Error,
                "warn" | "warning" => log::Level::Warn,
                "info" => log::Level::Info,
                "debug" => log::Level::Debug,
                "trace" => log::Level::Trace,
                _ => log::Level::Info,
            },
            analyzer_ip: conf.analyzer_ip().to_owned(),
            analyzer_port: conf.analyzer_port() as u16,
            max_escape: Duration::from_secs(conf.max_escape_seconds() as u64),
            proxy_controller_ip: conf.proxy_controller_ip().to_owned(),
            proxy_controller_port: conf.proxy_controller_port() as u16,
            epc_id: conf.epc_id(),
            vtap_id: (conf.vtap_id() & 0xFFFFFFFF) as u16,
            collector_socket_type: conf.collector_socket_type(),
            compressor_socket_type: conf.compressor_socket_type(),
            npb_socket_type: conf.npb_socket_type(),
            trident_type: conf.trident_type(),
            capture_packet_size: conf.capture_packet_size(),
            inactive_server_port_enabled: conf.inactive_server_port_enabled(),
            inactive_ip_enabled: conf.inactive_ip_enabled(),
            libvirt_xml_path: conf.libvirt_xml_path().to_owned(),
            l7_log_packet_size: conf.l7_log_packet_size(),
            l4_log_collect_nps_threshold: conf.l4_log_collect_nps_threshold(),
            l7_log_collect_nps_threshold: conf.l7_log_collect_nps_threshold(),
            l7_metrics_enabled: conf.l7_metrics_enabled(),
            app_proto_log_enabled: !conf.l7_log_store_tap_types.is_empty(),
            l7_log_store_tap_types: {
                let mut tap_types = [false; 256];
                for t in conf.l7_log_store_tap_types.drain(..) {
                    if t >= u16::from(TapType::Max) as u32 {
                        warn!("invalid tap type: {}", t);
                    } else {
                        tap_types[t as usize] = true;
                    }
                }
                tap_types
            },
            decap_types: conf
                .decap_type
                .drain(..)
                .filter_map(|t| match TunnelType::try_from(t as u8) {
                    Ok(t) => Some(t),
                    Err(_) => {
                        warn!("invalid tunnel type: {}", t);
                        None
                    }
                })
                .collect(),
            http_log_proxy_client: conf.http_log_proxy_client().to_owned(),
            http_log_trace_id: conf.http_log_trace_id().to_owned(),
            http_log_span_id: conf.http_log_span_id().to_owned(),
            http_log_x_request_id: conf.http_log_x_request_id().to_owned(),
            region_id: conf.region_id(),
            pod_cluster_id: conf.pod_cluster_id(),
            log_retention: conf.log_retention(),
            capture_socket_type: conf.capture_socket_type(),
            process_threshold: conf.process_threshold(),
            thread_threshold: conf.thread_threshold(),
            capture_bpf: conf.capture_bpf().to_owned(),
            l4_performance_enabled: conf.l4_performance_enabled(),
            kubernetes_api_enabled: conf.kubernetes_api_enabled(),
            ntp_enabled: conf.ntp_enabled(),
            sys_free_memory_limit: conf.sys_free_memory_limit(),
            log_file_size: conf.log_file_size(),
            external_agent_http_proxy_enabled: conf.external_agent_http_proxy_enabled(),
            external_agent_http_proxy_port: conf.external_agent_http_proxy_port() as u16,
            yaml_config: YamlConfig::load(conf.local_config())?,
        };
        rc.validate()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        Ok(rc)
    }
}

// resolve domain name (without port) to ip address
fn resolve_domain(addr: &str) -> Option<String> {
    match format!("{}:1", addr).to_socket_addrs() {
        Ok(mut addr) => match addr.next() {
            Some(addr) => Some(addr.ip().to_string()),
            None => None,
        },
        Err(e) => {
            eprintln!("{:?}", e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_yaml_file() {
        // TODO: improve test cases
        let c = Config::load_from_file("config/deepflow-agent.yaml")
            .expect("failed loading config file");
        assert_eq!(c.controller_ips.len(), 1);
        assert_eq!(&c.controller_ips[0], "127.0.0.1");
    }
}
