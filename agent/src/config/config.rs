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

use std::cmp::{max, min};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "android"))]
use envmnt::{ExpandOptions, ExpansionType};
use log::{debug, error, info, warn};
use md5::{Digest, Md5};
#[cfg(any(target_os = "linux", target_os = "android"))]
use procfs::process::Process;
use regex::Regex;
use serde::{
    de::{self, Unexpected},
    Deserialize, Deserializer,
};
use thiserror::Error;
use tokio::runtime::Runtime;

use crate::common::l7_protocol_log::L7ProtocolParser;
use crate::dispatcher::recv_engine::DEFAULT_BLOCK_SIZE;
use crate::flow_generator::{DnsLog, MemcachedLog, OracleLog, TlsLog};
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::platform::{get_container_id, OsAppTag, ProcessData};
use crate::{
    common::{
        decapsulate::TunnelType, enums::CaptureNetworkType, DEFAULT_LOG_FILE,
        L7_PROTOCOL_INFERENCE_MAX_FAIL_COUNT, L7_PROTOCOL_INFERENCE_TTL,
    },
    flow_generator::protocol_logs::SLOT_WIDTH,
    metric::document::TapSide,
    rpc::Session,
    trident::RunningMode,
};

use public::{
    bitmap::Bitmap,
    consts::NPB_DEFAULT_PORT,
    proto::{
        agent::{self, SocketType, SystemLoadMetric},
        common,
        trident::{self, KubernetesClusterIdRequest, TapMode},
    },
    utils::bitmap::parse_u16_range_list_to_bitmap,
};

pub const K8S_CA_CRT_PATH: &str = "/run/secrets/kubernetes.io/serviceaccount/ca.crt";
const MINUTE: Duration = Duration::from_secs(60);
const DEFAULT_STANDALONE_CONFIG: &str = "/etc/deepflow-agent-standalone.yaml";

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

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum AgentIdType {
    #[default]
    IpMac,
    Ip,
}

impl<'de> Deserialize<'de> for AgentIdType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match String::deserialize(deserializer)?.as_str() {
            "ip-and-mac" | "ip_and_mac" => Ok(Self::IpMac),
            "ip" => Ok(Self::Ip),
            other => Err(de::Error::invalid_value(
                Unexpected::Str(other),
                &"ip|ip-and-mac|ip_and_mac",
            )),
        }
    }
}

impl From<AgentIdType> for trident::AgentIdentifier {
    fn from(t: AgentIdType) -> Self {
        match t {
            AgentIdType::IpMac => trident::AgentIdentifier::IpAndMac,
            AgentIdType::Ip => trident::AgentIdentifier::Ip,
        }
    }
}

impl From<AgentIdType> for agent::AgentIdentifier {
    fn from(t: AgentIdType) -> Self {
        match t {
            AgentIdType::IpMac => agent::AgentIdentifier::IpAndMac,
            AgentIdType::Ip => agent::AgentIdentifier::Ip,
        }
    }
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
    pub kubernetes_cluster_name: Option<String>,
    pub vtap_group_id_request: String,
    pub controller_domain_name: Vec<String>,
    #[serde(skip)]
    pub agent_mode: RunningMode,
    pub override_os_hostname: Option<String>,
    pub async_worker_thread_number: u16,
    pub agent_unique_identifier: AgentIdType,
    #[cfg(target_os = "linux")]
    pub pid_file: String,
    pub team_id: String,
    pub cgroups_disabled: bool,
    pub new_rpc: bool,
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

            // convert relative path to absolute
            if Path::new(&cfg.log_file).is_relative() {
                let Ok(mut pb) = env::current_dir() else {
                    return Err(ConfigError::YamlConfigInvalid("get cwd failed".to_owned()));
                };
                pb.push(&cfg.log_file);
                match pb.to_str() {
                    Some(s) => cfg.log_file = s.to_owned(),
                    None => {
                        return Err(ConfigError::YamlConfigInvalid(format!(
                            "invalid log path {}",
                            cfg.log_file
                        )))
                    }
                }
            }

            Ok(cfg)
        }
    }

    pub async fn async_get_k8s_cluster_id(session: &Session, config: &Config) -> Option<String> {
        let ca_md5 = match fs::read_to_string(K8S_CA_CRT_PATH) {
            Ok(c) => Some(
                Md5::digest(c.as_bytes())
                    .into_iter()
                    .fold(String::new(), |s, c| s + &format!("{:02x}", c)),
            ),
            Err(e) => {
                info!(
                     "get kubernetes_cluster_id error: failed to read {} error: {}, this shows that agent is not running in K8s.",
                     K8S_CA_CRT_PATH, e
                 );
                return None;
            }
        };

        loop {
            let request = KubernetesClusterIdRequest {
                ca_md5: ca_md5.clone(),
                kubernetes_cluster_name: config.kubernetes_cluster_name.clone(),
                team_id: Some(config.team_id.clone()),
            };

            match session
                .grpc_get_kubernetes_cluster_id_with_statsd(request)
                .await
            {
                Ok(response) => {
                    let cluster_id_response = response.into_inner();
                    if !cluster_id_response.error_msg().is_empty() {
                        error!(
                            "get_kubernetes_cluster_id grpc call from server error: {}",
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
                            // FIXME: The channel in the session will become invalid after success here, so reset the session.
                            // ==============================================================================================
                            // FIXME: 这里获取成功后 Session 中的 Channel 会失效，所以在这里重置 Session
                            session.reset();
                            return Some(id);
                        }
                        None => {
                            error!("call get_kubernetes_cluster_id return response is none")
                        }
                    }
                }
                Err(e) => error!("get_kubernetes_cluster_id grpc call error: {}", e),
            }
            tokio::time::sleep(MINUTE).await;
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
    pub fn get_k8s_cluster_id(
        runtime: &Runtime,
        session: &Session,
        config: &Config,
    ) -> Option<String> {
        runtime.block_on(Self::async_get_k8s_cluster_id(session, config))
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
            kubernetes_cluster_name: Default::default(),
            vtap_group_id_request: "".into(),
            controller_domain_name: vec![],
            agent_mode: Default::default(),
            override_os_hostname: None,
            async_worker_thread_number: 16,
            agent_unique_identifier: Default::default(),
            #[cfg(target_os = "linux")]
            pid_file: Default::default(),
            team_id: "".into(),
            cgroups_disabled: false,
            new_rpc: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct TagExtraction {
    pub script_command: Vec<String>,
    pub exec_username: String,
}

impl Default for TagExtraction {
    fn default() -> Self {
        Self {
            script_command: vec![],
            exec_username: "deepflow".to_string(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub enum ProcessMatchType {
    Cmd,
    ProcessName,
    ParentProcessName,
    Tag,
    CmdWithArgs,
}

impl From<&str> for ProcessMatchType {
    fn from(value: &str) -> Self {
        match value {
            OS_PROC_REGEXP_MATCH_TYPE_CMD => Self::Cmd,
            OS_PROC_REGEXP_MATCH_TYPE_PARENT_PROC_NAME => Self::ParentProcessName,
            OS_PROC_REGEXP_MATCH_TYPE_TAG => Self::Tag,
            OS_PROC_REGEXP_MATCH_TYPE_CMD_WITH_ARGS => Self::CmdWithArgs,
            _ => Self::ProcessName,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub enum ProcessMatchAction {
    Accept,
    Drop,
}

impl From<&str> for ProcessMatchAction {
    fn from(value: &str) -> Self {
        match value {
            OS_PROC_REGEXP_MATCH_ACTION_DROP => ProcessMatchAction::Drop,
            _ => ProcessMatchAction::Accept,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ProcessMatcher {
    #[serde(deserialize_with = "to_match_regex")]
    pub match_regex: Regex,
    pub match_type: ProcessMatchType,
    pub match_languages: Vec<String>,
    pub match_usernames: Vec<String>,
    pub only_in_container: bool,
    pub only_with_tag: bool,
    pub ignore: bool,
    pub rewrite_name: String,
    pub enabled_features: Vec<String>,
    pub action: ProcessMatchAction,
}

impl Eq for ProcessMatcher {}

impl PartialEq for ProcessMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.match_regex.as_str() == other.match_regex.as_str()
            && self.match_type == other.match_type
            && self.match_languages == other.match_languages
            && self.match_usernames == other.match_usernames
            && self.only_in_container == other.only_in_container
            && self.only_with_tag == other.only_with_tag
            && self.ignore == other.ignore
            && self.rewrite_name == other.rewrite_name
            && self.enabled_features == other.enabled_features
            && self.action == other.action
    }
}

fn to_match_regex<'de, D>(deserializer: D) -> Result<Regex, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    if let Ok(regex) = Regex::new(raw.as_str()) {
        Ok(regex)
    } else {
        Err(de::Error::invalid_value(
            Unexpected::Str(raw.as_str()),
            &"See: https://regexr.com/",
        ))
    }
}

impl Default for ProcessMatcher {
    fn default() -> Self {
        Self {
            match_regex: Regex::new("deepflow-*").unwrap(),
            match_type: ProcessMatchType::Cmd,
            match_languages: vec![],
            match_usernames: vec![],
            only_in_container: false,
            only_with_tag: false,
            ignore: false,
            rewrite_name: "".to_string(),
            enabled_features: vec![
                "ebpf.profile.on_cpu".to_string(),
                "ebpf.profile.off_cpu".to_string(),
            ],
            action: ProcessMatchAction::Accept,
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl ProcessMatcher {
    // TODO: match_languages
    pub fn get_process_data(
        &self,
        process: &Process,
        tag_map: &HashMap<u64, OsAppTag>,
    ) -> Option<ProcessData> {
        if self.only_in_container && get_container_id(process).is_none() {
            return None;
        }
        if self.only_with_tag && !tag_map.contains_key(&(process.pid as u64)) {
            return None;
        }

        let env_rewrite = |r: String| {
            envmnt::expand(
                r.as_str(),
                Some(ExpandOptions {
                    expansion_type: Some(ExpansionType::Windows),
                    default_to_empty: true,
                }),
            )
        };
        let Ok(mut process_data) = ProcessData::try_from(process) else {
            return None;
        };
        let mut match_replace_fn =
            |reg: &Regex, act: &ProcessMatchAction, s: &String, replace: &String| {
                if reg.is_match(s.as_str()) {
                    if act == &ProcessMatchAction::Accept && !replace.is_empty() {
                        process_data.name = reg.replace_all(s.as_str(), replace).to_string();
                    }
                    true
                } else {
                    false
                }
            };
        let replace = env_rewrite(self.rewrite_name.clone());

        match self.match_type {
            ProcessMatchType::Cmd => {
                if match_replace_fn(&self.match_regex, &self.action, &process_data.cmd, &replace) {
                    Some(process_data)
                } else {
                    None
                }
            }
            ProcessMatchType::CmdWithArgs => {
                if match_replace_fn(
                    &self.match_regex,
                    &self.action,
                    &process_data.cmd_with_args.join(" "),
                    &replace,
                ) {
                    Some(process_data)
                } else {
                    None
                }
            }
            ProcessMatchType::ProcessName => {
                if match_replace_fn(
                    &self.match_regex,
                    &self.action,
                    &process_data.process_name,
                    &replace,
                ) {
                    Some(process_data)
                } else {
                    None
                }
            }
            ProcessMatchType::ParentProcessName => {
                fn match_parent(proc: &ProcessData, reg: &Regex) -> Option<ProcessData> {
                    const MAX_DEPTH: usize = 10;
                    let mut ppid = proc.ppid;
                    let mut pid = proc.pid;
                    for _ in 0..MAX_DEPTH {
                        if ppid == 0 {
                            return None;
                        }

                        let Ok(parent) = Process::new(ppid as i32) else {
                            return None;
                        };

                        let Ok(parent_data) = ProcessData::try_from(&parent) else {
                            error!("pid {} have no parent proc with ppid: {}", pid, ppid);
                            return None;
                        };

                        if reg.is_match(&parent_data.process_name.as_str()) {
                            return Some(parent_data);
                        }
                        ppid = parent_data.ppid;
                        pid = parent_data.pid;
                    }

                    None
                }

                match_parent(&process_data, &self.match_regex)
            }
            ProcessMatchType::Tag => {
                if let Some(tag) = tag_map.get(&process_data.pid) {
                    let mut found = None;
                    for tag_kv in tag.tags.iter() {
                        let composed = format!("{}:{}", &tag_kv.key, &tag_kv.value);
                        if self.match_regex.is_match(&composed.as_str()) {
                            found = Some(process_data);
                            break;
                        }
                    }
                    found
                } else {
                    None
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct GolangSpecific {
    pub enabled: bool,
}

impl Default for GolangSpecific {
    fn default() -> Self {
        Self { enabled: false }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Java {
    #[serde(with = "humantime_serde")]
    pub refresh_defer_duration: Duration,
    pub max_symbol_file_size: usize,
}

impl Default for Java {
    fn default() -> Self {
        Self {
            refresh_defer_duration: Duration::from_secs(60),
            max_symbol_file_size: 10,
        }
    }
}

#[derive(Clone, Copy, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SymbolTable {
    pub golang_specific: GolangSpecific,
    pub java: Java,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Proc {
    pub enabled: bool,
    pub proc_dir_path: String,
    #[serde(with = "humantime_serde")]
    pub sync_interval: Duration,
    #[serde(with = "humantime_serde")]
    pub min_lifetime: Duration,
    pub tag_extraction: TagExtraction,
    pub process_matcher: Vec<ProcessMatcher>,
    pub symbol_table: SymbolTable,
}

impl Default for Proc {
    fn default() -> Self {
        Self {
            enabled: false,
            proc_dir_path: "/proc".to_string(),
            sync_interval: Duration::from_secs(10),
            min_lifetime: Duration::from_secs(3),
            tag_extraction: TagExtraction::default(),
            process_matcher: vec![],
            symbol_table: SymbolTable::default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(remote = "agent::PacketCaptureType")]
enum PacketCaptureTypeDef {
    #[serde(rename = "0")]
    Local,
    #[serde(rename = "1")]
    Mirror,
    #[serde(rename = "2")]
    Analyzer,
    #[serde(rename = "3")]
    Decap,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Common {
    #[serde(with = "PacketCaptureTypeDef")]
    pub capture_mode: agent::PacketCaptureType,
}

impl Default for Common {
    fn default() -> Self {
        Self {
            capture_mode: agent::PacketCaptureType::Local,
        }
    }
}

fn to_capture_socket_type<'de, D>(deserializer: D) -> Result<agent::CaptureSocketType, D::Error>
where
    D: Deserializer<'de>,
{
    match u8::deserialize(deserializer)? {
        0 => Ok(agent::CaptureSocketType::Auto),
        2 => Ok(agent::CaptureSocketType::AfPacketV2),
        3 => Ok(agent::CaptureSocketType::AfPacketV3),
        o => Err(de::Error::invalid_value(
            Unexpected::Unsigned(o as u64),
            &"0|2|3",
        )),
    }
}

fn to_trident_capture_socket_type<'de, D>(
    deserializer: D,
) -> Result<trident::CaptureSocketType, D::Error>
where
    D: Deserializer<'de>,
{
    match u8::deserialize(deserializer)? {
        0 => Ok(trident::CaptureSocketType::Auto),
        1 => Ok(trident::CaptureSocketType::AfPacketV1),
        2 => Ok(trident::CaptureSocketType::AfPacketV2),
        3 => Ok(trident::CaptureSocketType::AfPacketV3),
        o => Err(de::Error::invalid_value(
            Unexpected::Unsigned(o as u64),
            &"0|1|2|3",
        )),
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AfPacketTunning {
    #[serde(deserialize_with = "to_capture_socket_type")]
    pub socket_version: agent::CaptureSocketType,
    pub ring_blocks_enabled: bool,
    pub ring_blocks: usize,
    pub packet_fanout_count: usize,
    pub packet_fanout_mode: u32,
}

impl Default for AfPacketTunning {
    fn default() -> Self {
        Self {
            socket_version: agent::CaptureSocketType::Auto,
            ring_blocks_enabled: false,
            ring_blocks: 128,
            packet_fanout_count: 1,
            packet_fanout_mode: 0,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct BondInterface {
    pub slave_interfaces: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AfPacket {
    pub interface_regex: String,
    pub bond_interfaces: Vec<BondInterface>,
    pub extra_netns_regex: String,
    pub extra_bpf_filter: String,
    pub src_interfaces: Vec<String>,
    pub vlan_pcp_in_physical_mirror_traffic: u16,
    pub bpf_filter_disabled: bool,
    pub tunning: AfPacketTunning,
}

impl Default for AfPacket {
    fn default() -> Self {
        Self {
            interface_regex: "^(tap.*|cali.*|veth.*|eth.*|en[osipx].*|lxc.*|lo|[0-9a-f]+_h)$"
                .to_string(),
            bond_interfaces: vec![],
            extra_netns_regex: "".to_string(),
            extra_bpf_filter: "".to_string(),
            vlan_pcp_in_physical_mirror_traffic: 0,
            bpf_filter_disabled: false,
            tunning: AfPacketTunning::default(),
            src_interfaces: vec![],
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Dpdk {
    pub enabled: bool,
}

impl Default for Dpdk {
    fn default() -> Self {
        Self { enabled: false }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Libpcap {
    pub enabled: bool,
}

impl Default for Libpcap {
    fn default() -> Self {
        Self { enabled: false }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct VhostUser {
    pub vhost_socket_path: String,
}

impl Default for VhostUser {
    fn default() -> Self {
        Self {
            vhost_socket_path: "".to_string(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct PhysicalSwitch {
    pub sflow_ports: Vec<u16>,
    pub netflow_ports: Vec<u16>,
}

impl Default for PhysicalSwitch {
    fn default() -> Self {
        Self {
            sflow_ports: vec![],
            netflow_ports: vec![],
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SpecialNetwork {
    pub dpdk: Dpdk,
    pub libpcap: Libpcap,
    pub vhost_user: VhostUser,
    pub physical_switch: PhysicalSwitch,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct CbpfTunning {
    pub dispatcher_queue_enabled: bool,
    pub max_capture_packet_size: u32,
    pub raw_packet_buffer_block_size: usize,
    pub raw_packet_queue_size: usize,
    pub max_capture_pps: u64,
}

impl Default for CbpfTunning {
    fn default() -> Self {
        Self {
            dispatcher_queue_enabled: false,
            max_capture_packet_size: 65535,
            raw_packet_buffer_block_size: 65536,
            raw_packet_queue_size: 131072,
            max_capture_pps: 200000,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct PreProcess {
    pub tunnel_decap_protocols: Vec<u8>,
    pub tunnel_trim_protocols: Vec<String>,
    pub packet_segmentation_reassembly: Vec<u16>,
}

impl Default for PreProcess {
    fn default() -> Self {
        Self {
            tunnel_decap_protocols: vec![1, 2],
            tunnel_trim_protocols: vec![],
            packet_segmentation_reassembly: vec![],
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct PhysicalMirror {
    pub default_capture_network_type: u16,
    pub packet_dedup_disabled: bool,
    pub private_cloud_gateway_traffic: bool,
}

impl Default for PhysicalMirror {
    fn default() -> Self {
        Self {
            default_capture_network_type: 3,
            packet_dedup_disabled: false,
            private_cloud_gateway_traffic: false,
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Cbpf {
    pub common: Common,
    pub af_packet: AfPacket,
    pub special_network: SpecialNetwork,
    pub tunning: CbpfTunning,
    pub preprocess: PreProcess,
    pub physical_mirror: PhysicalMirror,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct EbpfSocketUprobeTls {
    pub enabled: bool,
}

impl Default for EbpfSocketUprobeTls {
    fn default() -> Self {
        Self { enabled: false }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct EbpfSocketUprobeGolang {
    pub enabled: bool,
    #[serde(with = "humantime_serde")]
    pub tracing_timeout: Duration,
}

impl Default for EbpfSocketUprobeGolang {
    fn default() -> Self {
        Self {
            enabled: false,
            tracing_timeout: Duration::from_secs(120),
        }
    }
}

#[derive(Clone, Copy, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct EbpfSocketUprobe {
    pub golang: EbpfSocketUprobeGolang,
    pub tls: EbpfSocketUprobeTls,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct EbpfSocketKprobePorts {
    pub ports: String,
}

impl Default for EbpfSocketKprobePorts {
    fn default() -> Self {
        Self {
            ports: "".to_string(),
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct EbpfSocketKprobe {
    pub blacklist: EbpfSocketKprobePorts,
    pub whitelist: EbpfSocketKprobePorts,
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct EbpfSocketTunning {
    pub max_capture_rate: u64,
    pub syscall_trace_id_disabled: bool,
    pub map_prealloc_disabled: bool,
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct EbpfSocket {
    pub uprobe: EbpfSocketUprobe,
    pub kprobe: EbpfSocketKprobe,
    pub tunning: EbpfSocketTunning,
    pub preprocess: EbpfSocketPreprocess,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct EbpfFileIoEvent {
    pub collect_mode: usize,
    #[serde(with = "humantime_serde")]
    pub minimal_duration: Duration,
}

impl Default for EbpfFileIoEvent {
    fn default() -> Self {
        Self {
            collect_mode: 1,
            minimal_duration: Duration::from_millis(1),
        }
    }
}

#[derive(Clone, Copy, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct EbpfFile {
    pub io_event: EbpfFileIoEvent,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct EbpfProfileOnCpu {
    pub disabled: bool,
    pub sampling_frequency: i32,
    pub aggregate_by_cpu: bool,
}

impl Default for EbpfProfileOnCpu {
    fn default() -> Self {
        Self {
            disabled: false,
            sampling_frequency: 99,
            aggregate_by_cpu: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct EbpfProfileOffCpu {
    pub disabled: bool,
    #[serde(with = "humantime_serde")]
    pub min_blocking_time: Duration,
    pub aggregate_by_cpu: bool,
}

impl Default for EbpfProfileOffCpu {
    fn default() -> Self {
        Self {
            disabled: true,
            min_blocking_time: Duration::from_micros(50),
            aggregate_by_cpu: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct EbpfProfileMemory {
    pub disabled: bool,
    #[serde(with = "humantime_serde")]
    pub report_interval: Duration,
}

impl Default for EbpfProfileMemory {
    fn default() -> Self {
        Self {
            disabled: true,
            report_interval: Duration::from_secs(10),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct EbpfProfilePreprocess {
    pub stack_compression: bool,
}

impl Default for EbpfProfilePreprocess {
    fn default() -> Self {
        Self {
            stack_compression: true,
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Unwinding {
    pub dwarf_disabled: bool,
    pub dwarf_regex: String,
    pub dwarf_process_map_size: u32,
    pub dwarf_shard_map_size: u32,
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct EbpfProfile {
    pub on_cpu: EbpfProfileOnCpu,
    pub off_cpu: EbpfProfileOffCpu,
    pub memory: EbpfProfileMemory,
    pub unwinding: Unwinding,
    pub preprocess: EbpfProfilePreprocess,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct EbpfTunning {
    pub collector_queue_size: usize,
    pub userspace_worker_threads: i32,
    pub perf_pages_count: u32,
    pub kernel_ring_size: u32,
    pub max_socket_entries: u32,
    pub socket_map_reclaim_threshold: u32,
    pub max_trace_entries: u32,
}

impl Default for EbpfTunning {
    fn default() -> Self {
        Self {
            collector_queue_size: 65535,
            userspace_worker_threads: 1,
            perf_pages_count: 128,
            kernel_ring_size: 65536,
            max_socket_entries: 131072,
            socket_map_reclaim_threshold: 120000,
            max_trace_entries: 131072,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct EbpfSocketPreprocess {
    pub out_of_order_reassembly_cache_size: usize,
    pub out_of_order_reassembly_protocols: Vec<String>,
    pub segmentation_reassembly_protocols: Vec<String>,
}

impl Default for EbpfSocketPreprocess {
    fn default() -> Self {
        Self {
            out_of_order_reassembly_cache_size: 16,
            out_of_order_reassembly_protocols: vec![],
            segmentation_reassembly_protocols: vec![],
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Ebpf {
    pub disabled: bool,
    pub socket: EbpfSocket,
    pub file: EbpfFile,
    pub profile: EbpfProfile,
    pub tunning: EbpfTunning,
    #[serde(skip)]
    pub java_symbol_file_refresh_defer_interval: i32,
}

impl Default for Ebpf {
    fn default() -> Self {
        Self {
            disabled: false,
            socket: EbpfSocket::default(),
            file: EbpfFile::default(),
            profile: EbpfProfile::default(),
            tunning: EbpfTunning::default(),
            java_symbol_file_refresh_defer_interval: 60,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct PrivateCloud {
    pub hypervisor_resource_enabled: bool,
    #[serde(deserialize_with = "to_if_mac_source")]
    pub vm_mac_source: agent::IfMacSource,
    pub vm_xml_directory: String,
    pub vm_mac_mapping_script: String,
}

impl Default for PrivateCloud {
    fn default() -> Self {
        Self {
            hypervisor_resource_enabled: false,
            vm_mac_source: agent::IfMacSource::IfMac,
            vm_xml_directory: "/etc/libvirt/qemu/".to_string(),
            vm_mac_mapping_script: "".to_string(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ApiResources {
    pub name: String,
    pub disabled: bool,
    pub group: String,
    pub version: String,
    pub field_selector: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
pub enum KubernetesPollerType {
    Adaptive,
    Active,
    Passive,
}

fn to_kubernetes_poller_type<'de, D>(deserializer: D) -> Result<KubernetesPollerType, D::Error>
where
    D: Deserializer<'de>,
{
    match String::deserialize(deserializer)?.to_uppercase().as_str() {
        "ADAPTIVE" => Ok(KubernetesPollerType::Adaptive),
        "ACTIVE" => Ok(KubernetesPollerType::Active),
        "PASSIVE" => Ok(KubernetesPollerType::Passive),
        other => Err(de::Error::invalid_value(
            Unexpected::Str(other),
            &"Adaptive|Active|Passive",
        )),
    }
}

impl KubernetesPollerType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Adaptive => "adaptive",
            Self::Active => "active",
            Self::Passive => "passive",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Kubernetes {
    pub kubernetes_namespace: String,
    pub api_resources: Vec<ApiResources>,
    pub api_list_page_size: u32,
    #[serde(with = "humantime_serde")]
    pub api_list_max_interval: Duration,
    pub ingress_flavour: String,
    #[serde(deserialize_with = "to_kubernetes_poller_type")]
    pub pod_mac_collection_method: KubernetesPollerType,
}

impl Default for Kubernetes {
    fn default() -> Self {
        Self {
            kubernetes_namespace: "".to_string(),
            api_resources: vec![
                ApiResources {
                    name: "namespaces".to_string(),
                    ..Default::default()
                },
                ApiResources {
                    name: "nodes".to_string(),
                    ..Default::default()
                },
                ApiResources {
                    name: "pods".to_string(),
                    ..Default::default()
                },
                ApiResources {
                    name: "replicationcontrollers".to_string(),
                    ..Default::default()
                },
                ApiResources {
                    name: "services".to_string(),
                    ..Default::default()
                },
                ApiResources {
                    name: "daemonsets".to_string(),
                    ..Default::default()
                },
                ApiResources {
                    name: "deployments".to_string(),
                    ..Default::default()
                },
                ApiResources {
                    name: "replicasets".to_string(),
                    ..Default::default()
                },
                ApiResources {
                    name: "statefulsets".to_string(),
                    ..Default::default()
                },
                ApiResources {
                    name: "ingresses".to_string(),
                    ..Default::default()
                },
            ],
            api_list_page_size: 1000,
            api_list_max_interval: Duration::from_millis(10),
            ingress_flavour: "kubernetes".to_string(),
            pod_mac_collection_method: KubernetesPollerType::Adaptive,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct PullResourceFromController {
    pub domain_filter: Vec<usize>,
    pub only_kubernetes_pod_ip_in_local_cluster: bool,
}

impl Default for PullResourceFromController {
    fn default() -> Self {
        Self {
            domain_filter: vec![0],
            only_kubernetes_pod_ip_in_local_cluster: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Resources {
    #[serde(with = "humantime_serde")]
    pub push_interval: Duration,
    pub private_cloud: PrivateCloud,
    pub kubernetes: Kubernetes,
    pub pull_resource_from_controller: PullResourceFromController,
}

impl Default for Resources {
    fn default() -> Self {
        Self {
            push_interval: Duration::from_secs(10),
            private_cloud: PrivateCloud::default(),
            kubernetes: Kubernetes::default(),
            pull_resource_from_controller: PullResourceFromController::default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct PrometheusExtraLabels {
    pub enabled: bool,
    pub extra_labels: Vec<String>,
    pub label_length: usize,
    pub value_length: usize,
}

impl Default for PrometheusExtraLabels {
    fn default() -> Self {
        Self {
            enabled: false,
            extra_labels: vec![],
            label_length: 1024,
            value_length: 4096,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct FeatureControl {
    pub profile_integration_disabled: bool,
    pub trace_integration_disabled: bool,
    pub metric_integration_disabled: bool,
    pub log_integration_disabled: bool,
}

impl Default for FeatureControl {
    fn default() -> Self {
        Self {
            profile_integration_disabled: false,
            trace_integration_disabled: false,
            metric_integration_disabled: false,
            log_integration_disabled: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Compression {
    pub trace: bool,
    pub profile: bool,
}

impl Default for Compression {
    fn default() -> Self {
        Self {
            trace: true,
            profile: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Integration {
    pub enabled: bool,
    pub listen_port: u16,
    pub compression: Compression,
    pub prometheus_extra_labels: PrometheusExtraLabels,
    pub feature_control: FeatureControl,
}

impl Default for Integration {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_port: 38086,
            compression: Compression::default(),
            prometheus_extra_labels: PrometheusExtraLabels::default(),
            feature_control: FeatureControl::default(),
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Inputs {
    pub proc: Proc,
    pub cbpf: Cbpf,
    pub ebpf: Ebpf,
    pub resources: Resources,
    pub integration: Integration,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Policy {
    pub fast_path_map_size: usize,
    pub fast_path_disabled: bool,
    pub forward_table_capacity: usize,
    pub max_first_path_level: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            fast_path_map_size: 16384,
            fast_path_disabled: false,
            forward_table_capacity: 16384,
            max_first_path_level: 8,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct TcpHeader {
    pub block_size: usize,
    pub sender_queue_size: usize,
    pub sender_queue_count: usize,
    pub header_fields_flag: u8,
}

impl Default for TcpHeader {
    fn default() -> Self {
        Self {
            block_size: 256,
            sender_queue_size: 65536,
            sender_queue_count: 1,
            header_fields_flag: 0b0000_0000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct PcapStream {
    pub receiver_queue_size: usize,
    pub buffer_size_per_flow: u32,
    pub total_buffer_size: u64,
    #[serde(with = "humantime_serde")]
    pub flush_interval: Duration,
}

impl Default for PcapStream {
    fn default() -> Self {
        Self {
            receiver_queue_size: 65536,
            buffer_size_per_flow: 65536,
            total_buffer_size: 88304,
            flush_interval: Duration::from_secs(60),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Toa {
    pub sender_queue_size: usize,
    pub cache_size: usize,
}

impl Default for Toa {
    fn default() -> Self {
        Self {
            sender_queue_size: 65536,
            cache_size: 65536,
        }
    }
}

#[derive(Clone, Copy, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Packet {
    pub policy: Policy,
    pub tcp_header: TcpHeader,
    pub pcap_stream: PcapStream,
    pub toa: Toa,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct OracleConfig {
    pub is_be: bool,
    pub int_compressed: bool,
    pub resp_0x04_extra_byte: bool,
}

impl Default for OracleConfig {
    fn default() -> Self {
        Self {
            is_be: true,
            int_compressed: true,
            resp_0x04_extra_byte: false,
        }
    }
}

#[derive(Clone, Copy, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ProtocolSpecialConfig {
    pub oracle: OracleConfig,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ApplicationProtocolInference {
    pub inference_max_retries: usize,
    #[serde(with = "humantime_serde")]
    pub inference_result_ttl: Duration,
    pub enabled_protocols: Vec<String>,
    pub protocol_special_config: ProtocolSpecialConfig,
}

impl Default for ApplicationProtocolInference {
    fn default() -> Self {
        Self {
            inference_max_retries: 5,
            inference_result_ttl: Duration::from_secs(60),
            enabled_protocols: vec![
                "HTTP".to_string(),
                "HTTP2".to_string(),
                "Dubbo".to_string(),
                "SofaRPC".to_string(),
                "FastCGI".to_string(),
                "bRPC".to_string(),
                "MySQL".to_string(),
                "PostgreSQL".to_string(),
                "Oracle".to_string(),
                "Redis".to_string(),
                "MongoDB".to_string(),
                "Memcached".to_string(),
                "Kafka".to_string(),
                "MQTT".to_string(),
                "AMQP".to_string(),
                "OpenWire".to_string(),
                "NATS".to_string(),
                "Pulsar".to_string(),
                "ZMTP".to_string(),
                "DNS".to_string(),
                "TLS".to_string(),
                "Custom".to_string(),
            ],
            protocol_special_config: ProtocolSpecialConfig::default(),
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct TagFilterOperator {
    pub name: String,
    pub operator: String,
    pub value: String,
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Filters {
    pub port_number_prefilters: HashMap<String, String>,
    pub tag_filters: HashMap<String, Vec<TagFilterOperator>>,
    pub unconcerned_dns_nxdomain_response_suffixes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Timeouts {
    #[serde(with = "humantime_serde")]
    pub tcp_request_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub udp_request_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub session_aggregate_window_duration: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            tcp_request_timeout: Duration::from_secs(1800),
            udp_request_timeout: Duration::from_secs(150),
            session_aggregate_window_duration: Duration::from_secs(120),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct TracingTag {
    pub http_real_client: String,
    pub x_request_id: String,
    pub apm_trace_id: Vec<String>,
    pub apm_span_id: Vec<String>,
}

impl Default for TracingTag {
    fn default() -> Self {
        Self {
            http_real_client: "X_Forwarded_For".to_string(),
            x_request_id: "X_Request_ID".to_string(),
            apm_trace_id: vec!["traceparent".to_string(), "sw8".to_string()],
            apm_span_id: vec!["traceparent".to_string(), "sw8".to_string()],
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct HttpEndpointMatchRule {
    pub url_prefix: String,
    pub keep_segments: usize,
}

impl Default for HttpEndpointMatchRule {
    fn default() -> Self {
        Self {
            url_prefix: "".to_string(),
            keep_segments: 2,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct HttpEndpoint {
    pub extraction_disabled: bool,
    pub match_rules: Vec<HttpEndpointMatchRule>,
}

impl Default for HttpEndpoint {
    fn default() -> Self {
        Self {
            extraction_disabled: false,
            match_rules: vec![HttpEndpointMatchRule::default()],
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct CustomFields {
    pub field_name: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RequestLogTagExtraction {
    pub tracing_tag: TracingTag,
    pub http_endpoint: HttpEndpoint,
    pub custom_fields: HashMap<String, Vec<CustomFields>>,
    pub obfuscate_protocols: Vec<String>,
}

impl Default for RequestLogTagExtraction {
    fn default() -> Self {
        Self {
            tracing_tag: TracingTag::default(),
            http_endpoint: HttpEndpoint::default(),
            custom_fields: HashMap::new(),
            obfuscate_protocols: vec!["Redis".to_string()],
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RequestLogTunning {
    pub payload_truncation: u32,
    pub session_aggregate_slot_capacity: usize,
    pub consistent_timestamp_in_l7_metrics: bool,
}

impl Default for RequestLogTunning {
    fn default() -> Self {
        Self {
            payload_truncation: 1024,
            session_aggregate_slot_capacity: 1024,
            consistent_timestamp_in_l7_metrics: false,
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RequestLog {
    pub application_protocol_inference: ApplicationProtocolInference,
    pub filters: Filters,
    pub timeouts: Timeouts,
    pub tag_extraction: RequestLogTagExtraction,
    pub tunning: RequestLogTunning,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct TimeWindow {
    #[serde(with = "humantime_serde")]
    pub max_tolerable_packet_delay: Duration,
    #[serde(with = "humantime_serde")]
    pub extra_tolerable_flow_delay: Duration,
}

impl Default for TimeWindow {
    fn default() -> Self {
        Self {
            max_tolerable_packet_delay: Duration::from_secs(1),
            extra_tolerable_flow_delay: Duration::ZERO,
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct FlowGeneration {
    pub server_ports: Vec<u16>,
    pub cloud_traffic_ignore_mac: bool,
    pub ignore_l2_end: bool,
    pub idc_traffic_ignore_vlan: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ConntrackTimeouts {
    #[serde(with = "humantime_serde")]
    pub established: Duration,
    #[serde(with = "humantime_serde")]
    pub closing_rst: Duration,
    #[serde(with = "humantime_serde")]
    pub opening_rst: Duration,
    #[serde(with = "humantime_serde")]
    pub others: Duration,
}

impl Default for ConntrackTimeouts {
    fn default() -> Self {
        Self {
            established: Duration::from_secs(300),
            closing_rst: Duration::from_secs(35),
            opening_rst: Duration::from_secs(1),
            others: Duration::from_secs(5),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Conntrack {
    #[serde(with = "humantime_serde")]
    pub flow_flush_interval: Duration,
    pub flow_generation: FlowGeneration,
    pub timeouts: ConntrackTimeouts,
}

impl Default for Conntrack {
    fn default() -> Self {
        Self {
            flow_flush_interval: Duration::from_secs(1),
            flow_generation: FlowGeneration::default(),
            timeouts: ConntrackTimeouts::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ProcessorsFlowLogTunning {
    pub flow_map_hash_slots: u32,
    pub concurrent_flow_limit: u32,
    pub memory_pool_size: usize,
    pub max_batched_buffer_size: usize,
    pub flow_aggregator_queue_size: usize,
    pub flow_generator_queue_size: usize,
    pub quadruple_generator_queue_size: usize,
}

impl Default for ProcessorsFlowLogTunning {
    fn default() -> Self {
        Self {
            flow_map_hash_slots: 131072,
            concurrent_flow_limit: 65535,
            memory_pool_size: 65536,
            max_batched_buffer_size: 131072,
            flow_aggregator_queue_size: 65535,
            flow_generator_queue_size: 65536,
            quadruple_generator_queue_size: 262144,
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ProcessorsFlowLog {
    pub time_window: TimeWindow,
    pub conntrack: Conntrack,
    pub tunning: ProcessorsFlowLogTunning,
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Processors {
    pub packet: Packet,
    pub request_log: RequestLog,
    pub flow_log: ProcessorsFlowLog,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Limits {
    pub max_millicpus: u32,
    pub max_memory: u64,
    pub max_log_backhaul_rate: u32,
    pub max_local_log_file_size: u32,
    pub local_log_retention: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_millicpus: 1000,
            max_memory: 768,
            max_log_backhaul_rate: 300,
            max_local_log_file_size: 1000,
            local_log_retention: Duration::from_secs(300 * 24 * 3600),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Alerts {
    pub thread_threshold: u32,
    pub process_threshold: u32,
    pub check_core_file_disabled: bool,
}

impl Default for Alerts {
    fn default() -> Self {
        Self {
            thread_threshold: 500,
            process_threshold: 10,
            check_core_file_disabled: false,
        }
    }
}

#[derive(Clone, Copy, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SysFreeMemoryPercentage {
    pub trigger_threshold: u32,
}

fn to_system_load_metric<'de, D>(deserializer: D) -> Result<agent::SystemLoadMetric, D::Error>
where
    D: Deserializer<'de>,
{
    match u8::deserialize(deserializer)? {
        0 => Ok(agent::SystemLoadMetric::Load1),
        1 => Ok(agent::SystemLoadMetric::Load5),
        2 => Ok(agent::SystemLoadMetric::Load15),
        other => Err(de::Error::invalid_value(
            Unexpected::Unsigned(other as u64),
            &"[0-2]",
        )),
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialOrd)]
#[serde(default)]
pub struct RelativeSysLoad {
    pub trigger_threshold: f32,
    pub recovery_threshold: f32,
    #[serde(deserialize_with = "to_system_load_metric")]
    pub system_load_circuit_breaker_metric: agent::SystemLoadMetric,
}

impl PartialEq for RelativeSysLoad {
    fn eq(&self, other: &Self) -> bool {
        self.trigger_threshold == other.trigger_threshold
            || self.recovery_threshold == other.recovery_threshold
            || self.system_load_circuit_breaker_metric == other.system_load_circuit_breaker_metric
    }
}
impl Eq for RelativeSysLoad {}

impl Default for RelativeSysLoad {
    fn default() -> Self {
        RelativeSysLoad {
            trigger_threshold: 1.0,
            recovery_threshold: 0.9,
            system_load_circuit_breaker_metric: agent::SystemLoadMetric::Load15,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct TxThroughput {
    pub trigger_threshold: u64,
    pub throughput_monitoring_interval: Duration,
}

impl Default for TxThroughput {
    fn default() -> Self {
        Self {
            trigger_threshold: 0,
            throughput_monitoring_interval: Duration::from_secs(10),
        }
    }
}

#[derive(Clone, Copy, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct CircuitBreakers {
    pub sys_free_memory_percentage: SysFreeMemoryPercentage,
    pub relative_sys_load: RelativeSysLoad,
    pub tx_throughput: TxThroughput,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Tunning {
    pub cpu_affinity: Vec<usize>,
    pub process_scheduling_priority: usize,
    pub idle_memory_trimming: bool,
    pub resource_monitoring_interval: Duration,
}

impl Default for Tunning {
    fn default() -> Self {
        Self {
            cpu_affinity: vec![],
            process_scheduling_priority: 0,
            idle_memory_trimming: false,
            resource_monitoring_interval: Duration::from_secs(10),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Ntp {
    pub enabled: bool,
    pub max_drift: Duration,
    pub min_drift: Duration,
}

impl Default for Ntp {
    fn default() -> Self {
        Self {
            enabled: false,
            max_drift: Duration::from_secs(300),
            min_drift: Duration::from_secs(10),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Communication {
    pub proactive_request_interval: Duration,
    pub max_escape_duration: Duration,
    pub ingester_ip: String,
    pub ingester_port: u16,
    pub grpc_buffer_size: usize,
    pub request_via_nat_ip: bool,
    pub proxy_controller_ip: String,
    pub proxy_controller_port: u16,
}

impl Default for Communication {
    fn default() -> Self {
        Self {
            proactive_request_interval: Duration::from_secs(60),
            max_escape_duration: Duration::from_secs(3600),
            proxy_controller_ip: "".to_string(),
            proxy_controller_port: 30035,
            ingester_ip: "".to_string(),
            ingester_port: 30033,
            grpc_buffer_size: 5,
            request_via_nat_ip: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(remote = "log::Level")]
enum LevelDef {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Log {
    #[serde(with = "LevelDef")]
    pub log_level: log::Level,
    pub log_file: String,
    pub log_backhaul_enabled: bool,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            log_level: log::Level::Info,
            log_file: "/var/log/deepflow_agent/deepflow_agent.log".to_string(),
            log_backhaul_enabled: true,
        }
    }
}

#[derive(Clone, Copy, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Profile {
    pub enabled: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Debug {
    pub enabled: bool,
    pub local_udp_port: u16,
    pub debug_metrics_enabled: bool,
}

impl Default for Debug {
    fn default() -> Self {
        Self {
            local_udp_port: 0,
            debug_metrics_enabled: false,
            enabled: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SelfMonitoring {
    pub log: Log,
    pub profile: Profile,
    pub debug: Debug,
    pub hostname: String,
    pub interval: Duration,
}

impl Default for SelfMonitoring {
    fn default() -> Self {
        Self {
            log: Log::default(),
            profile: Profile::default(),
            debug: Debug::default(),
            hostname: "".to_string(),
            interval: Duration::from_secs(10),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct StandaloneMode {
    pub max_data_file_size: u32,
    pub data_file_dir: String,
}

impl Default for StandaloneMode {
    fn default() -> Self {
        Self {
            max_data_file_size: 200,
            data_file_dir: "/var/log/deepflow_agent/".to_string(),
        }
    }
}

fn to_agent_type<'de, D>(deserializer: D) -> Result<agent::AgentType, D::Error>
where
    D: Deserializer<'de>,
{
    match u8::deserialize(deserializer)? {
        0 => Ok(agent::AgentType::TtUnknown),
        1 => Ok(agent::AgentType::TtProcess),
        2 => Ok(agent::AgentType::TtVm),
        3 => Ok(agent::AgentType::TtPublicCloud),
        5 => Ok(agent::AgentType::TtPhysicalMachine),
        6 => Ok(agent::AgentType::TtDedicatedPhysicalMachine),
        7 => Ok(agent::AgentType::TtHostPod),
        8 => Ok(agent::AgentType::TtVmPod),
        9 => Ok(agent::AgentType::TtTunnelDecapsulation),
        10 => Ok(agent::AgentType::TtHyperVCompute),
        11 => Ok(agent::AgentType::TtHyperVNetwork),
        12 => Ok(agent::AgentType::TtK8sSidecar),
        other => Err(de::Error::invalid_value(
            Unexpected::Unsigned(other as u64),
            &"[0-12]",
        )),
    }
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
pub struct GlobalCommon {
    pub enabled: bool,
    #[serde(deserialize_with = "to_agent_type")]
    pub agent_type: agent::AgentType,
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
pub struct Global {
    pub limits: Limits,
    pub alerts: Alerts,
    pub circuit_breakers: CircuitBreakers,
    pub tunning: Tunning,
    pub ntp: Ntp,
    pub communication: Communication,
    pub self_monitoring: SelfMonitoring,
    pub standalone_mode: StandaloneMode,
    pub common: GlobalCommon,
}

fn to_agent_socket_type<'de, D>(deserializer: D) -> Result<agent::SocketType, D::Error>
where
    D: Deserializer<'de>,
{
    match String::deserialize(deserializer)?.as_str() {
        "FILE" => Ok(agent::SocketType::File),
        "TCP" => Ok(agent::SocketType::Tcp),
        "UDP" => Ok(agent::SocketType::Udp),
        "RAW_UDP" => Ok(agent::SocketType::RawUdp),
        "ZMQ" => Ok(agent::SocketType::Zmq),
        "" => Ok(agent::SocketType::File),
        other => Err(de::Error::invalid_value(
            Unexpected::Str(other),
            &"FILE|TCP|UDP|RAW_UDP|ZMQ",
        )),
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Socket {
    #[serde(deserialize_with = "to_agent_socket_type")]
    pub data_socket_type: agent::SocketType,
    #[serde(deserialize_with = "to_agent_socket_type")]
    pub npb_socket_type: agent::SocketType,
    pub raw_udp_qos_bypass: bool,
    pub multiple_sockets_to_ingester: bool,
}

impl Default for Socket {
    fn default() -> Self {
        Self {
            data_socket_type: agent::SocketType::Tcp,
            npb_socket_type: agent::SocketType::RawUdp,
            raw_udp_qos_bypass: false,
            multiple_sockets_to_ingester: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct FlowLogFilters {
    pub l4_capture_network_types: Vec<u16>,
    pub l7_capture_network_types: Vec<u16>,
    pub l4_ignored_observation_points: Vec<u16>,
    pub l7_ignored_observation_points: Vec<u16>,
}

impl Default for FlowLogFilters {
    fn default() -> Self {
        Self {
            l4_capture_network_types: vec![0],
            l7_capture_network_types: vec![],
            l4_ignored_observation_points: vec![],
            l7_ignored_observation_points: vec![],
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Throttles {
    pub l4_throttle: u64,
    pub l7_throttle: u64,
}

impl Default for Throttles {
    fn default() -> Self {
        Self {
            l4_throttle: 10000,
            l7_throttle: 10000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct OutputsFlowLogTunning {
    pub collector_queue_size: usize,
    pub collector_queue_count: usize,
}

impl Default for OutputsFlowLogTunning {
    fn default() -> Self {
        Self {
            collector_queue_size: 65536,
            collector_queue_count: 1,
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct OutputsFlowLog {
    pub filters: FlowLogFilters,
    pub throttles: Throttles,
    pub tunning: OutputsFlowLogTunning,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct FlowMetricsFilters {
    pub inactive_server_port_aggregation: bool,
    pub inactive_ip_aggregation: bool,
    pub npm_metrics: bool,
    pub apm_metrics: bool,
    pub second_metrics: bool,
}

impl Default for FlowMetricsFilters {
    fn default() -> Self {
        Self {
            inactive_server_port_aggregation: false,
            inactive_ip_aggregation: false,
            npm_metrics: true,
            apm_metrics: true,
            second_metrics: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct FlowMetricsTunning {
    pub sender_queue_size: usize,
    pub sender_queue_count: usize,
}

impl Default for FlowMetricsTunning {
    fn default() -> Self {
        Self {
            sender_queue_size: 65536,
            sender_queue_count: 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct FlowMetrics {
    pub enabled: bool,
    pub filters: FlowMetricsFilters,
    pub tunning: FlowMetricsTunning,
}

impl Default for FlowMetrics {
    fn default() -> Self {
        Self {
            enabled: true,
            filters: FlowMetricsFilters::default(),
            tunning: FlowMetricsTunning::default(),
        }
    }
}

fn to_vlan_mode<'de, D>(deserializer: D) -> Result<agent::VlanMode, D::Error>
where
    D: Deserializer<'de>,
{
    match u8::deserialize(deserializer)? {
        0 => Ok(agent::VlanMode::None),
        1 => Ok(agent::VlanMode::Qinq),
        2 => Ok(agent::VlanMode::Vlan),
        other => Err(de::Error::invalid_value(
            Unexpected::Unsigned(other as u64),
            &"0|1|2",
        )),
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Npb {
    pub max_mtu: u32,
    pub raw_udp_vlan_tag: u16,
    #[serde(deserialize_with = "to_vlan_mode")]
    pub extra_vlan_header: agent::VlanMode,
    pub traffic_global_dedup: bool,
    pub target_port: u16,
    pub custom_vxlan_flags: u8,
    pub overlay_vlan_header_trimming: bool,
    pub max_tx_throughput: u64,
}

impl Default for Npb {
    fn default() -> Self {
        Self {
            max_mtu: 1500,
            raw_udp_vlan_tag: 0,
            extra_vlan_header: agent::VlanMode::None,
            traffic_global_dedup: true,
            target_port: 4789,
            custom_vxlan_flags: 0b1111_1111,
            overlay_vlan_header_trimming: false,
            max_tx_throughput: 1000,
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Outputs {
    pub socket: Socket,
    pub flow_log: OutputsFlowLog,
    pub flow_metrics: FlowMetrics,
    pub npb: Npb,
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Plugins {
    pub update_time: Duration,
    pub wasm_plugins: Vec<String>,
    pub so_plugins: Vec<String>,
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Dev {
    pub feature_flags: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default = "UserConfig::standalone_default")]
pub struct UserConfig {
    pub global: Global,
    pub inputs: Inputs,
    pub outputs: Outputs,
    pub processors: Processors,
    pub plugins: Plugins,
    pub dev: Dev,
}

impl From<&RuntimeConfig> for UserConfig {
    fn from(rc: &RuntimeConfig) -> Self {
        let mut user_config = Self {
            global: Global {
                limits: Limits {
                    max_millicpus: rc.max_millicpus,
                    max_memory: rc.max_memory,
                    max_log_backhaul_rate: rc.log_threshold,
                    max_local_log_file_size: rc.log_file_size,
                    local_log_retention: Duration::from_secs(rc.log_retention as u64),
                },
                alerts: Alerts {
                    thread_threshold: rc.thread_threshold,
                    process_threshold: rc.process_threshold,
                    check_core_file_disabled: rc.yaml_config.check_core_file_disabled,
                },
                circuit_breakers: CircuitBreakers {
                    sys_free_memory_percentage: SysFreeMemoryPercentage {
                        trigger_threshold: rc.sys_free_memory_limit,
                    },
                    relative_sys_load: RelativeSysLoad {
                        trigger_threshold: rc.system_load_circuit_breaker_threshold,
                        recovery_threshold: rc.system_load_circuit_breaker_recover,
                        system_load_circuit_breaker_metric: SystemLoadMetric::from_str_name(
                            rc.system_load_circuit_breaker_metric.as_str_name(),
                        )
                        .unwrap_or(SystemLoadMetric::Load15),
                    },
                    tx_throughput: TxThroughput {
                        trigger_threshold: rc.server_tx_bandwidth_threshold,
                        throughput_monitoring_interval: rc.bandwidth_probe_interval,
                    },
                },
                tunning: Tunning {
                    cpu_affinity: if rc.yaml_config.cpu_affinity.is_empty() {
                        vec![]
                    } else {
                        rc.yaml_config
                            .cpu_affinity
                            .split(',')
                            .map(|s| s.parse::<usize>().unwrap_or_default())
                            .collect()
                    },
                    process_scheduling_priority: rc.yaml_config.process_scheduling_priority
                        as usize,
                    idle_memory_trimming: rc.yaml_config.memory_trim_disabled,
                    resource_monitoring_interval: rc.yaml_config.guard_interval,
                },
                ntp: Ntp {
                    enabled: rc.ntp_enabled,
                    max_drift: rc.yaml_config.ntp_max_interval,
                    min_drift: rc.yaml_config.ntp_min_interval,
                },
                communication: Communication {
                    proactive_request_interval: Duration::from_secs(rc.sync_interval),
                    max_escape_duration: Duration::from_secs(rc.max_escape),
                    proxy_controller_ip: rc.proxy_controller_ip.clone(),
                    proxy_controller_port: rc.proxy_controller_port,
                    ingester_ip: rc.analyzer_ip.clone(),
                    ingester_port: rc.analyzer_port,
                    grpc_buffer_size: rc.yaml_config.grpc_buffer_size,
                    request_via_nat_ip: false, // TODO: This configuration is not used
                },
                self_monitoring: SelfMonitoring {
                    log: Log {
                        log_level: rc.log_level,
                        log_file: rc.yaml_config.log_file.clone(),
                        log_backhaul_enabled: rc.rsyslog_enabled,
                    },
                    profile: Profile {
                        enabled: rc.yaml_config.profiler,
                    },
                    debug: Debug {
                        enabled: rc.debug_enabled,
                        local_udp_port: rc.yaml_config.debug_listen_port,
                        debug_metrics_enabled: rc.yaml_config.enable_debug_stats,
                    },
                    hostname: rc.host.clone(),
                    interval: Duration::from_secs(rc.stats_interval),
                },
                standalone_mode: StandaloneMode {
                    max_data_file_size: rc.yaml_config.standalone_data_file_size,
                    data_file_dir: rc.yaml_config.standalone_data_file_dir.clone(),
                },
                common: GlobalCommon {
                    enabled: rc.enabled,
                    agent_type: agent::AgentType::from_str_name(rc.trident_type.as_str_name())
                        .unwrap_or(agent::AgentType::TtUnknown),
                },
            },
            inputs: Inputs {
                proc: Proc {
                    enabled: rc.yaml_config.os_proc_sync_enabled,
                    proc_dir_path: rc.yaml_config.os_proc_root.clone(),
                    sync_interval: Duration::from_secs(
                        rc.yaml_config.os_proc_socket_sync_interval as u64,
                    ),
                    min_lifetime: Duration::from_secs(
                        rc.yaml_config.os_proc_socket_min_lifetime as u64,
                    ),
                    tag_extraction: TagExtraction {
                        script_command: rc.yaml_config.os_app_tag_exec.clone(),
                        exec_username: rc.yaml_config.os_app_tag_exec_user.clone(),
                    },
                    process_matcher: {
                        let mut matchers = vec![];
                        if !rc.yaml_config.ebpf.on_cpu_profile.disabled {
                            if let Ok(regex) =
                                Regex::new(rc.yaml_config.ebpf.on_cpu_profile.regex.as_str())
                            {
                                matchers.push(ProcessMatcher {
                                    match_regex: regex,
                                    match_type: ProcessMatchType::ProcessName,
                                    enabled_features: vec!["ebpf.profile.on_cpu".to_string()],
                                    ..Default::default()
                                });
                            } else {
                                warn!(
                                    "Invalid on_cpu_profile regex: {}",
                                    rc.yaml_config.ebpf.on_cpu_profile.regex
                                );
                            }
                        }
                        if !rc.yaml_config.ebpf.off_cpu_profile.disabled {
                            if let Ok(regex) =
                                Regex::new(rc.yaml_config.ebpf.off_cpu_profile.regex.as_str())
                            {
                                matchers.push(ProcessMatcher {
                                    match_regex: regex,
                                    match_type: ProcessMatchType::ProcessName,
                                    enabled_features: vec!["ebpf.profile.off_cpu".to_string()],
                                    ..Default::default()
                                });
                            } else {
                                warn!(
                                    "Invalid off_cpu_profile regex: {}",
                                    rc.yaml_config.ebpf.off_cpu_profile.regex
                                );
                            }
                        }
                        if !rc.yaml_config.ebpf.memory_profile.disabled {
                            if let Ok(regex) =
                                Regex::new(rc.yaml_config.ebpf.memory_profile.regex.as_str())
                            {
                                matchers.push(ProcessMatcher {
                                    match_regex: regex,
                                    match_type: ProcessMatchType::ProcessName,
                                    enabled_features: vec!["ebpf.profile.memory".to_string()],
                                    ..Default::default()
                                });
                            } else {
                                warn!(
                                    "Invalid memory_profile regex: {}",
                                    rc.yaml_config.ebpf.memory_profile.regex
                                );
                            }
                        }
                        if rc.yaml_config.os_proc_socket_sync_interval > 0 {
                            matchers.push(ProcessMatcher {
                                match_regex: Regex::new(".*").unwrap(),
                                match_type: ProcessMatchType::ProcessName,
                                enabled_features: vec!["proc.socket_list".to_string()],
                                ..Default::default()
                            });
                        }
                        if !rc.yaml_config.ebpf.uprobe_proc_regexp.golang.is_empty() {
                            if let Ok(regex) =
                                Regex::new(rc.yaml_config.ebpf.uprobe_proc_regexp.golang.as_str())
                            {
                                matchers.push(ProcessMatcher {
                                    match_regex: regex,
                                    match_type: ProcessMatchType::Cmd,
                                    enabled_features: vec!["ebpf.socket.uprobe.golang".to_string()],
                                    ..Default::default()
                                });
                            } else {
                                warn!(
                                    "Invalid golang uprobe regex: {}",
                                    rc.yaml_config.ebpf.uprobe_proc_regexp.golang
                                );
                            }
                        }
                        if !rc
                            .yaml_config
                            .ebpf
                            .uprobe_proc_regexp
                            .golang_symbol
                            .is_empty()
                        {
                            if let Ok(regex) = Regex::new(
                                rc.yaml_config
                                    .ebpf
                                    .uprobe_proc_regexp
                                    .golang_symbol
                                    .as_str(),
                            ) {
                                matchers.push(ProcessMatcher {
                                    match_regex: regex,
                                    match_type: ProcessMatchType::Cmd,
                                    enabled_features: vec!["proc.golang_symbol_table".to_string()],
                                    ..Default::default()
                                });
                            } else {
                                warn!(
                                    "Invalid golang symbol_table uprobe regex: {}",
                                    rc.yaml_config.ebpf.uprobe_proc_regexp.golang_symbol
                                );
                            }
                        }
                        if !rc.yaml_config.ebpf.uprobe_proc_regexp.openssl.is_empty() {
                            if let Ok(regex) =
                                Regex::new(rc.yaml_config.ebpf.uprobe_proc_regexp.openssl.as_str())
                            {
                                matchers.push(ProcessMatcher {
                                    match_regex: regex,
                                    match_type: ProcessMatchType::Cmd,
                                    enabled_features: vec!["ebpf.socket.uprobe.tls".to_string()],
                                    ..Default::default()
                                });
                            } else {
                                warn!(
                                    "Invalid tls uprobe regex: {}",
                                    rc.yaml_config.ebpf.uprobe_proc_regexp.openssl
                                );
                            }
                        }
                        for o in &rc.yaml_config.os_proc_regex {
                            let Ok(regex) = Regex::new(o.match_regex.as_str()) else {
                                warn!("Invalid gprocess info regex: {}", o.match_regex);
                                continue;
                            };
                            matchers.push(ProcessMatcher {
                                match_regex: regex,
                                match_type: ProcessMatchType::from(o.match_type.as_str()),
                                rewrite_name: o.rewrite_name.clone(),
                                action: ProcessMatchAction::from(o.action.as_str()),
                                enabled_features: vec!["proc.gprocess_info".to_string()],
                                ..Default::default()
                            });
                        }
                        matchers
                    },
                    symbol_table: SymbolTable {
                        golang_specific: GolangSpecific {
                            enabled: rc
                                .yaml_config
                                .ebpf
                                .uprobe_proc_regexp
                                .golang_symbol
                                .is_empty(),
                        },
                        java: Java {
                            refresh_defer_duration: rc
                                .yaml_config
                                .ebpf
                                .java_symbol_file_refresh_defer_interval,
                            max_symbol_file_size: 10, // TODO: No corresponding configuration is found
                        },
                    },
                },
                cbpf: Cbpf {
                    common: Common {
                        capture_mode: agent::PacketCaptureType::from_str_name(
                            rc.tap_mode.as_str_name(),
                        )
                        .unwrap_or(agent::PacketCaptureType::Local),
                    },
                    af_packet: AfPacket {
                        interface_regex: rc.tap_interface_regex.clone(),
                        bond_interfaces: rc
                            .yaml_config
                            .tap_interface_bond_groups
                            .iter()
                            .map(|g| BondInterface {
                                slave_interfaces: g.tap_interfaces.clone(),
                            })
                            .collect(),
                        #[cfg(target_os = "linux")]
                        extra_netns_regex: rc.extra_netns_regex.clone(),
                        extra_bpf_filter: rc.capture_bpf.clone(),
                        vlan_pcp_in_physical_mirror_traffic: rc.yaml_config.mirror_traffic_pcp,
                        bpf_filter_disabled: false, // TODO: No corresponding configuration is found
                        tunning: AfPacketTunning {
                            socket_version: agent::CaptureSocketType::from_str_name(
                                rc.capture_socket_type.as_str_name(),
                            )
                            .unwrap_or(agent::CaptureSocketType::Auto),
                            ring_blocks_enabled: rc.yaml_config.af_packet_blocks_enabled,
                            ring_blocks: rc.yaml_config.af_packet_blocks,
                            packet_fanout_count: rc.yaml_config.local_dispatcher_count,
                            packet_fanout_mode: rc.yaml_config.packet_fanout_mode,
                        },
                        src_interfaces: vec![],
                        ..Default::default()
                    },
                    special_network: SpecialNetwork {
                        dpdk: Dpdk {
                            enabled: rc.yaml_config.dpdk_enabled,
                        },
                        libpcap: Libpcap {
                            enabled: rc.yaml_config.libpcap_enabled,
                        },
                        vhost_user: VhostUser {
                            vhost_socket_path: rc.yaml_config.vhost_socket_path.clone(),
                        },
                        physical_switch: PhysicalSwitch {
                            sflow_ports: rc
                                .yaml_config
                                .xflow_collector
                                .sflow_ports
                                .iter()
                                .map(|p| p.parse::<u16>().unwrap_or_default())
                                .collect(),
                            netflow_ports: rc
                                .yaml_config
                                .xflow_collector
                                .netflow_ports
                                .iter()
                                .map(|p| p.parse::<u16>().unwrap_or_default())
                                .collect(),
                        },
                    },
                    tunning: CbpfTunning {
                        dispatcher_queue_enabled: rc.yaml_config.dispatcher_queue,
                        max_capture_packet_size: rc.capture_packet_size,
                        raw_packet_buffer_block_size: rc.yaml_config.analyzer_raw_packet_block_size,
                        raw_packet_queue_size: rc.yaml_config.analyzer_queue_size,
                        max_capture_pps: rc.global_pps_threshold,
                    },
                    preprocess: PreProcess {
                        tunnel_decap_protocols: rc.decap_types.iter().map(|d| *d as u8).collect(),
                        tunnel_trim_protocols: rc.yaml_config.trim_tunnel_types.clone(),
                        packet_segmentation_reassembly: vec![],
                    },
                    physical_mirror: PhysicalMirror {
                        default_capture_network_type: rc.yaml_config.default_tap_type as u16,
                        packet_dedup_disabled: rc.yaml_config.analyzer_dedup_disabled,
                        private_cloud_gateway_traffic: rc.yaml_config.cloud_gateway_traffic,
                    },
                },
                ebpf: Ebpf {
                    disabled: rc.yaml_config.ebpf.disabled,
                    socket: EbpfSocket {
                        uprobe: EbpfSocketUprobe {
                            golang: EbpfSocketUprobeGolang {
                                enabled: rc.yaml_config.ebpf.uprobe_golang_trace_enabled,
                                tracing_timeout: Duration::from_secs(
                                    rc.yaml_config.ebpf.go_tracing_timeout as u64,
                                ),
                            },
                            tls: EbpfSocketUprobeTls {
                                enabled: rc.yaml_config.ebpf.uprobe_openssl_trace_enabled,
                            },
                        },
                        kprobe: EbpfSocketKprobe {
                            blacklist: EbpfSocketKprobePorts {
                                ports: rc.yaml_config.ebpf.kprobe_blacklist.port_list.clone(),
                            },
                            whitelist: EbpfSocketKprobePorts {
                                ports: rc.yaml_config.ebpf.kprobe_whitelist.port_list.clone(),
                            },
                        },
                        tunning: EbpfSocketTunning {
                            max_capture_rate: rc.yaml_config.ebpf.global_ebpf_pps_threshold,
                            syscall_trace_id_disabled: rc
                                .yaml_config
                                .ebpf
                                .syscall_trace_id_disabled,
                            map_prealloc_disabled: rc.yaml_config.ebpf.map_prealloc_disabled,
                        },
                        preprocess: EbpfSocketPreprocess {
                            out_of_order_reassembly_cache_size: rc
                                .yaml_config
                                .ebpf
                                .syscall_out_of_order_cache_size,
                            out_of_order_reassembly_protocols: rc
                                .yaml_config
                                .ebpf
                                .syscall_out_of_order_reassembly
                                .clone(),
                            segmentation_reassembly_protocols: rc
                                .yaml_config
                                .ebpf
                                .syscall_segmentation_reassembly
                                .clone(),
                        },
                    },
                    file: EbpfFile {
                        io_event: EbpfFileIoEvent {
                            collect_mode: rc.yaml_config.ebpf.io_event_collect_mode,
                            minimal_duration: rc.yaml_config.ebpf.io_event_minimal_duration,
                        },
                    },
                    profile: EbpfProfile {
                        on_cpu: EbpfProfileOnCpu {
                            disabled: rc.yaml_config.ebpf.on_cpu_profile.disabled,
                            sampling_frequency: rc.yaml_config.ebpf.on_cpu_profile.frequency as i32,
                            aggregate_by_cpu: rc.yaml_config.ebpf.on_cpu_profile.cpu > 0,
                        },
                        off_cpu: EbpfProfileOffCpu {
                            disabled: rc.yaml_config.ebpf.off_cpu_profile.disabled,
                            min_blocking_time: rc.yaml_config.ebpf.off_cpu_profile.min_block,
                            aggregate_by_cpu: rc.yaml_config.ebpf.off_cpu_profile.cpu > 0,
                        },
                        memory: EbpfProfileMemory {
                            disabled: rc.yaml_config.ebpf.memory_profile.disabled,
                            report_interval: rc.yaml_config.ebpf.memory_profile.report_interval,
                        },
                        unwinding: Unwinding {
                            dwarf_disabled: rc.yaml_config.ebpf.dwarf_disabled,
                            dwarf_regex: rc.yaml_config.ebpf.dwarf_regex.clone(),
                            dwarf_process_map_size: rc.yaml_config.ebpf.dwarf_process_map_size
                                as u32,
                            dwarf_shard_map_size: rc.yaml_config.ebpf.dwarf_shard_map_size as u32,
                        },
                        preprocess: EbpfProfilePreprocess {
                            stack_compression: rc.yaml_config.ebpf.preprocess.stack_compression,
                        },
                    },
                    tunning: EbpfTunning {
                        collector_queue_size: rc.yaml_config.ebpf_collector_queue_size,
                        userspace_worker_threads: rc.yaml_config.ebpf.thread_num as i32,
                        perf_pages_count: rc.yaml_config.ebpf.perf_pages_count as u32,
                        kernel_ring_size: rc.yaml_config.ebpf.ring_size as u32,
                        max_socket_entries: rc.yaml_config.ebpf.max_socket_entries as u32,
                        socket_map_reclaim_threshold: rc.yaml_config.ebpf.socket_map_max_reclaim
                            as u32,
                        max_trace_entries: rc.yaml_config.ebpf.max_trace_entries as u32,
                    },
                    java_symbol_file_refresh_defer_interval: rc
                        .yaml_config
                        .ebpf
                        .java_symbol_file_refresh_defer_interval
                        .as_secs()
                        as i32,
                },
                resources: Resources {
                    push_interval: Duration::from_secs(rc.platform_sync_interval),
                    private_cloud: PrivateCloud {
                        hypervisor_resource_enabled: rc.platform_enabled,
                        vm_mac_source: agent::IfMacSource::from_str_name(
                            rc.if_mac_source.as_str_name(),
                        )
                        .unwrap_or(agent::IfMacSource::IfMac),
                        vm_xml_directory: rc.libvirt_xml_path.clone(),
                        vm_mac_mapping_script: rc.yaml_config.tap_mac_script.clone(),
                    },
                    kubernetes: Kubernetes {
                        kubernetes_namespace: rc.yaml_config.kubernetes_namespace.clone(),
                        api_resources: rc
                            .yaml_config
                            .kubernetes_resources
                            .iter()
                            .map(|r| ApiResources {
                                name: r.name.clone(),
                                disabled: r.disabled,
                                group: r.group.clone(),
                                version: r.version.clone(),
                                field_selector: r.field_selector.clone(),
                            })
                            .collect(),
                        api_list_page_size: rc.yaml_config.kubernetes_api_list_limit,
                        api_list_max_interval: rc.yaml_config.kubernetes_api_list_interval,
                        ingress_flavour: "kubernetes".to_string(), // deprecated
                        pod_mac_collection_method: rc.yaml_config.kubernetes_poller_type,
                    },
                    pull_resource_from_controller: PullResourceFromController {
                        domain_filter: vec![], // TODO: No corresponding configuration is found
                        only_kubernetes_pod_ip_in_local_cluster: false, // TODO: No corresponding configuration is found
                    },
                },
                integration: Integration {
                    enabled: rc.external_agent_http_proxy_enabled,
                    listen_port: rc.external_agent_http_proxy_port,
                    compression: Compression {
                        trace: rc.yaml_config.external_agent_http_proxy_compressed,
                        profile: rc.yaml_config.external_agent_http_proxy_profile_compressed,
                    },
                    prometheus_extra_labels: PrometheusExtraLabels {
                        enabled: rc.yaml_config.prometheus_extra_config.enabled,
                        extra_labels: rc.yaml_config.prometheus_extra_config.labels.clone(),
                        label_length: rc.yaml_config.prometheus_extra_config.labels_limit as usize,
                        value_length: rc.yaml_config.prometheus_extra_config.values_limit as usize,
                    },
                    feature_control: FeatureControl {
                        profile_integration_disabled: rc
                            .yaml_config
                            .external_profile_integration_disabled,
                        trace_integration_disabled: rc
                            .yaml_config
                            .external_trace_integration_disabled,
                        metric_integration_disabled: rc
                            .yaml_config
                            .external_metric_integration_disabled,
                        log_integration_disabled: rc.yaml_config.external_log_integration_disabled,
                    },
                },
            },
            outputs: Outputs {
                socket: Socket {
                    data_socket_type: SocketType::from_str_name(
                        rc.collector_socket_type.as_str_name(),
                    )
                    .unwrap_or(SocketType::Tcp),
                    npb_socket_type: SocketType::from_str_name(rc.npb_socket_type.as_str_name())
                        .unwrap_or(SocketType::Tcp),
                    raw_udp_qos_bypass: rc.yaml_config.enable_qos_bypass,
                    multiple_sockets_to_ingester: rc.yaml_config.multiple_sockets_to_ingester,
                },
                flow_log: OutputsFlowLog {
                    filters: FlowLogFilters {
                        l4_capture_network_types: rc
                            .l4_log_store_tap_types
                            .iter()
                            .map(|t| *t as u16)
                            .collect(),
                        l7_capture_network_types: rc
                            .l7_log_store_tap_types
                            .iter()
                            .map(|t| *t as u16)
                            .collect(),
                        l4_ignored_observation_points: rc
                            .l4_log_ignore_tap_sides
                            .iter()
                            .map(|i| *i as u8 as u16)
                            .collect(),
                        l7_ignored_observation_points: rc
                            .l7_log_ignore_tap_sides
                            .iter()
                            .map(|i| *i as u8 as u16)
                            .collect(),
                    },
                    throttles: Throttles {
                        l4_throttle: rc.l4_log_collect_nps_threshold,
                        l7_throttle: rc.l7_log_collect_nps_threshold,
                    },
                    tunning: OutputsFlowLogTunning {
                        collector_queue_size: rc.yaml_config.flow_sender_queue_size,
                        collector_queue_count: rc.yaml_config.flow_sender_queue_count,
                    },
                },
                flow_metrics: FlowMetrics {
                    enabled: rc.collector_enabled,
                    filters: FlowMetricsFilters {
                        inactive_server_port_aggregation: rc.inactive_server_port_enabled,
                        inactive_ip_aggregation: rc.inactive_ip_enabled,
                        npm_metrics: rc.l4_performance_enabled,
                        apm_metrics: rc.l7_metrics_enabled,
                        second_metrics: rc.vtap_flow_1s_enabled,
                    },
                    tunning: FlowMetricsTunning {
                        sender_queue_size: rc.yaml_config.collector_sender_queue_size,
                        sender_queue_count: rc.yaml_config.collector_sender_queue_count,
                    },
                },
                npb: Npb {
                    max_mtu: rc.mtu,
                    raw_udp_vlan_tag: rc.output_vlan,
                    extra_vlan_header: agent::VlanMode::from_str_name(
                        rc.npb_vlan_mode.as_str_name(),
                    )
                    .unwrap_or(agent::VlanMode::None),
                    traffic_global_dedup: rc.npb_dedup_enabled,
                    target_port: rc.yaml_config.npb_port,
                    custom_vxlan_flags: rc.yaml_config.vxlan_flags,
                    overlay_vlan_header_trimming: rc.yaml_config.ignore_overlay_vlan,
                    max_tx_throughput: rc.npb_bps_threshold,
                },
            },
            processors: Processors {
                packet: Packet {
                    policy: Policy {
                        fast_path_map_size: rc.yaml_config.fast_path_map_size,
                        fast_path_disabled: rc.yaml_config.fast_path_disabled,
                        forward_table_capacity: rc.yaml_config.forward_capacity,
                        max_first_path_level: rc.yaml_config.first_path_level as usize,
                    },
                    tcp_header: TcpHeader {
                        block_size: rc.yaml_config.packet_sequence_block_size,
                        sender_queue_size: rc.yaml_config.packet_sequence_queue_size,
                        sender_queue_count: rc.yaml_config.packet_sequence_queue_count,
                        header_fields_flag: rc.yaml_config.packet_sequence_flag,
                    },
                    pcap_stream: PcapStream {
                        receiver_queue_size: rc.yaml_config.pcap.queue_size as usize,
                        buffer_size_per_flow: rc.yaml_config.pcap.flow_buffer_size,
                        total_buffer_size: rc.yaml_config.pcap.buffer_size,
                        flush_interval: rc.yaml_config.pcap.flush_interval,
                    },
                    toa: Toa {
                        sender_queue_size: rc.yaml_config.toa_sender_queue_size,
                        cache_size: rc.yaml_config.toa_lru_cache_size,
                    },
                },
                request_log: RequestLog {
                    application_protocol_inference: ApplicationProtocolInference {
                        inference_max_retries: rc.yaml_config.l7_protocol_inference_max_fail_count,
                        inference_result_ttl: Duration::from_secs(
                            rc.yaml_config.l7_protocol_inference_ttl as u64,
                        ),
                        enabled_protocols: rc.yaml_config.l7_protocol_enabled.clone(),
                        protocol_special_config: ProtocolSpecialConfig {
                            oracle: OracleConfig {
                                is_be: rc.yaml_config.oracle_parse_config.is_be,
                                int_compressed: rc.yaml_config.oracle_parse_config.int_compress,
                                resp_0x04_extra_byte: rc
                                    .yaml_config
                                    .oracle_parse_config
                                    .resp_0x04_extra_byte,
                            },
                        },
                    },
                    filters: Filters {
                        port_number_prefilters: rc.yaml_config.l7_protocol_ports.clone(),
                        tag_filters: {
                            let mut output = HashMap::new();
                            for (k, v) in rc.yaml_config.l7_log_blacklist.iter() {
                                output.insert(
                                    k.clone(),
                                    v.iter()
                                        .map(|l| TagFilterOperator {
                                            name: l.field_name.clone(),
                                            operator: l.operator.clone(),
                                            value: l.value.clone(),
                                        })
                                        .collect(),
                                );
                            }
                            output
                        },
                        unconcerned_dns_nxdomain_response_suffixes: rc
                            .yaml_config
                            .l7_protocol_advanced_features
                            .unconcerned_dns_nxdomain_response_suffixes
                            .clone(),
                    },
                    timeouts: Timeouts {
                        tcp_request_timeout: rc.yaml_config.rrt_tcp_timeout,
                        udp_request_timeout: rc.yaml_config.rrt_udp_timeout,
                        session_aggregate_window_duration: rc
                            .yaml_config
                            .l7_log_session_aggr_timeout,
                    },
                    tag_extraction: RequestLogTagExtraction {
                        tracing_tag: TracingTag {
                            http_real_client: rc.http_log_proxy_client.clone(),
                            x_request_id: rc.http_log_x_request_id.clone(),
                            apm_trace_id: rc
                                .http_log_trace_id
                                .split(',')
                                .map(|s| s.to_string())
                                .collect(),
                            apm_span_id: rc
                                .http_log_span_id
                                .split(',')
                                .map(|s| s.to_string())
                                .collect(),
                        },
                        http_endpoint: HttpEndpoint {
                            extraction_disabled: rc
                                .yaml_config
                                .l7_protocol_advanced_features
                                .http_endpoint_extraction
                                .disabled,
                            match_rules: rc
                                .yaml_config
                                .l7_protocol_advanced_features
                                .http_endpoint_extraction
                                .match_rules
                                .iter()
                                .map(|r| HttpEndpointMatchRule {
                                    url_prefix: r.prefix.clone(),
                                    keep_segments: r.keep_segments,
                                })
                                .collect(),
                        },
                        custom_fields: {
                            let mut fields = HashMap::new();
                            fields.insert(
                                "http".to_string(),
                                rc.yaml_config
                                    .l7_protocol_advanced_features
                                    .extra_log_fields
                                    .http
                                    .iter()
                                    .map(|f| CustomFields {
                                        field_name: f.field_name.clone(),
                                    })
                                    .collect(),
                            );
                            fields.insert(
                                "http2".to_string(),
                                rc.yaml_config
                                    .l7_protocol_advanced_features
                                    .extra_log_fields
                                    .http2
                                    .iter()
                                    .map(|f| CustomFields {
                                        field_name: f.field_name.clone(),
                                    })
                                    .collect(),
                            );
                            fields
                        },
                        obfuscate_protocols: rc
                            .yaml_config
                            .l7_protocol_advanced_features
                            .obfuscate_enabled_protocols
                            .clone(),
                    },
                    tunning: RequestLogTunning {
                        payload_truncation: rc.l7_log_packet_size,
                        session_aggregate_slot_capacity: rc
                            .yaml_config
                            .l7_log_session_slot_capacity,
                        consistent_timestamp_in_l7_metrics: rc
                            .yaml_config
                            .consistent_timestamp_in_l7_metrics,
                    },
                },
                flow_log: ProcessorsFlowLog {
                    time_window: TimeWindow {
                        max_tolerable_packet_delay: rc.yaml_config.packet_delay,
                        extra_tolerable_flow_delay: rc.yaml_config.second_flow_extra_delay,
                    },
                    conntrack: Conntrack {
                        flow_flush_interval: rc.yaml_config.flow.flush_interval,
                        flow_generation: FlowGeneration {
                            server_ports: rc.yaml_config.server_ports.clone(),
                            cloud_traffic_ignore_mac: rc.yaml_config.flow.ignore_tor_mac,
                            ignore_l2_end: rc.yaml_config.flow.ignore_l2_end,
                            idc_traffic_ignore_vlan: rc.yaml_config.flow.ignore_idc_vlan,
                        },
                        timeouts: ConntrackTimeouts {
                            established: rc.yaml_config.flow.established_timeout,
                            closing_rst: rc.yaml_config.flow.closing_rst_timeout,
                            opening_rst: rc.yaml_config.flow.opening_rst_timeout,
                            others: rc.yaml_config.flow.others_timeout,
                        },
                    },
                    tunning: ProcessorsFlowLogTunning {
                        flow_map_hash_slots: rc.yaml_config.flow.hash_slots,
                        concurrent_flow_limit: rc.yaml_config.flow.capacity,
                        memory_pool_size: rc.yaml_config.flow.memory_pool_size,
                        max_batched_buffer_size: rc.yaml_config.batched_buffer_size_limit,
                        flow_aggregator_queue_size: rc.yaml_config.flow.aggr_queue_size as usize,
                        flow_generator_queue_size: rc.yaml_config.flow_queue_size,
                        quadruple_generator_queue_size: rc.yaml_config.quadruple_queue_size,
                    },
                },
            },
            plugins: Plugins::default(),
            dev: Dev {
                feature_flags: rc.yaml_config.feature_flags.clone(),
            },
        };
        user_config.modify();
        user_config
    }
}

const MB: u64 = 1048576;

impl UserConfig {
    const DEFAULT_DNS_PORTS: &'static str = "53,5353";
    const DEFAULT_TLS_PORTS: &'static str = "443,6443";
    const DEFAULT_ORACLE_PORTS: &'static str = "1521";
    const DEFAULT_MEMCACHED_PORTS: &'static str = "11211";
    const PACKET_FANOUT_MODE_MAX: u32 = 7;

    pub fn get_fast_path_map_size(&self, mem_size: u64) -> usize {
        if self.processors.packet.policy.fast_path_map_size > 0 {
            return self.processors.packet.policy.fast_path_map_size;
        }

        min(max((mem_size / MB / 128 * 32000) as usize, 32000), 1 << 20)
    }

    pub fn get_af_packet_blocks(
        &self,
        capture_mode: agent::PacketCaptureType,
        mem_size: u64,
    ) -> usize {
        if capture_mode == agent::PacketCaptureType::Analyzer
            || self.inputs.cbpf.af_packet.tunning.ring_blocks_enabled
        {
            self.inputs.cbpf.af_packet.tunning.ring_blocks.max(8)
        } else {
            (mem_size as usize / DEFAULT_BLOCK_SIZE / 16).min(128)
        }
    }

    pub fn get_protocol_port(&self) -> HashMap<String, String> {
        let mut new = self
            .processors
            .request_log
            .filters
            .port_number_prefilters
            .clone();

        let dns_str = L7ProtocolParser::DNS(DnsLog::default()).as_str();
        // dns default only parse 53,5353 port. when l7_protocol_ports config without DNS, need to reserve the dns default config.
        if !self
            .processors
            .request_log
            .filters
            .port_number_prefilters
            .contains_key(dns_str)
        {
            new.insert(dns_str.to_string(), Self::DEFAULT_DNS_PORTS.to_string());
        }
        let tls_str = L7ProtocolParser::TLS(TlsLog::default()).as_str();
        // tls default only parse 443,6443 port. when l7_protocol_ports config without TLS, need to reserve the tls default config.
        if !self
            .processors
            .request_log
            .filters
            .port_number_prefilters
            .contains_key(tls_str)
        {
            new.insert(tls_str.to_string(), Self::DEFAULT_TLS_PORTS.to_string());
        }
        let oracle_str = L7ProtocolParser::Oracle(OracleLog::default()).as_str();
        // oracle default only parse 1521 port. when l7_protocol_ports config without ORACLE, need to reserve the oracle default config.
        if !self
            .processors
            .request_log
            .filters
            .port_number_prefilters
            .contains_key(oracle_str)
        {
            new.insert(
                oracle_str.to_string(),
                Self::DEFAULT_ORACLE_PORTS.to_string(),
            );
        }
        let memcached_str = L7ProtocolParser::Memcached(MemcachedLog::default()).as_str();
        // memcached default only parse 11211 port. when l7_protocol_ports config without MEMCACHED, need to reserve the memcached default config.
        if !self
            .processors
            .request_log
            .filters
            .port_number_prefilters
            .contains_key(memcached_str)
        {
            new.insert(
                memcached_str.to_string(),
                Self::DEFAULT_MEMCACHED_PORTS.to_string(),
            );
        }

        new
    }

    pub fn get_protocol_port_parse_bitmap(&self) -> Vec<(String, Bitmap)> {
        /*
            parse all protocol port range
            format example:

                l7-protocol-ports:
                    "HTTP": "80,8080,1000-2000"
                ...
        */
        let l7_protocol_ports = self.get_protocol_port();
        let mut port_bitmap = Vec::new();
        for (protocol_name, port_range) in l7_protocol_ports.iter() {
            port_bitmap.push((
                protocol_name.clone(),
                parse_u16_range_list_to_bitmap(port_range, false).unwrap(),
            ));
        }
        port_bitmap.sort_unstable_by_key(|p| p.0.clone());
        port_bitmap
    }

    pub fn load_from_file<T: AsRef<Path>>(path: T) -> Result<Self, io::Error> {
        let contents = fs::read_to_string(path)?;
        let mut c = if contents.len() == 0 {
            Self::standalone_default()
        } else {
            serde_yaml::from_str(contents.as_str())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?
        };

        c.set_standalone();
        c.validate()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        Ok(c)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.global.communication.proactive_request_interval < Duration::from_secs(1)
            || self.global.communication.proactive_request_interval > Duration::from_secs(60 * 60)
        {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "proactive_request_interval {:?} not in [1s, 1h]",
                self.global.communication.proactive_request_interval
            )));
        }
        if self.inputs.resources.push_interval < Duration::from_secs(10)
            || self.inputs.resources.push_interval > Duration::from_secs(60 * 60)
        {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "push_interval {:?} not in [10s, 1h]",
                self.inputs.resources.push_interval
            )));
        }
        if self.global.self_monitoring.interval < Duration::from_secs(1)
            || self.global.self_monitoring.interval > Duration::from_secs(60 * 60)
        {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "interval {:?} not in [1s, 1h]",
                self.global.self_monitoring.interval
            )));
        }

        // 虽然RFC 791里最低MTU是68，但是此时compressor会崩溃，
        // 所以MTU最低限定到200以确保deepflow-agent能够成功运行
        if self.outputs.npb.max_mtu < 200 {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "MTU({}) specified smaller than 200",
                self.outputs.npb.max_mtu
            )));
        }

        if self.outputs.npb.raw_udp_vlan_tag > 4095 {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "raw_udp_vlan_tag({}) out of range (0-4095)",
                self.outputs.npb.raw_udp_vlan_tag
            )));
        }

        if self.global.communication.ingester_port == 0 {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "ingester_port({}) invalid",
                self.global.communication.ingester_port
            )));
        }
        #[cfg(target_os = "linux")]
        if regex::Regex::new(&self.inputs.cbpf.af_packet.extra_netns_regex).is_err() {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "malformed extra_netns_regex({})",
                self.inputs.cbpf.af_packet.extra_netns_regex
            )));
        }

        if !self.inputs.cbpf.af_packet.interface_regex.is_empty()
            && regex::Regex::new(&self.inputs.cbpf.af_packet.interface_regex).is_err()
        {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "malformed interface_regex({})",
                self.inputs.cbpf.af_packet.interface_regex
            )));
        }

        if self.global.communication.max_escape_duration < Duration::from_secs(600)
            || self.global.communication.max_escape_duration
                > Duration::from_secs(30 * 24 * 60 * 60)
        {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "max_escape_duration {:?} not in [600s, 30d]",
                self.global.communication.max_escape_duration
            )));
        }

        if self.global.communication.proxy_controller_port == 0 {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "proxy_controller_port({}) invalid",
                self.global.communication.proxy_controller_port
            )));
        }

        if !(128..=65535).contains(&self.inputs.cbpf.tunning.max_capture_packet_size) {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "max_capture_packet_size {} not in [128, 65535]",
                self.inputs.cbpf.tunning.max_capture_packet_size
            )));
        }

        if self.outputs.socket.data_socket_type == agent::SocketType::RawUdp {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "invalid data_socket_type {:?}",
                self.outputs.socket.data_socket_type
            )));
        }

        Ok(())
    }

    fn modify_decap_types(&mut self) {
        for tunnel_type in &self.inputs.cbpf.preprocess.tunnel_trim_protocols {
            self.inputs
                .cbpf
                .preprocess
                .tunnel_decap_protocols
                .push(TunnelType::from(tunnel_type.as_str()) as u8)
        }
    }

    fn modify_unit(&mut self) {
        self.global.circuit_breakers.tx_throughput.trigger_threshold <<= 20;
        self.global.communication.grpc_buffer_size <<= 20;
        self.global.limits.max_memory <<= 20;
        self.global.limits.max_local_log_file_size <<= 20;
        self.global.standalone_mode.max_data_file_size <<= 20;
        self.inputs.proc.symbol_table.java.max_symbol_file_size <<= 20;
        self.outputs.npb.max_tx_throughput <<= 20;
    }

    fn modify(&mut self) {
        self.modify_unit();
        self.modify_decap_types();
    }

    fn set_standalone(&mut self) {
        self.global.common.enabled = true;
        self.global.communication.ingester_ip = "127.0.0.1".to_string();
        self.global.communication.ingester_port = 30033;
        self.global.communication.proxy_controller_ip = "127.0.0.1".to_string();
        self.global.communication.proxy_controller_port = 30035;
        self.global.ntp.enabled = false;
        self.outputs.socket.data_socket_type = agent::SocketType::File;
        self.outputs.flow_log.filters.l4_capture_network_types = vec![3];
        self.outputs.flow_log.filters.l7_capture_network_types = vec![3];
        self.modify();
    }

    pub fn standalone_default() -> Self {
        let mut config = Self::default();
        config.set_standalone();

        config
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct UprobeProcRegExp {
    pub golang_symbol: String,
    pub golang: String,
    pub openssl: String,
}

impl Default for UprobeProcRegExp {
    fn default() -> Self {
        Self {
            golang_symbol: String::new(),
            golang: String::new(),
            openssl: String::new(),
        }
    }
}

pub const OS_PROC_REGEXP_MATCH_TYPE_CMD: &'static str = "cmdline";
pub const OS_PROC_REGEXP_MATCH_TYPE_PROC_NAME: &'static str = "process_name";
pub const OS_PROC_REGEXP_MATCH_TYPE_PARENT_PROC_NAME: &'static str = "parent_process_name";
pub const OS_PROC_REGEXP_MATCH_TYPE_TAG: &'static str = "tag";
pub const OS_PROC_REGEXP_MATCH_TYPE_CMD_WITH_ARGS: &'static str = "cmdline_with_args";

pub const OS_PROC_REGEXP_MATCH_ACTION_ACCEPT: &'static str = "accept";
pub const OS_PROC_REGEXP_MATCH_ACTION_DROP: &'static str = "drop";
// use for proc scan match and replace
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Default)]
#[serde(default, rename_all = "kebab-case")]
pub struct OsProcRegexp {
    pub match_regex: String,
    pub match_type: String, // one of cmdline or process_name
    pub rewrite_name: String,
    pub action: String, // one of accept or drop
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Default)]
#[serde(default, rename_all = "kebab-case")]
pub struct EbpfKprobePortlist {
    pub port_list: String,
}

impl From<&EbpfSocketKprobePorts> for EbpfKprobePortlist {
    fn from(p: &EbpfSocketKprobePorts) -> Self {
        Self {
            port_list: p.ports.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct OnCpuProfile {
    pub disabled: bool,
    pub frequency: u16,
    pub cpu: u16,
    pub regex: String,
}

impl Default for OnCpuProfile {
    fn default() -> Self {
        OnCpuProfile {
            disabled: false,
            frequency: 99,
            cpu: 0,
            regex: "^deepflow-.*".to_string(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct OffCpuProfile {
    pub disabled: bool,
    pub regex: String,
    pub cpu: u16,
    #[serde(rename = "minblock", with = "humantime_serde")]
    pub min_block: Duration,
}

impl Default for OffCpuProfile {
    fn default() -> Self {
        OffCpuProfile {
            disabled: false,
            regex: "^deepflow-.*".to_string(),
            cpu: 0,
            min_block: Duration::from_micros(50),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct MemoryProfile {
    pub disabled: bool,
    pub regex: String,
    #[serde(with = "humantime_serde")]
    pub report_interval: Duration,
}

impl Default for MemoryProfile {
    fn default() -> Self {
        MemoryProfile {
            disabled: true,
            regex: "^java".to_string(),
            report_interval: Duration::from_secs(10),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct Preprocess {
    pub stack_compression: bool,
}

impl Default for Preprocess {
    fn default() -> Self {
        Preprocess {
            stack_compression: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct EbpfYamlConfig {
    pub disabled: bool,
    pub log_file: String,
    pub global_ebpf_pps_threshold: u64,
    pub kprobe_whitelist: EbpfKprobePortlist,
    pub kprobe_blacklist: EbpfKprobePortlist,
    #[serde(rename = "uprobe-process-name-regexs")]
    pub uprobe_proc_regexp: UprobeProcRegExp,
    pub thread_num: usize,
    pub perf_pages_count: usize,
    pub ring_size: usize,
    pub max_socket_entries: usize,
    pub max_trace_entries: usize,
    pub socket_map_max_reclaim: usize,
    pub go_tracing_timeout: usize,
    pub dwarf_disabled: bool,
    pub dwarf_regex: String,
    pub dwarf_process_map_size: usize,
    pub dwarf_shard_map_size: usize,
    pub io_event_collect_mode: usize,
    #[serde(with = "humantime_serde")]
    pub io_event_minimal_duration: Duration,
    #[serde(with = "humantime_serde")]
    pub java_symbol_file_refresh_defer_interval: Duration,
    pub on_cpu_profile: OnCpuProfile,
    pub off_cpu_profile: OffCpuProfile,
    pub memory_profile: MemoryProfile,
    pub preprocess: Preprocess,
    pub syscall_out_of_order_cache_size: usize,
    pub syscall_out_of_order_reassembly: Vec<String>,
    pub syscall_segmentation_reassembly: Vec<String>,
    pub syscall_trace_id_disabled: bool,
    pub map_prealloc_disabled: bool,
    pub uprobe_golang_trace_enabled: bool,
    pub uprobe_openssl_trace_enabled: bool,
}

impl Default for EbpfYamlConfig {
    fn default() -> Self {
        EbpfYamlConfig {
            disabled: false,
            log_file: String::new(),
            global_ebpf_pps_threshold: 0,
            thread_num: 1,
            perf_pages_count: 128,
            ring_size: 65536,
            max_socket_entries: 131072,
            max_trace_entries: 131072,
            socket_map_max_reclaim: 120000,
            kprobe_whitelist: EbpfKprobePortlist::default(),
            kprobe_blacklist: EbpfKprobePortlist::default(),
            uprobe_proc_regexp: UprobeProcRegExp::default(),
            go_tracing_timeout: 120,
            io_event_collect_mode: 1,
            io_event_minimal_duration: Duration::from_millis(1),
            dwarf_disabled: true,
            dwarf_regex: "".to_owned(),
            dwarf_process_map_size: 1024,
            dwarf_shard_map_size: 128,
            java_symbol_file_refresh_defer_interval: Duration::from_secs(60),
            on_cpu_profile: OnCpuProfile::default(),
            off_cpu_profile: OffCpuProfile::default(),
            memory_profile: MemoryProfile::default(),
            preprocess: Preprocess::default(),
            syscall_out_of_order_reassembly: vec![],
            syscall_segmentation_reassembly: vec![],
            syscall_out_of_order_cache_size: 16,
            syscall_trace_id_disabled: false,
            map_prealloc_disabled: false,
            uprobe_golang_trace_enabled: false,
            uprobe_openssl_trace_enabled: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct PrometheusExtraConfig {
    pub enabled: bool,
    pub labels: Vec<String>,
    pub labels_limit: u32,
    pub values_limit: u32,
}

impl Default for PrometheusExtraConfig {
    fn default() -> Self {
        PrometheusExtraConfig {
            enabled: false,
            labels: vec![],
            labels_limit: 1024,
            values_limit: 4096,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct KubernetesResourceConfig {
    pub name: String,
    pub group: String,
    pub version: String,
    pub disabled: bool,
    pub field_selector: String,
}

impl From<&ApiResources> for KubernetesResourceConfig {
    fn from(r: &ApiResources) -> Self {
        Self {
            name: r.name.clone(),
            group: r.group.clone(),
            version: r.version.clone(),
            disabled: r.disabled.clone(),
            field_selector: r.field_selector.clone(),
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct MatchRule {
    pub prefix: String,
    pub keep_segments: usize,
}

impl From<&HttpEndpointMatchRule> for MatchRule {
    fn from(r: &HttpEndpointMatchRule) -> Self {
        Self {
            prefix: r.url_prefix.clone(),
            keep_segments: r.keep_segments,
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct HttpEndpointExtraction {
    pub disabled: bool,
    pub match_rules: Vec<MatchRule>,
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct ExtraLogFieldsInfo {
    pub field_name: String,
}

impl From<&CustomFields> for ExtraLogFieldsInfo {
    fn from(c: &CustomFields) -> Self {
        Self {
            field_name: c.field_name.clone(),
        }
    }
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct ExtraLogFields {
    pub http: Vec<ExtraLogFieldsInfo>,
    pub http2: Vec<ExtraLogFieldsInfo>,
}

impl ExtraLogFields {
    pub fn deduplicate(&mut self) {
        fn deduplicate_fields(fields: &mut Vec<ExtraLogFieldsInfo>) {
            fields
                .iter_mut()
                .for_each(|f| f.field_name.make_ascii_lowercase());
            fields.sort_by(|a, b| a.field_name.cmp(&b.field_name));
            fields.dedup_by(|a, b| a.field_name == b.field_name);
        }

        deduplicate_fields(&mut self.http);
        deduplicate_fields(&mut self.http2);
    }
}

fn default_obfuscate_enabled_protocols() -> Vec<String> {
    vec!["Redis".to_string()]
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct L7ProtocolAdvancedFeatures {
    pub http_endpoint_extraction: HttpEndpointExtraction,
    #[serde(default = "default_obfuscate_enabled_protocols")]
    pub obfuscate_enabled_protocols: Vec<String>,
    pub extra_log_fields: ExtraLogFields,
    pub unconcerned_dns_nxdomain_response_suffixes: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, rename_all = "kebab-case")]
pub struct L7LogBlacklist {
    pub field_name: String,
    pub operator: String,
    pub value: String,
}

impl From<&TagFilterOperator> for L7LogBlacklist {
    fn from(o: &TagFilterOperator) -> Self {
        Self {
            field_name: o.name.to_string(),
            operator: o.operator.to_string(),
            value: o.value.to_string(),
        }
    }
}

#[derive(Clone, Copy, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct OracleParseConfig {
    pub is_be: bool,
    pub int_compress: bool,
    pub resp_0x04_extra_byte: bool,
}

#[derive(Clone, Default, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct BondGroup {
    pub tap_interfaces: Vec<String>,
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
    pub multiple_sockets_to_ingester: bool,
    pub fast_path_map_size: usize,
    pub first_path_level: u32,
    pub local_dispatcher_count: usize,
    pub packet_fanout_mode: u32,
    pub src_interfaces: Vec<String>,
    pub tap_interface_bond_groups: Vec<BondGroup>,
    pub mirror_traffic_pcp: u16,
    pub pcap: PcapConfig,
    pub flow: FlowGeneratorConfig,
    pub flow_queue_size: usize,
    pub quadruple_queue_size: usize,
    pub analyzer_queue_size: usize,
    pub analyzer_raw_packet_block_size: usize,
    pub batched_buffer_size_limit: usize,
    pub dpdk_enabled: bool,
    pub dispatcher_queue: bool,
    pub libpcap_enabled: bool,
    pub vhost_socket_path: String,
    pub xflow_collector: XflowGeneratorConfig,
    pub vxlan_flags: u8,
    pub ignore_overlay_vlan: bool,
    pub collector_sender_queue_size: usize,
    pub collector_sender_queue_count: usize,
    pub toa_sender_queue_size: usize,
    pub toa_lru_cache_size: usize,
    pub flow_sender_queue_size: usize,
    pub flow_sender_queue_count: usize,
    #[serde(rename = "second-flow-extra-delay-second", with = "humantime_serde")]
    pub second_flow_extra_delay: Duration,
    #[serde(with = "humantime_serde")]
    pub packet_delay: Duration,
    pub triple: TripleMapConfig,
    pub kubernetes_poller_type: KubernetesPollerType,
    pub trim_tunnel_types: Vec<String>,
    pub analyzer_ip: String,
    pub grpc_buffer_size: usize,
    #[serde(with = "humantime_serde")]
    pub l7_log_session_aggr_timeout: Duration,
    pub l7_log_session_slot_capacity: usize,
    pub tap_mac_script: String,
    pub cloud_gateway_traffic: bool,
    pub kubernetes_namespace: String,
    pub kubernetes_api_list_limit: u32,
    #[serde(with = "humantime_serde")]
    pub kubernetes_api_list_interval: Duration,
    pub kubernetes_resources: Vec<KubernetesResourceConfig>,
    pub external_metrics_sender_queue_size: usize,
    pub ebpf_collector_queue_size: usize,
    pub l7_protocol_inference_max_fail_count: usize,
    pub l7_protocol_inference_ttl: usize,
    pub packet_sequence_block_size: usize, // Enterprise Edition Feature: packet-sequence
    pub packet_sequence_queue_size: usize, // Enterprise Edition Feature: packet-sequence
    pub packet_sequence_queue_count: usize, // Enterprise Edition Feature: packet-sequence
    pub packet_sequence_flag: u8,          // Enterprise Edition Feature: packet-sequence
    pub feature_flags: Vec<String>,
    pub l7_protocol_enabled: Vec<String>,
    pub ebpf: EbpfYamlConfig,
    pub external_agent_http_proxy_compressed: bool,
    pub external_agent_http_proxy_profile_compressed: bool,
    pub standalone_data_file_size: u32,
    pub standalone_data_file_dir: String,
    pub log_file: String,
    #[serde(rename = "l7-protocol-ports")]
    // hashmap<protocolName, portRange>
    pub l7_protocol_ports: HashMap<String, String>,
    pub l7_log_blacklist: HashMap<String, Vec<L7LogBlacklist>>,
    pub npb_port: u16,
    // process and socket scan config
    pub os_proc_root: String,
    pub os_proc_socket_sync_interval: u32, // for sec
    pub os_proc_socket_min_lifetime: u32,  // for sec
    pub os_proc_regex: Vec<OsProcRegexp>,
    pub os_app_tag_exec_user: String,
    pub os_app_tag_exec: Vec<String>,
    // whether to sync os socket and proc info.
    // only make sense when process_info_enabled() == true
    pub os_proc_sync_enabled: bool,
    // sync os socket and proc info only when the process has been tagged.
    pub os_proc_sync_tagged_only: bool,
    #[serde(with = "humantime_serde")]
    pub guard_interval: Duration,
    pub check_core_file_disabled: bool,
    pub memory_trim_disabled: bool,
    pub forward_capacity: usize,
    pub fast_path_disabled: bool,
    // rrt timeout must gt aggr SLOT_WIDTH
    #[serde(with = "humantime_serde")]
    pub rrt_tcp_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub rrt_udp_timeout: Duration,
    pub prometheus_extra_config: PrometheusExtraConfig,
    pub process_scheduling_priority: i8,
    pub cpu_affinity: String,
    pub external_profile_integration_disabled: bool,
    pub external_trace_integration_disabled: bool,
    pub external_metric_integration_disabled: bool,
    pub external_log_integration_disabled: bool,
    #[serde(with = "humantime_serde")]
    pub ntp_max_interval: Duration,
    #[serde(with = "humantime_serde")]
    pub ntp_min_interval: Duration,
    pub l7_protocol_advanced_features: L7ProtocolAdvancedFeatures,
    pub oracle_parse_config: OracleParseConfig,
    pub server_ports: Vec<u16>,
    pub consistent_timestamp_in_l7_metrics: bool,
    pub packet_segmentation_reassembly: Vec<u16>,
}

impl YamlConfig {
    const DEFAULT_DNS_PORTS: &'static str = "53,5353";
    const DEFAULT_TLS_PORTS: &'static str = "443,6443";
    const DEFAULT_ORACLE_PORTS: &'static str = "1521";
    const DEFAULT_MEMCACHED_PORTS: &'static str = "11211";
    const PACKET_FANOUT_MODE_MAX: u32 = 7;
    const DEFAULT_L7_PROTOCOL_ENABLED: [&'static str; 7] =
        ["HTTP", "HTTP2", "MySQL", "Redis", "Kafka", "DNS", "TLS"];

    pub fn load_from_file<T: AsRef<Path>>(path: T, tap_mode: TapMode) -> Result<Self, io::Error> {
        let contents = fs::read_to_string(path)?;
        Self::load(&contents, tap_mode)
    }

    pub fn load<C: AsRef<str>>(contents: C, tap_mode: TapMode) -> Result<Self, io::Error> {
        let contents = contents.as_ref();
        let mut c = if contents.len() == 0 {
            // parsing empty string leads to EOF error
            Self::default()
        } else {
            serde_yaml::from_str(contents)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?
        };

        if c.pcap.queue_size == 0 {
            c.pcap.queue_size = 1 << 16;
        }
        if c.pcap.flow_buffer_size <= 0 {
            c.pcap.flow_buffer_size = 1 << 20;
        }
        if c.pcap.buffer_size <= 0 {
            c.pcap.buffer_size = 1 << 23;
        }
        if c.pcap.flush_interval < MINUTE {
            c.pcap.flush_interval = MINUTE;
        }

        if c.flow.flush_interval < Duration::from_secs(1)
            || c.flow.flush_interval > Duration::from_secs(10)
        {
            c.flow.flush_interval = Duration::from_secs(1);
        }
        if c.flow_queue_size == 0 {
            c.flow_queue_size = 1 << 16;
        }
        if c.quadruple_queue_size == 0 {
            c.quadruple_queue_size = 1 << 18;
        }
        if c.analyzer_queue_size == 0 {
            c.analyzer_queue_size = 1 << 17;
        }
        if c.analyzer_raw_packet_block_size < 65536 {
            c.analyzer_raw_packet_block_size = 65536;
        }
        if c.batched_buffer_size_limit < 1024 {
            c.batched_buffer_size_limit = 1024;
        }
        if c.collector_sender_queue_size == 0 {
            c.collector_sender_queue_size = if tap_mode == TapMode::Analyzer {
                8 << 20
            } else {
                1 << 16
            };
        }
        if c.flow_sender_queue_size == 0 {
            c.flow_sender_queue_size = if tap_mode == TapMode::Analyzer {
                8 << 20
            } else {
                1 << 16
            };
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

        if c.l7_log_session_slot_capacity < 1024 {
            c.l7_log_session_slot_capacity = 1024;
        }

        if c.external_metrics_sender_queue_size == 0 {
            c.external_metrics_sender_queue_size = 1 << 12;
        }

        if c.ebpf_collector_queue_size < 4096 {
            c.ebpf_collector_queue_size = 1 << 16;
        }

        if c.l7_protocol_inference_max_fail_count == 0 {
            c.l7_protocol_inference_max_fail_count = L7_PROTOCOL_INFERENCE_MAX_FAIL_COUNT;
        }

        if c.l7_protocol_inference_ttl == 0 {
            c.l7_protocol_inference_ttl = L7_PROTOCOL_INFERENCE_TTL;
        }

        // Enterprise Edition Feature: packet-sequence
        if c.packet_sequence_block_size <= 0 || c.packet_sequence_block_size >= 1024 {
            c.packet_sequence_block_size = 256;
        }

        // Enterprise Edition Feature: packet-sequence
        if c.packet_sequence_queue_size == 0 {
            if tap_mode == TapMode::Analyzer {
                c.packet_sequence_queue_size = 8 << 20;
            } else {
                c.packet_sequence_queue_size = 1 << 16;
            }
        }

        // Enterprise Edition Feature: packet-sequence
        if c.packet_sequence_queue_count == 0 {
            c.packet_sequence_queue_count = 1;
        }

        if c.vxlan_flags == 0x08 || c.vxlan_flags == 0 {
            c.vxlan_flags = 0xff;
        }
        c.vxlan_flags |= 0x08;

        if c.standalone_data_file_size == 0 {
            c.standalone_data_file_size = 200;
        }

        if c.standalone_data_file_dir.len() == 0 {
            c.standalone_data_file_dir = Path::new(DEFAULT_LOG_FILE)
                .parent()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
        }
        if c.npb_port == 0 {
            c.npb_port = NPB_DEFAULT_PORT;
        }
        if c.ebpf.thread_num == 0 {
            c.ebpf.thread_num = 1;
        }
        if c.ebpf.perf_pages_count < 32 || c.ebpf.perf_pages_count > 8192 {
            c.ebpf.perf_pages_count = 128
        }
        if c.ebpf.ring_size < 8192 || c.ebpf.ring_size > 131072 {
            c.ebpf.ring_size = 65536;
        }
        if c.ebpf.max_socket_entries < 10000 || c.ebpf.max_socket_entries > 2000000 {
            c.ebpf.max_socket_entries = 131072;
        }
        if c.ebpf.socket_map_max_reclaim < 8000 || c.ebpf.socket_map_max_reclaim > 2000000 {
            c.ebpf.socket_map_max_reclaim = 120000;
        }
        if c.ebpf.max_trace_entries < 10000 || c.ebpf.max_trace_entries > 2000000 {
            c.ebpf.max_trace_entries = 131072;
        }
        if c.ebpf.java_symbol_file_refresh_defer_interval < Duration::from_secs(5)
            || c.ebpf.java_symbol_file_refresh_defer_interval > Duration::from_secs(3600)
        {
            c.ebpf.java_symbol_file_refresh_defer_interval = Duration::from_secs(60)
        }
        c.ebpf.off_cpu_profile.min_block = c
            .ebpf
            .off_cpu_profile
            .min_block
            .clamp(Duration::from_micros(0), Duration::from_micros(3600000000));
        c.ebpf.memory_profile.report_interval = c
            .ebpf
            .memory_profile
            .report_interval
            .clamp(Duration::from_secs(1), Duration::from_secs(60));
        if !(8..=1024).contains(&c.ebpf.syscall_out_of_order_cache_size) {
            c.ebpf.syscall_out_of_order_cache_size = 16;
        }

        if c.guard_interval < Duration::from_secs(1) || c.guard_interval > Duration::from_secs(3600)
        {
            c.guard_interval = Duration::from_secs(10);
        }

        if c.kubernetes_api_list_limit < 10 {
            c.kubernetes_api_list_limit = 10;
        }

        if c.kubernetes_api_list_interval < Duration::from_secs(600) {
            c.kubernetes_api_list_interval = Duration::from_secs(600);
        }

        if c.forward_capacity < 1 << 14 {
            c.forward_capacity = 1 << 14;
        }

        if let Err(e) = c.validate() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, e.to_string()));
        }
        c.rrt_tcp_timeout = c
            .rrt_tcp_timeout
            .max(Duration::from_secs(SLOT_WIDTH))
            .min(Duration::from_secs(3600));

        c.rrt_udp_timeout = c
            .rrt_udp_timeout
            .max(Duration::from_secs(SLOT_WIDTH))
            .min(Duration::from_secs(300));

        if c.prometheus_extra_config.labels_limit < 1024
            || c.prometheus_extra_config.labels_limit > 1024 * 1024
        {
            c.prometheus_extra_config.labels_limit = 1024;
        }

        if c.prometheus_extra_config.values_limit < 4096
            || c.prometheus_extra_config.values_limit > 4096 * 1024
        {
            c.prometheus_extra_config.values_limit = 4096;
        }

        let mut valid_labels = vec![];
        let re = Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]*$").unwrap();
        for label in c.prometheus_extra_config.labels {
            if re.is_match(&label) {
                valid_labels.push(label);
            } else {
                debug!("invalid prometheus_extra_config label: {:?}", label);
            }
        }
        c.prometheus_extra_config.labels = valid_labels;

        if c.process_scheduling_priority < -20 || c.process_scheduling_priority > 19 {
            c.process_scheduling_priority = 0;
        }

        if c.local_dispatcher_count == 0 {
            c.local_dispatcher_count = 1;
        }

        if c.packet_fanout_mode > Self::PACKET_FANOUT_MODE_MAX {
            c.packet_fanout_mode = 0;
        }

        if c.mirror_traffic_pcp > 9 {
            c.mirror_traffic_pcp = 0;
        }

        Ok(c)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        Ok(())
    }

    pub fn get_protocol_port(&self) -> HashMap<String, String> {
        let mut new = self.l7_protocol_ports.clone();

        let dns_str = L7ProtocolParser::DNS(DnsLog::default()).as_str();
        // dns default only parse 53,5353 port. when l7_protocol_ports config without DNS, need to reserve the dns default config.
        if !self.l7_protocol_ports.contains_key(dns_str) {
            new.insert(dns_str.to_string(), Self::DEFAULT_DNS_PORTS.to_string());
        }
        let tls_str = L7ProtocolParser::TLS(TlsLog::default()).as_str();
        // tls default only parse 443,6443 port. when l7_protocol_ports config without TLS, need to reserve the tls default config.
        if !self.l7_protocol_ports.contains_key(tls_str) {
            new.insert(tls_str.to_string(), Self::DEFAULT_TLS_PORTS.to_string());
        }
        let oracle_str = L7ProtocolParser::Oracle(OracleLog::default()).as_str();
        // oracle default only parse 1521 port. when l7_protocol_ports config without ORACLE, need to reserve the oracle default config.
        if !self.l7_protocol_ports.contains_key(oracle_str) {
            new.insert(
                oracle_str.to_string(),
                Self::DEFAULT_ORACLE_PORTS.to_string(),
            );
        }
        let memcached_str = L7ProtocolParser::Memcached(MemcachedLog::default()).as_str();
        // memcached default only parse 11211 port. when l7_protocol_ports config without MEMCACHED, need to reserve the memcached default config.
        if !self.l7_protocol_ports.contains_key(memcached_str) {
            new.insert(
                memcached_str.to_string(),
                Self::DEFAULT_MEMCACHED_PORTS.to_string(),
            );
        }

        new
    }

    pub fn get_protocol_port_parse_bitmap(&self) -> Vec<(String, Bitmap)> {
        /*
            parse all protocol port range
            format example:

                l7-protocol-ports:
                    "HTTP": "80,8080,1000-2000"
                ...
        */
        let l7_protocol_ports = self.get_protocol_port();
        let mut port_bitmap = Vec::new();
        for (protocol_name, port_range) in l7_protocol_ports.iter() {
            port_bitmap.push((
                protocol_name.clone(),
                parse_u16_range_list_to_bitmap(port_range, false).unwrap(),
            ));
        }
        port_bitmap.sort_unstable_by_key(|p| p.0.clone());
        port_bitmap
    }
}

impl Default for YamlConfig {
    fn default() -> Self {
        Self {
            log_level: log::Level::Info,
            profiler: false,
            af_packet_blocks_enabled: false,
            af_packet_blocks: 128,
            enable_debug_stats: false,
            analyzer_dedup_disabled: false,
            default_tap_type: 3,
            debug_listen_port: 0,
            enable_qos_bypass: false,
            multiple_sockets_to_ingester: false,
            fast_path_map_size: 0,
            first_path_level: 0,
            src_interfaces: vec![],
            tap_interface_bond_groups: vec![],
            mirror_traffic_pcp: 0,
            pcap: Default::default(),
            flow: Default::default(),
            flow_queue_size: 65536,
            quadruple_queue_size: 262144,
            analyzer_queue_size: 131072,
            analyzer_raw_packet_block_size: 65536,
            batched_buffer_size_limit: 131072,
            dpdk_enabled: false,
            dispatcher_queue: false,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            libpcap_enabled: false,
            #[cfg(target_os = "windows")]
            libpcap_enabled: true,
            vhost_socket_path: "".into(),
            xflow_collector: Default::default(),
            vxlan_flags: 0xff,
            ignore_overlay_vlan: false,
            // default size changes according to tap_mode
            collector_sender_queue_size: 1 << 16,
            collector_sender_queue_count: 1,
            toa_sender_queue_size: 1 << 16,
            toa_lru_cache_size: 1 << 16,
            // default size changes according to tap_mode
            flow_sender_queue_size: 1 << 16,
            flow_sender_queue_count: 1,
            second_flow_extra_delay: Duration::from_secs(0),
            packet_delay: Duration::from_secs(1),
            triple: Default::default(),
            kubernetes_poller_type: KubernetesPollerType::Adaptive,
            trim_tunnel_types: vec![],
            analyzer_ip: "".into(),
            grpc_buffer_size: 5,
            l7_log_session_aggr_timeout: Duration::from_secs(120),
            l7_log_session_slot_capacity: 1024,
            tap_mac_script: "".into(),
            cloud_gateway_traffic: false,
            kubernetes_namespace: "".into(),
            kubernetes_api_list_limit: 1000,
            kubernetes_api_list_interval: Duration::from_secs(600),
            kubernetes_resources: vec![],
            external_metrics_sender_queue_size: 1 << 12,
            l7_protocol_inference_max_fail_count: L7_PROTOCOL_INFERENCE_MAX_FAIL_COUNT,
            l7_protocol_inference_ttl: L7_PROTOCOL_INFERENCE_TTL,
            packet_sequence_block_size: 256, // Enterprise Edition Feature: packet-sequence
            packet_sequence_queue_size: 1 << 16, // Enterprise Edition Feature: packet-sequence
            packet_sequence_queue_count: 1,  // Enterprise Edition Feature: packet-sequence
            packet_sequence_flag: 0,         // Enterprise Edition Feature: packet-sequence
            feature_flags: vec![],
            l7_protocol_enabled: Self::DEFAULT_L7_PROTOCOL_ENABLED
                .iter()
                .map(|s| s.to_string())
                .collect(),
            external_agent_http_proxy_compressed: false,
            external_agent_http_proxy_profile_compressed: true,
            standalone_data_file_size: 200,
            standalone_data_file_dir: Path::new(DEFAULT_LOG_FILE)
                .parent()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string(),

            log_file: DEFAULT_LOG_FILE.into(),
            l7_protocol_ports: HashMap::from([
                (String::from("DNS"), String::from(Self::DEFAULT_DNS_PORTS)),
                (String::from("TLS"), String::from(Self::DEFAULT_TLS_PORTS)),
            ]),
            l7_log_blacklist: HashMap::new(),
            ebpf: EbpfYamlConfig::default(),
            npb_port: NPB_DEFAULT_PORT,
            os_proc_root: "/proc".into(),
            os_proc_socket_sync_interval: 10,
            os_proc_socket_min_lifetime: 3,
            os_proc_regex: vec![OsProcRegexp {
                match_regex: ".*".into(),
                match_type: OS_PROC_REGEXP_MATCH_TYPE_PROC_NAME.into(),
                rewrite_name: "".into(),
                action: OS_PROC_REGEXP_MATCH_ACTION_ACCEPT.into(),
            }],
            os_app_tag_exec_user: "deepflow".to_string(),
            os_app_tag_exec: vec![],
            os_proc_sync_enabled: false,
            os_proc_sync_tagged_only: false,
            guard_interval: Duration::from_secs(10),
            check_core_file_disabled: false,
            memory_trim_disabled: false,
            fast_path_disabled: false,
            forward_capacity: 1 << 14,
            rrt_tcp_timeout: Duration::from_secs(1800),
            rrt_udp_timeout: Duration::from_secs(150),
            prometheus_extra_config: PrometheusExtraConfig::default(),
            process_scheduling_priority: 0,
            cpu_affinity: "".to_string(),
            external_profile_integration_disabled: false,
            external_trace_integration_disabled: false,
            external_metric_integration_disabled: false,
            external_log_integration_disabled: false,
            ntp_max_interval: Duration::from_secs(300),
            ntp_min_interval: Duration::from_secs(10),
            l7_protocol_advanced_features: L7ProtocolAdvancedFeatures::default(),
            local_dispatcher_count: 1,
            packet_fanout_mode: 0,
            oracle_parse_config: OracleParseConfig {
                is_be: true,
                int_compress: true,
                resp_0x04_extra_byte: false,
            },
            ebpf_collector_queue_size: 65535,
            server_ports: vec![],
            consistent_timestamp_in_l7_metrics: false,
            packet_segmentation_reassembly: vec![],
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct PortConfig {
    pub analyzer_port: u16,
    pub proxy_controller_port: u16,
}

impl Default for PortConfig {
    fn default() -> Self {
        let config = UserConfig::default();
        PortConfig {
            analyzer_port: config.global.communication.ingester_port,
            proxy_controller_port: config.global.communication.proxy_controller_port,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct PcapConfig {
    pub queue_size: u32,
    #[serde(with = "humantime_serde")]
    pub flush_interval: Duration,
    pub buffer_size: u64,
    pub flow_buffer_size: u32,
}

impl Default for PcapConfig {
    fn default() -> Self {
        PcapConfig {
            queue_size: 65536,
            flush_interval: Duration::from_secs(60),
            buffer_size: 96 << 10,      // 96K
            flow_buffer_size: 64 << 10, // 64K
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
    #[serde(with = "humantime_serde")]
    pub opening_rst_timeout: Duration,

    #[serde(rename = "flow-slots-size")]
    pub hash_slots: u32,
    #[serde(rename = "flow-count-limit")]
    pub capacity: u32,
    #[serde(with = "humantime_serde")]
    pub flush_interval: Duration,
    #[serde(rename = "flow-aggr-queue-size")]
    pub aggr_queue_size: u32,
    pub memory_pool_size: usize,

    pub ignore_tor_mac: bool,
    pub ignore_l2_end: bool,
    pub ignore_idc_vlan: bool,
}

impl Default for FlowGeneratorConfig {
    fn default() -> Self {
        FlowGeneratorConfig {
            established_timeout: Duration::from_secs(300),
            closing_rst_timeout: Duration::from_secs(35),
            others_timeout: Duration::from_secs(5),
            opening_rst_timeout: Duration::from_secs(1),

            hash_slots: 131072,
            capacity: 65535,
            flush_interval: Duration::from_secs(1),
            aggr_queue_size: 65535,
            memory_pool_size: 65536,

            ignore_tor_mac: false,
            ignore_l2_end: false,
            ignore_idc_vlan: false,
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

#[derive(Debug, Deserialize)]
#[serde(default = "RuntimeConfig::standalone_default")]
pub struct RuntimeConfig {
    pub vtap_group_id: String,
    #[serde(skip)]
    pub enabled: bool,
    pub max_millicpus: u32,
    pub max_memory: u64,
    pub sync_interval: u64,          // unit(second)
    pub platform_sync_interval: u64, // unit(second)
    pub stats_interval: u64,         // unit(second)
    #[serde(rename = "max_collect_pps")]
    pub global_pps_threshold: u64,
    #[cfg(target_os = "linux")]
    #[serde(skip)]
    pub extra_netns_regex: String,
    pub tap_interface_regex: String,
    #[serde(skip)]
    pub host: String,
    #[serde(deserialize_with = "bool_from_int")]
    pub rsyslog_enabled: bool,
    #[serde(skip)]
    pub output_vlan: u16,
    pub mtu: u32,
    #[serde(rename = "max_npb_bps")]
    pub npb_bps_threshold: u64,
    #[serde(deserialize_with = "bool_from_int")]
    pub collector_enabled: bool,
    pub l4_log_store_tap_types: Vec<u8>,
    #[serde(skip)]
    pub app_proto_log_enabled: bool,
    pub l7_log_store_tap_types: Vec<u8>,
    #[serde(deserialize_with = "tap_side_vec_de")]
    pub l4_log_ignore_tap_sides: Vec<TapSide>,
    #[serde(deserialize_with = "tap_side_vec_de")]
    pub l7_log_ignore_tap_sides: Vec<TapSide>,
    #[serde(deserialize_with = "bool_from_int")]
    pub platform_enabled: bool,
    #[serde(skip)]
    pub system_load_circuit_breaker_threshold: f32,
    #[serde(skip)]
    pub system_load_circuit_breaker_recover: f32,
    #[serde(skip)]
    pub system_load_circuit_breaker_metric: trident::SystemLoadMetric,
    #[serde(skip)]
    pub server_tx_bandwidth_threshold: u64,
    #[serde(skip)]
    pub bandwidth_probe_interval: Duration,
    #[serde(deserialize_with = "to_trident_vlan_mode")]
    pub npb_vlan_mode: trident::VlanMode,
    #[serde(skip)]
    pub npb_dedup_enabled: bool,
    #[serde(deserialize_with = "to_trident_if_mac_source")]
    pub if_mac_source: trident::IfMacSource,
    #[serde(deserialize_with = "bool_from_int")]
    pub vtap_flow_1s_enabled: bool,
    #[serde(skip)]
    pub debug_enabled: bool,
    pub log_threshold: u32,
    #[serde(deserialize_with = "to_log_level")]
    pub log_level: log::Level,
    pub analyzer_ip: String,
    pub analyzer_port: u16,
    #[serde(rename = "max_escape_seconds")]
    pub max_escape: u64,
    #[serde(skip)]
    pub proxy_controller_ip: String,
    pub proxy_controller_port: u16,
    #[serde(skip)]
    pub epc_id: u32,
    #[serde(skip)]
    pub vtap_id: u16,
    #[serde(skip)]
    pub team_id: u32,
    #[serde(skip)]
    pub organize_id: u32,
    #[serde(deserialize_with = "to_trident_socket_type")]
    pub collector_socket_type: trident::SocketType,
    #[serde(deserialize_with = "to_trident_socket_type")]
    pub npb_socket_type: trident::SocketType,
    #[serde(skip)]
    pub trident_type: common::TridentType,
    pub capture_packet_size: u32,
    #[serde(deserialize_with = "bool_from_int")]
    pub inactive_server_port_enabled: bool,
    #[serde(deserialize_with = "bool_from_int")]
    pub inactive_ip_enabled: bool,
    #[serde(rename = "vm_xml_path")]
    pub libvirt_xml_path: String,
    pub l7_log_packet_size: u32,
    pub l4_log_collect_nps_threshold: u64,
    pub l7_log_collect_nps_threshold: u64,
    #[serde(deserialize_with = "bool_from_int")]
    pub l7_metrics_enabled: bool,
    #[serde(deserialize_with = "to_tunnel_types")]
    pub decap_types: Vec<TunnelType>,
    pub http_log_proxy_client: String,
    pub http_log_trace_id: String,
    pub http_log_span_id: String,
    pub http_log_x_request_id: String,
    #[serde(skip)]
    pub region_id: u32,
    #[serde(skip)]
    pub pod_cluster_id: u32,
    pub log_retention: u32,
    #[serde(deserialize_with = "to_trident_capture_socket_type")]
    pub capture_socket_type: trident::CaptureSocketType,
    pub process_threshold: u32,
    pub thread_threshold: u32,
    pub capture_bpf: String,
    #[serde(deserialize_with = "bool_from_int")]
    pub l4_performance_enabled: bool,
    #[serde(skip)]
    pub kubernetes_api_enabled: bool,
    #[serde(deserialize_with = "bool_from_int")]
    pub ntp_enabled: bool,
    pub sys_free_memory_limit: u32,
    pub log_file_size: u32,
    #[serde(deserialize_with = "bool_from_int")]
    pub external_agent_http_proxy_enabled: bool,
    pub external_agent_http_proxy_port: u16,
    #[serde(deserialize_with = "to_tap_mode")]
    pub tap_mode: TapMode,
    #[serde(skip)]
    pub plugins: Option<trident::PluginConfig>,
    pub secret_key: String,
    // TODO: expand and remove
    #[serde(rename = "static_config")]
    pub yaml_config: YamlConfig,
}

impl RuntimeConfig {
    pub fn load_from_file<T: AsRef<Path>>(path: T) -> Result<Self, io::Error> {
        let contents = fs::read_to_string(path)?;
        let mut c = if contents.len() == 0 {
            // parsing empty string leads to EOF error
            Self::standalone_default()
        } else {
            serde_yaml::from_str(contents.as_str())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?
        };

        // reset below switch in standalone mode
        c.app_proto_log_enabled = !c.l7_log_store_tap_types.is_empty();
        c.ntp_enabled = false;
        c.validate()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        Ok(c)
    }

    fn standalone_default() -> Self {
        Self {
            vtap_group_id: Default::default(),
            enabled: true,
            max_millicpus: 1000,
            max_memory: 768,
            sync_interval: 60,
            platform_sync_interval: 10,
            stats_interval: 10,
            global_pps_threshold: 2000000,
            #[cfg(target_os = "linux")]
            extra_netns_regex: Default::default(),
            tap_interface_regex: "".into(),
            host: Default::default(),
            rsyslog_enabled: false,
            output_vlan: 0,
            mtu: 1500,
            npb_bps_threshold: 1000,
            collector_enabled: true,
            l4_log_store_tap_types: vec![0],
            platform_enabled: false,
            system_load_circuit_breaker_threshold: 1.0,
            system_load_circuit_breaker_recover: 0.9,
            system_load_circuit_breaker_metric: trident::SystemLoadMetric::Load15,
            server_tx_bandwidth_threshold: 1,
            bandwidth_probe_interval: Duration::from_secs(60),
            npb_vlan_mode: trident::VlanMode::None,
            npb_dedup_enabled: false,
            if_mac_source: trident::IfMacSource::IfMac,
            vtap_flow_1s_enabled: true,
            debug_enabled: true,
            log_threshold: 300,
            log_level: log::Level::Info,
            analyzer_ip: "127.0.0.1".into(),
            analyzer_port: 30033,
            max_escape: 3600,
            proxy_controller_ip: "127.0.0.1".into(),
            proxy_controller_port: 30035,
            epc_id: 3302,
            vtap_id: 3302,
            team_id: 0,
            organize_id: 0,
            collector_socket_type: trident::SocketType::File,
            npb_socket_type: trident::SocketType::RawUdp,
            trident_type: common::TridentType::TtProcess,
            capture_packet_size: 65535,
            inactive_server_port_enabled: true,
            inactive_ip_enabled: true,
            libvirt_xml_path: "/etc/libvirt/qemu/".into(),
            l7_log_packet_size: 1024,
            l4_log_collect_nps_threshold: 10000,
            l7_log_collect_nps_threshold: 10000,
            l7_metrics_enabled: true,
            app_proto_log_enabled: true,
            l7_log_store_tap_types: vec![0],
            l4_log_ignore_tap_sides: vec![],
            l7_log_ignore_tap_sides: vec![],
            decap_types: Default::default(),
            http_log_proxy_client: "X-Forwarded-For".into(),
            http_log_trace_id: "traceparent, sw8".into(),
            http_log_span_id: "traceparent, sw8".into(),
            http_log_x_request_id: "X-Request-ID".into(),
            region_id: 3302,
            pod_cluster_id: 0,
            log_retention: 300,
            capture_socket_type: trident::CaptureSocketType::Auto,
            process_threshold: 10,
            thread_threshold: 500,
            capture_bpf: Default::default(),
            l4_performance_enabled: true,
            kubernetes_api_enabled: false,
            ntp_enabled: false,
            sys_free_memory_limit: 0,
            log_file_size: 1000,
            external_agent_http_proxy_enabled: false,
            external_agent_http_proxy_port: 38086,
            tap_mode: TapMode::Local,
            yaml_config: YamlConfig::load("", TapMode::Local).unwrap(), // Default configuration that needs to be corrected to be available
            plugins: Default::default(),
            secret_key: Default::default(),
        }
    }

    fn modify_decap_types(&mut self) {
        for tunnel_type in &self.yaml_config.trim_tunnel_types {
            self.decap_types
                .push(TunnelType::from(tunnel_type.as_str()));
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.sync_interval < 1 || self.sync_interval > 60 * 60 {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "sync-interval {:?} not in [1s, 1h]",
                Duration::from_secs(self.sync_interval)
            )));
        }
        if self.platform_sync_interval < 10 || self.platform_sync_interval > 60 * 60 {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "platform-sync-interval {:?} not in [10s, 1h]",
                Duration::from_secs(self.platform_sync_interval)
            )));
        }
        if self.stats_interval < 1 || self.stats_interval > 60 * 60 {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "stats-interval {:?} not in [1s, 1h]",
                Duration::from_secs(self.stats_interval)
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

        if self.analyzer_port == 0 {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "analyzer-port({}) invalid",
                self.analyzer_port
            )));
        }
        #[cfg(target_os = "linux")]
        if regex::Regex::new(&self.extra_netns_regex).is_err() {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "malformed extra-netns-regex({})",
                self.extra_netns_regex
            )));
        }

        if !self.tap_interface_regex.is_empty()
            && regex::Regex::new(&self.tap_interface_regex).is_err()
        {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "malformed tap-interface-regex({})",
                self.tap_interface_regex
            )));
        }

        if self.max_escape < 600 || self.max_escape > 30 * 24 * 60 * 60 {
            return Err(ConfigError::RuntimeConfigInvalid(format!(
                "max-escape-seconds {:?} not in [600s, 30d]",
                self.max_escape
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

    fn try_from(conf: trident::Config) -> Result<Self, io::Error> {
        let mut rc = Self {
            vtap_group_id: Default::default(),
            enabled: conf.enabled(),
            max_millicpus: {
                // Compatible with max_cpus and max_millicpus, take the smaller value in milli-cores.
                let max_cpus = conf.max_cpus() * 1000;
                let max_millicpus = conf.max_millicpus.unwrap_or(max_cpus); // conf.max_millicpus may be None, handle the case where conf.max_millicpus is None
                if max_cpus != 0 && max_millicpus != 0 {
                    max_cpus.min(max_millicpus)
                } else {
                    max_cpus | max_millicpus
                }
            },
            max_memory: conf.max_memory() as u64,
            sync_interval: conf.sync_interval() as u64,
            platform_sync_interval: conf.platform_sync_interval() as u64,
            stats_interval: conf.stats_interval() as u64,
            global_pps_threshold: conf.global_pps_threshold(),
            #[cfg(target_os = "linux")]
            extra_netns_regex: conf.extra_netns_regex().to_owned(),
            tap_interface_regex: conf.tap_interface_regex().to_owned(),
            host: conf.host().to_owned(),
            rsyslog_enabled: conf.rsyslog_enabled(),
            output_vlan: (conf.output_vlan() & 0xFFFFFFFF) as u16,
            mtu: conf.mtu(),
            npb_bps_threshold: conf.npb_bps_threshold(),
            collector_enabled: conf.collector_enabled(),
            l4_log_store_tap_types: conf
                .l4_log_tap_types
                .iter()
                .filter_map(|&i| {
                    if i >= u16::from(CaptureNetworkType::Max) as u32 {
                        warn!("invalid tap type: {}", i);
                        None
                    } else {
                        Some(i as u8)
                    }
                })
                .collect(),
            platform_enabled: conf.platform_enabled(),
            system_load_circuit_breaker_threshold: conf.system_load_circuit_breaker_threshold(),
            system_load_circuit_breaker_recover: conf.system_load_circuit_breaker_recover(),
            system_load_circuit_breaker_metric: conf.system_load_circuit_breaker_metric(),
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
            max_escape: conf.max_escape_seconds() as u64,
            proxy_controller_ip: conf.proxy_controller_ip().to_owned(),
            proxy_controller_port: conf.proxy_controller_port() as u16,
            epc_id: conf.epc_id(),
            vtap_id: (conf.vtap_id() & 0xFFFFFFFF) as u16,
            team_id: conf.team_id(),
            organize_id: conf.organize_id(),
            collector_socket_type: conf.collector_socket_type(),
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
            l7_log_store_tap_types: conf
                .l7_log_store_tap_types
                .iter()
                .filter_map(|&i| {
                    if i >= u16::from(CaptureNetworkType::Max) as u32 {
                        warn!("invalid tap type: {}", i);
                        None
                    } else {
                        Some(i as u8)
                    }
                })
                .collect(),
            l4_log_ignore_tap_sides: conf
                .l4_log_ignore_tap_sides
                .iter()
                .filter_map(|s| match TapSide::try_from(*s as u8) {
                    Ok(side) => Some(side),
                    Err(_) => {
                        warn!("invalid tap side: {}", s);
                        None
                    }
                })
                .collect(),
            l7_log_ignore_tap_sides: conf
                .l7_log_ignore_tap_sides
                .iter()
                .filter_map(|s| match TapSide::try_from(*s as u8) {
                    Ok(side) => Some(side),
                    Err(_) => {
                        warn!("invalid tap side: {}", s);
                        None
                    }
                })
                .collect(),
            decap_types: conf
                .decap_type
                .iter()
                .filter_map(|&t| match TunnelType::try_from(t as u8) {
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
            tap_mode: conf.tap_mode(),
            yaml_config: YamlConfig::load(conf.local_config(), conf.tap_mode())?,
            plugins: conf.plugins,
            secret_key: Default::default(),
        };
        rc.modify_decap_types();
        rc.validate()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        Ok(rc)
    }
}

fn to_tunnel_types<'de, D>(deserializer: D) -> Result<Vec<TunnelType>, D::Error>
where
    D: Deserializer<'de>,
{
    Vec::<u8>::deserialize(deserializer)?
        .into_iter()
        .map(|t| {
            TunnelType::try_from(t).map_err(|_| {
                de::Error::invalid_value(
                    Unexpected::Unsigned(t as u64),
                    &"None|Vxlan|Ipip|TencentGre|Geneve|ErspanOrTeb",
                )
            })
        })
        .collect()
}

fn to_trident_socket_type<'de, D>(deserializer: D) -> Result<trident::SocketType, D::Error>
where
    D: Deserializer<'de>,
{
    match String::deserialize(deserializer)?.as_str() {
        "FILE" => Ok(trident::SocketType::File),
        "TCP" => Ok(trident::SocketType::Tcp),
        "UDP" => Ok(trident::SocketType::Udp),
        "RAW_UDP" => Ok(trident::SocketType::RawUdp),
        "" => Ok(trident::SocketType::File),
        other => Err(de::Error::invalid_value(
            Unexpected::Str(other),
            &"FILE|TCP|UDP|RAW_UDP",
        )),
    }
}

fn to_log_level<'de, D>(deserializer: D) -> Result<log::Level, D::Error>
where
    D: Deserializer<'de>,
{
    match String::deserialize(deserializer)?.to_lowercase().as_str() {
        "error" => Ok(log::Level::Error),
        "warn" | "warning" => Ok(log::Level::Warn),
        "info" => Ok(log::Level::Info),
        "debug" => Ok(log::Level::Debug),
        "trace" => Ok(log::Level::Trace),
        "" => Ok(log::Level::Info),
        other => Err(de::Error::invalid_value(
            Unexpected::Str(other),
            &"trace|debug|info|warn|error",
        )),
    }
}

fn to_if_mac_source<'de, D>(deserializer: D) -> Result<agent::IfMacSource, D::Error>
where
    D: Deserializer<'de>,
{
    match u8::deserialize(deserializer)? {
        0 => Ok(agent::IfMacSource::IfMac),
        1 => Ok(agent::IfMacSource::IfName),
        2 => Ok(agent::IfMacSource::IfLibvirtXml),
        other => Err(de::Error::invalid_value(
            Unexpected::Unsigned(other as u64),
            &"0|1|2",
        )),
    }
}

fn to_trident_if_mac_source<'de, D>(deserializer: D) -> Result<trident::IfMacSource, D::Error>
where
    D: Deserializer<'de>,
{
    match u8::deserialize(deserializer)? {
        0 => Ok(trident::IfMacSource::IfMac),
        1 => Ok(trident::IfMacSource::IfName),
        2 => Ok(trident::IfMacSource::IfLibvirtXml),
        other => Err(de::Error::invalid_value(
            Unexpected::Unsigned(other as u64),
            &"0|1|2",
        )),
    }
}

fn to_trident_vlan_mode<'de, D>(deserializer: D) -> Result<trident::VlanMode, D::Error>
where
    D: Deserializer<'de>,
{
    match u8::deserialize(deserializer)? {
        0 => Ok(trident::VlanMode::None),
        1 => Ok(trident::VlanMode::Qinq),
        2 => Ok(trident::VlanMode::Vlan),
        other => Err(de::Error::invalid_value(
            Unexpected::Unsigned(other as u64),
            &"0|1|2",
        )),
    }
}

fn to_tap_mode<'de, D>(deserializer: D) -> Result<TapMode, D::Error>
where
    D: Deserializer<'de>,
{
    match u8::deserialize(deserializer)? {
        0 => Ok(TapMode::Local),
        1 => Ok(TapMode::Mirror),
        2 => Ok(TapMode::Analyzer),
        other => Err(de::Error::invalid_value(
            Unexpected::Unsigned(other as u64),
            &"0|1|2",
        )),
    }
}

fn bool_from_int<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    match u8::deserialize(deserializer)? {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(de::Error::invalid_value(
            Unexpected::Unsigned(other as u64),
            &"0|1",
        )),
    }
}

fn tap_side_vec_de<'de, D>(deserializer: D) -> Result<Vec<TapSide>, D::Error>
where
    D: Deserializer<'de>,
{
    Vec::<u8>::deserialize(deserializer)?
        .into_iter()
        .map(|t| TapSide::try_from(t).map_err(de::Error::custom))
        .collect()
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
