use std::fs;
use std::io;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

use crate::proto::{common::TridentType, trident};

#[cfg(unix)]
const DEFAULT_LOG_FILE: &str = "/var/log/trident/trident.log";
#[cfg(windows)]
const DEFAULT_LOG_FILE: &str = "C:\\Deepflow\\trident\\log\\trident.log";

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("controller-ips is empty")]
    ControllerIpsEmpty,
    #[error("controller-ips invalid")]
    ControllerIpsInvalid,
}

#[derive(Debug, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct Config {
    pub controller_ips: Vec<String>,
    pub controller_port: u16,
    pub controller_tls_port: u16,
    pub genesis_rpc_port: u16,
    pub genesis_rpc_tls_port: u16,
    pub log_file: String,
    #[serde(with = "LevelDef")]
    pub log_level: log::Level,
    pub profiler: bool,
    pub afpacket_blocks_enabled: bool,
    pub afpacket_blocks: u32,
    pub enable_debug_stats: bool,
    pub analyzer_dedup_disabled: bool,
    pub default_tap_type: u32,
    pub debug_listen_port: u16,
    pub enable_qos_bypass: bool,
    pub fast_path_map_size: u32,
    pub first_path_level: u32,
    pub src_interfaces: Vec<String>,
    #[serde(with = "TapModeDef")]
    pub tap_mode: trident::TapMode,
    pub mirror_traffic_pcp: u16,
    pub controller_cert_file_prefix: String,
    pub vtap_group_id_request: String,
    pub pcap: PcapConfig,
    pub flow: FlowGeneratorConfig,
    pub flow_queue_size: u32,
    pub quadruple_queue_size: u32,
    pub analyzer_queue_size: u32,
    #[serde(rename = "ovs-dpdk-enable")]
    pub ovs_dpdk_enabled: bool,
    pub dpdk_pmd_core_id: u32,
    pub dpdk_ring_port: String,
    pub xflow_collector: XflowGeneratorConfig,
    pub vxlan_port: u16,
    pub collector_sender_queue_size: u32,
    pub collector_sender_queue_count: u32,
    pub flow_sender_queue_size: u32,
    pub flow_sender_queue_count: u32,
    #[serde(with = "humantime_serde")]
    pub second_flow_extra_delay: Duration,
    #[serde(with = "humantime_serde")]
    pub packet_delay: Duration,
    pub triple: TripleMapConfig,
    pub kubernetes_poller_type: KubernetesPollerType,
    pub decap_erspan: bool,
    pub analyzer_ip: String,
    pub kubernetes_cluster_id: String,
    pub ingress_flavour: IngressFlavour,
}

impl Config {
    pub fn load_from_file<T: AsRef<Path>>(path: T) -> Result<Config, io::Error> {
        let contents = fs::read_to_string(path)?;
        let mut c: Config = serde_yaml::from_str(&contents)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

        c.controller_ips = c
            .controller_ips
            .drain(..)
            .filter_map(|addr| Config::resolve_domain(&addr))
            .collect();

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
        if let Err(e) = c.validate() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, e.to_string()));
        }
        Ok(c)
    }

    // resolve domain name (without port) to ip address
    fn resolve_domain(addr: &str) -> Option<String> {
        format!("{}:1", addr)
            .to_socket_addrs()
            .ok()
            .and_then(|mut iter| iter.next())
            .map(|addr| addr.ip().to_string())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.controller_ips.is_empty() {
            return Err(ConfigError::ControllerIpsEmpty);
        }
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            controller_ips: vec!["127.0.0.1".into()],
            controller_port: 20035,
            controller_tls_port: 20135,
            genesis_rpc_port: 20036,
            genesis_rpc_tls_port: 20136,
            log_file: DEFAULT_LOG_FILE.into(),
            log_level: log::Level::Info,
            profiler: false,
            afpacket_blocks_enabled: false,
            afpacket_blocks: 0,
            enable_debug_stats: false,
            analyzer_dedup_disabled: false,
            default_tap_type: 3,
            debug_listen_port: 0,
            enable_qos_bypass: false,
            fast_path_map_size: 0,
            first_path_level: 0,
            src_interfaces: vec!["dummy0".into(), "dummy1".into()],
            tap_mode: trident::TapMode::Local,
            mirror_traffic_pcp: 0,
            controller_cert_file_prefix: "".into(),
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
            kubernetes_cluster_id: "".into(),
            ingress_flavour: IngressFlavour::Kubernetes,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(remote = "log::Level", rename_all = "kebab-case")]
enum LevelDef {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
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
    pub file_directory: String,
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

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
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
#[serde(rename_all = "kebab-case")]
pub enum KubernetesPollerType {
    Adaptive,
    Active,
    Passive,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IngressFlavour {
    Kubernetes,
    Openshift,
}

#[cfg(test)]
mod tests {
    use crate::config::Config;
    use std::fs;

    #[test]
    fn read_yaml_file() {
        // TODO: improve test cases
        let c = Config::load_from_file("config/trident.yaml").expect("failed loading config file");
        assert_eq!(c.controller_ips.len(), 1);
        assert_eq!(&c.controller_ips[0], "127.0.0.1");
    }
}
