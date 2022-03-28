use std::path::Path;
use std::sync::Arc;
use std::thread;

use anyhow::{Context, Result};
use flexi_logger::{
    colored_opt_format, Age, Cleanup, Criterion, Duplicate, FileSpec, Logger, Naming,
};
use log::info;

use crate::{
    common::{enums::TapType, tap_types::TapTyper},
    config::Config,
    dispatcher::{self, recv_engine::af_packet::OptTpacketVersion, Dispatcher, DispatcherBuilder},
    monitor::Monitor,
    platform::LibvirtXmlExtractor,
    rpc::{Session, Synchronizer, DEFAULT_TIMEOUT},
    utils::{net, queue, stats, LeakyBucket},
};

pub struct Trident {
    synchronizer: Arc<Synchronizer>,
    monitor: Monitor,
    dispatchers: Vec<Dispatcher>,
    libvirt_xml_extractor: Arc<LibvirtXmlExtractor>,
}

impl Trident {
    pub fn new(config_path: &dyn AsRef<Path>, revision: String) -> Result<Trident> {
        let config = Arc::new(Config::load_from_file(config_path)?);

        let mut logger = Logger::try_with_str("info")?
            .format_for_files(colored_opt_format)
            .log_to_file(FileSpec::try_from(&config.log_file)?)
            .rotate(Criterion::Age(Age::Day), Naming::Timestamps, Cleanup::Never)
            .create_symlink(&config.log_file)
            .append();
        if nix::unistd::getppid().as_raw() != 1 {
            logger = logger.duplicate_to_stderr(Duplicate::All);
        }
        logger.start()?;

        let (ctrl_ip, ctrl_mac) =
            net::get_route_src_ip_and_mac(&config.controller_ips[0].parse().unwrap())
                .context("failed getting control ip and mac")?;

        let stats_collector = Arc::new(stats::Collector::new(&config.controller_ips));
        stats_collector.start();

        let monitor = Monitor::new(stats_collector.clone())?;
        let libvirt_xml_extractor = Arc::new(LibvirtXmlExtractor::new());

        let (flow_sender, flow_receiver, counter) = queue::bounded(65536);
        stats_collector.register_countable("flow_queue", Arc::new(counter), vec![]);
        thread::spawn(|| {
            for flow in flow_receiver {
                info!("{}", flow);
            }
        });
        let (log_sender, log_receiver, counter) = queue::bounded(65536);
        stats_collector.register_countable("log_queue", Arc::new(counter), vec![]);
        thread::spawn(|| for _ in log_receiver {});

        let dispatcher = DispatcherBuilder::new()
            .id(0)
            .ctrl_mac(ctrl_mac)
            .leaky_bucket(Arc::new(LeakyBucket::new(None)))
            .options(Arc::new(dispatcher::Options {
                af_packet_blocks: 128,
                af_packet_version: OptTpacketVersion::TpacketVersionHighestavailablet,
                tap_mode: config.tap_mode,
                tap_mac_script: config.tap_mac_script.clone(),
                is_ipv6: ctrl_ip.is_ipv6(),
                vxlan_port: config.vxlan_port,
                controller_port: config.controller_port,
                controller_tls_port: config.controller_tls_port,
                ..Default::default()
            }))
            .default_tap_type(TapType::Tor)
            .mirror_traffic_pcp(7)
            .tap_typer(Arc::new(TapTyper::new()))
            .analyzer_dedup_disabled(false)
            .libvirt_xml_extractor(libvirt_xml_extractor.clone())
            .flow_output_queue(flow_sender)
            .log_output_queue(log_sender)
            .static_config(config.clone())
            .stats_collector(stats_collector.clone())
            .build()
            .unwrap();

        let session = Arc::new(Session::new(
            config.controller_port,
            config.controller_tls_port,
            DEFAULT_TIMEOUT,
            config.controller_cert_file_prefix.clone(),
            config.controller_ips.clone(),
        ));
        let synchronizer = Arc::new(Synchronizer::new(
            session.clone(),
            revision,
            ctrl_ip.to_string(),
            ctrl_mac.to_string(),
            config.vtap_group_id_request.clone(),
            config.kubernetes_cluster_id.clone(),
            dispatcher.listener(),
        ));
        stats_collector.register_countable("synchronizer", synchronizer.clone(), vec![]);

        Ok(Trident {
            synchronizer,
            monitor,
            dispatchers: vec![dispatcher],
            libvirt_xml_extractor,
        })
    }

    pub fn start(&self) {
        info!("==================== Launching YUNSHAN DeepFlow vTap (a.k.a. Trident) ====================");
        self.synchronizer.start();
        self.monitor.start();
        let rt_config = Arc::new(self.synchronizer.runtime_config());

        for dispatcher in self.dispatchers.iter() {
            dispatcher.start(rt_config.clone());
        }
        self.libvirt_xml_extractor.start();
    }

    pub fn stop(&self) {
        info!("Gracefully stopping");
        self.synchronizer.stop();
        self.monitor.stop();
        for dispatcher in self.dispatchers.iter() {
            dispatcher.stop();
        }
        self.libvirt_xml_extractor.stop();
    }
}
