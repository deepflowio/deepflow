use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use flexi_logger::{
    colored_opt_format, writers::FileLogWriter, Age, Cleanup, Criterion, Duplicate, FileSpec,
    Logger, LoggerHandle, Naming,
};
use log::{info, LevelFilter, Log};

use crate::config::Config;
use crate::rpc::{Session, Synchronizer, DEFAULT_TIMEOUT};
use crate::utils::{net, stats};

pub struct Trident {
    synchronizer: Arc<Synchronizer>,
}

impl Trident {
    pub fn new(config_path: &dyn AsRef<Path>, revision: String) -> Result<Trident> {
        let config = Config::load_from_file(config_path)?;

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

        let stats_collector = stats::Collector::new(&config.controller_ips);
        stats_collector.start();

        let session = Arc::new(Session::new(
            config.controller_port,
            config.controller_tls_port,
            DEFAULT_TIMEOUT,
            config.controller_cert_file_prefix,
            config.controller_ips,
        ));
        let synchronizer = Arc::new(Synchronizer::new(
            session.clone(),
            revision,
            ctrl_ip.to_string(),
            ctrl_mac.to_string(),
            config.vtap_group_id_request,
            config.kubernetes_cluster_id,
        ));
        stats_collector.register_countable("synchronizer", synchronizer.clone(), vec![]);
        Ok(Trident { synchronizer })
    }

    pub fn start(&self) {
        info!("==================== Launching YUNSHAN DeepFlow vTap (a.k.a. Trident) ====================");
        self.synchronizer.start();
    }

    pub fn stop(&self) {
        info!("Gracefully stopping");
        self.synchronizer.stop();
    }
}
