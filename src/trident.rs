use std::error::Error;
use std::path::Path;

use flexi_logger::{colored_opt_format, Age, Cleanup, Criterion, FileSpec, Logger, Naming};
use log::info;

use crate::config::Config;

pub struct Trident {}

impl Trident {
    pub fn new(config_path: &dyn AsRef<Path>, revision: &str) -> Result<Trident, Box<dyn Error>> {
        let config = Config::load_from_file(config_path)?;

        let logger = Logger::try_with_str("info")?
            .format_for_files(colored_opt_format)
            .log_to_file(FileSpec::try_from(&config.log_file)?)
            .rotate(Criterion::Age(Age::Day), Naming::Timestamps, Cleanup::Never)
            .create_symlink(&config.log_file)
            .append()
            .start()?;
        Ok(Trident {})
    }

    pub fn start(&self) {
        info!("==================== Launching YUNSHAN DeepFlow vTap (a.k.a. Trident) ====================");
    }

    pub fn stop(&self) {
        info!("Gracefully stopping");
    }
}
