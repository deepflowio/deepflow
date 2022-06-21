use std::path::Path;

use anyhow::Result;
use clap::Parser;
use signal_hook::consts::TERM_SIGNALS;
use signal_hook::iterator::Signals;

use ::metaflow_agent::*;

#[derive(Parser)]
#[clap(version=concat!(env!("REV_COUNT"), "-", env!("REVISION"), " ", env!("COMMIT_DATE"), "\n", env!("RUSTC_VERSION")))]
struct Opts {
    /// Specify config file location
    #[clap(short = 'f', long, default_value = "/etc/metaflow-agent.yaml")]
    config_file: String,

    /// Display the version
    #[clap(short, long)]
    version: bool,

    /// Dump interface info
    #[clap(long = "dump-ifs")]
    dump_interfaces: bool,

    // TODO: use enum type
    /// Interface mac source type, used with '--dump-ifs'
    #[clap(long, default_value = "mac")]
    if_mac_source: String,

    /// Libvirt XML path, used with '--dump-ifs' and '--if-mac-source xml'
    #[clap(long, default_value = "/etc/libvirt/qemu")]
    xml_path: String,

    /// Check privileges under kubernetes
    #[clap(long)]
    check_privileges: bool,

    /// grant capabilities including cap_net_admin, cap_net_raw,cap_net_bind_service
    #[clap(long)]
    add_cap: bool,
}

#[cfg(unix)]
fn wait_on_signals() {
    let mut signals = Signals::new(TERM_SIGNALS).unwrap();
    signals.forever().next();
    signals.handle().close();
}

#[cfg(windows)]
fn wait_on_signals() {}

fn main() -> Result<()> {
    let opts = Opts::parse();
    let version = format!("{}-{}", env!("REV_COUNT"), env!("REVISION"));
    let mut t = trident::Trident::start(&Path::new(&opts.config_file), version)?;
    wait_on_signals();
    t.stop();

    Ok(())
}
