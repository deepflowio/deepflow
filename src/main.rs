use std::error::Error;
use std::path::Path;

use clap::{AppSettings, Parser};
use signal_hook::consts::TERM_SIGNALS;
use signal_hook::iterator::Signals;

use ::trident::*;

#[derive(Parser)]
#[clap(setting = AppSettings::DisableVersionFlag)]
struct Opts {
    /// Specify config file location
    #[clap(short = 'f', long, default_value = "/etc/trident.yaml")]
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

fn main() -> Result<(), Box<dyn Error>> {
    let opts = Opts::parse();
    let version = format!("{}-{}", env!("REV_COUNT"), env!("REVISION"));

    if opts.version {
        println!(
            "{} {}\n{}",
            version,
            env!("COMMIT_DATE"),
            env!("RUSTC_VERSION")
        );
        return Ok(());
    }

    let t = trident::Trident::new(&Path::new(&opts.config_file), &version)?;
    t.start();
    wait_on_signals();
    t.stop();

    Ok(())
}
