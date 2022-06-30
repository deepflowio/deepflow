use std::path::Path;
use std::process::exit;
use std::thread;
use std::time::Duration;

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

#[allow(dead_code)]
#[cfg(unix)]
fn wait_on_signals() {
    let mut signals = Signals::new(TERM_SIGNALS).unwrap();
    signals.forever().next();
    signals.handle().close();
}

#[allow(dead_code)]
#[cfg(windows)]
fn wait_on_signals() {}

/*
fn main() -> Result<()> {
    let opts = Opts::parse();
    let version = format!("{}-{}", env!("REV_COUNT"), env!("REVISION"));
    let mut t = trident::Trident::start(&Path::new(&opts.config_file), version)?;
    wait_on_signals();
    t.stop();

    Ok(())
}
 */

//FIXME: 为了适配metaflow-server容器环境IP变化，隔1分钟去刷DNS获取最新控制器IP，然后重启agent
// 等做好域名解析之后就去掉
// ======================================================================================
//FIXME: In order to adapt to the IP changes of the metaflow-server container environment,
// refresh the DNS every 1 minute to obtain the latest controller IP, and then restart the agent.
// After has completed the domain name resolution, it will be removed.
fn main() -> Result<()> {
    let opts = Opts::parse();
    let version = format!("{}-{}", env!("REV_COUNT"), env!("REVISION"));
    let mut config = Config::load_from_file(&Path::new(&opts.config_file))?;
    let mut t = trident::Trident::start(&Path::new(&opts.config_file), version.clone())?;
    loop {
        let tmp_config = Config::load_from_file(&Path::new(&opts.config_file))?;
        if config.controller_ips != tmp_config.controller_ips {
            println!(
                "controller_ips change from {:?} to {:?}, restart metaflow-agent.",
                config.controller_ips, tmp_config.controller_ips
            );
            t.stop();
            thread::sleep(Duration::from_secs(1));
            exit(0);
        }
        thread::sleep(Duration::from_secs(60));
    }
}
