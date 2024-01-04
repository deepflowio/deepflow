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

use std::panic;
use std::path::Path;

use anyhow::Result;
use clap::{ArgAction, Parser};
use log::error;
#[cfg(any(target_os = "linux", target_os = "android"))]
use signal_hook::{consts::TERM_SIGNALS, iterator::Signals};

use ::deepflow_agent::*;

#[derive(Parser)]
struct Opts {
    /// Specify config file location
    #[clap(
        short = 'f',
        visible_short_alias = 'c',
        long,
        default_value = "/etc/deepflow-agent.yaml"
    )]
    config_file: String,

    /// Enable standalone mode, default config path is /etc/deepflow-agent-standalone.yaml
    #[clap(long)]
    standalone: bool,

    /// Display the version
    #[clap(short, long, action = ArgAction::SetTrue)]
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

    /// Grant capabilities including cap_net_admin, cap_net_raw,cap_net_bind_service
    #[clap(long)]
    add_cap: bool,

    /// Run agent in sidecar mode.
    /// Environment variable `CTRL_NETWORK_INTERFACE` must be specified and
    /// optionally `K8S_POD_IP_FOR_DEEPFLOW` can be set to override ip address.
    #[clap(long)]
    sidecar: bool,
}

#[cfg(unix)]
fn wait_on_signals() {
    let mut signals = Signals::new(TERM_SIGNALS).unwrap();
    signals.forever().next();
    signals.handle().close();
}

#[cfg(windows)]
fn wait_on_signals() {}

const VERSION_INFO: &'static trident::VersionInfo = &trident::VersionInfo {
    name: env!("AGENT_NAME"),
    branch: env!("BRANCH"),
    commit_id: env!("COMMIT_ID"),
    rev_count: env!("REV_COUNT"),
    compiler: env!("RUSTC_VERSION"),
    compile_time: env!("COMPILE_TIME"),

    revision: concat!(
        env!("BRANCH"),
        " ",
        env!("REV_COUNT"),
        "-",
        env!("COMMIT_ID")
    ),
};

fn main() -> Result<()> {
    panic::set_hook(Box::new(|panic_info| {
        error!("{:?}", panic_info.to_string());
    }));
    let opts = Opts::parse();
    if opts.version {
        println!("{}", VERSION_INFO);
        return Ok(());
    }
    let mut t = trident::Trident::start(
        &Path::new(&opts.config_file),
        VERSION_INFO,
        if opts.standalone {
            trident::RunningMode::Standalone
        } else {
            trident::RunningMode::Managed
        },
        opts.sidecar,
    )?;
    wait_on_signals();
    t.stop();

    Ok(())
}
