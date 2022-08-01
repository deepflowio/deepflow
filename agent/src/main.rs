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

use std::path::Path;

use anyhow::Result;
use clap::{ArgAction, Parser};
#[cfg(target_os = "linux")]
use signal_hook::{consts::TERM_SIGNALS, iterator::Signals};

use ::deepflow_agent::*;

#[derive(Parser)]
struct Opts {
    /// Specify config file location
    #[clap(short = 'f', long, default_value = "/etc/deepflow-agent.yaml")]
    config_file: String,

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
    let version = concat!(env!("REV_COUNT"), "-", env!("REVISION"));
    if opts.version {
        println!("{} {}", version, env!("COMMIT_DATE"));
        println!("deepflow-agent community edition");
        println!(env!("RUSTC_VERSION"));
        return Ok(());
    }
    let mut t =
        trident::Trident::start(&Path::new(&opts.config_file), env!("AGENT_NAME"), version)?;
    wait_on_signals();
    t.stop();

    Ok(())
}
