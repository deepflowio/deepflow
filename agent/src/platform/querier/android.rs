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

use std::hash::Hasher;

use ahash::AHasher;
use log::{debug, trace};

use crate::{
    config::handler::PlatformConfig,
    platform::platform_synchronizer::{get_all_process_in, process_info_enabled, ProcessData},
    utils::command::{get_hostname, get_ip_address},
};

use public::proto::trident as pb;

pub struct Querier {
    override_os_hostname: Option<String>,

    digest: u64,

    raw_hostname: Option<String>,
    raw_ip_addrs: Vec<String>,

    process_data: Vec<ProcessData>,
}

impl Querier {
    pub fn new(override_os_hostname: Option<String>) -> Self {
        Self {
            override_os_hostname,

            digest: Default::default(),

            raw_hostname: Default::default(),
            raw_ip_addrs: Default::default(),

            process_data: Default::default(),
        }
    }

    pub fn digest(&self) -> u64 {
        self.digest
    }

    // returns digest
    pub fn update(&mut self, config: &PlatformConfig) -> u64 {
        let mut hasher = AHasher::default();

        self.update_raw_hostname(&mut hasher);
        self.update_raw_ip_addr(&mut hasher);

        self.update_process_data(config, &mut hasher);

        self.digest = hasher.finish();
        self.digest()
    }

    pub fn generate_message(&self, config: &PlatformConfig) -> pb::GenesisSyncRequest {
        let mut platform_data = pb::GenesisPlatformData {
            platform_enabled: Some(config.enabled),
            raw_hostname: self.raw_hostname.clone(),
            raw_ip_netns: vec!["default".into()],
            raw_ip_addrs: self.raw_ip_addrs.clone(),
            ..Default::default()
        };

        pb::GenesisSyncRequest {
            platform_data: Some(platform_data),
            process_data: Some(pb::GenesisProcessData {
                process_entries: self
                    .process_data
                    .iter()
                    .map(|data| pb::ProcessInfo::from(data))
                    .collect(),
            }),
            ..Default::default()
        }
    }

    fn update_raw_hostname(&mut self, hasher: &mut AHasher) {
        if let Some(hostname) = self.override_os_hostname.as_ref() {
            if self.raw_hostname.is_none() {
                self.raw_hostname = Some(hostname.clone());
            }
            return;
        }
        match get_hostname() {
            Ok(hostname) => {
                debug!("get_hostname() = {}", hostname);
                hasher.write(hostname.as_bytes());
                trace!("digest={:016x}", hasher.finish());
                self.raw_hostname = Some(hostname);
            }
            Err(e) => debug!("get_hostname failed: {}", e),
        }
    }

    fn update_raw_ip_addr(&mut self, hasher: &mut AHasher) {
        let raw_host_ip_addr = get_ip_address()
            .map_err(|err| debug!("get_ip_address error:{}", err))
            .ok();
        if let Some(ip_addr) = raw_host_ip_addr.as_ref() {
            for line in ip_addr.lines() {
                // 忽略可能变化的行避免version频繁更新
                if line.contains("valid_lft") {
                    continue;
                }
                hasher.write(line.as_bytes());
            }
        }
        self.raw_ip_addrs.push(raw_host_ip_addr.unwrap_or_default());
        debug!("updated ip addresses");
        trace!("digest={:016x}", hasher.finish());
    }

    fn update_process_data(&mut self, config: &PlatformConfig, hasher: &mut AHasher) {
        if !(process_info_enabled(config.trident_type)
            && config.os_proc_scan_conf.os_proc_sync_enabled)
        {
            return;
        }
        trace!("get process data with {:?}", config.os_proc_scan_conf);
        self.process_data.clear();
        get_all_process_in(&config.os_proc_scan_conf, &mut self.process_data);
        // sort and use pid for digest
        self.process_data.sort_by_key(|p| p.pid);
        for p in self.process_data.iter() {
            hasher.write_u64(p.pid);
        }
        debug!(
            "updated process data returned {} entries",
            self.process_data.len()
        );
        trace!("digest={:016x}", hasher.finish());
    }
}
