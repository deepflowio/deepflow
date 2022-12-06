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

use std::{
    sync::atomic::{AtomicBool, AtomicU32},
    sync::Arc,
    time::Duration,
};

use public::proto::common::TridentType;

pub const TIMEOUT_OTHERS: Duration = Duration::from_secs(5);
pub const TIMEOUT_ESTABLISHED: Duration = Duration::from_secs(300);
pub const TIMEOUT_CLOSING: Duration = Duration::from_secs(35);

pub struct TcpTimeout {
    pub established: Duration,
    pub closing_rst: Duration,
    pub others: Duration,
}

impl Default for TcpTimeout {
    fn default() -> Self {
        Self {
            established: TIMEOUT_ESTABLISHED,
            closing_rst: TIMEOUT_CLOSING,
            others: TIMEOUT_OTHERS,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FlowTimeout {
    pub opening: Duration,
    pub established: Duration,
    pub closing: Duration,
    pub established_rst: Duration,
    pub exception: Duration,
    pub closed_fin: Duration,
    pub single_direction: Duration,

    pub min: Duration,
    pub max: Duration, // time window
}

impl From<TcpTimeout> for FlowTimeout {
    fn from(t: TcpTimeout) -> Self {
        let mut ft = Self {
            opening: t.others,
            established: t.established,
            closing: t.others,
            established_rst: t.closing_rst,
            exception: t.others,
            closed_fin: Duration::from_secs(2),
            single_direction: t.others,
            min: Duration::from_secs(0),
            max: Duration::from_secs(0),
        };
        ft.update_min_max();
        ft
    }
}

impl FlowTimeout {
    fn update_min_max(&mut self) {
        self.min = self
            .opening
            .min(self.established)
            .min(self.closing)
            .min(self.established_rst)
            .min(self.exception)
            .min(self.closed_fin)
            .min(self.single_direction);
        self.max = self
            .opening
            .max(self.established)
            .max(self.closing)
            .max(self.established_rst)
            .max(self.exception)
            .max(self.closed_fin)
            .max(self.single_direction);
    }
}

#[derive(Default)]
pub struct FlowMapRuntimeConfig {
    pub l7_metrics_enabled: AtomicBool,
    pub l4_performance_enabled: AtomicBool,
    pub app_proto_log_enabled: AtomicBool,
    pub l7_log_packet_size: AtomicU32,
}

#[derive(Clone)]
pub struct FlowMapConfig {
    pub vtap_id: u16,
    pub trident_type: TridentType,
    pub cloud_gateway_traffic: bool,
    pub collector_enabled: bool,
    pub tap_types: [bool; 256],

    pub packet_delay: Duration,
    pub flush_interval: Duration,
    pub flow_timeout: FlowTimeout,
    pub ignore_tor_mac: bool,
    pub ignore_l2_end: bool,

    pub runtime_config: Arc<FlowMapRuntimeConfig>,
}
