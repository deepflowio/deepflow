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

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

use npb_pcap_policy::{NpbTunnelType, PolicyData};
use public::{
    counter::{CounterType, CounterValue, OwnedCountable},
    leaky_bucket::LeakyBucket,
    queue::DebugSender,
};

pub const NOT_SUPPORT: bool = true;

#[derive(Debug)]
pub enum NpbMode {
    L2,
    IPv4,
    IPv6,
    IPv4TCP,
    IPv6TCP,
}

#[derive(Default)]
pub struct NpbHandlerCounter {
    pub rx: AtomicUsize,
    pub rx_bytes: AtomicUsize,
    pub tx: AtomicUsize,
    pub tx_bytes: AtomicUsize,
}

impl NpbHandlerCounter {
    fn reset(&self) {
        self.rx.store(0, Ordering::Relaxed);
        self.rx_bytes.store(0, Ordering::Relaxed);
        self.tx.store(0, Ordering::Relaxed);
        self.tx_bytes.store(0, Ordering::Relaxed);
    }
}

pub struct StatsNpbHandlerCounter(pub Weak<NpbHandlerCounter>);

impl OwnedCountable for StatsNpbHandlerCounter {
    fn closed(&self) -> bool {
        return self.0.strong_count() == 0;
    }

    fn get_counters(&self) -> Vec<public::counter::Counter> {
        match self.0.upgrade() {
            Some(x) => {
                let (rx, rx_bytes, tx, tx_bytes) = (
                    x.rx.load(Ordering::Relaxed) as u64,
                    x.rx_bytes.load(Ordering::Relaxed) as u64,
                    x.tx.load(Ordering::Relaxed) as u64,
                    x.tx_bytes.load(Ordering::Relaxed) as u64,
                );
                x.reset();

                vec![
                    ("in", CounterType::Counted, CounterValue::Unsigned(rx)),
                    (
                        "in_bytes",
                        CounterType::Counted,
                        CounterValue::Unsigned(rx_bytes),
                    ),
                    ("out", CounterType::Counted, CounterValue::Unsigned(tx)),
                    (
                        "out_bytes",
                        CounterType::Counted,
                        CounterValue::Unsigned(tx_bytes),
                    ),
                ]
            }
            None => {
                vec![]
            }
        }
    }
}

pub struct NpbHandler;

impl NpbHandler {
    pub fn new(
        _id: usize,
        _mtu: usize,
        _pseudo_tunnel_header: [Vec<u8>; NpbTunnelType::Max as usize],
        _underlay_vlan_header_size: usize,
        _overlay_vlan: bool,
        _bps_limit: Arc<LeakyBucket>,
        _counter: Arc<NpbHandlerCounter>,
        _sender: DebugSender<(u64, usize, Vec<u8>)>,
    ) -> Self {
        NpbHandler {}
    }

    pub fn handle(
        &mut self,
        _policy: Option<&Arc<PolicyData>>,
        _npb_mode: &NpbMode,
        _timestamp: u64,
        _packet: &[u8],
        _packet_size: usize,
        _l2_opt_size: usize,
        _l3_opt_size: usize,
        _l4_opt_size: usize,
        _ipv6_last_option_offset: usize,
        _ipv6_fragment_option_offset: usize,
    ) {
    }
}

#[derive(Default)]
pub struct NpbHeader {
    pub total_length: u16,
}

impl NpbHeader {
    pub const SIZEOF: usize = 16;

    pub fn new(_: u16, _: u8, _: u32, _: u64) -> Self {
        NpbHeader::default()
    }

    pub fn encode(&self, _buffer: &mut [u8]) -> usize {
        Self::SIZEOF
    }

    pub fn decode(&mut self, _buffer: &[u8]) -> usize {
        Self::SIZEOF
    }
}

impl TryFrom<&[u8]> for NpbHeader {
    type Error = bool;
    fn try_from(_buffer: &[u8]) -> Result<Self, Self::Error> {
        Ok(NpbHeader::default())
    }
}
