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

use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::Ipv4Addr,
    str::FromStr,
    sync::{
        atomic::{AtomicU16, Ordering},
        RwLock,
    },
};

use log::warn;

use public::proto::trident;

use super::{enums::TapType, XflowKey};

const VLAN_MAX: u16 = 4096;

pub struct TapTyper {
    packet: [AtomicU16; (VLAN_MAX + 1) as usize],
    xflow: RwLock<HashMap<XflowKey, TapType>>,
    //xflowmissed 没有删除操作，只有插入操作，这是业务要求(仅打印一次)，问过苑超说key不会一直增长，应该不会有内存泄漏问题
    _xflow_missed: RwLock<HashSet<XflowKey>>,
}

impl TapTyper {
    const TAP_TYPE_ANY: AtomicU16 = AtomicU16::new(0);
    pub fn new() -> Self {
        Self {
            packet: [Self::TAP_TYPE_ANY; (VLAN_MAX + 1) as usize],
            xflow: RwLock::new(HashMap::new()),
            _xflow_missed: RwLock::new(HashSet::new()),
        }
    }

    pub fn get_tap_type_by_vlan(&self, vlan: u16) -> Option<TapType> {
        if vlan > VLAN_MAX {
            return None;
        }

        let p = &self.packet[vlan as usize];
        let tt = p.load(Ordering::Relaxed).try_into().unwrap();
        if tt == TapType::Any {
            warn!("vlan {}'s tap_type is unknown", vlan);
            let _ = p.compare_exchange(
                TapType::Any.into(),
                TapType::Unknown.into(),
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
            None
        } else {
            Some(tt)
        }
    }

    pub fn get_tap_type_by_xflow_key(&self, xflow_key: &XflowKey) -> Option<TapType> {
        let xflow_guard = self.xflow.read().unwrap();
        if xflow_guard.contains_key(xflow_key) {
            return xflow_guard.get(xflow_key).map(|t| *t);
        }
        drop(xflow_guard);

        let xflow_missed_guard = self._xflow_missed.read().unwrap();
        if !xflow_missed_guard.contains(xflow_key) {
            drop(xflow_missed_guard);
            self._xflow_missed.write().unwrap().insert(*xflow_key);
            warn!("xflowKey {}'s tap_type is unknown", xflow_key);
        }
        None
    }

    pub fn on_tap_types_change(&self, tap_types: Vec<trident::TapType>) {
        for tap in self.packet.iter() {
            tap.store(TapType::Any.into(), Ordering::Relaxed);
        }
        let mut xflow = HashMap::new();
        for tap_type in tap_types {
            match tap_type.packet_type() {
                trident::PacketType::Packet => {
                    let vlan = tap_type.vlan() as u16;
                    let tap = tap_type.tap_type() as u16;

                    if vlan > VLAN_MAX || tap == 0 {
                        warn!("invalid vlan({}) or tap_type is {}", vlan, tap);
                        continue;
                    }
                    if let Err(e) = TapType::try_from(tap) {
                        warn!("parse tap_type from protocol buffer TapType error: {}", e);
                    } else {
                        self.packet[vlan as usize].store(tap, Ordering::Relaxed);
                    }
                }
                _ => {
                    let tap = tap_type.tap_type() as u16;
                    let tap_idx = tap_type.tap_port();
                    let ip = Ipv4Addr::from_str(tap_type.source_ip());
                    if ip.is_err() || tap == 0 || tap_idx == 0 {
                        warn!(
                            "invalid source_ip({}) or interface_index is ({}) or tap_type is ({})",
                            tap_type.source_ip(),
                            tap_idx,
                            tap
                        );
                        continue;
                    }
                    match TapType::try_from(tap) {
                        Ok(tap_type) => {
                            let xflow_key = XflowKey {
                                ip: ip.unwrap(),
                                tap_idx,
                            };
                            xflow.insert(xflow_key, tap_type);
                        }
                        Err(err) => {
                            warn!("prase tap_type from protocol buffer TapType error: {}", err);
                        }
                    }
                }
            }
        }

        *self.xflow.write().unwrap() = xflow;
    }
}

impl Default for TapTyper {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TapTyper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let packet: Vec<(u16, TapType)> = self
            .packet
            .iter()
            .enumerate()
            .filter_map(|(vlan, tap_type)| {
                let tap_type = TapType::try_from(tap_type.load(Ordering::Relaxed)).unwrap();
                if tap_type != TapType::Any {
                    Some((vlan as u16, tap_type))
                } else {
                    None
                }
            })
            .collect();

        let xflow_str = self.xflow.read().unwrap().iter().fold(
            "".to_string(),
            |mut result, (key, tap_type)| {
                result.push_str(format!("[{},{}]", *key, *tap_type).as_str());
                result
            },
        );

        write!(
            f,
            "packet taptypes:{:?} xlfow taptypes {}",
            packet, xflow_str
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update_vlan(tap_typer: &mut TapTyper, vlan: u16, tap: u16) {
        let pb_tap_type = trident::TapType {
            tap_type: Some(tap as u32),
            vlan: Some(vlan as u32),
            packet_type: Some(trident::PacketType::Packet as i32),
            source_ip: None,
            tap_port: None,
        };
        tap_typer.on_tap_types_change(vec![pb_tap_type]);
    }

    fn verify_vlan(tap_typer: &TapTyper, vlan: u16, tap: u16) {
        let tap_actual = tap_typer.get_tap_type_by_vlan(vlan).unwrap();
        assert_eq!(
            tap,
            u16::from(tap_actual),
            "actual tap_type[vlan:{0}, taptype:{1}], but expected tap_type[vlan:{0}, taptype:{2}]",
            vlan,
            u16::from(tap_actual),
            tap
        );
    }

    fn update_xflow(tap_typer: &mut TapTyper, ip: &str, tap_idx: u32, tap: u16) {
        let pb_tap_type = trident::TapType {
            tap_type: Some(tap as u32),
            packet_type: Some(trident::PacketType::Sflow as i32),
            source_ip: Some(ip.to_string()),
            tap_port: Some(tap_idx),
            vlan: None,
        };

        tap_typer.on_tap_types_change(vec![pb_tap_type]);
    }

    fn verify_xflow(tap_typer: &mut TapTyper, ip: &str, tap_idx: u32, tap: u16) {
        let ip = Ipv4Addr::from_str(ip).unwrap();
        let xflow_key = XflowKey { ip, tap_idx };
        let tap_actual = tap_typer.get_tap_type_by_xflow_key(&xflow_key).unwrap();

        assert_eq!(tap, u16::from(tap_actual),
            "actual tap_type[flowKey:{0}, taptype:{1}], but expected tap_type[flowKey:{0}, taptype:{2}]",
            xflow_key, u16::from(tap_actual), tap
        );
    }

    #[test]
    fn assert_tap_typer_update() {
        let mut tap_typer = TapTyper::new();

        update_vlan(&mut tap_typer, 100, 2);
        verify_vlan(&tap_typer, 100, 2);

        update_xflow(&mut tap_typer, "1.2.3.4", 20, 3);
        verify_xflow(&mut tap_typer, "1.2.3.4", 20, 3);
    }

    #[test]
    #[should_panic]
    fn assert_tap_typer_failed_vlan() {
        let mut tap_typer = TapTyper::new();
        update_vlan(&mut tap_typer, 100, 2);
        verify_vlan(&tap_typer, 100, 100);
    }

    #[test]
    #[should_panic]
    fn assert_tap_typer_failed_xflow() {
        let mut tap_typer = TapTyper::new();
        update_xflow(&mut tap_typer, "1.2.3.4", 20, 2);
        verify_xflow(&mut tap_typer, "1.2.3.4", 20, 100);
    }
}
