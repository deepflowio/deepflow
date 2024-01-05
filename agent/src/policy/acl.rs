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

use std::fmt;

use crate::common::enums::TapType;
use crate::common::policy::{NpbAction, PolicyData};
use public::proto::trident::FlowAcl;

use super::port_range::{PortRange, PortRangeList};

#[derive(Default)]
pub struct Acl {
    pub id: u32,
    pub tap_type: TapType,
    pub src_groups: Vec<u32>,
    pub dst_groups: Vec<u32>,
    pub src_port_ranges: Vec<PortRange>, // 0仅表示采集端口0
    pub dst_port_ranges: Vec<PortRange>, // 0仅表示采集端口0
    pub proto: u16,                      // 256表示全采集, 0表示采集采集协议0

    pub npb_actions: Vec<NpbAction>,
    pub policy: PolicyData,
    // TODO: DDBS
}

impl Acl {
    fn to_port_ranges(ports: Vec<u16>) -> Vec<PortRange> {
        let mut list = Vec::new();
        let mut min: u16 = 0;
        let mut max: u16 = 0;
        let mut i = 0;
        let ports_len = ports.len();
        for port in ports {
            if i == 0 {
                min = port;
                max = port;
                if ports_len == i + 1 {
                    list.push(PortRange::new(min, max));
                }
                i += 1;
                continue;
            }

            if port == max + 1 {
                max = port
            } else {
                list.push(PortRange::new(min, max));
                min = port;
                max = port;
            }

            if ports_len == i + 1 {
                list.push(PortRange::new(min, max));
            }
            i += 1;
        }
        return list;
    }
}

impl TryFrom<FlowAcl> for Acl {
    type Error = String;

    fn try_from(a: FlowAcl) -> Result<Self, Self::Error> {
        let tap_type = TapType::try_from((a.tap_type.unwrap_or_default() & 0xff) as u16);
        if tap_type.is_err() {
            return Err(format!(
                "Acl tap_type parse error: {:?}.\n",
                tap_type.unwrap_err()
            ));
        }
        let src_ports = PortRangeList::try_from(a.src_ports.unwrap_or_default());
        if src_ports.is_err() {
            return Err(format!(
                "Acl src port parse error: {:?}.\n",
                src_ports.unwrap_err()
            ));
        }
        let dst_ports = PortRangeList::try_from(a.dst_ports.unwrap_or_default());
        if dst_ports.is_err() {
            return Err(format!(
                "Acl dst port parse error: {:?}.\n",
                dst_ports.unwrap_err()
            ));
        }
        Ok(Acl {
            id: a.id.unwrap_or_default(),
            tap_type: tap_type.unwrap(),
            src_groups: a
                .src_group_ids
                .iter()
                .map(|x| (x & 0xffff) as u32)
                .collect(),
            dst_groups: a
                .dst_group_ids
                .iter()
                .map(|x| (x & 0xffff) as u32)
                .collect(),
            src_port_ranges: src_ports.unwrap().element().to_vec(),
            dst_port_ranges: dst_ports.unwrap().element().to_vec(),
            proto: (a.protocol.unwrap_or_default() & 0xffff) as u16,
            ..Default::default()
        })
    }
}

impl fmt::Display for Acl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id:{} TapType:{} SrcGroups:{:?} DstGroups:{:?} SrcPortRange:{:?} DstPortRange:{:?} Proto:{} NpbActions:{:?}",
            self.id, self.tap_type, self.src_groups, self.dst_groups, self.src_port_ranges, self.dst_port_ranges, self.proto, self.npb_actions)
    }
}
