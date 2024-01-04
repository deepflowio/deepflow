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

use std::net::{IpAddr, Ipv4Addr};

use super::{endpoint::EPC_FROM_DEEPFLOW, error::Error, IPV4_MAX_MASK_LEN, IPV6_MAX_MASK_LEN};

use public::proto::trident;
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct IpSubnet {
    pub raw_ip: IpAddr,
    pub netmask: u32,
    pub subnet_id: u32,
}

impl Default for IpSubnet {
    fn default() -> IpSubnet {
        IpSubnet {
            raw_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            netmask: 32,
            subnet_id: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum IfType {
    WAN = 3,
    LAN = 4,
}

impl TryFrom<u8> for IfType {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            3 => Ok(Self::WAN),
            4 => Ok(Self::LAN),
            _ => Err("invalid number"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PlatformData {
    pub mac: u64,
    pub ips: Vec<IpSubnet>,
    pub epc_id: i32,
    pub id: u32,
    pub region_id: u32,
    pub pod_cluster_id: u32,
    pub pod_node_id: u32,
    pub if_type: IfType,
    pub device_type: u8,
    pub is_vip_interface: bool,
    // 适配windows hyper-v场景出现的在不同Region存在相同MAC，PlatformData查询GRPC下发的Region id,
    // PlatformData不在同一Region中，该字段为True, 若为true不会创建mac表
    pub skip_mac: bool,
    // 当kvm内的虚拟机为k8s node时，不采集该虚拟的流量，虚拟机流量由k8s node内的trident采集
    // 目前通过pod_node_id>0 && pod_cluster_id>0判定
    pub skip_tap_interface: bool,
    // 适配青云场景，同子网跨宿主机时采集中间网卡流量，流量MAC地址均为虚拟机MAC（可以打上L3end），但是无法打上L2end为了区分需要
    // 链路追踪具体统计哪一端，引入该字段
    pub is_local: bool, // 平台数据为当前宿主机的虚拟机（local segment）设置为true
}

impl Default for PlatformData {
    fn default() -> PlatformData {
        PlatformData {
            mac: 0,
            ips: Vec::new(),
            epc_id: 0,
            id: 0,
            region_id: 0,
            pod_cluster_id: 0,
            pod_node_id: 0,
            if_type: IfType::LAN,
            device_type: 0,
            is_vip_interface: false,
            skip_mac: false,
            skip_tap_interface: false,
            is_local: false,
        }
    }
}

impl TryFrom<&trident::Interface> for PlatformData {
    type Error = Error;

    fn try_from(p: &trident::Interface) -> Result<Self, Self::Error> {
        let mut ips = vec![];
        for ip_res in p.ip_resources.iter() {
            let ip = ip_res.ip().parse::<IpAddr>().map_err(|e| {
                Error::ParsePlatformData(format!(
                    "parse trident::Interface to platform data ip-resource failed: {:?} {}",
                    ip_res.ip(),
                    e
                ))
            })?;
            let max = if ip.is_ipv6() {
                IPV6_MAX_MASK_LEN as u32
            } else {
                IPV4_MAX_MASK_LEN as u32
            };
            ips.push(IpSubnet {
                raw_ip: ip,
                netmask: ip_res.masklen().max(max),
                subnet_id: ip_res.subnet_id(),
            });
        }

        let epc_id = if p.epc_id() > 0 {
            (p.epc_id() & 0xffff) as i32
        } else if p.epc_id() == 0 {
            EPC_FROM_DEEPFLOW
        } else {
            p.epc_id() as i32
        };

        Ok(PlatformData {
            mac: p.mac().try_into().map_err(|e| {
                Error::ParsePlatformData(format!(
                    "parse trident::Interface to platform data mac address failed: {}",
                    e
                ))
            })?,
            ips,
            epc_id,
            id: p.id(),
            region_id: p.region_id(),
            pod_cluster_id: p.pod_cluster_id(),
            pod_node_id: p.pod_node_id(),
            if_type: IfType::try_from(p.if_type() as u8).map_err(|e| {
                Error::ParsePlatformData(format!(
                    "parse trident::Interface to platform data if_type failed: {}",
                    e
                ))
            })?,
            device_type: p.device_type() as u8,
            is_vip_interface: p.is_vip_interface(),
            skip_mac: false,
            skip_tap_interface: p.pod_node_id() > 0 && p.pod_cluster_id() > 0,
            is_local: false,
        })
    }
}
