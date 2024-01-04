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

use bitflags::bitflags;
use std::{net::IpAddr, net::Ipv4Addr, sync::Arc};

use super::platform_data::PlatformData;

pub const EPC_FROM_DEEPFLOW: i32 = -1;
pub const EPC_FROM_INTERNET: i32 = -2;
pub const GROUP_INTERNET: i32 = -2;

bitflags! {
    #[derive(Default)]
    pub struct FeatureFlags: u32 {
        const NONE = 0;
        const DEDUP = 0b01;
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EndpointInfo {
    pub real_ip: IpAddr, // IsVIP为true时，该字段有值
    pub l2_epc_id: i32,  // 负数表示特殊值
    pub l3_epc_id: i32,  // 负数表示特殊值
    pub l2_end: bool,
    pub l3_end: bool,
    pub is_device: bool,
    pub is_vip_interface: bool,
    pub is_vip: bool,
    pub is_local_mac: bool, // 对应平台数据中的IsLocal字段
    pub is_local_ip: bool,  // 对应平台数据中的IsLocal字段
}

impl EndpointInfo {
    pub fn set_l3_l2_end(&mut self, ends: L3L2End) {
        let ends: (bool, bool) = ends.into();
        self.l2_end = ends.0;
        self.l3_end = ends.1;
        // L3和L2都是TRUE的时候, 更新L3EpcId
        if self.l2_end && self.l3_end {
            if self.l2_epc_id != 0 && self.l3_epc_id == EPC_FROM_INTERNET {
                self.l3_epc_id = self.l2_epc_id;
            }
        }
        // L2End不是true, 一定不是VIP设备采集的流量
        if !self.l2_end {
            self.is_vip_interface = false
        }
    }

    pub fn get_l3_l2_end(&self) -> L3L2End {
        (self.l2_end, self.l3_end).into()
    }

    pub fn set_l2_data(&mut self, data: &PlatformData) {
        if data.epc_id > 0 {
            self.l2_epc_id = data.epc_id;
        }
        self.is_device = true;
        self.is_local_mac = data.is_local;
    }

    pub fn set_l3_data(&mut self, data: &PlatformData) {
        self.l3_epc_id = data.epc_id;
        self.is_device = true;
        self.is_local_ip = data.is_local;
    }

    pub fn set_loopback(&mut self, local_epc: i32) {
        self.l2_epc_id = local_epc;
        self.l3_epc_id = local_epc;
        self.is_device = true;
        self.is_local_mac = true;
        self.is_local_ip = true;
    }
}

impl Default for EndpointInfo {
    fn default() -> EndpointInfo {
        EndpointInfo {
            real_ip: Ipv4Addr::UNSPECIFIED.into(),
            l2_epc_id: 0,
            l3_epc_id: 0,
            l2_end: false,
            l3_end: false,
            is_device: false,
            is_vip_interface: false,
            is_vip: false,
            is_local_mac: false,
            is_local_ip: false,
        }
    }
}

// 数据结构内容由策略模块初始化，其他组件只读
#[derive(Debug, Default, Clone, Copy)]
pub struct EndpointData {
    pub src_info: EndpointInfo,
    pub dst_info: EndpointInfo,
}

impl EndpointData {
    pub fn reversed(&self) -> EndpointData {
        EndpointData {
            src_info: self.dst_info.clone(),
            dst_info: self.src_info.clone(),
        }
    }

    pub fn new(src: EndpointInfo, dst: EndpointInfo) -> EndpointData {
        EndpointData {
            src_info: src,
            dst_info: dst,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct EndpointDataPov {
    data: Arc<EndpointData>,
    // point of view
    // 0 for src -> dst
    // 1 for dst -> src
    pov: u8,
}

impl EndpointDataPov {
    pub fn new(data: Arc<EndpointData>) -> Self {
        Self { data, pov: 0 }
    }

    pub fn reverse(&mut self) {
        self.pov = 1 - self.pov;
    }

    pub fn reversed(&self) -> Self {
        Self {
            data: self.data.clone(),
            pov: 1 - self.pov,
        }
    }

    pub fn src_info(&self) -> &EndpointInfo {
        match self.pov {
            0 => &self.data.src_info,
            1 => &self.data.dst_info,
            _ => unreachable!(),
        }
    }

    pub fn dst_info(&self) -> &EndpointInfo {
        match self.pov {
            0 => &self.data.dst_info,
            1 => &self.data.src_info,
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum L3L2End {
    FalseFalse,
    FalseTrue,
    TrueFalse,
    TrueTrue,
    Max,
}

impl From<usize> for L3L2End {
    fn from(v: usize) -> L3L2End {
        match v {
            0 => L3L2End::FalseFalse,
            1 => L3L2End::FalseTrue,
            2 => L3L2End::TrueFalse,
            3 => L3L2End::TrueTrue,
            4 => L3L2End::Max,
            _ => unimplemented!(),
        }
    }
}

impl From<(bool, bool)> for L3L2End {
    // order is (L2, L3)
    fn from(ends: (bool, bool)) -> Self {
        match ends {
            (false, false) => L3L2End::FalseFalse,
            (true, false) => L3L2End::FalseTrue,
            (false, true) => L3L2End::TrueFalse,
            (true, true) => L3L2End::TrueTrue,
        }
    }
}

impl From<L3L2End> for (bool, bool) {
    // order is (L2, L3)
    fn from(ends: L3L2End) -> Self {
        match ends {
            L3L2End::FalseFalse => (false, false),
            L3L2End::FalseTrue => (true, false),
            L3L2End::TrueFalse => (false, true),
            L3L2End::TrueTrue => (true, true),
            _ => unimplemented!(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct EndpointStore {
    datas: [[Arc<EndpointData>; L3L2End::Max as usize]; L3L2End::Max as usize],
}

impl From<EndpointData> for EndpointStore {
    fn from(e: EndpointData) -> Self {
        let mut store = EndpointStore::default();

        for i in 0..L3L2End::Max as usize {
            for j in 0..L3L2End::Max as usize {
                let mut item = e;
                item.src_info.set_l3_l2_end(L3L2End::from(i));
                item.dst_info.set_l3_l2_end(L3L2End::from(j));
                store.datas[i][j] = Arc::new(item);
            }
        }

        store
    }
}

impl EndpointStore {
    pub fn get(
        &self,
        l2_end_0: bool,
        l2_end_1: bool,
        l3_end_0: bool,
        l3_end_1: bool,
    ) -> Arc<EndpointData> {
        return Arc::clone(
            &self.datas[L3L2End::from((l2_end_0, l3_end_0)) as usize]
                [L3L2End::from((l2_end_1, l3_end_1)) as usize],
        );
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_endpoint_store() {
        let endpoints = EndpointData {
            src_info: EndpointInfo {
                l2_epc_id: 10,
                l3_epc_id: 20,
                ..Default::default()
            },
            dst_info: EndpointInfo {
                l2_epc_id: 30,
                l3_epc_id: 40,
                ..Default::default()
            },
        };
        let store = EndpointStore::from(endpoints);
        let result = store.get(false, true, false, false);
        assert_eq!(result.src_info.l2_end, false);
        assert_eq!(result.dst_info.l2_end, true);
        assert_eq!(result.src_info.l3_end, false);
        assert_eq!(result.dst_info.l3_end, false);

        let result = store.get(true, false, true, true);
        assert_eq!(result.src_info.l2_end, true);
        assert_eq!(result.dst_info.l2_end, false);
        assert_eq!(result.src_info.l3_end, true);
        assert_eq!(result.dst_info.l3_end, true);

        let result = store.get(true, true, true, false);
        assert_eq!(result.src_info.l2_end, true);
        assert_eq!(result.dst_info.l2_end, true);
        assert_eq!(result.src_info.l3_end, true);
        assert_eq!(result.dst_info.l3_end, false);

        let result = store.get(false, false, false, true);
        assert_eq!(result.src_info.l2_end, false);
        assert_eq!(result.dst_info.l2_end, false);
        assert_eq!(result.src_info.l3_end, false);
        assert_eq!(result.dst_info.l3_end, true);

        assert_eq!(result.src_info.l2_epc_id, 10);
        assert_eq!(result.src_info.l3_epc_id, 20);
        assert_eq!(result.dst_info.l2_epc_id, 30);
        assert_eq!(result.dst_info.l3_epc_id, 40);
    }
}
