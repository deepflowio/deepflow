use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use bitflags::bitflags;

use super::{LookupKey, PlatformData, TapType};

pub const EPC_FROM_DEEPFLOW: i32 = -1;
pub const EPC_FROM_INTERNET: i32 = -1;
pub const GROUP_INTERNET: i32 = -2;

bitflags! {
    #[derive(Default)]
    pub struct FeatureFlags: u32 {
        const NPM = 0b01;
        const NPB = 0b10;
    }
}

#[derive(Debug)]
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
}

#[derive(Debug)]
pub struct EndpointData {
    pub src_info: Arc<Mutex<EndpointInfo>>,
    pub dst_info: Arc<Mutex<EndpointInfo>>,
}

impl EndpointData {
    pub fn set_l2_end(&mut self, key: &LookupKey) {
        if key.tap_type == TapType::Tor {
            self.src_info.lock().unwrap().l2_end = key.l2_end_0;
            self.dst_info.lock().unwrap().l2_end = key.l2_end_1;
        }
    }

    pub fn reversed(&self) -> EndpointData {
        EndpointData {
            src_info: self.dst_info.clone(),
            dst_info: self.src_info.clone(),
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
