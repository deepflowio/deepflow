use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, PartialEq)]
pub struct IpNet {
    pub raw_ip: IpAddr,
    pub netmask: u32,
    pub subnet_id: u32,
}

impl Default for IpNet {
    fn default() -> IpNet {
        IpNet {
            raw_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            netmask: 32,
            subnet_id: 0,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum IfType {
    WAN = 3,
    LAN = 4,
}

#[derive(Debug, PartialEq)]
pub struct PlatformData {
    pub mac: u64,
    pub ips: Vec<IpNet>,
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
