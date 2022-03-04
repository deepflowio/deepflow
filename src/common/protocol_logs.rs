use std::{fmt, net::IpAddr, time::Duration};

use super::{
    enums::{IpProtocol, TapType},
    flow::L7Protocol,
    tap_port::TapPort,
};

use crate::utils::net::MacAddr;

#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(u8)]
pub enum L7ResponseStatus {
    Ok,
    Error,
    NotExist,
    ServerError,
    ClientError,
}

impl Default for L7ResponseStatus {
    fn default() -> Self {
        L7ResponseStatus::Ok
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum LogMessageType {
    Request,
    Response,
    Session,
    Other,
    Max,
}

impl Default for LogMessageType {
    fn default() -> Self {
        LogMessageType::Other
    }
}

pub struct AppProtoHead {
    pub proto: L7Protocol,
    pub msg_type: LogMessageType, // HTTP，DNS: request/response
    pub status: L7ResponseStatus, // 状态描述：0：正常，1：已废弃使用(先前用于表示异常)，2：不存在，3：服务端异常，4：客户端异常
    pub code: u16,                // HTTP状态码: 1xx-5xx, DNS状态码: 0-7
    pub rrt: u64,                 // HTTP，DNS时延: response-request
}

pub struct AppProtoLogsBaseInfo {
    start_time: Duration,
    end_time: Duration,
    flow_id: u64,
    tap_port: TapPort,
    vtap_id: u16,
    tap_type: TapType,
    is_ipv6: bool,
    tap_side: u8,
    app_proto_head: AppProtoHead,

    /* L2 */
    mac_src: MacAddr,
    mac_dst: MacAddr,
    /* L3 ipv4 or ipv6 */
    ip_src: IpAddr,
    ip_dst: IpAddr,
    /* L3EpcID */
    l3_epc_id_src: i32,
    l3_epc_id_dst: i32,
    /* L4 */
    port_src: u16,
    port_dst: u16,
    /* First L7 TCP Seq */
    req_tcp_seq: u32,
    resp_tcp_seq: u32,

    protocol: IpProtocol,
    is_vip_interface_src: bool,
    is_vip_interface_dst: bool,
}

pub struct AppProtoLogsData<T: L7LogMethod> {
    pub app_proto_logs_base_info: AppProtoLogsBaseInfo,
    pub proto_special_info: T,
}

pub trait L7LogMethod {
    fn write_to_pb(&self);
}

impl fmt::Display for AppProtoLogsBaseInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "start_time: {:?} end_time: {:?} flow_id: {} vtap_id: {} tap_type: {} tap_port: {} proto: {:?} msg_type: {:?} code: {} \
            status: {:?} rrt: {} tap_side {} is_vip_interface_src {:?} is_vip_interface_dst {:?} mac_src: {} mac_dst: {} \
            ip_src: {} ip_dst: {} proto: {:?} port_src: {} port_dst: {} l3_epc_id_src: {} l3_epc_id_dst: {} req_tcp_seq: {} resp_tcp_seq: {}",
            self.start_time, self.end_time, self.flow_id, self.vtap_id, self.tap_type, self.tap_port, self.app_proto_head.proto, self.app_proto_head.msg_type, self.app_proto_head.code,
            self.app_proto_head.status, self.app_proto_head.rrt, self.tap_side, self.is_vip_interface_src, self.is_vip_interface_dst, self.mac_src, self.mac_dst,
            self.ip_src, self.ip_dst, self.protocol, self.port_src, self.port_dst, self.l3_epc_id_src, self.l3_epc_id_dst, self.req_tcp_seq, self.resp_tcp_seq
        )
    }
}
