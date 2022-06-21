use std::net::IpAddr;

use crate::common::{
    enums::IpProtocol, erspan::GRE_PROTO_ERSPAN_III, DROPLET_PORT, NPB_VXLAN_FLAGS,
};

pub(crate) struct Builder {
    pub is_ipv6: bool,
    pub vxlan_port: u16,
    pub controller_port: u16,
    pub controller_tls_port: u16,
    pub proxy_controller_ip: IpAddr,
    pub analyzer_source_ip: IpAddr,
}

impl Builder {
    pub fn build_pcap_syntax(self) -> String {
        let mut conditions = vec![];
        let ip_version = if self.is_ipv6 { "ip6" } else { "ip" };

        // 不采集和控制器通信的流量
        conditions.push(format!(
            "not ({} and src host {} and tcp and (src port {} or {}))",
            ip_version, self.proxy_controller_ip, self.controller_port, self.controller_tls_port
        ));
        conditions.push(format!(
            "not ({} and dst host {} and tcp and (dst port {} or {}))",
            ip_version, self.proxy_controller_ip, self.controller_port, self.controller_tls_port
        ));

        // 不采集和TSDB通信的流量
        conditions.push(format!(
            "not ({} and src host {} and dst port {})",
            ip_version, self.analyzer_source_ip, DROPLET_PORT
        ));
        conditions.push(format!(
            "not ({} and dst host {} and src port {})",
            ip_version, self.analyzer_source_ip, DROPLET_PORT
        ));

        // 不采集分发的VXLAN流量
        conditions.push(format!(
            "not (udp and dst port {} and udp[8:1]={:#x})",
            self.vxlan_port, NPB_VXLAN_FLAGS
        ));

        // 不采集分发的ERSPANIII
        conditions.push(format!(
            "not (ip[9:1]={:#x} and ip[22:2]={:#x})",
            u8::from(IpProtocol::Gre),
            GRE_PROTO_ERSPAN_III
        ));
        conditions.push(format!(
            "not (ip6[6:1]={:#x} and ip6[42:2]={:#x})",
            u8::from(IpProtocol::Gre),
            GRE_PROTO_ERSPAN_III
        ));

        conditions.join(" and ")
    }
}
