pub const FIELD_OFFSET_DA: usize = 0;
pub const FIELD_OFFSET_SA: usize = 6;
pub const FIELD_OFFSET_VLANTAG: usize = 14;
// 在之后按需增加4B的DOT1Q偏移量
pub const FIELD_OFFSET_ETH_TYPE: usize = 12;
pub const FIELD_OFFSET_ARP: usize = 14;
pub const FIELD_OFFSET_PAYLOAD_LEN: usize = 18;
pub const FIELD_OFFSET_IP6_SRC: usize = 22;
pub const FIELD_OFFSET_IP6_DST: usize = 38;
pub const FIELD_OFFSET_IHL: usize = 14;
pub const FIELD_OFFSET_TOTAL_LEN: usize = 16;
pub const FIELD_OFFSET_ID: usize = 18;
pub const FIELD_OFFSET_FRAG: usize = 20;
pub const FIELD_OFFSET_TTL: usize = 22;
pub const FIELD_OFFSET_PROTO: usize = 23;
pub const FIELD_OFFSET_SIP: usize = 26;
pub const FIELD_OFFSET_DIP: usize = 30;
// 在之后按需增加(4+IHL*4-20)B的DOT1Q + IPv4 option偏移量;
pub const FIELD_OFFSET_ICMP_TYPE_CODE: usize = 34;
pub const FIELD_OFFSET_ICMP_ID_SEQ: usize = 38;
pub const FIELD_OFFSET_ICMP_REST: usize = 38;
pub const FIELD_OFFSET_SPORT: usize = 34;
pub const FIELD_OFFSET_DPORT: usize = 36;
pub const FIELD_OFFSET_IP6_SPORT: usize = 54;
pub const FIELD_OFFSET_IP6_DPORT: usize = 56;
pub const FIELD_OFFSET_TCP_SEQ: usize = 38;
pub const FIELD_OFFSET_TCP_ACK: usize = 42;
pub const FIELD_OFFSET_TCP_DATAOFF: usize = 46;
pub const FIELD_OFFSET_TCP_FLAG: usize = 47;
pub const FIELD_OFFSET_TCP_WIN: usize = 48;
pub const FIELD_OFFSET_VXLAN_FLAGS: usize = 42;
pub const FIELD_OFFSET_VXLAN_VNI: usize = 46;

pub const NORMAL_EXIT_WITH_RESTART: i32 = 3;
pub const TRIDENT_PROCESS_LIMIT: u32 = 10;
pub const TRIDENT_THREAD_LIMIT: u32 = 100;

#[cfg(target_os = "linux")]
mod platform_consts {
    pub const DEFAULT_LOGFILE: &'static str = "/var/log/trident/trident.log";
    pub const DEFAULT_CONF_FILE: &'static str = "/etc/trident.yaml";
    pub const COREFILE_FORMAT: &'static str = "core";
    pub const DEFAULT_COREFILE_PATH: &'static str = "/tmp";
    pub const DEFAULT_LIBVIRT_XML_PATH: &'static str = "/etc/libvirt/qemu";
}

#[cfg(target_os = "windows")]
mod platform_consts {
    pub const DEFAULT_LOGFILE: &str = "C:\\DeepFlow\\trident\\log\\trident.log";
    // NOTE yaml must be full path, otherwise service wouldn't start as you wish.
    pub const DEFAULT_CONF_FILE: &str = "C:\\DeepFlow\\trident\\trident-windows.yaml";
    pub const DEFAULT_COREFILE_PATH: &str = "C:\\DeepFlow\\trident";
    pub const COREFILE_FORMAT: &str = "dump";
}

pub use platform_consts::*;
