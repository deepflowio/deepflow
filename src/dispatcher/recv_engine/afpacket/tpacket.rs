use std::{error::Error, ffi::CString, io, time::Duration};

use libc::{
    c_int, c_uint, c_void, getsockopt, mmap, munmap, off_t, poll, pollfd, size_t, sockaddr,
    sockaddr_ll, socklen_t, AF_PACKET, ETH_P_ALL, MAP_LOCKED, MAP_NORESERVE, MAP_SHARED, POLLERR,
    POLLIN, PROT_READ, PROT_WRITE, SOL_PACKET, SOL_SOCKET, SO_ATTACH_FILTER,
};
use pcap_sys::{bpf_program, pcap_compile_nopcap};
use socket::{self, Socket};

use crate::dispatcher::recv_engine::afpacket::*;
use crate::error::Error as tError;
use crate::utils::net::link_by_name;

const PACKET_VERSION: c_int = 10;
const PACKET_RX_RING: c_int = 5;
const PACKET_STATISTICS: c_int = 6;
const MILLI_SECONDS: u32 = 1000000;

// https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-01.html
const LINKTYPE_ETHERNET: c_int = 1;

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Stats {
    pub packets: i64,
    pub polls: i64,
}

#[derive(Clone, Debug, Copy)]
#[repr(C)]
pub struct TpacketStats {
    pub tp_packets: c_uint,
    pub tp_drops: c_uint,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct TpacketStatsV3 {
    pub tp_packets: c_uint,
    pub tp_drops: c_uint,
    pub tp_freeze_q_cnt: c_uint,
}

pub struct Tpacket {
    _stats: Stats,

    raw_socket: socket::Socket,
    ring: *mut u8,
    opts: options::Options,

    offset: u32,
    current: Option<Box<dyn header::Header>>,

    should_release_packet: bool,
    header_next_needed: bool,

    tp_version: options::OptTpacketVersion,

    v3: Option<*mut header::V3Wrapper>,
}

#[derive(Debug)]
pub struct Packet<'a> {
    pub timestamp: Duration,
    pub if_index: isize,
    pub capture_length: isize,

    pub data: &'a [u8],
}

impl Tpacket {
    fn bind(&self) -> Result<(), Box<dyn Error>> {
        let mut if_index: i32 = 0;

        if self.opts.iface != "" {
            // 根据网卡名称获取网卡if_index
            let link = link_by_name(self.opts.iface.clone())?;
            if_index = link.if_index as i32;
        }
        unsafe {
            let mut sa: sockaddr_ll = std::mem::zeroed();
            sa.sll_family = AF_PACKET as u16;
            sa.sll_protocol = (ETH_P_ALL as u16).to_be();
            sa.sll_ifindex = if_index as i32;

            let res = libc::bind(
                self.raw_socket.fileno(),
                &sa as *const sockaddr_ll as *const sockaddr,
                std::mem::size_of::<sockaddr_ll>() as u32,
            );
            if res == -1 {
                return Err(Box::from(io::Error::last_os_error()));
            }
        }
        Ok(())
    }
    // TODO: 这里看起来不需要，golang版本未涉及该配置，后续有需要再添加
    #[allow(dead_code)]
    fn set_promisc(&self) -> Result<(), Box<dyn Error>> {
        // 设置混杂模式

        //raw_socket.set_flag(IFF_PROMISC as u64)?;

        // TODO:
        //let mut mreq: packet_mreq = std::mem::zeroed();
        //mreq.mr_ifindex = interface.index as i32;
        //mreq.mr_type = PACKET_MR_PROMISC as u16;

        //raw_socket.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, (&mreq as *const packet_mreq) as *const libc::c_void);
        return Ok(());
    }

    fn set_version_internal(&mut self, tp_version: options::OptTpacketVersion) -> bool {
        // 设置af packet版本
        if self
            .raw_socket
            .setsockopt(SOL_PACKET, PACKET_VERSION, tp_version as c_int)
            .is_ok()
        {
            return true;
        }
        return false;
    }

    fn set_version(&mut self) -> Result<(), Box<dyn Error>> {
        if (self.tp_version == options::OptTpacketVersion::TpacketVersionHighestavailablet
            || self.tp_version == options::OptTpacketVersion::TpacketVersion3)
            && self.set_version_internal(options::OptTpacketVersion::TpacketVersion3)
        {
            self.tp_version = options::OptTpacketVersion::TpacketVersion3;
            return Ok(());
        } else if (self.tp_version == options::OptTpacketVersion::TpacketVersionHighestavailablet
            || self.tp_version == options::OptTpacketVersion::TpacketVersion2)
            && self.set_version_internal(options::OptTpacketVersion::TpacketVersion2)
        {
            self.tp_version = options::OptTpacketVersion::TpacketVersion2;
            return Ok(());
        }
        return Err(Box::new(tError::InvalidTpVersion(self.tp_version as isize)));
    }

    fn set_ring(&self) -> Result<(), Box<dyn Error>> {
        if self.tp_version == options::OptTpacketVersion::TpacketVersion2 {
            let mut req: header::TpacketReq = Default::default();
            req.tp_block_nr = self.opts.num_blocks;
            req.tp_block_size = self.opts.block_size;
            req.tp_frame_nr = self.opts.frames_per_block * self.opts.num_blocks;
            req.tp_frame_size = self.opts.frame_size;
            self.raw_socket
                .setsockopt(SOL_PACKET, PACKET_RX_RING, req)?;
            return Ok(());
        } else if self.tp_version == options::OptTpacketVersion::TpacketVersion3 {
            let mut req: header::TpacketReq3 = Default::default();
            req.tp_block_size = self.opts.block_size;
            req.tp_block_nr = self.opts.num_blocks;
            req.tp_frame_size = self.opts.frame_size;
            req.tp_frame_nr = self.opts.frames_per_block * self.opts.num_blocks;
            req.tp_retire_blk_tov = self.opts.block_timeout / MILLI_SECONDS;
            self.raw_socket
                .setsockopt(SOL_PACKET, PACKET_RX_RING, req)?;
            return Ok(());
        }
        return Err(Box::new(tError::InvalidTpVersion(self.tp_version as isize)));
    }

    fn mmap_ring(&mut self) -> Result<(), Box<dyn Error>> {
        // 接收队列
        unsafe {
            let ret = mmap(
                std::ptr::null_mut(),
                (self.opts.block_size * self.opts.num_blocks) as size_t,
                (PROT_READ | PROT_WRITE) as c_int,
                (MAP_SHARED | MAP_LOCKED | MAP_NORESERVE) as c_int,
                self.raw_socket.fileno() as c_int,
                0 as off_t,
            ) as isize;
            if ret == -1 {
                return Err(Box::from(io::Error::last_os_error()));
            }
            self.ring = ret as *mut u8;
        }
        // bind rx ring
        Ok(())
    }

    fn get_packet_header(&mut self) -> Box<dyn header::Header> {
        match self.tp_version {
            options::OptTpacketVersion::TpacketVersion2 => {
                // AF_PACKET 2
                if self.offset >= self.opts.frames_per_block * self.opts.num_blocks {
                    self.offset = 0
                }

                let position: *mut u8 =
                    (self.ring as usize + (self.opts.frame_size * self.offset) as usize) as *mut u8;
                return Box::from(header::Tpacket2Hdr::from(position));
            }
            options::OptTpacketVersion::TpacketVersion3 => {
                // AF_PACKET 3
                if self.offset >= self.opts.num_blocks {
                    self.offset = 0;
                }
                let position: *mut u8 = (self.ring as usize
                    + (self.opts.frame_size * self.offset * self.opts.frames_per_block) as usize)
                    as *mut u8;
                return Box::from(header::V3Wrapper::from(position));
            }
            _ => {
                panic!("Unknown afpacket version.");
            }
        }
    }

    fn poll_for_first_packet(&mut self) -> bool {
        let timeout = self.opts.poll_timeout / MILLI_SECONDS as isize;
        if let Some(header) = self.current.as_ref() {
            while (header.get_status() & header::TP_STATUS_USER) == 0 {
                let mut poll_fd = pollfd {
                    fd: self.raw_socket.fileno(),
                    events: POLLIN | POLLERR,
                    revents: 0,
                };

                unsafe {
                    poll(&mut poll_fd, 1, timeout as i32);
                }

                if poll_fd.revents & POLLERR > 0 {
                    return false;
                }
            }
            self.should_release_packet = true;
            return true;
        }
        return false;
    }

    pub fn read(&mut self) -> Option<Packet> {
        if self.current.is_none()
            || !self.header_next_needed
            || !self.current.as_mut().unwrap().next()
        {
            if self.should_release_packet {
                if let Some(x) = self.current.as_mut() {
                    x.clear_status();
                }
                self.offset += 1;
                self.should_release_packet = false;
            }
            self.current = Some(self.get_packet_header());
            let ok = self.poll_for_first_packet();
            if !ok {
                self.header_next_needed = false;
                return None;
            }
            if let Some(x) = self.current.as_ref() {
                if x.get_length() == 0 {
                    // TODO: retry
                    return None;
                }
            }
        }
        if let Some(x) = self.current.as_ref() {
            let packet = Packet {
                timestamp: x.get_time(),
                if_index: x.get_iface_index(),
                data: x.get_data(),
                capture_length: x.get_length(),
            };
            self.header_next_needed = true;
            return Some(packet);
        }
        return None;
    }

    pub fn set_bpf(&self, syntax: CString) -> Result<(), Box<dyn Error>> {
        let mut prog: bpf_program = bpf_program {
            bf_len: 0,
            bf_insns: std::ptr::null_mut(),
        };
        unsafe {
            let ret = pcap_compile_nopcap(
                0xffff as c_int,
                LINKTYPE_ETHERNET,
                &mut prog,
                syntax.as_ptr(),
                1,
                0xffffffff,
            );
            if ret != 0 {
                return Err(Box::from(io::Error::last_os_error()));
            }
        }
        self.raw_socket
            .setsockopt(SOL_SOCKET, SO_ATTACH_FILTER, prog)?;
        Ok(())
    }

    pub fn get_socket_stats(&self) -> Result<TpacketStats, Box<dyn Error>> {
        if self.tp_version == options::OptTpacketVersion::TpacketVersion3 {
            let mut stats_v3 = TpacketStatsV3 {
                tp_packets: 0,
                tp_drops: 0,
                tp_freeze_q_cnt: 0,
            };
            let mut opt_len = std::mem::size_of_val(&stats_v3) as socklen_t;
            unsafe {
                let ret = getsockopt(
                    self.raw_socket.fileno(),
                    SOL_PACKET,
                    PACKET_STATISTICS,
                    &mut stats_v3 as *const TpacketStatsV3 as *mut c_void,
                    &mut opt_len as *mut u32,
                );
                if ret != 0 {
                    return Err(Box::from(io::Error::last_os_error()));
                }
            }
            return Ok(TpacketStats {
                tp_packets: stats_v3.tp_packets,
                tp_drops: stats_v3.tp_drops,
            });
        } else if self.tp_version == options::OptTpacketVersion::TpacketVersion2 {
            let mut stats = TpacketStats {
                tp_packets: 0,
                tp_drops: 0,
            };
            let mut opt_len = std::mem::size_of_val(&stats) as socklen_t;
            unsafe {
                let ret = getsockopt(
                    self.raw_socket.fileno(),
                    SOL_PACKET,
                    PACKET_STATISTICS,
                    &mut stats as *const TpacketStats as *mut c_void,
                    &mut opt_len as *mut u32,
                );
                if ret != 0 {
                    return Err(Box::from(io::Error::last_os_error()));
                }
            }
            return Ok(stats);
        }

        return Err(Box::new(tError::InvalidTpVersion(self.tp_version as isize)));
    }

    pub fn new(opts: options::Options) -> Result<Self, Box<dyn Error>> {
        opts.check()?;
        // 创建原始socket
        let raw_socket = Socket::new(
            AF_PACKET,
            opts.socket_type.to_i32(),
            (ETH_P_ALL as u16).to_be() as i32,
        )?;
        let mut tpacket = Tpacket {
            _stats: Stats {
                packets: 0,
                polls: 0,
            },
            raw_socket,
            ring: std::ptr::null_mut(),
            opts: opts.clone(),
            offset: 0,
            current: Option::None,
            should_release_packet: false,
            header_next_needed: false,
            tp_version: opts.version,
            v3: Option::None,
        };
        tpacket.bind()?;
        tpacket.set_version()?;
        tpacket.set_ring()?;
        tpacket.mmap_ring()?;
        Ok(tpacket)
    }
}

impl Drop for Tpacket {
    fn drop(&mut self) {
        if !self.ring.is_null() {
            unsafe {
                munmap(
                    self.ring as *mut c_void,
                    (self.opts.block_size * self.opts.num_blocks) as size_t,
                );
            }
            if let Err(_e) = self.raw_socket.close() {}
            self.ring = std::ptr::null_mut();
        }
    }
}
