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

use std::slice;
use std::time::Duration;

use libc::{c_uint, sockaddr_ll};

const TP_STATUS_KERNEL: u32 = 0;
const TPACKET_ALIGNMENT: usize = 0x10;
pub const TP_STATUS_USER: isize = 1;

fn to_align(n: usize) -> usize {
    return (n + TPACKET_ALIGNMENT - 1) & !(TPACKET_ALIGNMENT - 1);
}

pub trait Header {
    fn get_status(&self) -> isize;
    fn clear_status(&mut self);
    fn get_time(&self) -> Duration;
    fn get_data(&self) -> &mut [u8];
    fn get_length(&self) -> isize;
    fn get_iface_index(&self) -> isize;
    fn next(&mut self) -> bool;
}

#[derive(Clone, Debug)]
#[repr(C)]
///Lower-level settings about ring buffer allocation and behavior
///tp_frame_size * tp_frame_nr must equal tp_block_size * tp_block_nr
pub struct TpacketReq3 {
    ///Block size of ring
    pub tp_block_size: c_uint,
    ///Number of blocks allocated for ring
    pub tp_block_nr: c_uint,
    ///Frame size of ring
    pub tp_frame_size: c_uint,
    ///Number of frames in ring
    pub tp_frame_nr: c_uint,
    ///Timeout in milliseconds
    pub tp_retire_blk_tov: c_uint,
    ///Offset to private data area
    pub tp_sizeof_priv: c_uint,
    ///Controls whether RXHASH is filled - 0 for false, 1 for true
    pub tp_feature_req_word: c_uint,
}

impl Default for TpacketReq3 {
    fn default() -> TpacketReq3 {
        TpacketReq3 {
            tp_block_size: 32768,
            tp_block_nr: 10000,
            tp_frame_size: 2048,
            tp_frame_nr: 160000,
            tp_retire_blk_tov: 100,
            tp_sizeof_priv: 0,
            tp_feature_req_word: 0,
        }
    }
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct TpacketBlockDesc {
    version: u32,
    offset_to_priv: u32,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct TpacketBlockDescHeader {
    block_status: u32,
    pub num_pkts: u32,
    offset_to_first_pkt: u32,
    blk_len: u32,
    seq_num: u64,
    ts_first_pkt: TpacketBlockDescTimestamp,
    ts_last_pkt: TpacketBlockDescTimestamp,
}

#[derive(Clone, Debug)]
#[repr(C)]
struct TpacketBlockDescTimestamp {
    ts_sec: u32,
    ts_nsec: u32,
}

///Contains details about individual packets in a block
#[derive(Clone, Debug)]
#[repr(C)]
pub struct Tpacket3Hdr {
    pub tp_next_offset: u32,
    pub tp_sec: u32,
    pub tp_nsec: u32,
    pub tp_snaplen: u32,
    pub tp_len: u32,
    pub tp_status: u32,
    pub tp_mac: u16,
    pub tp_net: u16,
    pub hv1: TpacketHdrVariant1,
}

///Contains VLAN tags and RX Hash value (if enabled)
#[derive(Clone, Debug)]
#[repr(C)]
pub struct TpacketHdrVariant1 {
    pub tp_rxhash: u32,
    pub tp_vlan_tci: u32,
    pub tp_vlan_tpid: u16,
    _tp_padding: u16,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct TpacketReq {
    //Block size of ring
    pub tp_block_size: c_uint,
    ///Number of blocks allocated for ring
    pub tp_block_nr: c_uint,
    ///Frame size of ring
    pub tp_frame_size: c_uint,
    ///Number of frames in ring
    pub tp_frame_nr: c_uint,
}

impl Default for TpacketReq {
    fn default() -> TpacketReq {
        TpacketReq {
            tp_block_size: 32768,
            tp_block_nr: 10000,
            tp_frame_size: 2048,
            tp_frame_nr: 160000,
        }
    }
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct Tpacket2Hdr {
    pub tp_status: u32,
    pub tp_len: u32,
    pub tp_snaplen: u32,
    pub tp_mac: u16,
    pub tp_net: u16,
    pub tp_sec: u32,
    pub tp_nsec: u32,
    pub tp_vlan_tci: u16,
    pub tp_vlan_tpid: u16,
}

impl Tpacket2Hdr {
    pub fn from(raw: *mut u8) -> *mut Tpacket2Hdr {
        return raw as *mut Tpacket2Hdr;
    }
}

impl Header for *mut Tpacket2Hdr {
    fn get_status(&self) -> isize {
        unsafe {
            return (*(*self)).tp_status as isize;
        }
    }

    fn clear_status(&mut self) {
        unsafe {
            (*(*self)).tp_status = TP_STATUS_KERNEL;
        }
    }

    fn get_time(&self) -> Duration {
        unsafe {
            return Duration::new((*(*self)).tp_sec as u64, (*(*self)).tp_nsec);
        }
    }

    fn get_data(&self) -> &mut [u8] {
        unsafe {
            let ptr =
                ((*self) as *const Tpacket2Hdr as *const u8 as usize) + (*(*self)).tp_mac as usize;
            return slice::from_raw_parts_mut(ptr as *mut u8, (*(*self)).tp_snaplen as usize);
        }
    }

    fn get_length(&self) -> isize {
        unsafe {
            return (*(*self)).tp_len as isize;
        }
    }

    fn get_iface_index(&self) -> isize {
        let ptr = (*self) as *const Tpacket2Hdr as *const u8 as usize;
        unsafe {
            let ll = (ptr + to_align(std::mem::size_of::<Tpacket2Hdr>())) as *const sockaddr_ll;
            return (*ll).sll_ifindex as isize;
        }
    }

    fn next(&mut self) -> bool {
        return false;
    }
}

pub struct V3Wrapper {
    block: *mut TpacketBlockDesc,
    block_hdr: *mut TpacketBlockDescHeader,
    v3_header: *mut Tpacket3Hdr,
    used: u32,
}

impl V3Wrapper {
    pub fn from(raw: *mut u8) -> V3Wrapper {
        let v3 = V3Wrapper {
            block: raw as *mut TpacketBlockDesc,
            block_hdr: ((raw as usize) + std::mem::size_of::<TpacketBlockDesc>())
                as *mut TpacketBlockDescHeader,
            v3_header: ((raw as usize)
                + std::mem::size_of::<TpacketBlockDesc>()
                + std::mem::size_of::<TpacketBlockDescHeader>())
                as *mut Tpacket3Hdr,
            used: 0,
        };
        return v3;
    }
}

impl Header for V3Wrapper {
    fn get_status(&self) -> isize {
        unsafe {
            return (*(self.block_hdr)).block_status as isize;
        }
    }

    fn clear_status(&mut self) {
        unsafe {
            (*(self.block_hdr)).num_pkts = 0;

            let ptr = self.block as *const u8 as usize;
            let packet =
                (ptr + ((*self.block_hdr).offset_to_first_pkt) as usize) as *mut Tpacket3Hdr;

            *packet = Tpacket3Hdr {
                tp_next_offset: 0,
                tp_mac: 0,
                tp_sec: 0,
                tp_nsec: 0,
                tp_snaplen: 0,
                tp_len: 0,
                tp_net: 0,
                tp_status: 0,
                hv1: TpacketHdrVariant1 {
                    tp_rxhash: 0,
                    tp_vlan_tci: 0,
                    tp_vlan_tpid: 0,
                    _tp_padding: 0,
                },
            };

            (*self.block_hdr).offset_to_first_pkt = 0;
            (*self.block_hdr).block_status = TP_STATUS_KERNEL;
        }
    }

    fn get_time(&self) -> Duration {
        unsafe {
            return Duration::new((*self.v3_header).tp_sec as u64, (*self.v3_header).tp_nsec);
        }
    }

    fn get_data(&self) -> &mut [u8] {
        unsafe {
            let ptr = self.v3_header as *const u8 as usize;
            let packet = ptr + (*self.v3_header).tp_mac as usize;
            return slice::from_raw_parts_mut(
                packet as *mut u8,
                (*self.v3_header).tp_snaplen as usize,
            );
        }
    }

    fn get_length(&self) -> isize {
        unsafe {
            return (*self.v3_header).tp_len as isize;
        }
    }

    fn get_iface_index(&self) -> isize {
        let ptr = self.v3_header as *const u8 as usize;
        unsafe {
            let ll = (ptr + to_align(std::mem::size_of::<Tpacket3Hdr>())) as *const sockaddr_ll;
            return (*ll).sll_ifindex as isize;
        }
    }

    fn next(&mut self) -> bool {
        unsafe {
            self.used += 1;
            if self.used >= (*self.block_hdr).num_pkts {
                return false;
            }

            let mut next = self.v3_header as *const u8 as usize;
            if (*self.v3_header).tp_next_offset != 0 {
                next += (*self.v3_header).tp_next_offset as usize;
            } else {
                next += to_align(
                    ((*self.v3_header).tp_snaplen + (*self.v3_header).tp_mac as u32) as usize,
                )
            }
            self.v3_header = next as *mut Tpacket3Hdr;
            return true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_af_packet_header_v3() {
        let mut raw: [u8; 1000] = [10; 1000];
        let mut v3 = V3Wrapper::from(&mut raw as *mut u8);
        unsafe {
            assert_eq!((*v3.v3_header).tp_status, 0x0a0a0a0a);
            (*v3.block_hdr).offset_to_first_pkt = 48;
            (*v3.v3_header).tp_mac = 28 + 10;
            (*v3.v3_header).tp_snaplen = 60;
        }
        assert_eq!(v3.get_data(), [10; 60]);

        v3.clear_status();
        unsafe {
            assert_eq!((*v3.v3_header).tp_status, 0);
        }
        assert_ne!(raw, [10; 1000]);
    }
    #[test]
    fn test_af_packet_header_v2() {
        let mut raw: [u8; 1000] = [10; 1000];
        raw[50] = 10;
        let v2 = Tpacket2Hdr::from((&mut raw) as *mut u8);

        unsafe {
            (*v2).tp_mac = 100;
            (*v2).tp_snaplen = 60;

            assert_eq!(v2.get_data(), [10; 60]);
        }

        assert_ne!(raw, [10; 1000])
    }
}
