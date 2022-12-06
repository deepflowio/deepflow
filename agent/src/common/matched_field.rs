/*
 * Copyright (c) 2022 Yunshan Networks
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
use std::net;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops;

#[derive(Copy, Clone)]
#[repr(u8)]
pub enum MatchedFlag {
    SrcIp,
    DstIp,
    SrcEpc,
    DstEpc,
    SrcPort,
    DstPort,
    Proto,
    TapType,
}

#[derive(Clone, Debug)]
pub enum MatchedField {
    V4(MatchedFieldv4),
    V6(MatchedFieldv6),
}

impl MatchedField {
    pub fn get(&self, flag: MatchedFlag) -> u16 {
        match self {
            Self::V4(f) => f.get(flag),
            Self::V6(f) => f.get(flag),
        }
    }

    pub fn get_ip(&self, flag: MatchedFlag) -> net::IpAddr {
        match self {
            Self::V4(f) => f.get_ip(flag).into(),
            Self::V6(f) => f.get_ip(flag).into(),
        }
    }

    pub fn set(&mut self, flag: MatchedFlag, value: u16) {
        match self {
            Self::V4(f) => f.set(flag, value),
            Self::V6(f) => f.set(flag, value),
        }
    }

    pub fn set_mask(&mut self, flag: MatchedFlag, is_set: bool) {
        self.set(flag, if is_set { 0xFFFF } else { 0 })
    }

    pub fn set_ip(&mut self, flag: MatchedFlag, value: net::IpAddr) {
        match (self, value) {
            (Self::V4(f), IpAddr::V4(addr)) => f.set_ip(flag, addr),
            (Self::V6(f), IpAddr::V6(addr)) => f.set_ip(flag, addr),
            _ => panic!("The version of MatchedField and IpAddr conflict."),
        }
    }

    pub fn set_ip_mask(&mut self, flag: MatchedFlag, is_set: bool) {
        match self {
            Self::V4(f) => f.set_ip_mask(flag, is_set),
            Self::V6(f) => f.set_ip_mask(flag, is_set),
        }
    }

    pub fn is_bit_zero(&self, offset: usize) -> bool {
        match self {
            Self::V4(f) => f.is_bit_zero(offset),
            Self::V6(f) => f.is_bit_zero(offset),
        }
    }

    pub fn get_all_table_index(
        &self,
        mask_vector: &Self,
        mask: &Self,
        min: usize,
        max: usize,
        vector_bits: &Vec<usize>,
    ) -> Vec<u16> {
        match (self, mask_vector, mask) {
            (Self::V4(f), Self::V4(mv), Self::V4(m)) => {
                f.get_all_table_index(mv, m, min, max, vector_bits)
            }
            (Self::V6(f), Self::V6(mv), Self::V6(m)) => {
                f.get_all_table_index(mv, m, min, max, vector_bits)
            }
            _ => panic!("type mismatch"),
        }
    }

    pub fn get_table_index(&self, mask_vector: &Self, min: usize, max: usize) -> u16 {
        match (self, mask_vector) {
            (Self::V4(f), Self::V4(mv)) => f.get_table_index(mv, min, max),
            (Self::V6(f), Self::V6(mv)) => f.get_table_index(mv, min, max),
            _ => panic!("type mismatch"),
        }
    }
}

impl fmt::Display for MatchedField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{} epc: {} -> {} proto: {} tap: {}",
            self.get_ip(MatchedFlag::SrcIp),
            self.get(MatchedFlag::SrcPort),
            self.get_ip(MatchedFlag::DstIp),
            self.get(MatchedFlag::DstPort),
            self.get(MatchedFlag::SrcEpc),
            self.get(MatchedFlag::DstEpc),
            self.get(MatchedFlag::Proto),
            self.get(MatchedFlag::TapType)
        )
    }
}

// N for Ip address length in bytes
#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct MatchedFieldN<const N: usize> {
    // split up because [u8; 2 * N + 10] is not valid
    src_ip: [u8; N],
    dst_ip: [u8; N],
    others: [u8; 10],
}

const MATCHED_FIELD_OTHER_SIZE: usize = 10;

impl<const N: usize> Default for MatchedFieldN<N> {
    fn default() -> Self {
        Self {
            src_ip: [0; N],
            dst_ip: [0; N],
            others: [0; MATCHED_FIELD_OTHER_SIZE],
        }
    }
}

impl<const N: usize> MatchedFieldN<N> {
    const IPV4_ADDR_LEN: usize = 4;
    pub const SIZE: usize = MATCHED_FIELD_OTHER_SIZE + N * 2;
    pub fn bit_size(&self) -> usize {
        return (self.src_ip.len() * 2 + MATCHED_FIELD_OTHER_SIZE) * (u8::BITS as usize);
    }

    pub fn is_ipv6(&self) -> bool {
        return self.src_ip.len() != Self::IPV4_ADDR_LEN;
    }

    fn offset_of(flag: MatchedFlag) -> usize {
        match flag {
            MatchedFlag::SrcEpc => 0,
            MatchedFlag::DstEpc => 2,
            MatchedFlag::SrcPort => 4,
            MatchedFlag::DstPort => 6,
            MatchedFlag::Proto => 8,
            MatchedFlag::TapType => 9,
            MatchedFlag::SrcIp | MatchedFlag::DstIp => 0,
        }
    }

    pub fn get(&self, flag: MatchedFlag) -> u16 {
        let offset = Self::offset_of(flag);
        match flag {
            MatchedFlag::SrcEpc
            | MatchedFlag::DstEpc
            | MatchedFlag::SrcPort
            | MatchedFlag::DstPort => {
                u16::from_le_bytes(*<&[u8; 2]>::try_from(&self.others[offset..offset + 2]).unwrap())
            }
            MatchedFlag::Proto | MatchedFlag::TapType => self.others[offset] as u16,
            _ => unimplemented!(),
        }
    }

    pub fn set(&mut self, flag: MatchedFlag, value: u16) {
        let offset = Self::offset_of(flag);
        match flag {
            MatchedFlag::SrcEpc
            | MatchedFlag::DstEpc
            | MatchedFlag::SrcPort
            | MatchedFlag::DstPort => {
                self.others[offset..offset + 2].copy_from_slice(value.to_le_bytes().as_slice())
            }
            MatchedFlag::Proto | MatchedFlag::TapType => self.others[offset] = value as u8,
            _ => unimplemented!(),
        }
    }

    pub fn set_mask(&mut self, flag: MatchedFlag, is_set: bool) {
        self.set(flag, if is_set { 0xFFFF } else { 0 })
    }

    pub fn set_bits(&mut self, bits: &Vec<usize>) {
        self.src_ip = [0; N];
        self.dst_ip = [0; N];
        self.others = [0; 10];
        for b in bits {
            let b = *b;
            if b < 8 * N {
                self.src_ip[b >> 3] = 1 << (b & 7);
            } else if b < 8 * 2 * N {
                let b = b - 8 * N;
                self.dst_ip[b >> 3] = 1 << (b & 7);
            } else if b < 8 * (2 * N + 10) {
                let b = b - 8 * 2 * N;
                self.others[b >> 3] = 1 << (b & 7);
            } else {
                panic!("bits out of bounds")
            }
        }
    }

    pub fn get_all_table_index(
        &self,
        mask_vector: &Self,
        mask: &Self,
        min: usize,
        max: usize,
        vector_bits: &Vec<usize>,
    ) -> Vec<u16> {
        let mut index = self.get_table_index(mask_vector, min, max);
        let mut index_offset = Vec::with_capacity(1);
        for (i, offset) in vector_bits.iter().enumerate() {
            // mask bit 0 means all
            if mask.is_bit_zero(*offset) {
                index_offset.push(i);
            }
        }
        // index 101 -> 001
        for offset in index_offset.iter() {
            index &= !(1 << *offset);
        }

        let mut base = vec![index];
        for offset in index_offset {
            for i in 0..base.len() {
                base.push(base[i] | 1 << offset);
            }
        }
        base
    }

    pub fn get_table_index(&self, mask_vector: &Self, min: usize, max: usize) -> u16 {
        let result = self & mask_vector;
        let mut index = 0u16;
        let mut offset = 0u16;
        assert!(min <= max);
        for i in min..=max {
            if !result.is_bit_zero(i) {
                index |= (1 << offset) as u16;
            }
            if !mask_vector.is_bit_zero(i) {
                offset += 1;
            }
        }
        index
    }

    pub fn is_bit_zero(&self, offset: usize) -> bool {
        if offset < 8 * N {
            self.src_ip[offset >> 3] & (1 << (offset & 7)) == 0
        } else if offset < 8 * 2 * N {
            let offset = offset - 8 * N;
            self.dst_ip[offset >> 3] & (1 << (offset & 7)) == 0
        } else if offset < 8 * (2 * N + 10) {
            let offset = offset - 8 * 2 * N;
            self.others[offset >> 3] & (1 << (offset & 7)) == 0
        } else {
            panic!("bits out of bounds")
        }
    }
}

impl<'a, const N: usize> ops::BitAnd for &'a MatchedFieldN<N> {
    type Output = MatchedFieldN<N>;

    fn bitand(self, rhs: Self) -> Self::Output {
        let mut new_fields: Self::Output = Default::default();
        for i in 0..self.src_ip.len() {
            new_fields.src_ip[i] = self.src_ip[i] & rhs.src_ip[i];
            new_fields.dst_ip[i] = self.dst_ip[i] & rhs.dst_ip[i];
        }
        for i in 0..self.others.len() {
            new_fields.others[i] = self.others[i] & rhs.others[i];
        }
        new_fields
    }
}

impl<'a, const N: usize> ops::BitOr for &'a MatchedFieldN<N> {
    type Output = MatchedFieldN<N>;

    fn bitor(self, rhs: Self) -> Self::Output {
        let mut new_fields: Self::Output = Default::default();
        for i in 0..self.src_ip.len() {
            new_fields.src_ip[i] = self.src_ip[i] | rhs.src_ip[i];
            new_fields.dst_ip[i] = self.dst_ip[i] | rhs.dst_ip[i];
        }
        for i in 0..self.others.len() {
            new_fields.others[i] = self.others[i] | rhs.others[i];
        }
        new_fields
    }
}

pub type MatchedFieldv4 = MatchedFieldN<4>;

impl MatchedFieldv4 {
    pub fn get_ip(&self, flag: MatchedFlag) -> Ipv4Addr {
        match flag {
            MatchedFlag::SrcIp => self.src_ip.into(),
            MatchedFlag::DstIp => self.dst_ip.into(),
            _ => unimplemented!(),
        }
    }

    pub fn set_ip(&mut self, flag: MatchedFlag, value: Ipv4Addr) {
        match flag {
            MatchedFlag::SrcIp => self.src_ip.copy_from_slice(&value.octets()),
            MatchedFlag::DstIp => self.dst_ip.copy_from_slice(&value.octets()),
            _ => unimplemented!(),
        }
    }

    pub fn set_ip_mask(&mut self, flag: MatchedFlag, is_set: bool) {
        let set = if is_set { [0xFF; 4] } else { [0; 4] };
        match flag {
            MatchedFlag::SrcIp => self.src_ip = set,
            MatchedFlag::DstIp => self.dst_ip = set,
            _ => unimplemented!(),
        }
    }
}

pub type MatchedFieldv6 = MatchedFieldN<16>;

impl MatchedFieldv6 {
    pub fn get_ip(&self, flag: MatchedFlag) -> Ipv6Addr {
        match flag {
            MatchedFlag::SrcIp => self.src_ip.into(),
            MatchedFlag::DstIp => self.dst_ip.into(),
            _ => unimplemented!(),
        }
    }

    pub fn set_ip(&mut self, flag: MatchedFlag, value: Ipv6Addr) {
        match flag {
            MatchedFlag::SrcIp => self.src_ip.copy_from_slice(&value.octets()),
            MatchedFlag::DstIp => self.dst_ip.copy_from_slice(&value.octets()),
            _ => unimplemented!(),
        }
    }

    pub fn set_ip_mask(&mut self, flag: MatchedFlag, is_set: bool) {
        let set = if is_set { [0xFF; 16] } else { [0; 16] };
        match flag {
            MatchedFlag::SrcIp => self.src_ip = set,
            MatchedFlag::DstIp => self.dst_ip = set,
            _ => unimplemented!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    fn new_matched_field(
        tap_type: u16,
        proto: u8,
        src_ip: net::IpAddr,
        dst_ip: net::IpAddr,
        src_port: u16,
        dst_port: u16,
    ) -> MatchedField {
        let mut matched = match src_ip {
            IpAddr::V4(_) => MatchedField::V4(MatchedFieldv4::default()),
            IpAddr::V6(_) => MatchedField::V6(MatchedFieldv6::default()),
        };
        matched.set(MatchedFlag::TapType, tap_type);
        matched.set(MatchedFlag::Proto, proto as u16);
        matched.set_ip(MatchedFlag::SrcIp, src_ip);
        matched.set_ip(MatchedFlag::DstIp, dst_ip);
        matched.set(MatchedFlag::SrcPort, src_port);
        matched.set(MatchedFlag::DstPort, dst_port);
        matched
    }

    #[test]
    fn field_get_v4() {
        let matched = new_matched_field(
            66,
            3,
            "172.22.12.20".parse().unwrap(),
            "124.15.214.2".parse().unwrap(),
            50,
            60,
        );
        assert_eq!(
            matched.get(MatchedFlag::TapType),
            66,
            "MATCHED_TAP_TYPE error. {}",
            matched
        );
        assert_eq!(
            matched.get(MatchedFlag::Proto),
            3,
            "MATCHED_PROTO error. {}",
            matched
        );
        assert_eq!(
            matched.get_ip(MatchedFlag::SrcIp),
            IpAddr::V4(Ipv4Addr::new(172, 22, 12, 20)),
            "MATCHED_SRC_IP error. {}",
            matched
        );
        assert_eq!(
            matched.get_ip(MatchedFlag::DstIp),
            IpAddr::V4(Ipv4Addr::new(124, 15, 214, 2)),
            "MATCHED_DST_IP error. {}",
            matched
        );
        assert_eq!(
            matched.get(MatchedFlag::SrcPort),
            50,
            "MATCHED_SRC_PORT error. {}",
            matched
        );
        assert_eq!(
            matched.get(MatchedFlag::DstPort),
            60,
            "MATCHED_DST_PORT error. {}",
            matched
        );

        let matched = new_matched_field(
            0xFF,
            0x7,
            "172.22.12.20".parse().unwrap(),
            "124.15.214.2".parse().unwrap(),
            50,
            60,
        );
        assert_eq!(
            matched.get(MatchedFlag::TapType),
            0xFF,
            "MATCHED_TAP_TYPE error. {}",
            matched
        );
        assert_eq!(
            matched.get(MatchedFlag::Proto),
            0x7,
            "MATCHED_TAP_TYPE error. {}",
            matched
        );
    }

    #[test]
    fn field_get_v6() {
        let matched = new_matched_field(
            231,
            3,
            "aabb:ccdd::1".parse().unwrap(),
            "1122:3344::2".parse().unwrap(),
            50,
            60,
        );
        assert_eq!(
            matched.get(MatchedFlag::TapType),
            231,
            "MATCHED_TAP_TYPE error. {}",
            matched
        );
        assert_eq!(
            matched.get(MatchedFlag::Proto),
            3,
            "MATCHED_PROTO error. {}",
            matched
        );
        assert_eq!(
            matched.get_ip(MatchedFlag::SrcIp),
            "aabb:ccdd::1".parse::<IpAddr>().unwrap(),
            "MATCHED_SRC_IP error. {}",
            matched
        );
        assert_eq!(
            matched.get_ip(MatchedFlag::DstIp),
            "1122:3344::2".parse::<IpAddr>().unwrap(),
            "MATCHED_DST_IP error. {}",
            matched
        );
        assert_eq!(
            matched.get(MatchedFlag::SrcPort),
            50,
            "MATCHED_SRC_PORT error. {}",
            matched
        );
        assert_eq!(
            matched.get(MatchedFlag::DstPort),
            60,
            "MATCHED_DST_PORT error. {}",
            matched
        );
    }

    #[test]
    fn bit_zero() {
        let matched = new_matched_field(
            1,
            0,
            Ipv4Addr::new(0, 0, 0, 1).into(),
            Ipv4Addr::new(0, 0, 0, 1).into(),
            1,
            0,
        );
        assert!(!matched.is_bit_zero(24), "0 bits error. {}", matched);
        assert!(matched.is_bit_zero(128), "1 bits error. {}", matched);
    }

    #[test]
    fn table_index() {
        let matched = new_matched_field(
            1,
            1,
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1)),
            0,
            0,
        );
        let mask_vector = new_matched_field(
            1,
            1,
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            0,
            0,
        );
        let index = matched.get_table_index(&mask_vector, 128, 143);
        assert_eq!(index, 0x3, "expected index: 0x3, actual index: {}", index);

        let matched = new_matched_field(
            1,
            1,
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1)),
            1,
            1,
        );
        let mask_vector = new_matched_field(
            0,
            0,
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1)),
            1,
            1,
        );
        let index = matched.get_table_index(&mask_vector, 0, 143);
        assert_eq!(index, 0x7, "expected index: 0x7, actual index: {}", index);
    }

    #[test]
    fn all_table_index_v4() {
        let matched = new_matched_field(
            1,
            3,
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 20)),
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 40)),
            5,
            60,
        );
        let vector = new_matched_field(
            0,
            0,
            Ipv4Addr::UNSPECIFIED.into(),
            Ipv4Addr::UNSPECIFIED.into(),
            7,
            0,
        );
        let mask = new_matched_field(
            0,
            0,
            Ipv4Addr::UNSPECIFIED.into(),
            Ipv4Addr::UNSPECIFIED.into(),
            9,
            0,
        );
        let indices = matched.get_all_table_index(&vector, &mask, 96, 114, &vec![96, 97, 98]);
        assert_eq!(
            &indices,
            &vec![1, 3, 5, 7],
            "expected [1, 3, 5, 7], actual {:?}",
            indices
        );
    }

    #[test]
    fn all_table_index_v6() {
        let matched = new_matched_field(
            1,
            3,
            "aabb:ccdd::1".parse().unwrap(),
            "1122:3344::2".parse().unwrap(),
            5,
            60,
        );
        let vector = new_matched_field(
            0,
            0,
            Ipv6Addr::UNSPECIFIED.into(),
            Ipv6Addr::UNSPECIFIED.into(),
            7,
            0,
        );
        let mask = new_matched_field(
            0,
            0,
            Ipv6Addr::UNSPECIFIED.into(),
            Ipv6Addr::UNSPECIFIED.into(),
            9,
            0,
        );
        let indices = matched.get_all_table_index(&vector, &mask, 288, 304, &vec![288, 289, 290]);
        assert_eq!(
            &indices,
            &vec![1, 3, 5, 7],
            "expected [1, 3, 5, 7], actual {:?}",
            indices
        );
    }
}
