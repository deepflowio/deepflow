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

use std::convert::TryInto;
use std::mem;
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, TimeZone, Utc};
use num_enum::{IntoPrimitive, TryFromPrimitive};

#[derive(Clone, Copy, Debug, Eq, PartialEq, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum NtpMode {
    Reserved,
    SymmetricActive,
    SymmetricPassive,
    Client,
    Server,
    Broadcast,
    NtpControlMessage,
    Private,
}

const NSEC_IN_SEC: u32 = 1_000_000_000;

/// An NTP version 3 / 4 packet
#[repr(C)]
#[derive(Debug, Default, PartialEq)]
pub struct NtpPacket {
    li_vn_mode: u8,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub root_delay: u32,
    pub root_dispersion: u32,
    pub ref_id: u32,
    pub ts_ref: u64,
    pub ts_orig: u64,
    pub ts_recv: u64,
    pub ts_xmit: u64,
}

impl NtpPacket {
    pub fn new() -> Self {
        let mut p = NtpPacket::default();
        p.set_leap(3);
        p.set_version(4);
        p.set_mode(NtpMode::Client);
        p
    }

    pub fn get_leap(&self) -> u8 {
        self.li_vn_mode >> 6
    }

    pub fn set_leap(&mut self, li: u8) {
        self.li_vn_mode = (self.li_vn_mode & 0x3F) | (li << 6);
    }

    pub fn get_version(&self) -> u8 {
        (self.li_vn_mode >> 3) & 0x7
    }

    pub fn set_version(&mut self, version: u8) {
        self.li_vn_mode = (self.li_vn_mode & 0xC7) | (version << 3);
    }

    pub fn get_mode(&self) -> NtpMode {
        (self.li_vn_mode & 0x7).try_into().unwrap()
    }

    pub fn set_mode(&mut self, mode: NtpMode) {
        self.li_vn_mode = (self.li_vn_mode & 0xF8) | (mode as u8);
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = vec![];
        v.push(self.li_vn_mode);
        v.push(self.stratum);
        v.push(self.poll as u8);
        v.push(self.precision as u8);
        v.extend_from_slice(&self.root_delay.to_be_bytes());
        v.extend_from_slice(&self.root_dispersion.to_be_bytes());
        v.extend_from_slice(&self.ref_id.to_be_bytes());
        v.extend_from_slice(&self.ts_ref.to_be_bytes());
        v.extend_from_slice(&self.ts_orig.to_be_bytes());
        v.extend_from_slice(&self.ts_recv.to_be_bytes());
        v.extend_from_slice(&self.ts_xmit.to_be_bytes());
        v
    }

    pub fn offset(&self, recv_time: &SystemTime) -> i64 {
        // local clock offset
        //   offset = ((rec-org) + (xmt-dst)) / 2
        let recv = SystemTime::from(&NtpTime(self.ts_recv))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i64;
        let orig = SystemTime::from(&NtpTime(self.ts_orig))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i64;
        let xmit = SystemTime::from(&NtpTime(self.ts_xmit))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i64;
        let dest = recv_time.duration_since(UNIX_EPOCH).unwrap().as_nanos() as i64;

        let a = recv - orig;
        let b = xmit - dest;
        a + (b - a) / 2
    }
}

impl TryFrom<&[u8]> for NtpPacket {
    type Error = &'static str;

    fn try_from(bs: &[u8]) -> Result<Self, Self::Error> {
        if bs.len() < mem::size_of::<Self>() {
            return Err("buffer too short");
        }
        unsafe {
            let mut packet: Self = ptr::read(bs.as_ptr() as *const _);
            if NtpMode::try_from(packet.li_vn_mode & 0x7).is_err() {
                return Err("invalid ntp mode");
            }
            packet.root_delay = packet.root_delay.to_be();
            packet.root_dispersion = packet.root_dispersion.to_be();
            packet.ref_id = packet.ref_id.to_be();
            packet.ts_ref = packet.ts_ref.to_be();
            packet.ts_orig = packet.ts_orig.to_be();
            packet.ts_recv = packet.ts_recv.to_be();
            packet.ts_xmit = packet.ts_xmit.to_be();
            Ok(packet)
        }
    }
}

pub struct NtpTime(pub u64);

impl From<&SystemTime> for NtpTime {
    fn from(t: &SystemTime) -> Self {
        let n =
            DateTime::<Utc>::from(*t).signed_duration_since(Utc.ymd(1900, 1, 1).and_hms(0, 0, 0));
        let secs = n.num_seconds() as u64;
        let frac = (((n.num_nanoseconds().unwrap() as u64 - secs * NSEC_IN_SEC as u64) << 32)
            + NSEC_IN_SEC as u64
            - 1)
            / NSEC_IN_SEC as u64;
        Self(secs << 32 | frac)
    }
}

impl From<&NtpTime> for SystemTime {
    fn from(t: &NtpTime) -> Self {
        let nanos =
            (t.0 >> 32) * NSEC_IN_SEC as u64 + ((t.0 & 0xFFFFFFFF) * NSEC_IN_SEC as u64 >> 32);
        Utc.ymd(1900, 1, 1)
            .and_hms(0, 0, 0)
            .checked_add_signed(chrono::Duration::nanoseconds(nanos as i64))
            .unwrap()
            .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static NTP_REQ1: &[u8] = &[
        0xe1, 0x00, 0x0a, 0xfa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x90, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc5, 0x02, 0x04, 0xec, 0xec,
        0x42, 0xee, 0x92,
    ];

    #[test]
    fn time_convert() {
        let t = SystemTime::now();
        let nt = NtpTime::from(&t);
        let new_t = SystemTime::from(&nt);
        assert_eq!(t, new_t);
    }

    #[test]
    fn test_ntp_packet_simple() {
        let mut expected = NtpPacket {
            li_vn_mode: (3 << 6) | (3 << 3) | NtpMode::SymmetricActive as u8,
            stratum: 0,
            poll: 10,
            precision: -6,
            root_delay: 0,
            root_dispersion: 0x010290,
            ref_id: 0,
            ts_ref: 0,
            ts_orig: 0,
            ts_recv: 0,
            ts_xmit: 14195914391047827090u64,
        };
        let res = NtpPacket::try_from(NTP_REQ1).unwrap();
        expected.set_version(4);

        assert_eq!(res, expected);
    }
}
