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

use std::convert::TryInto;
use std::mem;
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

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
const NTP_ERA_SECONDS: i128 = 1i128 << 32;
const NTP_HALF_ERA_SECONDS: i128 = NTP_ERA_SECONDS / 2;
const NTP_UNIX_OFFSET_SECONDS: i128 = 2_208_988_800;
const NTP_FRACTION_MASK: u64 = u32::MAX as u64;

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

    pub fn offset(&self, recv_time: &SystemTime) -> Option<i64> {
        // local clock offset
        //   offset = ((rec-org) + (xmt-dst)) / 2
        let recv = NtpTime(self.ts_recv).to_unix_nanos_near(recv_time)?;
        let orig = NtpTime(self.ts_orig).to_unix_nanos_near(recv_time)?;
        let xmit = NtpTime(self.ts_xmit).to_unix_nanos_near(recv_time)?;
        let dest = unix_nanos(recv_time)?;

        let a = recv - orig;
        let b = xmit - dest;
        Some(a + (b - a) / 2)
    }
}

fn unix_nanos(time: &SystemTime) -> Option<i64> {
    time.duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos()
        .try_into()
        .ok()
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

impl NtpTime {
    fn to_unix_nanos_near(&self, reference_time: &SystemTime) -> Option<i64> {
        let reference = unix_nanos(reference_time)? as i128;
        let reference_seconds = reference / NSEC_IN_SEC as i128;
        let ntp_seconds = (self.0 >> 32) as i128;
        let era = (reference_seconds + NTP_UNIX_OFFSET_SECONDS - ntp_seconds
            + NTP_HALF_ERA_SECONDS)
            / NTP_ERA_SECONDS;
        let unix_seconds = ntp_seconds + era * NTP_ERA_SECONDS - NTP_UNIX_OFFSET_SECONDS;
        if unix_seconds < 0 {
            return None;
        }
        let nanos = unix_seconds * NSEC_IN_SEC as i128
            + ((self.0 & NTP_FRACTION_MASK) as i128 * NSEC_IN_SEC as i128 >> 32);
        nanos.try_into().ok()
    }
}

impl From<&SystemTime> for NtpTime {
    fn from(t: &SystemTime) -> Self {
        let duration = t.duration_since(UNIX_EPOCH).unwrap();
        let secs = duration.as_secs() + NTP_UNIX_OFFSET_SECONDS as u64;
        let frac = (((duration.subsec_nanos() as u64) << 32) + NSEC_IN_SEC as u64 - 1)
            / NSEC_IN_SEC as u64;
        Self(secs << 32 | frac)
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
        let new_t =
            UNIX_EPOCH + std::time::Duration::from_nanos(nt.to_unix_nanos_near(&t).unwrap() as u64);
        assert_eq!(t, new_t);
    }

    #[test]
    fn time_convert_after_2200_does_not_panic() {
        let t = UNIX_EPOCH + std::time::Duration::from_secs(7_258_118_400);
        let nt = NtpTime::from(&t);
        let new_t =
            UNIX_EPOCH + std::time::Duration::from_nanos(nt.to_unix_nanos_near(&t).unwrap() as u64);
        assert_eq!(t, new_t);
    }

    #[test]
    fn offset_uses_local_send_time_without_panic() {
        let send_time = UNIX_EPOCH + std::time::Duration::from_secs(10);
        let recv_time = send_time + std::time::Duration::from_millis(40);
        let server_recv = send_time + std::time::Duration::from_millis(10);
        let server_xmit = send_time + std::time::Duration::from_millis(20);
        let packet = NtpPacket {
            ts_orig: NtpTime::from(&send_time).0,
            ts_recv: NtpTime::from(&server_recv).0,
            ts_xmit: NtpTime::from(&server_xmit).0,
            ..Default::default()
        };

        assert_eq!(packet.offset(&recv_time), Some(-5_000_000));
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
