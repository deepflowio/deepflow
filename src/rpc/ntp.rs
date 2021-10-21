use std::convert::{TryFrom, TryInto};
use std::time::{Duration, SystemTime};

use nom::number::streaming::be_u8;
pub use nom::{Err, IResult};
use nom_derive::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq, NomBE)]
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

impl TryFrom<u8> for NtpMode {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            x if x == NtpMode::Reserved as u8 => Ok(NtpMode::Reserved),
            x if x == NtpMode::SymmetricActive as u8 => Ok(NtpMode::SymmetricActive),
            x if x == NtpMode::SymmetricPassive as u8 => Ok(NtpMode::SymmetricPassive),
            x if x == NtpMode::Client as u8 => Ok(NtpMode::Client),
            x if x == NtpMode::Server as u8 => Ok(NtpMode::Server),
            x if x == NtpMode::Broadcast as u8 => Ok(NtpMode::Broadcast),
            x if x == NtpMode::NtpControlMessage as u8 => Ok(NtpMode::NtpControlMessage),
            x if x == NtpMode::Private as u8 => Ok(NtpMode::Private),
            _ => Err(()),
        }
    }
}

pub type NtpTime = u64;

const NSEC_IN_SEC: u32 = 1_000_000_000;

/// An NTP version 3 / 4 packet
#[derive(Debug, PartialEq, NomBE)]
pub struct NtpPacket {
    #[nom(PreExec = "let (i, b0) = be_u8(i)?;")]
    #[nom(Value(b0 >> 6))]
    pub li: u8,
    #[nom(Value((b0 >> 3) & 0b111))]
    pub version: u8,
    #[nom(Value((b0 & 0b111).try_into().unwrap()))]
    pub mode: NtpMode,
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
        NtpPacket {
            li: 3,
            version: 4,
            mode: NtpMode::Client,
            stratum: 0,
            poll: 0,
            precision: 0,
            root_delay: 0,
            root_dispersion: 0,
            ref_id: 0,
            ts_ref: 0,
            ts_orig: 0,
            ts_recv: 0,
            ts_xmit: 0,
        }
    }

    pub fn set_leap(&mut self, li: u8) {
        self.li = li;
    }

    pub fn set_version(&mut self, version: u8) {
        self.version = version;
    }

    pub fn set_mode(&mut self, mode: NtpMode) {
        self.mode = mode;
    }

    pub fn get_version(&self) -> u8 {
        self.version
    }

    pub fn get_mode(&self) -> NtpMode {
        self.mode
    }

    pub fn get_leap(&self) -> u8 {
        self.li
    }
}

/// Parse an NTP packet, version 3 or 4
pub fn parse_ntp(i: &[u8]) -> Option<NtpPacket> {
    match NtpPacket::parse(i) {
        Ok((_, packet)) => Some(packet),
        Err(_) => None,
    }
}

/// convert `SystemTime` to `u64` seconds
pub fn to_ntp_time(now: SystemTime) -> Option<NtpTime> {
    match now.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => {
            let frac = (n.as_nanos() % NSEC_IN_SEC as u128) as u64;
            let secs = n.as_secs();
            Some(secs << 32 | frac)
        }
        Err(_) => None,
    }
}

/// get local clock offset
pub fn get_offset(packet: &NtpPacket, ts_recv: u64) -> Duration {
    let a = packet.ts_recv - packet.ts_orig;
    let b = packet.ts_xmit - ts_recv;
    Duration::from_nanos((a + b) / 2)
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
    fn test_ntp_packet_simple() {
        let bytes = NTP_REQ1;
        let mut expected = NtpPacket {
            li: 3,
            version: 3,
            mode: NtpMode::SymmetricActive,
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
        let res = parse_ntp(&bytes);
        expected.version = 4;

        assert_eq!(res, Some(expected));
    }
}
