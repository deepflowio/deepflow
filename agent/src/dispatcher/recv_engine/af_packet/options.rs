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

use page_size;

pub use public::error::af_packet::{Error, Result};

use public::proto::trident::CaptureSocketType;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd)]
pub enum OptTpacketVersion {
    TpacketVersionHighestavailablet = -1,
    TpacketVersion1,
    TpacketVersion2,
    TpacketVersion3,
}

impl Default for OptTpacketVersion {
    fn default() -> Self {
        Self::TpacketVersionHighestavailablet
    }
}

impl From<CaptureSocketType> for OptTpacketVersion {
    fn from(t: CaptureSocketType) -> Self {
        match t {
            CaptureSocketType::Auto => Self::TpacketVersionHighestavailablet,
            CaptureSocketType::AfPacketV1 => Self::TpacketVersion1,
            CaptureSocketType::AfPacketV2 => Self::TpacketVersion2,
            CaptureSocketType::AfPacketV3 => Self::TpacketVersion3,
        }
    }
}

impl OptTpacketVersion {
    fn invalid(&self) -> bool {
        if *self < OptTpacketVersion::TpacketVersionHighestavailablet
            || *self > OptTpacketVersion::TpacketVersion3
            || *self == OptTpacketVersion::TpacketVersion1
        {
            return true;
        }
        return false;
    }
}

#[derive(Clone, Copy, Debug)]
pub enum OptSocketType {
    SocketTypeDgram = 2,
    SocketTypeRaw = 3,
}

impl OptSocketType {
    pub fn to_i32(&self) -> i32 {
        return *self as i32;
    }
}

#[derive(Clone, Debug)]
pub struct Options {
    pub frame_size: u32,
    pub block_size: u32,
    pub num_blocks: u32,
    pub add_vlan_header: bool,
    pub block_timeout: u32,
    pub poll_timeout: isize,
    pub version: OptTpacketVersion,
    pub socket_type: OptSocketType,
    pub iface: String,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            frame_size: 4096,
            block_size: 4096 * 128,
            num_blocks: 128,
            add_vlan_header: false,
            block_timeout: 64 * 1000000,
            poll_timeout: -1 * 1000000,
            version: OptTpacketVersion::TpacketVersionHighestavailablet,
            socket_type: OptSocketType::SocketTypeRaw,
            iface: "".to_string(),
        }
    }
}

impl Options {
    pub fn check(&self) -> Result<()> {
        let page_size = page_size::get() as u32;
        if self.block_size % page_size != 0 {
            return Err(Error::InvalidOption(
                "block size must be divisible by page size.",
            ));
        }
        if self.block_size % self.frame_size != 0 {
            return Err(Error::InvalidOption(
                "block size must be divisible by frame size.",
            ));
        }
        if self.num_blocks < 1 {
            return Err(Error::InvalidOption("num blocks must be >=1."));
        }
        if self.block_timeout < 1000000 {
            return Err(Error::InvalidOption("block time must be >=1,000,000"));
        }
        if self.version.invalid() {
            return Err(Error::InvalidOption("tpacket version is invalid."));
        }
        Ok(())
    }

    pub fn frames_per_block(&self) -> u32 {
        self.block_size / self.frame_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_af_packet_opts_default() {
        let opts = Options {
            version: OptTpacketVersion::TpacketVersion2,
            ..Default::default()
        };
        assert_eq!(opts.block_size, 4096 * 128);
        assert_eq!(opts.version, OptTpacketVersion::TpacketVersion2);
    }

    #[test]
    fn test_af_packet_opts_check() {
        let opts = Options {
            block_size: 1,
            ..Default::default()
        };
        assert!(opts.check().is_err());
    }
}
