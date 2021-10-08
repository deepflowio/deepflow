use page_size;
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub enum OptTpacketVersion {
    TpacketVersionHighestavailablet = -1,
    TpacketVersion1,
    TpacketVersion2,
    TpacketVersion3,
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

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid tpacket version: {0}")]
    InvalidTpVersion(isize),
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
    pub frames_per_block: u32,
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
            frames_per_block: 128,
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
    pub fn check(&self) -> Result<(), &'static str> {
        let page_size = page_size::get() as u32;
        if self.block_size % page_size != 0 {
            return Err("block size must be divisible by page size.");
        }
        if self.block_size % self.frame_size != 0 {
            return Err("block size must be divisible by frame size.");
        }
        if self.num_blocks < 1 {
            return Err("num blocks must be >=1.");
        }
        if self.block_timeout < 1000000 {
            return Err("block time must be >=1,000,000");
        }
        if self.version.invalid() {
            return Err("tpacket version is invalid.");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_afpacket_opts_default() {
        let opts = Options {
            version: OptTpacketVersion::TpacketVersion2,
            ..Default::default()
        };
        assert_eq!(opts.block_size, 4096 * 128);
        assert_eq!(opts.version, OptTpacketVersion::TpacketVersion2);
    }

    #[test]
    fn test_afpacket_opts_check() {
        let opts = Options {
            block_size: 1,
            ..Default::default()
        };
        assert_ne!(Ok(()), opts.check());
    }
}
