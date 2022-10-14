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

use std::collections::HashSet;

use log::warn;
use nix::errno::Errno;
use nix::libc::ioctl;
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};

use super::error::{Error, Result};

// ioctl ethtool request
#[cfg(target_env = "gnu")]
const SIOCETHTOOL: u64 = 0x8946;
#[cfg(target_env = "musl")]
const SIOCETHTOOL: i32 = 0x8946;

// ethtool stats related constants.
const ETH_GSTRING_LEN: usize = 32;
const ETH_SS_FEATURES: u32 = 4;
const ETHTOOL_GSTRINGS: u32 = 0x1b;
const ETHTOOL_GSSET_INFO: u32 = 0x37; /* Get string set info */
const ETHTOOL_GFEATURES: u32 = 0x3a; /* Get device offload settings */

// Maximum size of an interface name
const IFNAMSIZ: usize = 16;

// MAX_GSTRINGS maximum number of stats entries that ethtool can
// retrieve currently.
const MAX_GSTRINGS: usize = 8192;
const MAX_FEATURE_BLOCKS: usize = (MAX_GSTRINGS + 32 - 1) / 32;

#[derive(Debug, Default)]
#[repr(C)]
struct SsetInfo {
    pub cmd: u32,
    pub reserved: u32,
    pub sset_mask: u32,
    pub data: usize,
}

#[derive(Debug)]
#[repr(C)]
struct GStrings {
    pub cmd: u32,
    pub string_set: u32,
    pub len: u32,
    pub data: [u8; MAX_GSTRINGS * ETH_GSTRING_LEN],
}

#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
struct GetFeaturesBlock {
    available: u32,
    requested: u32,
    active: u32,
    never_changed: u32,
}

#[derive(Debug)]
#[repr(C)]
struct Gfeatures {
    pub cmd: u32,
    pub size: u32,
    pub blocks: [GetFeaturesBlock; MAX_FEATURE_BLOCKS],
}

#[derive(Debug)]
#[repr(C)]
struct IfReq {
    ifr_name: [u8; IFNAMSIZ],
    ifr_data: usize,
}

fn ethtool_ioctl(fd: i32, if_name: [u8; IFNAMSIZ], data_ptr: usize) -> Result<i32> {
    let mut ifr = IfReq {
        ifr_name: if_name,
        ifr_data: data_ptr,
    };

    let code = unsafe { ioctl(fd, SIOCETHTOOL, &mut ifr) };
    if code == 0 {
        return Ok(code);
    }

    Err(Error::Errno(Errno::from_i32(code)))
}

/// shows supported features name and their index by interface name.
pub fn get_link_features(if_name: &str) -> Result<Vec<(String, usize)>> {
    let fd = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )?;

    let mut req_name = [0u8; IFNAMSIZ];
    if if_name.len() > IFNAMSIZ {
        return Err(Error::Ethtool(format!(
            "get interface features failed, because interface({}) name length({}) > IFNAMSIZ({})",
            if_name,
            if_name.len(),
            IFNAMSIZ
        )));
    }
    req_name
        .get_mut(..if_name.len())
        .unwrap()
        .copy_from_slice(if_name.as_bytes());

    let mut sset_info = SsetInfo {
        cmd: ETHTOOL_GSSET_INFO,
        sset_mask: 1 << ETH_SS_FEATURES,
        ..Default::default()
    };

    ethtool_ioctl(fd, req_name, &mut sset_info as *mut SsetInfo as usize)?;

    let length = sset_info.data as u32;
    if length == 0 {
        return Err(Error::Ethtool(format!(
            "get interface features failed, because cannot get interface({}) feature's length",
            if_name
        )));
    } else if length > MAX_GSTRINGS as u32 {
        return Err(Error::Ethtool(format!(
            "ethtool currently doesn't support more than {} entries, received {}",
            MAX_GSTRINGS, length
        )));
    }

    let mut gstrings = GStrings {
        cmd: ETHTOOL_GSTRINGS,
        string_set: ETH_SS_FEATURES,
        len: length,
        data: [0u8; MAX_GSTRINGS * ETH_GSTRING_LEN],
    };

    ethtool_ioctl(fd, req_name, &mut gstrings as *mut GStrings as usize)?;

    let names = (0..length as usize)
        .into_iter()
        .filter_map(|i| {
            let name_bytes = gstrings
                .data
                .get(i * ETH_GSTRING_LEN..(i + 1) * ETH_GSTRING_LEN)
                .unwrap();

            name_bytes
                .iter()
                .position(|b| *b == 0)
                .and_then(|end| {
                    std::str::from_utf8(&name_bytes[..end])
                        .map_err(|e| warn!("prase feature name failed: {}", e))
                        .ok()
                })
                .filter(|s| !s.is_empty())
                .map(|s| (s.to_string(), i))
        })
        .collect();

    Ok(names)
}

/// retrieves features only state is "on" of the given interface name.
pub fn get_link_enabled_features(if_name: &str) -> Result<HashSet<String>> {
    let name_pairs = get_link_features(if_name)?;

    if name_pairs.is_empty() {
        return Err(Error::Ethtool(String::from(
            "no supported features on interface",
        )));
    }

    let fd = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )?;

    let mut req_name = [0u8; IFNAMSIZ];
    if if_name.len() > IFNAMSIZ {
        return Err(Error::Ethtool(format!(
            "get interface features failed, because interface({}) name length({}) > IFNAMSIZ({})",
            if_name,
            if_name.len(),
            IFNAMSIZ
        )));
    }
    req_name
        .get_mut(..if_name.len())
        .unwrap()
        .copy_from_slice(if_name.as_bytes());

    let mut features = Gfeatures {
        cmd: ETHTOOL_GFEATURES,
        size: (name_pairs.len() as u32 + 32 - 1) / 32,
        blocks: [GetFeaturesBlock::default(); MAX_FEATURE_BLOCKS],
    };

    ethtool_ioctl(fd, req_name, &mut features as *mut Gfeatures as usize)?;

    let enabled_features = name_pairs
        .into_iter()
        .filter_map(|(name, index)| {
            if is_feature_bit_set(features.blocks.as_ref(), index) {
                Some(name)
            } else {
                None
            }
        })
        .collect::<HashSet<String>>();

    Ok(enabled_features)
}

fn is_feature_bit_set(blocks: &[GetFeaturesBlock], index: usize) -> bool {
    blocks[index / 32].active & (1 << (index % 32)) != 0
}
