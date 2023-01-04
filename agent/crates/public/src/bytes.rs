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

pub fn read_i16_be(bs: &[u8]) -> i16 {
    assert!(bs.len() >= 2);
    i16::from_be_bytes(bs[..2].try_into().unwrap())
}

pub fn read_u16_be(bs: &[u8]) -> u16 {
    assert!(bs.len() >= 2);
    u16::from_be_bytes(bs[..2].try_into().unwrap())
}

pub fn read_u16_le(bs: &[u8]) -> u16 {
    assert!(bs.len() >= 2);
    u16::from_le_bytes(bs[..2].try_into().unwrap())
}

pub fn read_u32_be(bs: &[u8]) -> u32 {
    assert!(bs.len() >= 4);
    u32::from_be_bytes(bs[..4].try_into().unwrap())
}

pub fn read_u32_le(bs: &[u8]) -> u32 {
    assert!(bs.len() >= 4);
    u32::from_le_bytes(bs[..4].try_into().unwrap())
}

pub fn read_u64_be(bs: &[u8]) -> u64 {
    assert!(bs.len() >= 8);
    u64::from_be_bytes(bs[..8].try_into().unwrap())
}

pub fn read_u64_le(bs: &[u8]) -> u64 {
    assert!(bs.len() >= 8);
    u64::from_le_bytes(bs[..8].try_into().unwrap())
}

pub fn write_u16_be(bs: &mut [u8], v: u16) {
    assert!(bs.len() >= 2);
    bs[0..2].copy_from_slice(v.to_be_bytes().as_slice())
}

pub fn write_u32_be(bs: &mut [u8], v: u32) {
    assert!(bs.len() >= 4);
    bs[0..4].copy_from_slice(v.to_be_bytes().as_slice())
}

pub fn write_u64_be(bs: &mut [u8], v: u64) {
    assert!(bs.len() >= 8);
    bs[0..8].copy_from_slice(v.to_be_bytes().as_slice())
}
