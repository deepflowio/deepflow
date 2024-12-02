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

pub fn decapsulate_gpe_vxlan(_packet: &mut [u8], _l2_len: usize) -> Option<(usize, u32)> {
    None
}

pub fn decapsulate_erspan(
    _packet: &[u8],
    _l2_len: usize,
    _flags: u16,
    _gre_protocol_type: u16,
    _ip_header_size: usize,
) -> Option<(usize, u32)> {
    None
}

pub fn decapsulate_teb(
    _packet: &[u8],
    _l2_len: usize,
    _flags: u16,
    _ip_header_size: usize,
) -> Option<(usize, u32)> {
    None
}

pub fn decapsulate_tencent_gre(
    _packet: &mut [u8],
    _l2_len: usize,
    _flags: u16,
    _gre_protocol_type: u16,
    _ip_header_size: usize,
) -> Option<(usize, u32)> {
    None
}
