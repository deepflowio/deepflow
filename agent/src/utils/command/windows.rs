/*
 * Copyright (c) 2023 Yunshan Networks
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

use std::io::{Error as IoError, ErrorKind, Result as IoResult};

use public::utils::net::{
    get_adapters_addresses, is_global, is_link_local_multicast, is_link_local_unicast, Error,
    LinkFlags, Result,
};

pub fn get_ip_address() -> Result<String, Error> {
    let (links, addrs) = get_adapters_addresses()?;
    let mut link_info = String::new();
    for link in links.iter() {
        let (link_type, brd) = if link.flags.contains(LinkFlags::LOOPBACK) {
            ("loopback", "00:00:00:00:00:00")
        } else {
            ("ether", "ff:ff:ff:ff:ff:ff")
        };
        link_info += &*format!(
            "{}: {}:\n    link/{} {} brd {}\n",
            link.if_index, link.name, link_type, link.mac_addr, brd
        );
        for addr in addrs.iter() {
            let ip_addr = addr.ip_addr;
            let scope = if ip_addr.is_loopback() {
                "host"
            } else if is_global(&ip_addr) {
                "global"
            } else if is_link_local_unicast(&ip_addr) || is_link_local_multicast(&ip_addr) {
                "link"
            } else {
                "unknown"
            };
            if link.if_index == addr.if_index {
                link_info += &*format!(
                    "    {} {}/{} scope {}\n",
                    if ip_addr.is_ipv6() { "inet6" } else { "inet" },
                    addr.ip_addr,
                    addr.prefix_len,
                    scope
                );
            }
        }
    }
    Ok(link_info)
}

pub fn get_hostname() -> IoResult<String> {
    hostname::get()?
        .into_string()
        .map_err(|_| IoError::new(ErrorKind::Other, "get hostname failed"))
}
