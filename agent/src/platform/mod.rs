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

#[cfg(target_os = "linux")]
mod kubernetes;
mod libvirt_xml_extractor;
mod platform_synchronizer;

#[cfg(target_os = "linux")]
pub use kubernetes::{ActivePoller, ApiWatcher, GenericPoller, Poller};
pub use libvirt_xml_extractor::LibvirtXmlExtractor;
pub use platform_synchronizer::ProcRegRewrite;
#[cfg(target_os = "linux")]
pub use platform_synchronizer::SocketSynchronizer;
pub use platform_synchronizer::{process_info_enabled, PlatformSynchronizer};
use public::utils::net::MacAddr;

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct InterfaceEntry {
    pub name: String,
    pub mac: MacAddr,
    pub domain_uuid: String,
    pub domain_name: String,
}
