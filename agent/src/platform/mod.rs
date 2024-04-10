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

cfg_if::cfg_if! {
    if #[cfg(target_os = "linux")] {
        mod libvirt_xml_extractor;
        pub mod kubernetes;
        pub mod prometheus;

        pub use libvirt_xml_extractor::LibvirtXmlExtractor;
        pub use kubernetes::{ApiWatcher, GenericPoller, Poller};
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use platform_synchronizer::{ProcRegRewrite, SocketSynchronizer};

mod platform_synchronizer;

pub use platform_synchronizer::process_info_enabled;

mod querier;
pub mod synchronizer;

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct InterfaceEntry {
    pub name: String,
    pub mac: public::utils::net::MacAddr,
    pub domain_uuid: String,
    pub domain_name: String,
}
