mod kubernetes;
mod libvirt_xml_extractor;
mod platform_synchronizer;

pub use libvirt_xml_extractor::LibvirtXmlExtractor;

pub use kubernetes::{ActivePoller, ApiWatcher, GenericPoller, Poller};
pub use platform_synchronizer::PlatformSynchronizer;

use crate::utils::net::MacAddr;

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct InterfaceEntry {
    pub name: String,
    pub mac: MacAddr,
    pub domain_uuid: String,
    pub domain_name: String,
}
