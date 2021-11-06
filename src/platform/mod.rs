mod kubernetes;
mod libvirt_xml_extractor;

use crate::utils::net::MacAddr;
mod platform_synchronizer;

#[derive(Debug)]
pub enum PollerType {
    Adaptive,
    Active,
    Passive,
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct InterfaceEntry {
    name: String,
    mac: MacAddr,
    domain_uuid: String,
    domain_name: String,
}
