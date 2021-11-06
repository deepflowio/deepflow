mod kubernetes;
mod libvirt_xml_extractor;

use crate::utils::net::MacAddr;

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct InterfaceEntry {
    name: String,
    mac: MacAddr,
    domain_uuid: String,
    domain_name: String,
}

#[derive(Debug)]
pub enum PollerType {
    Adaptive,
    Active,
    Passive,
}
