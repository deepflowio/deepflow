use std::process::Command;
use std::{
    fs::{read_dir, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard, RwLock,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use anyhow::{Context, Error, Result};
use flexi_logger::Logger;
use log::{debug, error, info, warn};
use roxmltree::Document;

const DEFAULT_LIBVIRT_XML_PATH: &'static str = "/etc/libvirt/qemu";

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct InterfaceEntry {
    name: String,
    mac_int: u64,
    domain_uuid: String,
    domain_name: String,
}

impl InterfaceEntry {
    pub fn get_name(&self) -> &str {
        &self.name
    }
    pub fn get_mac_int(&self) -> u64 {
        self.mac_int
    }
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }
    pub fn set_mac_int(&mut self, mac_int: u64) {
        self.mac_int = mac_int;
    }
    pub fn set_domain_uuid(&mut self, domain_uuid: String) {
        self.domain_uuid = domain_uuid;
    }
    pub fn set_domain_name(&mut self, domain_name: String) {
        self.domain_name = domain_name;
    }
}

#[derive(Debug)]
pub struct LibVirtXmlExtractor {
    path: Arc<Mutex<PathBuf>>,
    entries: Arc<RwLock<Vec<InterfaceEntry>>>,
    running: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl LibVirtXmlExtractor {
    /// create new libvirtxmlextractor
    pub fn new() -> Self {
        Self {
            path: Arc::new(Mutex::new(PathBuf::from(DEFAULT_LIBVIRT_XML_PATH))),
            entries: Arc::new(RwLock::new(Vec::new())),
            running: Arc::new(AtomicBool::new(false)),
            thread: Mutex::new(None),
        }
    }

    /// refresh interface info and store in `entries` field
    fn refresh(path_lock: MutexGuard<PathBuf>, arc_entries: Arc<RwLock<Vec<InterfaceEntry>>>) {
        let path = path_lock.clone();
        drop(path_lock);
        if let Ok(entries) = Self::extract_interface_info_from_xml(path.as_path()) {
            *arc_entries.write().unwrap() = entries;
        } else {
            error!("cannot extract interface info from xml");
        }
    }

    /// run extractor and get entries in every 60s
    pub fn start(&self) {
        // change status to RUNNING
        if self.running.swap(true, Ordering::SeqCst) == true {
            return;
        }
        let path = Arc::clone(&self.path);
        let entries = Arc::clone(&self.entries);
        let running = Arc::clone(&self.running);
        let mut thread_lock = self.thread.lock().unwrap();
        if thread_lock.is_none() {
            *thread_lock = Some(thread::spawn(move || {
                while running.load(Ordering::SeqCst) {
                    let (path_lock, entries) = (path.lock().unwrap(), Arc::clone(&entries));
                    LibVirtXmlExtractor::refresh(path_lock, entries);
                    if running.load(Ordering::SeqCst) == false {
                        break;
                    }
                    thread::sleep(Duration::new(60, 0));
                }
            }));
        }
    }

    pub fn stop(&self) {
        if self.running.swap(false, Ordering::SeqCst) == false {
            return;
        }

        if let Some(handle) = self.thread.lock().unwrap().take() {
            match handle.join() {
                Ok(_) => info!("exit refresh xml threads success"),
                Err(_) => error!("exit refresh xml threads failed"),
            }
        } else {
            warn!("no more thread to stop");
        }
    }

    /// get entries info protect by RWLock
    pub fn get_entries(&self) -> Option<Vec<InterfaceEntry>> {
        if let Ok(entries) = self.entries.read() {
            debug!("get entries from extractor");
            Some(entries.clone())
        } else {
            error!("cannot get interface entries from extractor");
            None
        }
    }
    /// set libvirt xml file extract path
    pub fn set_path(&self, path: PathBuf) {
        let mut path_lock = self.path.lock().unwrap();
        *path_lock = path;
    }

    fn extract_interfaces(document: &Document) -> Result<Vec<InterfaceEntry>> {
        let mut domain_name = None;
        let mut domain_uuid = None;
        let mut entries = vec![];
        for node in document.root_element().children() {
            if !node.is_element() {
                continue;
            }
            if node.has_tag_name("name") {
                domain_name = Some(String::from(node.text().unwrap_or_default()));
            }
            if node.has_tag_name("uuid") {
                domain_uuid = Some(String::from(node.text().unwrap_or_default()));
            }

            if !node.has_tag_name("devices") {
                continue;
            }
            for child in node.children() {
                if !child.has_tag_name("interface") {
                    continue;
                }
                let mut mac_int = 0;
                let mut dev = "";
                'INTERFACE: for subchild in child.children() {
                    if subchild.has_tag_name("mac") {
                        let mac = subchild.attribute("address").unwrap_or_default();
                        for n_s in mac.split(":") {
                            if let Ok(n) = u8::from_str_radix(n_s, 16) {
                                mac_int <<= 8;
                                mac_int |= n as u64;
                            } else {
                                error!(
                                    "invalid mac {} in domain name {} uuid {}",
                                    mac,
                                    domain_name.as_ref().unwrap_or(&format!("NO_DOMAIN_NAME")),
                                    domain_uuid.as_ref().unwrap_or(&format!("NO_DOMAIN_UUID"))
                                );
                                continue 'INTERFACE;
                            }
                        }
                    }

                    if subchild.has_tag_name("target") {
                        dev = subchild.attribute("dev").unwrap_or_default();
                    }
                }
                if mac_int == 0 || domain_name.is_none() || domain_uuid.is_none() {
                    continue;
                }
                if dev == "" {
                    return Err(Error::msg("no target dev in interface info"));
                }
                entries.push(InterfaceEntry {
                    name: String::from(dev),
                    mac_int,
                    domain_uuid: domain_uuid.clone().unwrap(),
                    domain_name: domain_name.clone().unwrap(),
                });
            }
        }

        Ok(entries)
    }

    fn extract_from<P: AsRef<Path>>(file_path: P) -> Result<Vec<InterfaceEntry>> {
        let mut f_conf = OpenOptions::new()
            .read(true)
            .open(&file_path)
            .with_context(|| {
                format!(
                    "could not open file_path={:?}",
                    file_path.as_ref().display()
                )
            })?;
        let mut buf = String::new();
        f_conf.read_to_string(&mut buf)?;

        let document = Document::parse(&buf)?;
        match Self::extract_interfaces(&document) {
            Ok(entrys) => Ok(entrys),
            Err(e) => {
                debug!(
                    "Fail back to virsh dumpxml for {}: {:?}",
                    file_path.as_ref().display(),
                    e
                );

                let mut domain_uuid = String::default();
                for node in document.root_element().children() {
                    if node.is_element() {
                        if node.has_tag_name("uuid") {
                            domain_uuid = String::from(node.text().unwrap_or_default());
                            break;
                        }
                    }
                }

                let output = Command::new("virsh")
                    .arg("dumpxml")
                    .arg(domain_uuid.as_str())
                    .output()?;

                if !output.status.success() {
                    return Err(Error::msg("failed to run virsh dumpxml"));
                }

                let bytes = String::from_utf8(output.stdout).unwrap();
                let document = Document::parse(&bytes).unwrap();

                match Self::extract_interfaces(&document) {
                    Ok(interfaces) => Ok(interfaces),
                    Err(e) => {
                        // 非运行状态缺少target信息正常，需要忽略错误
                        let output = Command::new("virsh")
                            .arg("domstate")
                            .arg(domain_uuid.as_str())
                            .output()?;
                        if !output.status.success() {
                            return Err(Error::msg("failed to run virsh domstate"));
                        }
                        let status_msg = String::from_utf8(output.stdout).unwrap();
                        if status_msg.starts_with("running") {
                            return Err(Error::msg(
                                "virsh dumpxml has no target dev in interface info",
                            ));
                        }
                        debug!("not running vm {} ignored", file_path.as_ref().display());
                        return Err(Error::msg(format!(
                            "Failed to extract interface info {:?}",
                            e
                        )));
                    }
                }
            }
        }
    }
    fn extract_interface_info_from_xml<P: AsRef<Path>>(
        directory: P,
    ) -> Result<Vec<InterfaceEntry>> {
        let mut files = vec![];
        let dir = read_dir(&directory).with_context(|| {
            format!(
                "xml directory doesn't exist or lacks permission or a non-directory file path: {}",
                directory.as_ref().display()
            )
        })?;
        for entry in dir {
            let file = entry?.path();
            if file.to_str().unwrap().ends_with(".xml") {
                files.push(file);
            }
        }

        debug!(
            "xml files under {}: {:?}",
            directory.as_ref().display(),
            files
        );

        let mut entries = vec![];
        for file in files.into_iter() {
            let mut single_entries = Self::extract_from(file.as_path()).with_context(|| {
                format!(
                    "extract xml interface entry info failed. file path {:?}",
                    file.as_path().display()
                )
            })?;
            entries.append(&mut single_entries);
        }

        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_xml() {
        if let Ok(entries) = LibVirtXmlExtractor::extract_from("src/platform/instance-00000054.xml")
        {
            assert_eq!(2, entries.len());
        }
    }

    #[test]
    fn test_libxml_extractor() {
        Logger::try_with_str("info").unwrap().start().unwrap();
        let entries =
            LibVirtXmlExtractor::extract_from("src/platform/instance-00000054.xml").unwrap();
        let file_path = PathBuf::from("src/platform");
        let extractor = LibVirtXmlExtractor::new();
        extractor.set_path(file_path);
        extractor.start();
        thread::sleep(Duration::from_secs(1));
        assert_eq!(extractor.get_entries().unwrap(), entries);
        extractor.stop();
    }
}
