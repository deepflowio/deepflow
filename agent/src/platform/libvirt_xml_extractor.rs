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

use std::{
    fs,
    io::{Error, ErrorKind, Read, Result},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Condvar, Mutex, MutexGuard, RwLock},
    thread::{self, JoinHandle},
    time::Duration,
};

use log::{debug, error, info};
use roxmltree::Document;

use public::utils::net::MacAddr;

use super::InterfaceEntry;

const DEFAULT_LIBVIRT_XML_PATH: &'static str = "/etc/libvirt/qemu";
const REFRESH_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub struct LibvirtXmlExtractor {
    path: Arc<Mutex<PathBuf>>,
    entries: Arc<RwLock<Vec<InterfaceEntry>>>,
    running: Arc<Mutex<bool>>,
    thread: Mutex<Option<JoinHandle<()>>>,
    timer: Arc<Condvar>,
}

impl LibvirtXmlExtractor {
    /// create new libvirtxmlextractor
    pub fn new() -> Self {
        Self {
            path: Arc::new(Mutex::new(PathBuf::from(DEFAULT_LIBVIRT_XML_PATH))),
            entries: Arc::new(RwLock::new(Vec::new())),
            running: Arc::new(Mutex::new(false)),
            thread: Mutex::new(None),
            timer: Arc::new(Condvar::new()),
        }
    }

    /// refresh interface info and store in `entries` field
    fn refresh(path_lock: MutexGuard<PathBuf>, arc_entries: Arc<RwLock<Vec<InterfaceEntry>>>) {
        let path = path_lock.clone();
        drop(path_lock);
        match Self::extract_interface_info_from_xml(path.as_path()) {
            Ok(entries) => *arc_entries.write().unwrap() = entries,
            Err(e) => error!("cannot extract interface info from xml, error: {}", e),
        }
    }

    /// run extractor and get entries in every 60s
    pub fn start(&self) {
        // change status to RUNNING
        let mut running_lock = self.running.lock().unwrap();
        if *running_lock {
            return;
        }
        *running_lock = true;
        drop(running_lock);

        let path = Arc::clone(&self.path);
        let entries = Arc::clone(&self.entries);
        let running = Arc::clone(&self.running);
        let timer = self.timer.clone();

        *self.thread.lock().unwrap() = Some(
            thread::Builder::new()
                .name("libvirt-xml-extractor".to_owned())
                .spawn(move || loop {
                    let (path_lock, entries) = (path.lock().unwrap(), Arc::clone(&entries));
                    if path_lock.exists() {
                        LibvirtXmlExtractor::refresh(path_lock, entries);
                    }

                    let guard = running.lock().unwrap();
                    if !*guard {
                        break;
                    }
                    let (guard, _) = timer.wait_timeout(guard, REFRESH_INTERVAL).unwrap();
                    if !*guard {
                        break;
                    }
                })
                .unwrap(),
        );

        info!("libvirt_xml_extractor started");
    }

    pub fn stop(&self) {
        let mut running_lock = self.running.lock().unwrap();
        if !*running_lock {
            return;
        }
        *running_lock = false;
        drop(running_lock);
        self.timer.notify_one();

        if let Some(handle) = self.thread.lock().unwrap().take() {
            let _ = handle.join();
        }
        info!("libvirt_xml_extractor stopped");
    }

    /// get entries info protect by RWLock
    pub fn get_entries(&self) -> Option<Vec<InterfaceEntry>> {
        self.entries.read().map(|entries| entries.clone()).ok()
    }
    /// set libvirt xml file extract path
    pub fn set_path(&self, path: PathBuf) {
        if path.exists() {
            *self.path.lock().unwrap() = path;
        }
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
                domain_name = node.text().map(String::from);
            }
            if node.has_tag_name("uuid") {
                domain_uuid = node.text().map(String::from);
            }

            if !node.has_tag_name("devices") || domain_name.is_none() || domain_uuid.is_none() {
                continue;
            }
            for child in node.children() {
                if !child.has_tag_name("interface") {
                    continue;
                }
                let mut dev = None;
                let mut mac = None;
                for subchild in child.children() {
                    if subchild.has_tag_name("mac") {
                        let mac_str = subchild.attribute("address").unwrap_or_default();
                        match mac_str.parse::<MacAddr>() {
                            Ok(m) => mac = Some(m),
                            Err(e) => debug!("{}", e),
                        }
                    }

                    if subchild.has_tag_name("target") {
                        dev = subchild.attribute("dev");
                    }
                }
                if mac.is_none() {
                    continue;
                }
                if dev.is_none() {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "no target dev in interface info",
                    ));
                }
                entries.push(InterfaceEntry {
                    name: String::from(dev.unwrap()),
                    mac: mac.unwrap(),
                    domain_uuid: domain_uuid.as_ref().map(String::from).unwrap(),
                    domain_name: domain_name.as_ref().map(String::from).unwrap(),
                });
            }
        }

        Ok(entries)
    }

    fn extract_from<P: AsRef<Path>>(file_path: P) -> Result<Vec<InterfaceEntry>> {
        let mut f_conf = fs::OpenOptions::new().read(true).open(&file_path)?;
        let mut buf = String::new();
        f_conf.read_to_string(&mut buf)?;

        let document = Document::parse(&buf).map_err(|e| Error::new(ErrorKind::Other, e))?;
        match Self::extract_interfaces(&document) {
            Ok(entrys) => Ok(entrys),
            Err(e) => {
                debug!(
                    "Fail back to virsh dumpxml for {}: {:?}",
                    file_path.as_ref().display(),
                    e
                );

                let domain_uuid = document
                    .root_element()
                    .children()
                    .into_iter()
                    .find(|node| node.is_element() && node.has_tag_name("uuid"))
                    .and_then(|node| node.text())
                    .map(String::from);

                if domain_uuid.is_none() {
                    return Err(Error::new(ErrorKind::Other, "cannot parse domain uuid"));
                }
                let domain_uuid = domain_uuid.unwrap();

                let output = Command::new("virsh")
                    .arg("dumpxml")
                    .arg(domain_uuid.as_str())
                    .output()?;

                if !output.status.success() {
                    return Err(Error::new(ErrorKind::Other, "failed to run virsh dumpxml"));
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
                            return Err(Error::new(
                                ErrorKind::Other,
                                "failed to run virsh domstate",
                            ));
                        }
                        if let Ok(status_msg) = String::from_utf8(output.stdout) {
                            if status_msg.starts_with("running") {
                                return Err(Error::new(
                                    ErrorKind::Other,
                                    "virsh dumpxml has no target dev in interface info",
                                ));
                            }
                        }
                        debug!("not running vm {} ignored", file_path.as_ref().display());
                        Err(Error::new(ErrorKind::Other, e))
                    }
                }
            }
        }
    }

    fn extract_interface_info_from_xml<P: AsRef<Path>>(
        directory: P,
    ) -> Result<Vec<InterfaceEntry>> {
        let mut files = vec![];
        for entry in fs::read_dir(&directory)? {
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
            match Self::extract_from(file.as_path()) {
                Ok(mut p) => entries.append(&mut p),
                Err(e) => {
                    debug!(
                        "extract xml interface entry info failed with file path {} error: {}",
                        file.as_path().display(),
                        e
                    );
                }
            }
        }

        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_xml() {
        if let Ok(entries) =
            LibvirtXmlExtractor::extract_from("resources/test/platform/instance-00000054.xml")
        {
            assert_eq!(2, entries.len());
        }
    }

    #[test]
    fn test_libxml_extractor() {
        let entries =
            LibvirtXmlExtractor::extract_from("resources/test/platform/instance-00000054.xml")
                .unwrap();
        let file_path = PathBuf::from("resources/test/platform");
        let extractor = LibvirtXmlExtractor::new();
        extractor.set_path(file_path);
        extractor.start();
        thread::sleep(Duration::from_secs(1));
        assert_eq!(extractor.get_entries().unwrap(), entries);
        extractor.stop();
    }
}
