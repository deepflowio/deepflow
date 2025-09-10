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

use std::fmt;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::PathBuf;

use log::trace;

#[derive(Debug)]
pub struct MemoryArea {
    pub m_start: u64,
    pub mx_start: u64, // start address of executable section
    pub m_end: u64,
    pub path: String,
}

impl fmt::Display for MemoryArea {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}-{:016x} {}", self.m_start, self.m_end, self.path)
    }
}

pub fn get_memory_mappings(pid: u32) -> io::Result<Vec<MemoryArea>> {
    let path: PathBuf = ["/proc", &pid.to_string(), "maps"].iter().collect();
    trace!("read process#{pid} maps from {}", path.display());
    let reader = io::BufReader::new(File::open(&path)?);

    let mut areas = vec![];
    let mut last_area: Option<MemoryArea> = None;
    let mut last_executable = false;
    for line in reader.lines() {
        let line = line?;
        let mut segs = line.split_whitespace();
        let addrs = segs.next();
        let perms = segs.next();
        let Some(path) = segs.nth(3) else {
            continue;
        };
        let mut addrs = addrs
            .unwrap()
            .splitn(2, "-")
            .map(|addr| u64::from_str_radix(addr, 16));
        let Some(Ok(m_start)) = addrs.next() else {
            continue;
        };
        let Some(Ok(m_end)) = addrs.next() else {
            continue;
        };
        let perms = perms.unwrap();
        match last_area.as_mut() {
            Some(area) if area.path == path => {
                if perms.contains('x') {
                    area.mx_start = m_start;
                    last_executable = true;
                }
                area.m_start = area.m_start.min(m_start);
                area.m_end = area.m_end.max(m_end);
            }
            _ => {
                if last_executable {
                    let la = last_area.take().unwrap();
                    trace!("found {:?}", la);
                    areas.push(la);
                }

                // CRITICAL FIX: Filter out dangerous device files to prevent infinite memory consumption
                // Skip device files like /dev/zero, /dev/null, etc. that can cause OOM when read
                if path.starts_with("/dev/zero")
                    || path.starts_with("/dev/null")
                    || path.starts_with("/dev/random")
                    || path.starts_with("/dev/urandom")
                    || path.contains("/dev/zero")
                    || path.contains("/dev/null")
                {
                    trace!("Skipping dangerous device file mapping: {}", path);
                    last_executable = false;
                    continue;
                }

                last_area.replace(MemoryArea {
                    m_start,
                    mx_start: if perms.contains('x') { m_start } else { 0 },
                    m_end,
                    path: path.to_owned(),
                });
                last_executable = perms.contains('x');
            }
        }
    }
    Ok(areas)
}
