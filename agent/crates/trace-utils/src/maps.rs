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
    pub offset: u64,
    pub path: String,
}

impl fmt::Display for MemoryArea {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:016x}-{:016x} {:08x} {}",
            self.m_start, self.m_end, self.offset, self.path
        )
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
        let offset = segs.next();
        let _dev = segs.next();
        let _inode = segs.next();
        let path = segs.next();

        let Some(path) = path else {
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
        let offset = u64::from_str_radix(offset.unwrap_or("0"), 16).unwrap_or(0);
        match last_area.as_mut() {
            Some(area) if area.path == path => {
                if perms.contains('x') {
                    area.mx_start = m_start;
                    area.offset = offset;
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

                // CRITICAL FIX: Filter out /dev/zero to prevent OOM in DWARF unwinder
                //
                // Background: PHP 8.0+ JIT uses mmap(/dev/zero) with executable permission (r-xs)
                // to create JIT buffers. This results in memory mappings like:
                //   488c0000-4c8c0000 r-xs 08000000 00:01 291490382  /dev/zero (deleted)
                //
                // Problem: DWARF unwinder (UnwindTable::load()) reads all executable mappings
                // via fs::read(/proc/{pid}/root/dev/zero). In container+XFS environments, this
                // triggers XFS readahead on the character device, causing infinite memory
                // allocation and OOM kill.
                //
                // Why only PHP JIT: Non-JIT PHP and other runtimes use /dev/zero without
                // executable permission (rw-s), which get_memory_mappings() filters out
                // (only returns mappings with 'x' permission). Only JIT buffers need r-xs.
                //
                // Why filter here: PHP unwinder's checks only protect its own code paths.
                // DWARF unwinder runs independently and processes all executable mappings.
                // Filtering at get_memory_mappings() protects all unwinders (PHP/Python/V8/DWARF).
                if path.contains("/dev/zero") {
                    trace!("Skipping /dev/zero mapping to prevent OOM: {}", path);
                    last_executable = false;
                    continue;
                }

                last_area.replace(MemoryArea {
                    m_start,
                    mx_start: if perms.contains('x') { m_start } else { 0 },
                    m_end,
                    offset,
                    path: path.to_owned(),
                });
                last_executable = perms.contains('x');
            }
        }
    }
    // push the last area if it is executable
    if last_executable {
        if let Some(la) = last_area.take() {
            trace!("found {:?}", la);
            areas.push(la);
        }
    }
    Ok(areas)
}
