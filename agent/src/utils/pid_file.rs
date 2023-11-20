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

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use log::trace;
use nix::{sys::signal::kill, unistd::Pid};

pub struct PidFile {
    path: PathBuf,
    fp: Option<File>,
}

impl PidFile {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path = path.as_ref();
        trace!("check {} for existing pid file", path.display());
        match fs::read_to_string(path) {
            Ok(pid_str) => match pid_str.trim().parse::<u32>() {
                // check process
                Ok(pid) if kill(Pid::from_raw(pid as i32), None).is_ok() => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "pid file exists with a running process",
                    ));
                }
                _ => trace!("no process found with pid {}", pid_str),
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                trace!("old pid file {} not exist", path.display())
            }
            Err(e) => return Err(e),
        }
        // create pid file
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut fp = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        let pid = std::process::id();
        write!(fp, "{}\n", pid)?;
        fp.sync_data()?;
        trace!(
            "pid file {} created and pid {} written",
            path.display(),
            pid
        );
        Ok(Self {
            path: path.to_owned(),
            fp: Some(fp),
        })
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        std::mem::drop(self.fp.take());
        let _ = fs::remove_file(&self.path);
    }
}
