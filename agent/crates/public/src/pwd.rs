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

use std::{fs, path::Path};

use log::error;

// Vec<uid, username>
pub struct PasswordInfo(Vec<(u32, String)>);

impl PasswordInfo {
    pub fn new(file: impl AsRef<Path>) -> std::io::Result<PasswordInfo> {
        let passwd_contents = fs::read_to_string(&file)?;
        let mut v = vec![];
        for line in passwd_contents.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 3 {
                error!(
                    "read pwd file {:?} fail, line `{}` can not parse",
                    file.as_ref().as_os_str(),
                    line
                );
                continue;
            }
            let Ok(uid) = fields[2].parse::<u32>() else {
                error!(
                    "read pwd file {:?} fail, line `{}` can not parse, uid {} is not integer",
                    file.as_ref().as_os_str(),
                    line,
                    fields[2]
                );
                continue;
            };
            v.push((uid, fields[0].to_string()));
        }
        Ok(PasswordInfo(v))
    }

    pub fn get_username_by_uid(&self, uid: u32) -> Option<String> {
        for (id, uname) in self.0.iter() {
            if *id == uid {
                return Some(uname.clone());
            }
        }
        None
    }

    pub fn get_uid_by_username(&self, username: &str) -> Option<u32> {
        for (id, uname) in self.0.iter() {
            if uname.as_str() == username {
                return Some(*id);
            }
        }
        None
    }
}
