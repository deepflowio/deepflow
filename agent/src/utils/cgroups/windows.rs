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

use super::Error;
use crate::config::handler::EnvironmentAccess;

pub struct Cgroups;

impl Cgroups {
    pub fn new(_pid: u64, _config: EnvironmentAccess) -> Result<Self, Error> {
        Err(Error::CgroupsNotSupported(
            "Windows agent's cgroups is not supported".to_string(),
        ))
    }
    pub fn start(&self) {}
    pub fn get_mount_path(&self) -> String {
        String::default()
    }
    pub fn is_v2(&self) -> bool {
        false
    }
    pub fn stop(&self) -> Result<(), Error> {
        Err(Error::CgroupsNotSupported(
            "Windows agent's cgroups is not supported".to_string(),
        ))
    }
}

pub fn is_kernel_available_for_cgroups() -> bool {
    false
}
