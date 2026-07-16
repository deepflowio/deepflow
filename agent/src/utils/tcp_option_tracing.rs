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

use std::{fs::OpenOptions, io, os::unix::io::AsRawFd};

const TOT_DEVICE_PATH: &str = "/dev/tot";

// Keep in sync with TOT_IOC_SET_AGENT_ID in tot/module/tot_ioctl.h:
// _IOW('T', 1, __u32)
nix::ioctl_write_ptr!(tot_set_agent_id, b'T', 1, u32);

pub(crate) fn set_agent_id(agent_id: u32) -> io::Result<()> {
    let device = OpenOptions::new()
        .read(true)
        .write(true)
        .open(TOT_DEVICE_PATH)?;

    unsafe { tot_set_agent_id(device.as_raw_fd(), &agent_id) }
        .map(|_| ())
        .map_err(|errno| io::Error::from_raw_os_error(errno as i32))
}
