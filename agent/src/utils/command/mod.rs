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

use std::{
    io::{Error, ErrorKind, Result},
    process::Command,
};

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use self::windows::*;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux::*;

fn exec_command(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program).args(args).output()?;
    if output.status.success() {
        Ok(String::from_utf8(output.stdout)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?)
    } else {
        Ok(String::from_utf8(output.stderr)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?)
    }
}
