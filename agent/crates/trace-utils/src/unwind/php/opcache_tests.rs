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

#[cfg(test)]
use super::*;
use semver::Version;

#[test]
fn test_opcache_creation() {
    let opcache = PhpOpcacheSupport::new(Version::new(8, 2, 0));
    assert!(!opcache.is_jit_available());
    assert!(opcache.get_jit_buffer_info().is_none());
}

#[test]
fn test_jit_buffer_info() {
    let buffer_info = JitBufferInfo {
        buffer_address: 0x7f8000000000,
        buffer_size: 1024 * 1024,
        opcache_base: 0x7f7000000000,
    };

    assert_eq!(buffer_info.buffer_address, 0x7f8000000000);
    assert_eq!(buffer_info.buffer_size, 1024 * 1024);
    assert_eq!(buffer_info.opcache_base, 0x7f7000000000);
}
