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

/// Thread Specific Data info for accessing per-thread PyThreadState.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TSDInfo {
    /// Offset from thread pointer base (TPBASE) to TSD storage
    pub offset: i16,
    /// TSD key multiplier (glibc=16, musl=8)
    pub multiplier: u8,
    /// Whether indirect addressing is needed (musl=1, glibc=0)
    pub indirect: u8,
}
