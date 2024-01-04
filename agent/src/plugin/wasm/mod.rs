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

// wasm plugin use for hook in some point and call function define in wasm module, and then retrive the result as some info of l7 protocol log.
// the process as follow:
/*
                                                                                                                                                                +----------------------+
                                                                                                                                                                |     host function:   |
                                                                                                                                                                |      init_wasm()     |
                                                                                                                                                                +----------+-----------+           +---------------------------------------------+
                                                                                                                                                                           |                       |                                             |
                                                                                                                                                                           |          +------------+   linker with wasi_snapshot_preview1        |
                                                                                                                                                                           |          |            |                                             |
                                                                                                                                                                           |          |            +---------------------------------------------+
                                                                                                                                                              +------------v----------v+
                                                                                                                                                              |        module          |
                                                                                                                                                              +------------+----------^+           +---------------------------------------------+
                                                                                                                                                                           |          |            |                                             |
                                                                                                                                                                           |          +------------+  linker with deepflow import function       |
                                                                                                                                                                           |                       |                                             |
                                                                                                                                                                           |                       +---------------------------------------------+
                                                                                                                                                                           |
                                                                                                                                                                           |
                                                                           +---------------------------+                                                         +---------v---------+                                                                                               +--------------------------+       +-----------+     +-----------------------------+    +------------------------+
                                                                           |         ParseParam        |                +----------------------------------------+      Instance     +---------------------------------------------------------------------------------------------->|    host function:        |       |  set the  |     |     host function:          |    |     host function:     |
                                                                           |    payload, path, ua,     |                |                                        +----------+--------+                                                                                               | Instance::parse_payload()|<------+ VmParseCtx|<----+   WasmVm::on_parse_payload()|<---+WasmLog::parse_payload()|
                                                                           |    content-type ...       |                |                                                   |                                                                                                        +-----------+--------------+       +------^----+     +-----------------------------+    +------------------------+
                                                                           +-------------+-------------+                |                                                   |                                                                                                                    |                             |
                                                                                         |                              |                                                   |                                                                                                                    |                      +------+----+
                                                                                         |                              |                                 +-----------------v-----------+     +------------+       +---------------------------+     +-------------------------+       +---------v----------+           | ParseParam|
                                                                                         |                 +------------v------------+                    |         host function:      |     |  set the   |       |    host function:         |     |     host function:      |       | vm export function:|           |   payload |
                                              +------------------------+                 |                 |     host function:      |                    |   Instanace::check_payload()<-----+ VmParseCtx |<------+ WasmVm::on_check_payload()|<----+ WasmLog::check_payload()|       |   parse_payload()  |           +-----------+
+--------------------------------+            |    host function:      |          +------v-----+           | Instance::on_http_req() |                    +-----------------+-----------+     +------^-----+       +---------------------------+     +-------------------------+       +---------+----------+
|host function: parse_http_v1()  +------------>  WasmVm::on_http_req() +---------->  set the   +----------->          or             |                                      |                        |                                                                                           |
+--------------------------------+            |         or             |          | VmParseCtx |           | Instance::on_http_resp()|                                      |                 +------+------+                                                               +--------------------v--------------------+
                                              | WasmVm::on_http_resp() |          +------------+           +------------+------------+                                      |                 |   ParseParam|                                                               |          host import function:          |
                                              +------------------------+                                                |                                       +-----------v---------+       |    payload  |                                                               |            vm_read_ctx_base()           |
                                                                                                                        |                                       | vm export function: |       +-------------+                                                               |   host serialize ctx  and  write to vm  |
                                                                                                          +-------------v------------+                          |  check_payload()    |                                                                                     +--------------------+--------------------+
                                                                                                          |     vm export function:  |                          +-----------+---------+                                                                                                          |
                                                                                                +---------+       on_http_req()      |                                      |                                                                                                                    |
                                                                                                |         |           or             |                                      |                                                                                                  +-----------------v------------------+
                                                                                                |         |       on_http_resp()     |                 +--------------------v--------------------+                                                                             |   return  to  vm export funcction  |
                                                                                                |         +--------------------------+                 |          host import function:          |                                                                             |          parse_payload()           |
                                                                                                |                                                      |            vm_read_ctx_base()           |                                                                             |          deserialize  ctx          |
                                                                                                |                                                      |   host serialize ctx  and  write to vm  |                                                                             +-----------------+------------------+
                                                          +-------------------------------------v-------------------------------------------+          +--------------------+--------------------+                                                                                               |
                                                          |                            host import function:                                |                               |                                                                                                                    |
                                                          |  vm_read_ctx_base()  and (vm_read_http_req_info()  or vm_read_http_resp_info()) |                               |                                                                                     +------------------------------v-------------------------------+
                                                          |                  host serialize ctx  and  write to vm                           |             +-----------------v------------------+                                                                  |                         in vm:                               |
                                                          +-------------------------------------+-------------------------------------------+             |   return  to  vm export funcction  |                                                                  | call user implement: parser.OnParsePayload() -> L7protocoInfo|
                                                                                                |                                                         |          check_payload()           |                                                                  +------------------------------+-------------------------------+
                                                                                                |                                                         |          deserialize  ctx          |                                                                                                 |
                                                                            +-------------------v-------------------+                                     +------------------+-----------------+                                                                                                 |
                                                                            |     return  to  vm export funcction:  |                                                        |                                                                                                      +------------v-----------+
                                                                            |             on_http_req()             |                                                        |                                                                                                      |        in vm:          |
                                                                            |                  or                   |                                                        |                                                                                                      |serialize L7ProtocolInfo|
                                                                            |              on_http_resp()           |                            +---------------------------v-----------------------------+                                                                        +------------+-----------+
                                                                            |            deserialize  ctx           |                            |                           in vm:                        |                                                                                     |
                                                                            +-------------------+-------------------+                            |   call user implement: parser.OnCheckPayload() -> uint8 |                                                                                     |
                                                                                                |                                                +---------------------------+-----------------------------+                                                                      +--------------v--------------+
                                                                                                |                                                                            |                                                                                                    |     host import function:   |
                                                                         +----------------------v------------------------+                                                   |                                                                                                    | host_read_l7_protocol_info()|
                                                                         |                   in vm:                      |                                          +--------v---------+                                                                                          +--------------+--------------+
                                                                         |   call user implement                         |                                          |      in host:    |                                                                                                         |
                                                                         |       parser.OnHttpReq() ->  (trace, attr)    |                                          | clean VmParseCtx |                                                                                                         |
                                                                         |                  or                           |                                          +--------+---------+                                                                                     +-------------------v------------------+
                                                                         |       parser.OnHttpResp() -> (trace, attr)    |                                                   |                                                                                               |              in host:                |
                                                                         +----------------------+------------------------+                                                   |                                                                                               | read L7protocolInfo and deserialize, |
                                                                                                |                                                   +------------------------v---------------------------+                                                                   | set it to VmParseCtx.                |
                                                                                     +----------v------------+                                      |                      in host:                      |                                                                   +-------------------+------------------+
                                                                                     |        in vm:         |                                      |  use vm return uint8 as the wasm inner protocol num|                                                                                       |
                                                                                     |  serialize the Result |                                      +----------------------------------------------------+                                                                                       |
                                                                                     +---------+-------------+                                                                                                                                                                  +----------------v----------------+
                                                                                               |                                                                                                                                                                                |           in host:              |
                                                                                +--------------v-------------+                                                                                                                                                                  |get L7protocolInfo from Ctx,     |
                                                                                |     host import function:  |                                                                                                                                                                  |clean the ctx and return the info|
                                                                                |    host_read_http_result() |                                                                                                                                                                  +---------------------------------+
                                                                                +---------------+------------+
                                                                                                |
                                                                                                |
                                                                    +---------------------------v----------------------------+
                                                                    |                    in host:                            |
                                                                    | read the result serialize in vm and deserialize to     |
                                                                    | KeyVal, and set in VmParseCtx.                         |
                                                                    +--------------------------+-----------------------------+
                                                                                               |
                                                                                               |
                                                                 +-----------------------------v----------------------------------+
                                                                 |                          in host:                              |
                                                                 | clean the VmParseCtx and merge the KeyVal to HttpInfo attribute|
                                                                 +----------------------------------------------------------------+
*/
mod abi_export;
mod abi_import;
mod host;
mod metric;
#[cfg(test)]
mod test;
mod vm;

use host::{
    StoreDataType, EXPORT_FUNC_CHECK_PAYLOAD, EXPORT_FUNC_GET_HOOK_BITMAP, EXPORT_FUNC_ON_HTTP_REQ,
    EXPORT_FUNC_ON_HTTP_RESP, EXPORT_FUNC_PARSE_PAYLOAD, IMPORT_FUNC_HOST_READ_L7_PROTOCOL_INFO,
    IMPORT_FUNC_HOST_READ_STR_RESULT, IMPORT_FUNC_VM_READ_CTX_BASE, IMPORT_FUNC_VM_READ_HTTP_REQ,
    IMPORT_FUNC_VM_READ_HTTP_RESP, IMPORT_FUNC_VM_READ_PAYLOAD, IMPORT_FUNC_WASM_LOG,
    LOG_LEVEL_ERR, LOG_LEVEL_INFO, LOG_LEVEL_WARN, WASM_MODULE_NAME,
};
use public::bytes::read_u16_be;
use vm::{VmCtxBase, VmHttpReqCtx, VmHttpRespCtx, VmParseCtx, VmResult};

pub use host::{WasmVm, WASM_EXPORT_FUNC_NAME};
pub use metric::WasmCounter;

#[macro_export]
macro_rules! wasm_info {
    ($ins: expr, $in_fn: expr, $fmt: expr, $($args: expr),* $(,)?) => {
        info!("wasn_instance: {:?} in_fn: {:?} {}", $ins, $in_fn, format!($fmt,$($args),*))
    };

    ($ins: expr, $in_fn: expr, $fmt: literal) => {
        info!("wasn_instance: {:?} in_fn: {:?} {}", $ins, $in_fn, $fmt)
    };

    ($ins: expr, $fmt: literal, $($ args: expr),* $(,)?) => {
        info!("wasn_instance: {:?} {}", $ins, format!($fmt,$($args),*))
    };

    ($ins: expr, $fmt: literal) => {
        info!("wasn_instance: {:?} {}", $ins, $fmt)
    };
}

#[macro_export]
macro_rules! wasm_warn {
    ($ins: expr, $in_fn: expr, $fmt: literal, $($args: expr),* $(,)?) => {
        warn!("wasn_instance: {:?} in_fn: {:?} {}", $ins, $in_fn, format!($fmt,$($args),*))
    };

    ($ins: expr, $in_fn: expr, $fmt: literal) => {
        warn!("wasn_instance: {:?} in_fn: {:?} {}", $ins, $in_fn, $fmt)
    };

    ($ins: expr, $fmt: literal, $($args: expr),* $(,)?) => {
        warn!("wasn_instance: {:?} {}", $ins, format!($fmt,$($args),*))
    };


    ($ins: expr, $fmt: literal) => {
        warn!("wasn_instance: {:?} {}", $ins, $fmt)
    };
}

#[macro_export]
macro_rules! wasm_error {
    ($ins: expr, $in_fn: expr, $fmt: literal, $($args: expr),* $(,)?) => {
        error!("wasn_instance: {:?} in_fn: {:?} {}", $ins, $in_fn, format!($fmt,$($args),*))
    };

    ($ins: expr, $in_fn: expr, $fmt: literal) => {
        error!("wasn_instance: {:?} in_fn: {:?} {}", $ins, $in_fn, $fmt)
    };

    ($ins: expr, $fmt: literal, $($ args: expr),* $(,)?) => {
        error!("wasn_instance: {:?} {}", $ins, format!($fmt,$($args),*))
    };

    ($ins: expr, $fmt: literal) => {
        error!("wasn_instance: {:?} {}", $ins, $fmt)
    };
}

pub fn read_wasm_str(data: &[u8], offset: &mut usize) -> Option<String> {
    let mut off = *offset;
    if off + 2 > data.len() {
        return None;
    }
    let len = read_u16_be(&data[off..off + 2]) as usize;
    off += 2;
    if off + len > data.len() {
        return None;
    }

    let s = String::from_utf8_lossy(&data[off..off + len]).to_string();
    off += len;
    *offset = off;
    Some(s)
}

pub(super) const HOOK_POINT_HTTP_REQ: u128 = 1 << 127;
pub(super) const HOOK_POINT_HTTP_RESP: u128 = 1 << 126;

pub(super) const HOOK_POINT_PAYLOAD_PARSE: u128 = 1;

pub(super) struct HookPointBitmap(u128);
impl HookPointBitmap {
    fn skip(&self, s: u128) -> bool {
        self.0 & s == 0
    }
}
