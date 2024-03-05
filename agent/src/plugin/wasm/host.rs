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

use std::{
    sync::atomic::Ordering,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use log::error;
use prost::Message as ProstMessage;
use wasmtime::{Engine, Linker, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder};

use crate::{
    common::l7_protocol_log::ParseParam,
    flow_generator::protocol_logs::HttpInfo,
    plugin::{CustomInfo, L7Protocol, PluginCounterInfo},
    wasm_error,
};

use super::{
    abi_export::{InstanceWrap, VmParser},
    abi_import::get_linker,
    VmCtxBase, VmHttpReqCtx, VmHttpRespCtx, VmOnCustomMessageCtx, VmParseCtx, HOOK_POINT_HTTP_REQ,
    HOOK_POINT_HTTP_RESP, HOOK_POINT_ON_CUSTOM_MESSAGE, HOOK_POINT_PAYLOAD_PARSE,
};

pub(super) const WASM_MODULE_NAME: &str = "deepflow";

pub(super) const EXPORT_FUNC_CHECK_PAYLOAD: &str = "check_payload";
pub(super) const EXPORT_FUNC_PARSE_PAYLOAD: &str = "parse_payload";
pub(super) const EXPORT_FUNC_ON_HTTP_REQ: &str = "on_http_req";
pub(super) const EXPORT_FUNC_ON_HTTP_RESP: &str = "on_http_resp";
pub(super) const EXPORT_FUNC_ON_CUSTOM_MESSAGE: &str = "on_custom_message";
pub(super) const EXPORT_FUNC_GET_HOOK_BITMAP: &str = "get_hook_bitmap";
pub(super) const EXPORT_FUNC_GET_CUSTOM_MESSAGE_HOOK: &str = "get_custom_message_hook";

pub(super) const IMPORT_FUNC_WASM_LOG: &str = "wasm_log";
pub(super) const IMPORT_FUNC_VM_READ_CTX_BASE: &str = "vm_read_ctx_base";
pub(super) const IMPORT_FUNC_VM_READ_PAYLOAD: &str = "vm_read_payload";
pub(super) const IMPORT_FUNC_VM_READ_HTTP_REQ: &str = "vm_read_http_req_info";
pub(super) const IMPORT_FUNC_VM_READ_HTTP_RESP: &str = "vm_read_http_resp_info";
pub(super) const IMPORT_FUNC_VM_READ_CUSTOM_MESSAGE: &str = "vm_read_custom_message_info";
pub(super) const IMPORT_FUNC_HOST_READ_L7_PROTOCOL_INFO: &str = "host_read_l7_protocol_info";
pub(super) const IMPORT_FUNC_HOST_READ_STR_RESULT: &str = "host_read_str_result";

pub(super) const LOG_LEVEL_INFO: i32 = 0;
pub(super) const LOG_LEVEL_WARN: i32 = 1;
pub(super) const LOG_LEVEL_ERR: i32 = 2;

pub const WASM_EXPORT_FUNC_NAME: [&'static str; 5] = [
    EXPORT_FUNC_CHECK_PAYLOAD,
    EXPORT_FUNC_PARSE_PAYLOAD,
    EXPORT_FUNC_ON_HTTP_REQ,
    EXPORT_FUNC_ON_HTTP_RESP,
    EXPORT_FUNC_ON_CUSTOM_MESSAGE,
];

pub(super) struct StoreDataType {
    pub(super) parse_ctx: Option<VmParseCtx>,
    pub(super) limiter: StoreLimits,
    pub(super) wasi_ctx: WasiCtx,
}

pub struct WasmVm {
    linker: Linker<StoreDataType>,
    store: Store<StoreDataType>,
    instance: Vec<InstanceWrap>,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub(super) enum HookPoint {
    ProtocolParse = 0,
    SessionFilter = 1,
    Sampling = 2,
}

pub struct WasmData {
    pub(super) hook_point: HookPoint,
    pub(super) type_code: u32,
    pub(super) protobuf: Vec<u8>,
}

impl WasmData {
    pub fn from_request<T: ProstMessage + Sized>(protocol: L7Protocol, message: T) -> WasmData {
        WasmData {
            hook_point: HookPoint::ProtocolParse,
            type_code: protocol as u32,
            protobuf: message.encode_to_vec(),
        }
    }
}

impl WasmVm {
    pub fn new<S: AsRef<str>, T: AsRef<[u8]>>(modules: &[(S, T)]) -> WasmVm {
        let limiter_builder = StoreLimitsBuilder::new();
        // load wasm instance up to 10
        let limiter = limiter_builder.memories(10).instances(10).build();

        let engine = Engine::default();
        let mut store = Store::<StoreDataType>::new(
            &engine,
            StoreDataType {
                parse_ctx: None,
                limiter,
                wasi_ctx: WasiCtxBuilder::new().build(),
            },
        );
        store.limiter(|s| &mut s.limiter);

        let linker = get_linker(engine.clone(), &mut store);
        let mut vm = WasmVm {
            linker,
            store,
            instance: vec![],
        };
        modules.into_iter().for_each(|(name, prog)| {
            if let Err(e) = vm.append_prog(name.as_ref(), prog.as_ref()) {
                wasm_error!(name.as_ref(), "add wasm prog fail: {}", e);
            }
        });

        vm
    }

    pub fn append_prog(&mut self, name: &str, prog: &[u8]) -> Result<()> {
        for ins in self.instance.iter() {
            if ins.name.as_str() == name {
                return Ok(());
            }
        }
        let ins = InstanceWrap::new(&mut self.store, &self.linker, name, prog)?;
        self.instance.push(ins);
        Ok(())
    }

    pub fn counters_in<'a>(&'a self, counters: &mut Vec<PluginCounterInfo<'a>>) {
        for i in self.instance.iter() {
            i.counters_in(counters);
        }
    }

    pub fn counters<'a>(&'a self) -> Vec<PluginCounterInfo<'a>> {
        let mut info = vec![];
        self.counters_in(&mut info);
        info
    }

    pub fn is_empty(&self) -> bool {
        self.instance.is_empty()
    }

    pub fn len(&self) -> usize {
        self.instance.len()
    }

    pub fn on_check_payload(&mut self, payload: &[u8], param: &ParseParam) -> Option<(u8, String)> {
        if self.instance.len() == 0 {
            return None;
        }

        let _ = self
            .store
            .data_mut()
            .parse_ctx
            .insert(VmParseCtx::ParseCtx(VmCtxBase::from((param, 0, payload))));

        let mut res = None;

        // traversal all wasm instance to check the payload, and return the wasm proto(range 0-255)
        for ins in self.instance.iter() {
            if ins.hook_point_bitmap.skip(HOOK_POINT_PAYLOAD_PARSE) {
                continue;
            }
            let start_time = SystemTime::now();
            let start_time = start_time.duration_since(UNIX_EPOCH).unwrap();

            self.store
                .data_mut()
                .parse_ctx
                .as_mut()
                .unwrap()
                .set_ins_name(ins.name.clone());

            let result = ins.check_payload(&mut self.store);

            ins.check_payload_counter
                .mem_size
                .swap(ins.get_mem_size(&mut self.store) as u64, Ordering::Relaxed);

            if result.is_err() {
                wasm_error!(ins.name, "check payload fail: {}", result.unwrap_err());
                ins.check_payload_counter
                    .fail_cnt
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }

            ins.check_payload_counter.exe_duration.swap(
                {
                    let end_time = SystemTime::now();
                    let end_time = end_time.duration_since(UNIX_EPOCH).unwrap();
                    // Local timestamp may be modified
                    if end_time > start_time {
                        (end_time - start_time).as_micros() as u64
                    } else {
                        0
                    }
                },
                Ordering::Relaxed,
            );

            let result = result.unwrap();
            if result == 0 {
                continue;
            }

            res = Some((result, "".to_string()));
            self.store
                .data_mut()
                .parse_ctx
                .as_mut()
                .unwrap()
                .take_str_result()
                .map(|s| res.as_mut().unwrap().1 = s);

            break;
        }

        // clean the ctx
        drop(self.store.data_mut().parse_ctx.take());
        res
    }

    pub fn on_parse_payload(
        &mut self,
        payload: &[u8],
        param: &ParseParam,
        proto: u8,
    ) -> Option<Vec<CustomInfo>> {
        if self.instance.len() == 0 {
            return None;
        }

        let _ = self
            .store
            .data_mut()
            .parse_ctx
            .insert(VmParseCtx::ParseCtx(VmCtxBase::from((
                param, proto, payload,
            ))));

        let mut ret = None;

        // traversal all wasm instance to parse the payload, read the serialize result from vm and deserialize to CustomInfo
        for ins in self.instance.iter() {
            if ins.hook_point_bitmap.skip(HOOK_POINT_PAYLOAD_PARSE) {
                continue;
            }

            let start_time = SystemTime::now();
            let start_time = start_time.duration_since(UNIX_EPOCH).unwrap();

            self.store
                .data_mut()
                .parse_ctx
                .as_mut()
                .unwrap()
                .set_ins_name(ins.name.clone());

            let abort = ins.parse_payload(&mut self.store);

            ins.parse_payload_counter
                .mem_size
                .swap(ins.get_mem_size(&mut self.store) as u64, Ordering::Relaxed);

            if abort.is_err() {
                wasm_error!(ins.name, "parse payload fail: {}", abort.unwrap_err());
                ins.parse_payload_counter
                    .fail_cnt
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }

            ins.parse_payload_counter.exe_duration.swap(
                {
                    let end_time = SystemTime::now();
                    let end_time = end_time.duration_since(UNIX_EPOCH).unwrap();
                    // Local timestamp may be modified
                    if end_time > start_time {
                        (end_time - start_time).as_micros() as u64
                    } else {
                        0
                    }
                },
                Ordering::Relaxed,
            );

            if !abort.unwrap() {
                continue;
            }

            ret = self
                .store
                .data_mut()
                .parse_ctx
                .as_mut()
                .unwrap()
                .take_l7_info_result()
                .map_or(Some(vec![]), |info| Some(info));
            break;
        }

        // clean the ctx
        drop(self.store.data_mut().parse_ctx.take());
        ret
    }

    pub fn on_http_req(
        &mut self,
        payload: &[u8],
        param: &ParseParam,
        info: &HttpInfo,
    ) -> Option<CustomInfo> {
        if self.instance.len() == 0 {
            return None;
        }

        let _ = self
            .store
            .data_mut()
            .parse_ctx
            .insert(VmParseCtx::HttpReqCtx(VmHttpReqCtx::from((
                param, info, payload,
            ))));
        let mut ret = None;

        for ins in self.instance.iter() {
            if ins.hook_point_bitmap.skip(HOOK_POINT_HTTP_REQ) {
                continue;
            }

            let start_time = SystemTime::now();
            let start_time = start_time.duration_since(UNIX_EPOCH).unwrap();

            self.store
                .data_mut()
                .parse_ctx
                .as_mut()
                .unwrap()
                .set_ins_name(ins.name.clone());

            let abort = ins.on_http_req(&mut self.store);

            ins.on_http_req_counter
                .mem_size
                .swap(ins.get_mem_size(&mut self.store) as u64, Ordering::Relaxed);

            if abort.is_err() {
                wasm_error!(ins.name, "wasm on http req fail: {}", abort.unwrap_err());
                ins.on_http_req_counter
                    .fail_cnt
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }

            ins.on_http_req_counter.exe_duration.swap(
                {
                    let end_time = SystemTime::now();
                    let end_time = end_time.duration_since(UNIX_EPOCH).unwrap();
                    // Local timestamp may be modified
                    if end_time > start_time {
                        (end_time - start_time).as_micros() as u64
                    } else {
                        0
                    }
                },
                Ordering::Relaxed,
            );

            if !abort.unwrap() {
                continue;
            }

            ret = self
                .store
                .data_mut()
                .parse_ctx
                .as_mut()
                .unwrap()
                .take_l7_info_result()
                .map_or(None, |mut r| r.pop());

            break;
        }

        // clean the ctx
        drop(self.store.data_mut().parse_ctx.take());
        ret
    }

    pub fn on_http_resp(
        &mut self,
        payload: &[u8],
        param: &ParseParam,
        info: &HttpInfo,
    ) -> Option<CustomInfo> {
        if self.instance.len() == 0 {
            return None;
        }

        let _ = self
            .store
            .data_mut()
            .parse_ctx
            .insert(VmParseCtx::HttpRespCtx(VmHttpRespCtx::from((
                param, info, payload,
            ))));

        let mut ret = None;
        for ins in self.instance.iter() {
            if ins.hook_point_bitmap.skip(HOOK_POINT_HTTP_RESP) {
                continue;
            }

            let start_time = SystemTime::now();
            let start_time = start_time.duration_since(UNIX_EPOCH).unwrap();

            self.store
                .data_mut()
                .parse_ctx
                .as_mut()
                .unwrap()
                .set_ins_name(ins.name.clone());

            let abort = ins.on_http_resp(&mut self.store);

            ins.on_http_resp_counter
                .mem_size
                .swap(ins.get_mem_size(&mut self.store) as u64, Ordering::Relaxed);

            if abort.is_err() {
                wasm_error!(ins.name, "wasm on http resp fail: {}", abort.unwrap_err());
                ins.on_http_resp_counter
                    .fail_cnt
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }

            ins.on_http_resp_counter.exe_duration.swap(
                {
                    let end_time = SystemTime::now();
                    let end_time = end_time.duration_since(UNIX_EPOCH).unwrap();
                    // Local timestamp may be modified
                    if end_time > start_time {
                        (end_time - start_time).as_micros() as u64
                    } else {
                        0
                    }
                },
                Ordering::Relaxed,
            );

            if !abort.unwrap() {
                continue;
            }

            ret = self
                .store
                .data_mut()
                .parse_ctx
                .as_mut()
                .unwrap()
                .take_l7_info_result()
                .map_or(None, |mut r| r.pop());

            break;
        }

        // clean the ctx
        drop(self.store.data_mut().parse_ctx.take());
        ret
    }

    pub fn on_custom_message(
        &mut self,
        payload: &[u8],
        param: &ParseParam,
        wasm_data: WasmData,
    ) -> Option<CustomInfo> {
        if self.instance.len() == 0 {
            return None;
        }

        let wasm_data_hook_point = wasm_data.hook_point as u16;
        let wasm_data_type_code = wasm_data.type_code;

        let _ = self
            .store
            .data_mut()
            .parse_ctx
            .insert(VmParseCtx::OnCustomMessageCtx(VmOnCustomMessageCtx::from(
                (param, payload, wasm_data),
            )));

        let mut ret = None;
        for ins in self.instance.iter() {
            if ins.hook_point_bitmap.skip(HOOK_POINT_ON_CUSTOM_MESSAGE) {
                continue;
            }
            if ins.vm_func_on_custom_message.is_none() {
                continue;
            }
            let Some(hook) = ins.custom_message_hook else {
                continue;
            };
            let hook_point = (hook >> 32 & 0xffff) as u16;
            let type_code = (hook & 0xffff_ffff) as u32;
            let hook_all = (hook >> 48 & 0xffff) as u16;
            if hook_all == 0 {
                if hook_point != wasm_data_hook_point || type_code != wasm_data_type_code {
                    continue;
                }
            }

            let start_time = SystemTime::now();
            let start_time = start_time.duration_since(UNIX_EPOCH).unwrap();

            self.store
                .data_mut()
                .parse_ctx
                .as_mut()
                .unwrap()
                .set_ins_name(ins.name.clone());

            let abort = ins.on_custom_message(&mut self.store);

            ins.on_custom_message_counter
                .mem_size
                .swap(ins.get_mem_size(&mut self.store) as u64, Ordering::Relaxed);

            if abort.is_err() {
                wasm_error!(
                    ins.name,
                    "wasm on custom message fail: {}",
                    abort.unwrap_err()
                );
                ins.on_custom_message_counter
                    .fail_cnt
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }

            ins.on_custom_message_counter.exe_duration.swap(
                {
                    let end_time = SystemTime::now();
                    let end_time = end_time.duration_since(UNIX_EPOCH).unwrap();
                    // Local timestamp may be modified
                    if end_time > start_time {
                        (end_time - start_time).as_micros() as u64
                    } else {
                        0
                    }
                },
                Ordering::Relaxed,
            );

            if !abort.unwrap() {
                continue;
            }

            ret = self
                .store
                .data_mut()
                .parse_ctx
                .as_mut()
                .unwrap()
                .take_l7_info_result()
                .map_or(None, |mut r| r.pop());

            break;
        }

        // clean the ctx
        drop(self.store.data_mut().parse_ctx.take());
        ret
    }
}
