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

use std::sync::{Arc, Weak};

use wasmtime::{
    AsContextMut, Instance, Linker, Memory, Module, Store, TypedFunc, WasmParams, WasmResults,
};

use super::{
    HookPointBitmap, StoreDataType, WasmCounter, EXPORT_FUNC_CHECK_PAYLOAD,
    EXPORT_FUNC_GET_HOOK_BITMAP, EXPORT_FUNC_ON_HTTP_REQ, EXPORT_FUNC_ON_HTTP_RESP,
    EXPORT_FUNC_PARSE_PAYLOAD,
};
use crate::{
    flow_generator::{
        Error::{self, WasmVmError},
        Result,
    },
    plugin::PluginCounterInfo,
};
use public::{
    bytes::read_u128_be,
    counter::{Countable, RefCountable},
};

pub(super) trait VmParser {
    fn on_http_req(&self, store: &mut Store<StoreDataType>) -> Result<bool>;
    fn on_http_resp(&self, store: &mut Store<StoreDataType>) -> Result<bool>;
    fn check_payload(&self, store: &mut Store<StoreDataType>) -> Result<u8>;
    fn parse_payload(&self, store: &mut Store<StoreDataType>) -> Result<bool>;
    fn get_hook_bitmap(&self, store: &mut Store<StoreDataType>) -> Result<HookPointBitmap>;
}

pub(super) struct InstanceWrap {
    pub(super) name: String,
    pub(super) hook_point_bitmap: HookPointBitmap,
    pub(super) ins: Instance,
    // the linear memory belong to this instance
    pub(super) memory: Memory,

    // metric counter
    pub(super) check_payload_counter: Arc<WasmCounter>,
    pub(super) parse_payload_counter: Arc<WasmCounter>,
    pub(super) on_http_req_counter: Arc<WasmCounter>,
    pub(super) on_http_resp_counter: Arc<WasmCounter>,

    /*
        correspond go export function:

        //export on_http_req
        func onHttpReq() bool {

        }
    */
    pub(super) vm_func_on_http_req: TypedFunc<(), i32>,
    /*
        correspond go export function:

        //export on_http_resp
        func onHttpResp() bool {

        }
    */
    pub(super) vm_func_on_http_resp: TypedFunc<(), i32>,
    /*
        correspond go export function:

        //export check_payload
        func checkPayload() uint8 {

        }
    */
    pub(super) vm_func_check_payload: TypedFunc<(), i32>,
    /*
        correspond go export function:

        //export parse_payload
        func parsePayload() bool {

        }
    */
    pub(super) vm_func_parse_payload: TypedFunc<(), i32>,
    /*
        correspond go export function:

        //export get_hook_bitmap
        func getHookBitmap() *byte {

        }
    */
    pub(super) vm_func_get_hook_bitmap: TypedFunc<(), i32>,
}

impl VmParser for InstanceWrap {
    fn check_payload(&self, store: &mut Store<StoreDataType>) -> Result<u8> {
        let proto = self
            .vm_func_check_payload
            .call(&mut *store, ())
            .map_err(|e| {
                WasmVmError(format!(
                    "vm call {} fail: {:?}",
                    EXPORT_FUNC_CHECK_PAYLOAD, e
                ))
            })?;

        match proto {
            0 => Ok(0),
            1..=255 => Ok(proto as u8),
            v => Err(WasmVmError(format!(
                "vm call check_payload return unexpect value : {}",
                v
            ))),
        }
    }

    fn parse_payload(&self, store: &mut Store<StoreDataType>) -> Result<bool> {
        let res = self
            .vm_func_parse_payload
            .call(&mut *store, ())
            .map_err(|e| {
                WasmVmError(format!(
                    "vm call {} fail: {:?}",
                    EXPORT_FUNC_PARSE_PAYLOAD, e
                ))
            })?;

        match res {
            0 => Ok(false),
            1 => Ok(true),
            v => Err(WasmVmError(format!(
                "vm call parse_payload return unexpect value : {}",
                v
            ))),
        }
    }

    fn on_http_req(&self, store: &mut Store<StoreDataType>) -> Result<bool> {
        let res = self
            .vm_func_on_http_req
            .call(&mut *store, ())
            .map_err(|e| {
                WasmVmError(format!("vm call {} fail: {:?}", EXPORT_FUNC_ON_HTTP_REQ, e))
            })?;

        match res {
            0 => Ok(false),
            1 => Ok(true),
            v => Err(WasmVmError(format!(
                "vm call on http req return unexpect value : {}",
                v
            ))),
        }
    }

    fn on_http_resp(&self, store: &mut Store<StoreDataType>) -> Result<bool> {
        let res = self
            .vm_func_on_http_resp
            .call(&mut *store, ())
            .map_err(|e| {
                WasmVmError(format!(
                    "vm call {} fail: {:?}",
                    EXPORT_FUNC_ON_HTTP_RESP, e
                ))
            })?;

        match res {
            0 => Ok(false),
            1 => Ok(true),
            v => Err(WasmVmError(format!(
                "vm call on http resp return unexpect value : {}",
                v
            ))),
        }
    }

    fn get_hook_bitmap(&self, store: &mut Store<StoreDataType>) -> Result<HookPointBitmap> {
        let bitmap_ptr = self
            .vm_func_get_hook_bitmap
            .call(&mut *store, ())
            .map_err(|e| {
                WasmVmError(format!(
                    "vm call {} fail: {:?}",
                    EXPORT_FUNC_GET_HOOK_BITMAP, e
                ))
            })? as usize;

        if bitmap_ptr == 0 {
            return Ok(HookPointBitmap(0));
        }

        let data = self.memory.data(store);
        if bitmap_ptr + 16 > data.len() {
            return Err(Error::WasmSerializeFail("get hook bitmap fail".to_string()));
        }
        Ok(HookPointBitmap(read_u128_be(
            &data[bitmap_ptr..bitmap_ptr + 16],
        )))
    }
}

impl InstanceWrap {
    pub fn new(
        store: &mut Store<StoreDataType>,
        linker: &Linker<StoreDataType>,
        name: &str,
        prog: &[u8],
    ) -> anyhow::Result<InstanceWrap> {
        let module = Module::from_binary(&store.engine().clone(), prog)?;
        let instance = linker.instantiate(&mut *store, &module)?;

        let memory = instance.get_export(&mut *store, "memory").map_or(
            Err(Error::WasmInitFail(format!(
                "wasm {} have no memory export",
                name
            ))),
            |mem| {
                if let Some(memory) = mem.into_memory() {
                    Ok(memory)
                } else {
                    Err(Error::WasmInitFail(format!(
                        "wasm {} can not get export memory",
                        name
                    )))
                }
            },
        )?;

        // get all vm export func
        let vm_func_on_http_req =
            get_instance_export_func::<(), i32>(&instance, &mut *store, EXPORT_FUNC_ON_HTTP_REQ)?;
        let vm_func_on_http_resp =
            get_instance_export_func::<(), i32>(&instance, &mut *store, EXPORT_FUNC_ON_HTTP_RESP)?;
        let vm_func_check_payload =
            get_instance_export_func::<(), i32>(&instance, &mut *store, EXPORT_FUNC_CHECK_PAYLOAD)?;
        let vm_func_parse_payload =
            get_instance_export_func::<(), i32>(&instance, &mut *store, EXPORT_FUNC_PARSE_PAYLOAD)?;
        let vm_func_get_hook_bitmap = get_instance_export_func::<(), i32>(
            &instance,
            &mut *store,
            EXPORT_FUNC_GET_HOOK_BITMAP,
        )?;

        // run _start as main to set the parser
        instance
            .get_typed_func::<(), ()>(&mut *store, "_start")
            .map_err(|e| WasmVmError(format!("get export function _start fail: {:?}", e)))?
            .call(&mut *store, ())
            .map_err(|e| WasmVmError(format!("vm call _start fail: {:?}", e)))?;

        let mut ins = InstanceWrap {
            ins: instance,
            hook_point_bitmap: HookPointBitmap(0),
            name: name.to_string(),
            memory,
            check_payload_counter: Default::default(),
            parse_payload_counter: Default::default(),
            on_http_req_counter: Default::default(),
            on_http_resp_counter: Default::default(),
            vm_func_on_http_req,
            vm_func_on_http_resp,
            vm_func_check_payload,
            vm_func_parse_payload,
            vm_func_get_hook_bitmap,
        };

        ins.hook_point_bitmap = ins.get_hook_bitmap(store)?;
        Ok(ins)
    }

    // linear memory size
    pub fn get_mem_size(&self, store: &mut Store<StoreDataType>) -> usize {
        let mem = self
            .ins
            .get_export(&mut *store, "memory")
            .unwrap()
            .into_memory()
            .unwrap();
        mem.data_size(store)
    }

    pub fn counters_in<'a>(&'a self, counters: &mut Vec<PluginCounterInfo<'a>>) {
        counters.push(PluginCounterInfo {
            plugin_name: self.name.as_str(),
            plugin_type: "wasm",
            function_name: EXPORT_FUNC_CHECK_PAYLOAD,
            counter: Countable::Ref(
                Arc::downgrade(&self.check_payload_counter) as Weak<dyn RefCountable>
            ),
        });
        counters.push(PluginCounterInfo {
            plugin_name: self.name.as_str(),
            plugin_type: "wasm",
            function_name: EXPORT_FUNC_PARSE_PAYLOAD,
            counter: Countable::Ref(
                Arc::downgrade(&self.parse_payload_counter) as Weak<dyn RefCountable>
            ),
        });
        counters.push(PluginCounterInfo {
            plugin_name: self.name.as_str(),
            plugin_type: "wasm",
            function_name: EXPORT_FUNC_ON_HTTP_REQ,
            counter: Countable::Ref(
                Arc::downgrade(&self.on_http_req_counter) as Weak<dyn RefCountable>
            ),
        });
        counters.push(PluginCounterInfo {
            plugin_name: self.name.as_str(),
            plugin_type: "wasm",
            function_name: EXPORT_FUNC_ON_HTTP_RESP,
            counter: Countable::Ref(
                Arc::downgrade(&self.on_http_resp_counter) as Weak<dyn RefCountable>
            ),
        });
    }
}

fn get_instance_export_func<Params, Results>(
    ins: &Instance,
    store: impl AsContextMut,
    fn_name: &str,
) -> Result<TypedFunc<Params, Results>>
where
    Params: WasmParams,
    Results: WasmResults,
{
    ins.get_typed_func::<Params, Results>(store, fn_name)
        .map_err(|e| WasmVmError(format!("get export function {} fail: {:?}", fn_name, e)))
}
