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

// TODO: 提供偏移量等数据
// TODO: 获取 lua 虚拟机栈地址等
// TODO: 提供加载到 bpf table 的函数

#[no_mangle]
pub unsafe extern "C" fn is_lua_process(_: u32) -> bool {
    // TODO: 判断是否是 lua/nginx 进程
    todo!()
}
