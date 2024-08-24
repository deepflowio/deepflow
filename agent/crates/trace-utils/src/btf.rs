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

use btf_rs::{Btf, Type};

use log::warn;

pub fn read_offset_of_stack_in_task_struct() -> Option<u32> {
    read_offset("task_struct", "stack")
}

const BTF_PATH: &'static str = "/sys/kernel/btf/vmlinux";

fn read_offset(struct_name: &str, field_name: &str) -> Option<u32> {
    let btf = match Btf::from_file(BTF_PATH) {
        Ok(btf) => btf,
        Err(e) => {
            warn!("Failed to read {BTF_PATH} for BTF info: {e}");
            return None;
        }
    };
    let Ok(ts) = btf.resolve_types_by_name(struct_name) else {
        warn!("Failed to find {struct_name} in {BTF_PATH}");
        return None;
    };
    for t in ts {
        match t {
            Type::Struct(s) => {
                for m in s.members.iter() {
                    match btf.resolve_name(m) {
                        Ok(name) if name == field_name => {
                            return Some(m.bit_offset() >> 3);
                        }
                        _ => (),
                    }
                }
            }
            _ => (),
        }
    }
    warn!("Failed to find field {field_name} of {struct_name} in {BTF_PATH}");
    None
}
