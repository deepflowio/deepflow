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

use super::ProcessData;

pub fn proc_scan_hook(process_datas: &mut Vec<ProcessData>) {
    // Enterprise: mark AI Agent processes with biz_type
    #[cfg(feature = "enterprise")]
    {
        if let Some(registry) = enterprise_utils::ai_agent::global_registry() {
            for pd in process_datas.iter_mut() {
                if registry.is_ai_agent(pd.pid as u32) {
                    pd.biz_type = crate::common::flow::BIZ_TYPE_AI_AGENT;
                }
            }
        }
    }
}
