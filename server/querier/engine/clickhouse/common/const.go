/*
 * Copyright (c) 2022 Yunshan Networks
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

package common

const PERMISSION_TYPE_NUM = 3

var DB_TABLE_MAP = map[string][]string{
	"flow_log":        []string{"l4_flow_log", "l7_flow_log", "l4_packet"},
	"flow_metrics":    []string{"vtap_flow_port", "vtap_flow_edge_port", "vtap_app_port", "vtap_app_edge_port", "vtap_acl"},
	"ext_metrics":     []string{"ext_common"},
	"deepflow_system": []string{"deepflow_system_common"},
	"event":           []string{"resource_event"},
}
