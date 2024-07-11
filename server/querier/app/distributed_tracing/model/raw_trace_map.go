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

package model

type RawTraceMap struct {
	AutoServiceId0   uint `json:"auto_service_id_0"`
	AutoServiceId1   uint `json:"auto_service_id_1"`
	AutoServiceType0 uint `json:"auto_service_type_0"`
	AutoServiceType1 uint `json:"auto_service_type_1"`
	// aggregate from `trace_tree`
	ResponseTotal uint `json:"response_total"`
	// aggregate from `trace_tree`
	ResponseStatusServerErrorCount uint   `json:"response_status_server_error_count"`
	ClientIconId                   int    `json:"client_icon_id"`
	ServerIconId                   int    `json:"server_icon_id"`
	ResponseDurationSum            uint64 `json:"response_duration_sum"`
	AutoService0                   string `json:"auto_service_0"`
	AutoService1                   string `json:"auto_service_1"`
	// encoding: auto_service_type+auto_service_id+auto_service+app_service+layer
	Uid0           string `json:"uid_0"`
	Uid1           string `json:"uid_1"`
	IP0            string `json:"ip_0"`
	IP1            string `json:"ip_1"`
	AppService0    string `json:"app_service_0"`
	AppService1    string `json:"app_service_1"`
	ClientNodeType string `json:"client_node_type"`
	ServerNodeType string `json:"server_node_type"`
}
