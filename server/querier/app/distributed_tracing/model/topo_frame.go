/*
 * Copyright (c) 2025 Yunshan Networks
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

type TopoFrame struct {
	Nodes []Node `json:"nodes"`
	Links []Link `json:"links"`
}

type Node struct {
	// unique id to match item in front-end
	LcUUID string `json:"lcuuid,omitempty"`
	// service uid from trace_map
	Name            string `json:"name,omitempty"`
	ServiceUID      string `json:"service_uid,omitempty"`
	AutoService     string `json:"auto_service,omitempty"`
	AutoServiceID   uint32 `json:"auto_service_id,omitempty"`
	AutoServiceType uint8  `json:"auto_service_type,omitempty"`
}

type Link struct {
	Client string `json:"client"`
	Server string `json:"server"`
}
