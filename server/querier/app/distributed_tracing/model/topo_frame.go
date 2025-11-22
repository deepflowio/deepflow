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
	Link  []Link `json:"link"`
}

type Node struct {
	// currently only id was used in api
	Item struct {
		ID uint32 `json:"id"`
	} `json:"item"`
	HashID string `json:"hash_id,omitempty"`
	// global unique id
	UID string `json:"uid,omitempty"`
	// compute by backend, service unique id
	ServiceUID      string `json:"service_uid,omitempty"`
	AutoService     string `json:"auto_service,omitempty"`
	AutoServiceID   uint32 `json:"auto_service_id,omitempty"`
	AutoServiceType uint8  `json:"auto_service_type,omitempty"`
	// is_internet => auto_service = ip
	// !is_internet => auto_service = auto_service_id
	IsInternet uint8  `json:"is_internet,omitempty"`
	Region     string `json:"region,omitempty"`
	RegionId   uint32 `json:"region_id,omitempty"`
}

type Link struct {
	Client string `json:"client"`
	Server string `json:"server"`
}
