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

package cache

type EventToolDataSet struct {
	VInterfaceLcuuidToDeviceInfo  map[string]*DeviceInfo
	VInterfaceLcuuidToNetworkInfo map[string]*NetworkInfo
	NetworkIDToName               map[int]string
	VMIDToName                    map[int]string
	PodNodeIDToName               map[int]string
	PodServiceIDToName            map[int]string
	PodIDToName                   map[int]string
	VInterfaceIDToLcuuid          map[int]string
	WANIPLcuuidToVInterfaceID     map[string]int
	WANIPLcuuidToIP               map[string]string
}

func NewEventToolDataSet() EventToolDataSet {
	return EventToolDataSet{
		VInterfaceLcuuidToDeviceInfo:  make(map[string]*DeviceInfo),
		VInterfaceLcuuidToNetworkInfo: make(map[string]*NetworkInfo),
		NetworkIDToName:               make(map[int]string),
		VMIDToName:                    make(map[int]string),
		PodNodeIDToName:               make(map[int]string),
		PodServiceIDToName:            make(map[int]string),
		PodIDToName:                   make(map[int]string),
		VInterfaceIDToLcuuid:          make(map[int]string),
		WANIPLcuuidToVInterfaceID:     make(map[string]int),
		WANIPLcuuidToIP:               make(map[string]string),
	}
}

type DeviceInfo struct {
	Type int
	ID   int
	Name string
}

type NetworkInfo struct {
	ID   int
	Name string
}
