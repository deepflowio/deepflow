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

import "github.com/deepflowys/deepflow/server/controller/common"

type EventToolDataSet struct {
	HostIDToName map[int]string
	HostIPToID   map[string]int

	VMIDToName           map[int]string
	VMIDToIPNetworkIDMap map[int]map[string]uint32

	VRouterIDToName map[int]string

	DHCPPortIDToName map[int]string

	NATGatewayIDToName map[int]string

	LBIDToName map[int]string

	RDSInstanceIDToName map[int]string

	RedisInstanceIDToName map[int]string

	PodNodeIDToName map[int]string

	PodServiceIDToName map[int]string

	PodIDToName           map[int]string
	PodIDToIPNetworkIDMap map[int]map[string]uint32

	NetworkIDToName           map[int]string
	VInterfaceIDToLcuuid      map[int]string
	WANIPLcuuidToVInterfaceID map[string]int
	WANIPLcuuidToIP           map[string]string
	LANIPLcuuidToVInterfaceID map[string]int
	LANIPLcuuidToIP           map[string]string
}

func NewEventToolDataSet() EventToolDataSet {
	return EventToolDataSet{
		HostIDToName: make(map[int]string),
		HostIPToID:   make(map[string]int),

		VMIDToName:           make(map[int]string),
		VMIDToIPNetworkIDMap: make(map[int]map[string]uint32),

		VRouterIDToName: make(map[int]string),

		DHCPPortIDToName: make(map[int]string),

		NATGatewayIDToName: make(map[int]string),

		LBIDToName: make(map[int]string),

		RDSInstanceIDToName: make(map[int]string),

		RedisInstanceIDToName: make(map[int]string),

		PodNodeIDToName: make(map[int]string),

		PodServiceIDToName: make(map[int]string),

		PodIDToName:           make(map[int]string),
		PodIDToIPNetworkIDMap: make(map[int]map[string]uint32),

		NetworkIDToName:           make(map[int]string),
		VInterfaceIDToLcuuid:      make(map[int]string),
		WANIPLcuuidToVInterfaceID: make(map[string]int),
		WANIPLcuuidToIP:           make(map[string]string),
		LANIPLcuuidToVInterfaceID: make(map[string]int),
		LANIPLcuuidToIP:           make(map[string]string),
	}
}

func (t *EventToolDataSet) setDeviceToIPNetworkMap(deviceType, deviceID, networkID int, ip string) {
	if deviceType == common.VIF_DEVICE_TYPE_VM {
		if t.VMIDToIPNetworkIDMap[deviceID] == nil {
			t.VMIDToIPNetworkIDMap[deviceID] = make(map[string]uint32)
		}
		t.VMIDToIPNetworkIDMap[deviceID][ip] = uint32(networkID)
	} else if deviceType == common.VIF_DEVICE_TYPE_POD {
		if t.PodIDToIPNetworkIDMap[deviceID] == nil {
			t.PodIDToIPNetworkIDMap[deviceID] = make(map[string]uint32)
		}
		t.PodIDToIPNetworkIDMap[deviceID][ip] = uint32(networkID)
	}
}

func (t *EventToolDataSet) deleteDeviceToIPNetworkMapIP(deviceType, deviceID, networkID int, ip string) {
	if deviceType == common.VIF_DEVICE_TYPE_VM {
		m, _ := t.VMIDToIPNetworkIDMap[deviceID]
		if m != nil {
			delete(m, ip)
		}
	} else if deviceType == common.VIF_DEVICE_TYPE_POD {
		m, _ := t.PodIDToIPNetworkIDMap[deviceID]
		if m != nil {
			delete(m, ip)
		}
	}
}

func (t *EventToolDataSet) GetVMIPNetworkMapByID(id int) (map[string]uint32, bool) {
	m, exists := t.VMIDToIPNetworkIDMap[id]
	if !exists {
		return make(map[string]uint32), false
	}
	return m, true
}

func (t *EventToolDataSet) GetPodIPNetworkMapByID(id int) (map[string]uint32, bool) {
	m, exists := t.PodIDToIPNetworkIDMap[id]
	if !exists {
		return make(map[string]uint32), false
	}
	return m, true
}
