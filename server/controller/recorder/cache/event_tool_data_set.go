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

import (
	"github.com/deepflowys/deepflow/server/controller/common"
)

type EventToolDataSet struct {
	hostIPToID   map[string]int
	hostIDtoInfo map[int]*hostInfo

	vmIDToInfo           map[int]*vmInfo
	VMIDToIPNetworkIDMap map[int]map[string]uint32

	vrouterIDToInfo map[int]*vrouterInfo

	dhcpPortIDToInfo map[int]*dhcpPortInfo

	nateGatewayIDToInfo map[int]*nateGatewayInfo

	lbIDToInfo map[int]*lbInfo

	rdsInstanceIDToInfo map[int]*rdsInstanceInfo

	redisInstanceIDToInfo map[int]*redisInstanceInfo

	podNodeIDToInfo map[int]*podNodeInfo

	podServiceIDToInfo map[int]*podServiceInfo

	podIDToInfo           map[int]*podInfo
	PodIDToIPNetworkIDMap map[int]map[string]uint32

	NetworkIDToName           map[int]string
	VInterfaceIDToLcuuid      map[int]string
	WANIPLcuuidToVInterfaceID map[string]int
	WANIPLcuuidToIP           map[string]string
	LANIPLcuuidToVInterfaceID map[string]int
	LANIPLcuuidToIP           map[string]string
}

type BaseInfo struct {
	RegionLcuuid string
	AZLcuuid     string
	VPCID        int
}

type hostInfo struct {
	BaseInfo
	Name string
}

type vmInfo struct {
	BaseInfo
	Name         string
	LaunchServer string
}

type vrouterInfo struct {
	BaseInfo
	Name string
}

type dhcpPortInfo struct {
	BaseInfo
	Name string
}

type nateGatewayInfo struct {
	BaseInfo
	Name string
}

type lbInfo struct {
	BaseInfo
	Name string
}

type rdsInstanceInfo struct {
	BaseInfo
	Name string
}

type redisInstanceInfo struct {
	BaseInfo
	Name string
}

type podNodeInfo struct {
	BaseInfo
	Name         string
	PodClusterID int
}

type podServiceInfo struct {
	BaseInfo
	Name         string
	PodClusterID int
	PodNSID      int
}

type podInfo struct {
	BaseInfo
	Name         string
	PodClusterID int
	PodNSID      int
	PodGroupID   int
	PodNodeID    int
}

func NewEventToolDataSet() EventToolDataSet {
	return EventToolDataSet{
		hostIPToID:   make(map[string]int),
		hostIDtoInfo: make(map[int]*hostInfo),

		vmIDToInfo:           make(map[int]*vmInfo),
		VMIDToIPNetworkIDMap: make(map[int]map[string]uint32),

		vrouterIDToInfo: make(map[int]*vrouterInfo),

		dhcpPortIDToInfo: make(map[int]*dhcpPortInfo),

		nateGatewayIDToInfo: make(map[int]*nateGatewayInfo),

		lbIDToInfo: make(map[int]*lbInfo),

		rdsInstanceIDToInfo: make(map[int]*rdsInstanceInfo),

		redisInstanceIDToInfo: make(map[int]*redisInstanceInfo),

		podNodeIDToInfo: make(map[int]*podNodeInfo),

		podServiceIDToInfo: make(map[int]*podServiceInfo),

		podIDToInfo:           make(map[int]*podInfo),
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
