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
	VMIDToIPNetworkIDMap map[int]map[string]int

	vrouterIDToInfo map[int]*vrouterInfo

	dhcpPortIDToInfo map[int]*dhcpPortInfo

	natGatewayIDToInfo map[int]*natGatewayInfo

	lbIDToInfo map[int]*lbInfo

	rdsInstanceIDToInfo map[int]*rdsInstanceInfo

	redisInstanceIDToInfo map[int]*redisInstanceInfo

	podNodeIDToInfo map[int]*podNodeInfo

	podServiceIDToInfo map[int]*podServiceInfo

	podIDToInfo           map[int]*podInfo
	PodIDToIPNetworkIDMap map[int]map[string]int

	NetworkIDToName           map[int]string
	VInterfaceIDToLcuuid      map[int]string
	WANIPLcuuidToVInterfaceID map[string]int
	WANIPLcuuidToIP           map[string]string
	LANIPLcuuidToVInterfaceID map[string]int
	LANIPLcuuidToIP           map[string]string
}

type hostInfo struct {
	Name     string
	RegionID int
	AZID     int
}

type vmInfo struct {
	Name     string
	RegionID int
	AZID     int
	VPCID    int
	HostID   int
}

type vrouterInfo struct {
	Name     string
	RegionID int
	VPCID    int
}

type dhcpPortInfo struct {
	Name     string
	RegionID int
	AZID     int
	VPCID    int
}

type natGatewayInfo struct {
	Name     string
	RegionID int
	AZID     int
	VPCID    int
}

type lbInfo struct {
	Name     string
	RegionID int
	VPCID    int
}

type rdsInstanceInfo struct {
	Name     string
	RegionID int
	AZID     int
	VPCID    int
}

type redisInstanceInfo struct {
	Name     string
	RegionID int
	AZID     int
	VPCID    int
}

type podNodeInfo struct {
	Name         string
	RegionID     int
	AZID         int
	VPCID        int
	PodClusterID int
}

type podServiceInfo struct {
	Name         string
	RegionID     int
	AZID         int
	VPCID        int
	PodClusterID int
	PodNSID      int
}

type podInfo struct {
	Name         string
	RegionID     int
	AZID         int
	VPCID        int
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
		VMIDToIPNetworkIDMap: make(map[int]map[string]int),

		vrouterIDToInfo: make(map[int]*vrouterInfo),

		dhcpPortIDToInfo: make(map[int]*dhcpPortInfo),

		natGatewayIDToInfo: make(map[int]*natGatewayInfo),

		lbIDToInfo: make(map[int]*lbInfo),

		rdsInstanceIDToInfo: make(map[int]*rdsInstanceInfo),

		redisInstanceIDToInfo: make(map[int]*redisInstanceInfo),

		podNodeIDToInfo: make(map[int]*podNodeInfo),

		podServiceIDToInfo: make(map[int]*podServiceInfo),

		podIDToInfo:           make(map[int]*podInfo),
		PodIDToIPNetworkIDMap: make(map[int]map[string]int),

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
			t.VMIDToIPNetworkIDMap[deviceID] = make(map[string]int)
		}
		t.VMIDToIPNetworkIDMap[deviceID][ip] = networkID
	} else if deviceType == common.VIF_DEVICE_TYPE_POD {
		if t.PodIDToIPNetworkIDMap[deviceID] == nil {
			t.PodIDToIPNetworkIDMap[deviceID] = make(map[string]int)
		}
		t.PodIDToIPNetworkIDMap[deviceID][ip] = networkID
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

func (t *EventToolDataSet) GetVMIPNetworkMapByID(id int) (map[string]int, bool) {
	m, exists := t.VMIDToIPNetworkIDMap[id]
	if !exists {
		return make(map[string]int), false
	}
	return m, true
}

func (t *EventToolDataSet) GetPodIPNetworkMapByID(id int) (map[string]int, bool) {
	m, exists := t.PodIDToIPNetworkIDMap[id]
	if !exists {
		return make(map[string]int), false
	}
	return m, true
}
