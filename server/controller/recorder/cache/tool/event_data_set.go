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

package tool

import "github.com/deepflowio/deepflow/server/controller/common"

type EventDataSet struct {
	hostIPToID   map[string]int
	hostIDtoInfo map[int]*hostInfo

	vmIDToInfo           map[int]*vmInfo
	vmIDToIPNetworkIDMap map[int]map[IPKey]int

	vrouterIDToInfo map[int]*vrouterInfo

	dhcpPortIDToInfo map[int]*dhcpPortInfo

	natGatewayIDToInfo map[int]*natGatewayInfo

	lbIDToInfo map[int]*lbInfo

	rdsInstanceIDToInfo map[int]*rdsInstanceInfo

	redisInstanceIDToInfo map[int]*redisInstanceInfo

	podNodeIDToInfo map[int]*podNodeInfo

	podServiceIDToInfo map[int]*podServiceInfo

	podIDToInfo           map[int]*podInfo
	podIDToIPNetworkIDMap map[int]map[IPKey]int

	networkIDToName           map[int]string
	vinterfaceIDToLcuuid      map[int]string
	wanIPLcuuidToVInterfaceID map[string]int
	wanIPLcuuidToIP           map[string]string
	lanIPLcuuidToVInterfaceID map[string]int
	lanIPLcuuidToIP           map[string]string

	vmPodNodeConnectionLcuuidToPodNodeID map[string]int
	podNodeIDToVMID                      map[int]int

	processLcuuidToInfo map[string]*processInfo
}

type IPKey struct {
	IP     string
	Mac    string
	Lcuuid string
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
	Name           string
	RegionID       int
	VPCID          int
	GWLaunchServer string
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
	DomainLcuuid string
	Name         string
	RegionID     int
	AZID         int
	VPCID        int
	PodClusterID int
}

type podServiceInfo struct {
	Name           string
	RegionID       int
	AZID           int
	VPCID          int
	PodClusterID   int
	PodNamespaceID int
}

type podInfo struct {
	DomainLcuuid   string
	Name           string
	RegionID       int
	AZID           int
	VPCID          int
	PodClusterID   int
	PodNamespaceID int
	PodGroupID     int
	PodNodeID      int
}

type processInfo struct {
	ID   int
	Name string
}

func NewEventDataSet() EventDataSet {
	return EventDataSet{
		hostIPToID:   make(map[string]int),
		hostIDtoInfo: make(map[int]*hostInfo),

		vmIDToInfo:           make(map[int]*vmInfo),
		vmIDToIPNetworkIDMap: make(map[int]map[IPKey]int),

		vrouterIDToInfo: make(map[int]*vrouterInfo),

		dhcpPortIDToInfo: make(map[int]*dhcpPortInfo),

		natGatewayIDToInfo: make(map[int]*natGatewayInfo),

		lbIDToInfo: make(map[int]*lbInfo),

		rdsInstanceIDToInfo: make(map[int]*rdsInstanceInfo),

		redisInstanceIDToInfo: make(map[int]*redisInstanceInfo),

		podNodeIDToInfo: make(map[int]*podNodeInfo),

		podServiceIDToInfo: make(map[int]*podServiceInfo),

		podIDToInfo:           make(map[int]*podInfo),
		podIDToIPNetworkIDMap: make(map[int]map[IPKey]int),

		networkIDToName:           make(map[int]string),
		vinterfaceIDToLcuuid:      make(map[int]string),
		wanIPLcuuidToVInterfaceID: make(map[string]int),
		wanIPLcuuidToIP:           make(map[string]string),
		lanIPLcuuidToVInterfaceID: make(map[string]int),
		lanIPLcuuidToIP:           make(map[string]string),

		vmPodNodeConnectionLcuuidToPodNodeID: make(map[string]int),
		podNodeIDToVMID:                      make(map[int]int),

		processLcuuidToInfo: make(map[string]*processInfo),
	}
}

func (t *EventDataSet) setDeviceToIPNetworkMap(deviceType, deviceID, networkID int, ip IPKey) {
	if deviceType == common.VIF_DEVICE_TYPE_VM {
		if t.vmIDToIPNetworkIDMap[deviceID] == nil {
			t.vmIDToIPNetworkIDMap[deviceID] = make(map[IPKey]int)
		}
		t.vmIDToIPNetworkIDMap[deviceID][ip] = networkID
	} else if deviceType == common.VIF_DEVICE_TYPE_POD {
		if t.podIDToIPNetworkIDMap[deviceID] == nil {
			t.podIDToIPNetworkIDMap[deviceID] = make(map[IPKey]int)
		}
		t.podIDToIPNetworkIDMap[deviceID][ip] = networkID
	}
}

func (t *EventDataSet) DeleteDeviceToIPNetworkMapIP(deviceType, deviceID, networkID int, ip IPKey) {
	if deviceType == common.VIF_DEVICE_TYPE_VM {
		m, _ := t.vmIDToIPNetworkIDMap[deviceID]
		if m != nil {
			delete(m, ip)
		}
	} else if deviceType == common.VIF_DEVICE_TYPE_POD {
		m, _ := t.podIDToIPNetworkIDMap[deviceID]
		if m != nil {
			delete(m, ip)
		}
	}
}

func (t *EventDataSet) GetVMIPNetworkMapByID(id int) (map[IPKey]int, bool) {
	m, exists := t.vmIDToIPNetworkIDMap[id]
	if !exists {
		return make(map[IPKey]int), false
	}
	return m, true
}

func (t *EventDataSet) GetPodIPNetworkMapByID(id int) (map[IPKey]int, bool) {
	m, exists := t.podIDToIPNetworkIDMap[id]
	if !exists {
		return make(map[IPKey]int), false
	}
	return m, true
}
