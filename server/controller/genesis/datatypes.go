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

package genesis

import (
	"reflect"
	"sync"
	"time"

	"github.com/deepflowys/deepflow/message/trident"
	cloudmodel "github.com/deepflowys/deepflow/server/controller/cloud/model"
	"github.com/deepflowys/deepflow/server/controller/model"
)

type VIFRPCMessage struct {
	msgType      int
	vtapID       uint32
	peer         string
	k8sClusterID string
	message      *trident.GenesisSyncRequest
}

type K8SRPCMessage struct {
	msgType int
	vtapID  uint32
	peer    string
	message *trident.KubernetesAPISyncRequest
}

type KubernetesResponse struct {
	ClusterID string
	ErrorMSG  string
	SyncedAt  time.Time
	Resources map[string][]string
}

type KubernetesInfo struct {
	ClusterID string
	ErrorMSG  string
	Version   uint64
	VtapID    uint32
	Epoch     time.Time
	Entries   []*trident.KubernetesAPIInfo
}

type PlatformData struct {
	IPs         []cloudmodel.IP
	Subnets     []cloudmodel.Subnet
	IPlastseens *PlatformDataOperation[model.GenesisIP]
	VMs         *PlatformDataOperation[model.GenesisVM]
	VPCs        *PlatformDataOperation[model.GenesisVpc]
	Hosts       *PlatformDataOperation[model.GenesisHost]
	Lldps       *PlatformDataOperation[model.GenesisLldp]
	Ports       *PlatformDataOperation[model.GenesisPort]
	Networks    *PlatformDataOperation[model.GenesisNetwork]
	Vinterfaces *PlatformDataOperation[model.GenesisVinterface]
}

type PlatformDataOperation[T model.GenesisVinterface | model.GenesisVpc | model.GenesisHost | model.GenesisVM | model.GenesisNetwork | model.GenesisPort | model.GenesisLldp | model.GenesisIP] struct {
	mutex    sync.Mutex
	lastSeen map[string]time.Time
	dataDict map[string]T
}

func (p *PlatformDataOperation[T]) Fetch() []T {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	data := []T{}
	for _, d := range p.dataDict {
		data = append(data, d)
	}
	return data
}

func (p *PlatformDataOperation[T]) Renew(other []T, timestamp time.Time) {
	for _, data := range other {
		tData := reflect.ValueOf(data)
		dataLcuuid := tData.FieldByName("Lcuuid").String()
		p.lastSeen[dataLcuuid] = timestamp
	}
}

func (p *PlatformDataOperation[T]) Update(other []T, timestamp time.Time) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, data := range other {
		tData := reflect.ValueOf(data)
		dataLcuuid := tData.FieldByName("Lcuuid").String()
		p.lastSeen[dataLcuuid] = timestamp
		p.dataDict[dataLcuuid] = data
	}
}

func (p *PlatformDataOperation[T]) Age(timestamp time.Time, timeout time.Duration) bool {
	ageTimestamp := timestamp.Add(-timeout)
	removed := false

	p.mutex.Lock()
	defer p.mutex.Unlock()

	for dataLcuuid := range p.dataDict {
		if ageTimestamp.After(p.lastSeen[dataLcuuid]) {
			removed = true
			delete(p.dataDict, dataLcuuid)
			delete(p.lastSeen, dataLcuuid)
		}
	}
	return removed
}

func NewHostPlatformDataOperation(dataList []model.GenesisHost) *PlatformDataOperation[model.GenesisHost] {
	vMap := map[string]model.GenesisHost{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	return &PlatformDataOperation[model.GenesisHost]{
		mutex:    sync.Mutex{},
		lastSeen: map[string]time.Time{},
		dataDict: vMap,
	}
}

func NewVMPlatformDataOperation(dataList []model.GenesisVM) *PlatformDataOperation[model.GenesisVM] {
	vMap := map[string]model.GenesisVM{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	return &PlatformDataOperation[model.GenesisVM]{
		mutex:    sync.Mutex{},
		lastSeen: map[string]time.Time{},
		dataDict: vMap,
	}
}

func NewVpcPlatformDataOperation(dataList []model.GenesisVpc) *PlatformDataOperation[model.GenesisVpc] {
	vMap := map[string]model.GenesisVpc{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	return &PlatformDataOperation[model.GenesisVpc]{
		mutex:    sync.Mutex{},
		lastSeen: map[string]time.Time{},
		dataDict: vMap,
	}
}

func NewPortPlatformDataOperation(dataList []model.GenesisPort) *PlatformDataOperation[model.GenesisPort] {
	vMap := map[string]model.GenesisPort{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	return &PlatformDataOperation[model.GenesisPort]{
		mutex:    sync.Mutex{},
		lastSeen: map[string]time.Time{},
		dataDict: vMap,
	}
}

func NewNetworkPlatformDataOperation(dataList []model.GenesisNetwork) *PlatformDataOperation[model.GenesisNetwork] {
	vMap := map[string]model.GenesisNetwork{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	return &PlatformDataOperation[model.GenesisNetwork]{
		mutex:    sync.Mutex{},
		lastSeen: map[string]time.Time{},
		dataDict: vMap,
	}
}

func NewVinterfacePlatformDataOperation(dataList []model.GenesisVinterface) *PlatformDataOperation[model.GenesisVinterface] {
	vMap := map[string]model.GenesisVinterface{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	return &PlatformDataOperation[model.GenesisVinterface]{
		mutex:    sync.Mutex{},
		lastSeen: map[string]time.Time{},
		dataDict: vMap,
	}
}

func NewIPLastSeenPlatformDataOperation(dataList []model.GenesisIP) *PlatformDataOperation[model.GenesisIP] {
	vMap := map[string]model.GenesisIP{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	return &PlatformDataOperation[model.GenesisIP]{
		mutex:    sync.Mutex{},
		lastSeen: map[string]time.Time{},
		dataDict: vMap,
	}
}

func NewLldpInfoPlatformDataOperation(dataList []model.GenesisLldp) *PlatformDataOperation[model.GenesisLldp] {
	vMap := map[string]model.GenesisLldp{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	return &PlatformDataOperation[model.GenesisLldp]{
		mutex:    sync.Mutex{},
		lastSeen: map[string]time.Time{},
		dataDict: vMap,
	}
}
