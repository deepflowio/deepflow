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

package genesis

import (
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/deepflowio/deepflow/message/trident"
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/model"
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

type PrometheusMessage struct {
	msgType int
	vtapID  uint32
	peer    string
	message *trident.PrometheusAPISyncRequest
}

type KubernetesInfo struct {
	ClusterID string
	ErrorMSG  string
	Version   uint64
	Epoch     time.Time
	Entries   map[string][]string
}

type PrometheusInfo struct {
	ClusterID string
	ErrorMSG  string
	Version   uint64
	Epoch     time.Time
	Entries   []cloudmodel.PrometheusTarget
}

type GenesisSyncData struct {
	IPLastSeens []model.GenesisIP
	VIPs        []model.GenesisVIP
	VMs         []model.GenesisVM
	VPCs        []model.GenesisVpc
	Hosts       []model.GenesisHost
	Lldps       []model.GenesisLldp
	Ports       []model.GenesisPort
	Networks    []model.GenesisNetwork
	Vinterfaces []model.GenesisVinterface
	Processes   []model.GenesisProcess
}
type GenesisSyncDataOperation struct {
	IPlastseens *GenesisSyncTypeOperation[model.GenesisIP]
	VIPs        *GenesisSyncTypeOperation[model.GenesisVIP]
	VMs         *GenesisSyncTypeOperation[model.GenesisVM]
	VPCs        *GenesisSyncTypeOperation[model.GenesisVpc]
	Hosts       *GenesisSyncTypeOperation[model.GenesisHost]
	Lldps       *GenesisSyncTypeOperation[model.GenesisLldp]
	Ports       *GenesisSyncTypeOperation[model.GenesisPort]
	Networks    *GenesisSyncTypeOperation[model.GenesisNetwork]
	Vinterfaces *GenesisSyncTypeOperation[model.GenesisVinterface]
	Processes   *GenesisSyncTypeOperation[model.GenesisProcess]
}

type GenesisSyncTypeOperation[T model.GenesisVinterface | model.GenesisVpc | model.GenesisHost | model.GenesisVM | model.GenesisVIP | model.GenesisNetwork | model.GenesisPort | model.GenesisLldp | model.GenesisIP | model.GenesisProcess] struct {
	mutex    sync.Mutex
	lastSeen map[string]time.Time
	dataDict map[string]T
}

func (g *GenesisSyncTypeOperation[T]) Fetch() []T {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	data := []T{}
	for _, d := range g.dataDict {
		data = append(data, d)
	}
	return data
}

func (g *GenesisSyncTypeOperation[T]) Renew(other []T, timestamp time.Time) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	for _, data := range other {
		tData := reflect.ValueOf(&data).Elem()
		dataLcuuid := tData.FieldByName("Lcuuid").String()
		g.lastSeen[dataLcuuid] = timestamp

		dataLastTime := tData.FieldByName("LastSeen")
		if dataLastTime.IsValid() && dataLastTime.CanSet() {
			dataLastTime.Set(reflect.ValueOf(timestamp))
			g.dataDict[dataLcuuid] = data
		}
	}
}

func (g *GenesisSyncTypeOperation[T]) Update(other []T, timestamp time.Time) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	for _, data := range other {
		tData := reflect.ValueOf(&data).Elem()
		dataLcuuid := tData.FieldByName("Lcuuid").String()
		g.lastSeen[dataLcuuid] = timestamp
		g.dataDict[dataLcuuid] = data
	}
}

func (g *GenesisSyncTypeOperation[T]) Age(timestamp time.Time, timeout time.Duration) bool {
	ageTimestamp := timestamp.Add(-timeout)
	removed := false

	g.mutex.Lock()
	defer g.mutex.Unlock()

	for dataLcuuid := range g.dataDict {
		if ageTimestamp.After(g.lastSeen[dataLcuuid]) {
			removed = true
			delete(g.dataDict, dataLcuuid)
			delete(g.lastSeen, dataLcuuid)
		}
	}
	return removed
}

func (g *GenesisSyncTypeOperation[T]) Load(timestamp time.Time, timeout time.Duration) {
	ageTimestamp := timestamp.Add(-timeout)

	g.mutex.Lock()
	defer g.mutex.Unlock()

	var items []T
	mysql.Db.Where("node_ip = ?", os.Getenv(common.NODE_IP_KEY)).Find(&items)
	for _, data := range items {
		iData := reflect.ValueOf(&data).Elem()
		dataLcuuid := iData.FieldByName("Lcuuid").String()
		var lastTime time.Time
		dataTime := iData.FieldByName("LastSeen")
		if dataTime.IsValid() {
			lastTime = dataTime.Interface().(time.Time)
		} else {
			lastTime = time.Now()
		}
		if ageTimestamp.After(lastTime) {
			continue
		}
		g.dataDict[dataLcuuid] = data
		g.lastSeen[dataLcuuid] = lastTime
	}
}

func (g *GenesisSyncTypeOperation[T]) Save() {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	nodeIP := os.Getenv(common.NODE_IP_KEY)
	// delete db old data
	var dataType T
	mysql.Db.Where("node_ip = ?", nodeIP).Delete(&dataType)

	// get effective vtap ids in current controller
	var storages []model.GenesisStorage
	nodeIPString := os.Getenv(common.NODE_IP_KEY)
	mysql.Db.Where("node_ip = ?", nodeIPString).Find(&storages)
	vtapIDMap := map[uint32]int{0: 0}
	for _, storage := range storages {
		vtapIDMap[storage.VtapID] = 0
	}

	// write current memory data
	var items []T
	for _, data := range g.dataDict {
		tData := reflect.ValueOf(&data).Elem()
		vtapID := tData.FieldByName("VtapID").Uint()
		if _, ok := vtapIDMap[uint32(vtapID)]; !ok {
			continue
		}
		nodeIP := tData.FieldByName("NodeIP")
		nodeIP.SetString(nodeIPString)
		items = append(items, data)
	}

	if len(items) > 0 {
		mysql.Db.CreateInBatches(items, 100)
	}
}

func NewHostPlatformDataOperation(dataList []model.GenesisHost) *GenesisSyncTypeOperation[model.GenesisHost] {
	vMap := map[string]model.GenesisHost{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	return &GenesisSyncTypeOperation[model.GenesisHost]{
		mutex:    sync.Mutex{},
		lastSeen: map[string]time.Time{},
		dataDict: vMap,
	}
}

func NewVMPlatformDataOperation(dataList []model.GenesisVM) *GenesisSyncTypeOperation[model.GenesisVM] {
	vMap := map[string]model.GenesisVM{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	return &GenesisSyncTypeOperation[model.GenesisVM]{
		mutex:    sync.Mutex{},
		lastSeen: map[string]time.Time{},
		dataDict: vMap,
	}
}

func NewVIPPlatformDataOperation(dataList []model.GenesisVIP) *GenesisSyncTypeOperation[model.GenesisVIP] {
	vMap := map[string]model.GenesisVIP{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	return &GenesisSyncTypeOperation[model.GenesisVIP]{
		mutex:    sync.Mutex{},
		lastSeen: map[string]time.Time{},
		dataDict: vMap,
	}
}

func NewVpcPlatformDataOperation(dataList []model.GenesisVpc) *GenesisSyncTypeOperation[model.GenesisVpc] {
	vMap := map[string]model.GenesisVpc{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	return &GenesisSyncTypeOperation[model.GenesisVpc]{
		mutex:    sync.Mutex{},
		lastSeen: map[string]time.Time{},
		dataDict: vMap,
	}
}

func NewPortPlatformDataOperation(dataList []model.GenesisPort) *GenesisSyncTypeOperation[model.GenesisPort] {
	vMap := map[string]model.GenesisPort{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	return &GenesisSyncTypeOperation[model.GenesisPort]{
		mutex:    sync.Mutex{},
		lastSeen: map[string]time.Time{},
		dataDict: vMap,
	}
}

func NewNetworkPlatformDataOperation(dataList []model.GenesisNetwork) *GenesisSyncTypeOperation[model.GenesisNetwork] {
	vMap := map[string]model.GenesisNetwork{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	return &GenesisSyncTypeOperation[model.GenesisNetwork]{
		mutex:    sync.Mutex{},
		lastSeen: map[string]time.Time{},
		dataDict: vMap,
	}
}

func NewVinterfacePlatformDataOperation(dataList []model.GenesisVinterface) *GenesisSyncTypeOperation[model.GenesisVinterface] {
	vMap := map[string]model.GenesisVinterface{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	return &GenesisSyncTypeOperation[model.GenesisVinterface]{
		mutex:    sync.Mutex{},
		lastSeen: map[string]time.Time{},
		dataDict: vMap,
	}
}

func NewIPLastSeenPlatformDataOperation(dataList []model.GenesisIP) *GenesisSyncTypeOperation[model.GenesisIP] {
	vMap := map[string]model.GenesisIP{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	return &GenesisSyncTypeOperation[model.GenesisIP]{
		mutex:    sync.Mutex{},
		lastSeen: map[string]time.Time{},
		dataDict: vMap,
	}
}

func NewLldpInfoPlatformDataOperation(dataList []model.GenesisLldp) *GenesisSyncTypeOperation[model.GenesisLldp] {
	vMap := map[string]model.GenesisLldp{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	return &GenesisSyncTypeOperation[model.GenesisLldp]{
		mutex:    sync.Mutex{},
		lastSeen: map[string]time.Time{},
		dataDict: vMap,
	}
}

func NewProcessPlatformDataOperation(dataList []model.GenesisProcess) *GenesisSyncTypeOperation[model.GenesisProcess] {
	vMap := map[string]model.GenesisProcess{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	return &GenesisSyncTypeOperation[model.GenesisProcess]{
		mutex:    sync.Mutex{},
		lastSeen: map[string]time.Time{},
		dataDict: vMap,
	}
}
