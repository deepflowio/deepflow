/*
 * Copyright (c) 2023 Yunshan Networks
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
	"fmt"
	"os"
	"reflect"
	"sync"
	"time"

	messagecommon "github.com/deepflowio/deepflow/message/common"
	"github.com/deepflowio/deepflow/message/trident"
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/model"
)

type VIFRPCMessage struct {
	msgType        int
	vtapID         uint32
	peer           string
	k8sClusterID   string
	storageRefresh bool
	message        *trident.GenesisSyncRequest
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
	Entries   []*messagecommon.KubernetesAPIInfo
}

type PrometheusInfo struct {
	ClusterID string
	ErrorMSG  string
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
	mutex     sync.Mutex
	lastSeen  map[string]time.Time
	dataDict  map[string]T
	dataDict2 map[uint32][]T
}

func (g *GenesisSyncTypeOperation[T]) Fetch() []T {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	data := []T{}
	for _, d := range g.dataDict {
		data = append(data, d)
	}

	for _, d := range g.dataDict2 {
		data = append(data, d...)
	}
	return data
}

func (g *GenesisSyncTypeOperation[T]) Renew(vtapID uint32, other []T, timestamp time.Time) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if vtapID != 0 {
		g.lastSeen[fmt.Sprintf("%d", vtapID)] = timestamp
		g.dataDict2[vtapID] = other
		return
	}

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

func (g *GenesisSyncTypeOperation[T]) Update(vtapID uint32, other []T, timestamp time.Time) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if vtapID != 0 {
		g.lastSeen[fmt.Sprintf("%d", vtapID)] = timestamp
		g.dataDict2[vtapID] = other
		return
	}

	for _, data := range other {
		tData := reflect.ValueOf(&data).Elem()
		dataLcuuid := tData.FieldByName("Lcuuid").String()
		g.lastSeen[dataLcuuid] = timestamp
		g.dataDict[dataLcuuid] = data
	}
}

func (g *GenesisSyncTypeOperation[T]) Age(timestamp time.Time, timeout time.Duration) bool {
	ageTimestamp := timestamp.Add(-timeout)
	var removed bool

	g.mutex.Lock()
	defer g.mutex.Unlock()

	for dataLcuuid := range g.dataDict {
		if ageTimestamp.After(g.lastSeen[dataLcuuid]) {
			removed = true
			delete(g.dataDict, dataLcuuid)
			delete(g.lastSeen, dataLcuuid)
		}
	}

	for vtapID := range g.dataDict2 {
		key := fmt.Sprintf("%d", vtapID)
		if ageTimestamp.After(g.lastSeen[key]) {
			removed = true
			delete(g.dataDict2, vtapID)
			delete(g.lastSeen, key)
		}
	}
	return removed
}

func (g *GenesisSyncTypeOperation[T]) Load(timestamp time.Time, timeout time.Duration) {
	ageTimestamp := timestamp.Add(-timeout)

	g.mutex.Lock()
	defer g.mutex.Unlock()

	var items []T
	err := mysql.Db.Where("node_ip = ? and vtap_id <> 0", os.Getenv(common.NODE_IP_KEY)).Find(&items).Error
	if err != nil {
		log.Warningf("load genesis sync type data failed: %s", err.Error())
		return
	}
	for _, data := range items {
		iData := reflect.ValueOf(&data).Elem()

		lastTime := time.Now()
		dataTime := iData.FieldByName("LastSeen")
		if dataTime.IsValid() {
			lastTime = dataTime.Interface().(time.Time)
		}
		if ageTimestamp.After(lastTime) {
			continue
		}

		vtapID := iData.FieldByName("VtapID").Uint()
		g.lastSeen[fmt.Sprintf("%d", vtapID)] = lastTime
		g.dataDict2[uint32(vtapID)] = append(g.dataDict2[uint32(vtapID)], data)
	}
}

func (g *GenesisSyncTypeOperation[T]) Save() {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	nodeIP := os.Getenv(common.NODE_IP_KEY)
	// delete db old data
	var dataType T
	err := mysql.Db.Where("node_ip = ?", nodeIP).Delete(&dataType).Error
	if err != nil {
		log.Warningf("delete genesis sync type data failed: %s", err.Error())
		return
	}

	// get effective vtap ids in current controller
	var storages []model.GenesisStorage
	err = mysql.Db.Where("node_ip = ?", nodeIP).Find(&storages).Error
	if err != nil {
		log.Warningf("get genesis storage data failed: %s", err.Error())
		return
	}
	vtapIDMap := map[uint32]int{0: 0}
	for _, storage := range storages {
		vtapIDMap[storage.VtapID] = 0
	}

	// write current memory data
	var items []T
	for vtapID, data := range g.dataDict2 {
		if _, ok := vtapIDMap[vtapID]; !ok {
			continue
		}
		items = append(items, data...)
	}

	if len(items) > 0 {
		err = mysql.Db.CreateInBatches(items, 100).Error
		if err != nil {
			log.Warningf("save genesis sync type data failed: %s", err.Error())
			return
		}
	}
}

func NewHostPlatformDataOperation(dataList []model.GenesisHost) *GenesisSyncTypeOperation[model.GenesisHost] {
	return &GenesisSyncTypeOperation[model.GenesisHost]{
		mutex:     sync.Mutex{},
		lastSeen:  map[string]time.Time{},
		dataDict:  map[string]model.GenesisHost{},
		dataDict2: map[uint32][]model.GenesisHost{},
	}
}

func NewVMPlatformDataOperation(dataList []model.GenesisVM) *GenesisSyncTypeOperation[model.GenesisVM] {
	return &GenesisSyncTypeOperation[model.GenesisVM]{
		mutex:     sync.Mutex{},
		lastSeen:  map[string]time.Time{},
		dataDict:  map[string]model.GenesisVM{},
		dataDict2: map[uint32][]model.GenesisVM{},
	}
}

func NewVIPPlatformDataOperation(dataList []model.GenesisVIP) *GenesisSyncTypeOperation[model.GenesisVIP] {
	return &GenesisSyncTypeOperation[model.GenesisVIP]{
		mutex:     sync.Mutex{},
		lastSeen:  map[string]time.Time{},
		dataDict:  map[string]model.GenesisVIP{},
		dataDict2: map[uint32][]model.GenesisVIP{},
	}
}

func NewVpcPlatformDataOperation(dataList []model.GenesisVpc) *GenesisSyncTypeOperation[model.GenesisVpc] {
	return &GenesisSyncTypeOperation[model.GenesisVpc]{
		mutex:     sync.Mutex{},
		lastSeen:  map[string]time.Time{},
		dataDict:  map[string]model.GenesisVpc{},
		dataDict2: map[uint32][]model.GenesisVpc{},
	}
}

func NewPortPlatformDataOperation(dataList []model.GenesisPort) *GenesisSyncTypeOperation[model.GenesisPort] {
	return &GenesisSyncTypeOperation[model.GenesisPort]{
		mutex:     sync.Mutex{},
		lastSeen:  map[string]time.Time{},
		dataDict:  map[string]model.GenesisPort{},
		dataDict2: map[uint32][]model.GenesisPort{},
	}
}

func NewNetworkPlatformDataOperation(dataList []model.GenesisNetwork) *GenesisSyncTypeOperation[model.GenesisNetwork] {
	return &GenesisSyncTypeOperation[model.GenesisNetwork]{
		mutex:     sync.Mutex{},
		lastSeen:  map[string]time.Time{},
		dataDict:  map[string]model.GenesisNetwork{},
		dataDict2: map[uint32][]model.GenesisNetwork{},
	}
}

func NewVinterfacePlatformDataOperation(dataList []model.GenesisVinterface) *GenesisSyncTypeOperation[model.GenesisVinterface] {
	return &GenesisSyncTypeOperation[model.GenesisVinterface]{
		mutex:     sync.Mutex{},
		lastSeen:  map[string]time.Time{},
		dataDict:  map[string]model.GenesisVinterface{},
		dataDict2: map[uint32][]model.GenesisVinterface{},
	}
}

func NewIPLastSeenPlatformDataOperation(dataList []model.GenesisIP) *GenesisSyncTypeOperation[model.GenesisIP] {
	return &GenesisSyncTypeOperation[model.GenesisIP]{
		mutex:     sync.Mutex{},
		lastSeen:  map[string]time.Time{},
		dataDict:  map[string]model.GenesisIP{},
		dataDict2: map[uint32][]model.GenesisIP{},
	}
}

func NewLldpInfoPlatformDataOperation(dataList []model.GenesisLldp) *GenesisSyncTypeOperation[model.GenesisLldp] {
	return &GenesisSyncTypeOperation[model.GenesisLldp]{
		mutex:     sync.Mutex{},
		lastSeen:  map[string]time.Time{},
		dataDict:  map[string]model.GenesisLldp{},
		dataDict2: map[uint32][]model.GenesisLldp{},
	}
}

func NewProcessPlatformDataOperation(dataList []model.GenesisProcess) *GenesisSyncTypeOperation[model.GenesisProcess] {
	return &GenesisSyncTypeOperation[model.GenesisProcess]{
		mutex:     sync.Mutex{},
		lastSeen:  map[string]time.Time{},
		dataDict:  map[string]model.GenesisProcess{},
		dataDict2: map[uint32][]model.GenesisProcess{},
	}
}
