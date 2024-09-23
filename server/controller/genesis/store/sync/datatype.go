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

package sync

import (
	"os"
	"reflect"
	"sync"
	"time"

	ccommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/genesis/common"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

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

type GenesisSyncTypeOperation[T common.GenesisSyncType] struct {
	mutex     sync.Mutex
	lastSeen  map[int]map[string]time.Time
	dataStore map[int]map[string]T
}

func (g *GenesisSyncTypeOperation[T]) Fetch() map[int][]T {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	result := map[int][]T{}
	for orgID, dataMap := range g.dataStore {
		data := []T{}
		for _, d := range dataMap {
			data = append(data, d)
		}
		result[orgID] = data
	}

	return result
}

func (g *GenesisSyncTypeOperation[T]) Renew(orgID int, timestamp time.Time, items []T) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	for _, item := range items {
		tData := reflect.ValueOf(&item).Elem()
		itemLcuuid := tData.FieldByName("Lcuuid").String()
		if oLastSeen, ok := g.lastSeen[orgID]; ok {
			oLastSeen[itemLcuuid] = timestamp
		}

		dataLastTime := tData.FieldByName("LastSeen")
		if dataLastTime.IsValid() && dataLastTime.CanSet() {
			dataLastTime.Set(reflect.ValueOf(timestamp))
			if odataStore, ok := g.dataStore[orgID]; ok {
				odataStore[itemLcuuid] = item
			}
		}
	}
}

func (g *GenesisSyncTypeOperation[T]) Update(orgID int, timestamp time.Time, items []T) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	for _, item := range items {
		tData := reflect.ValueOf(&item).Elem()
		itemLcuuid := tData.FieldByName("Lcuuid").String()
		if oLastSeen, ok := g.lastSeen[orgID]; ok {
			oLastSeen[itemLcuuid] = timestamp
		} else {
			g.lastSeen[orgID] = map[string]time.Time{itemLcuuid: timestamp}
		}
		if odataStore, ok := g.dataStore[orgID]; ok {
			odataStore[itemLcuuid] = item
		} else {
			g.dataStore[orgID] = map[string]T{itemLcuuid: item}
		}
	}
}

func (g *GenesisSyncTypeOperation[T]) Age(timestamp time.Time, timeout time.Duration) bool {
	ageTimestamp := timestamp.Add(-timeout)
	removed := false

	g.mutex.Lock()
	defer g.mutex.Unlock()
	for orgID := range g.dataStore {
		for dataLcuuid := range g.dataStore[orgID] {
			if ageTimestamp.After(g.lastSeen[orgID][dataLcuuid]) {
				removed = true
				delete(g.dataStore[orgID], dataLcuuid)
				delete(g.lastSeen[orgID], dataLcuuid)
			}
		}
	}

	return removed
}

func (g *GenesisSyncTypeOperation[T]) Load(timestamp time.Time, timeout time.Duration) {
	ageTimestamp := timestamp.Add(-timeout)

	g.mutex.Lock()
	defer g.mutex.Unlock()

	var items []T
	orgIDs, err := mysql.GetORGIDs()
	if err != nil {
		log.Error("get org ids failed")
		return
	}
	nodeIP := os.Getenv(ccommon.NODE_IP_KEY)
	for _, orgID := range orgIDs {
		db, err := mysql.GetDB(orgID)
		if err != nil {
			log.Error("get mysql session failed", logger.NewORGPrefix(orgID))
			continue
		}
		db.Where("node_ip = ?", nodeIP).Find(&items)
		dataStore := map[string]T{}
		lastSeen := map[string]time.Time{}
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
			dataStore[dataLcuuid] = data
			lastSeen[dataLcuuid] = lastTime
		}
		g.dataStore[db.ORGID] = dataStore
		g.lastSeen[db.ORGID] = lastSeen
	}

}

func (g *GenesisSyncTypeOperation[T]) Save() {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	nIP := os.Getenv(ccommon.NODE_IP_KEY)
	for orgID, dataMaps := range g.dataStore {
		db, err := mysql.GetDB(orgID)
		if err != nil {
			log.Error("get mysql session failed", logger.NewORGPrefix(orgID))
			continue
		}

		// delete db old data
		var dataType T
		db.Where("node_ip = ?", nIP).Delete(&dataType)

		// get effective vtap ids in current controller
		var storages []model.GenesisStorage
		db.Where("node_ip = ?", nIP).Find(&storages)
		vtapIDMap := map[uint32]int{0: 0}
		for _, storage := range storages {
			vtapIDMap[storage.VtapID] = 0
		}

		// write current memory data
		var items []T
		for _, data := range dataMaps {
			tData := reflect.ValueOf(&data).Elem()
			vtapID := tData.FieldByName("VtapID").Uint()
			if _, ok := vtapIDMap[uint32(vtapID)]; !ok {
				continue
			}
			items = append(items, data)
		}

		if len(items) > 0 {
			db.CreateInBatches(items, 100)
		}
	}

}

func NewHostPlatformDataOperation(orgID int, dataList []model.GenesisHost) *GenesisSyncTypeOperation[model.GenesisHost] {
	lastSeen := map[int]map[string]time.Time{}
	tMap := map[string]time.Time{}
	lastSeen[orgID] = tMap
	dataStore := map[int]map[string]model.GenesisHost{}
	vMap := map[string]model.GenesisHost{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	dataStore[orgID] = vMap
	return &GenesisSyncTypeOperation[model.GenesisHost]{
		mutex:     sync.Mutex{},
		lastSeen:  lastSeen,
		dataStore: dataStore,
	}
}

func NewVMPlatformDataOperation(orgID int, dataList []model.GenesisVM) *GenesisSyncTypeOperation[model.GenesisVM] {
	lastSeen := map[int]map[string]time.Time{}
	tMap := map[string]time.Time{}
	lastSeen[orgID] = tMap
	dataStore := map[int]map[string]model.GenesisVM{}
	vMap := map[string]model.GenesisVM{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	dataStore[orgID] = vMap
	return &GenesisSyncTypeOperation[model.GenesisVM]{
		mutex:     sync.Mutex{},
		lastSeen:  lastSeen,
		dataStore: dataStore,
	}
}

func NewVIPPlatformDataOperation(orgID int, dataList []model.GenesisVIP) *GenesisSyncTypeOperation[model.GenesisVIP] {
	lastSeen := map[int]map[string]time.Time{}
	tMap := map[string]time.Time{}
	lastSeen[orgID] = tMap
	dataStore := map[int]map[string]model.GenesisVIP{}
	vMap := map[string]model.GenesisVIP{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	dataStore[orgID] = vMap
	return &GenesisSyncTypeOperation[model.GenesisVIP]{
		mutex:     sync.Mutex{},
		lastSeen:  lastSeen,
		dataStore: dataStore,
	}
}

func NewVpcPlatformDataOperation(orgID int, dataList []model.GenesisVpc) *GenesisSyncTypeOperation[model.GenesisVpc] {
	lastSeen := map[int]map[string]time.Time{}
	tMap := map[string]time.Time{}
	lastSeen[orgID] = tMap
	dataStore := map[int]map[string]model.GenesisVpc{}
	vMap := map[string]model.GenesisVpc{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	dataStore[orgID] = vMap
	return &GenesisSyncTypeOperation[model.GenesisVpc]{
		mutex:     sync.Mutex{},
		lastSeen:  lastSeen,
		dataStore: dataStore,
	}
}

func NewPortPlatformDataOperation(orgID int, dataList []model.GenesisPort) *GenesisSyncTypeOperation[model.GenesisPort] {
	lastSeen := map[int]map[string]time.Time{}
	tMap := map[string]time.Time{}
	lastSeen[orgID] = tMap
	dataStore := map[int]map[string]model.GenesisPort{}
	vMap := map[string]model.GenesisPort{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	dataStore[orgID] = vMap
	return &GenesisSyncTypeOperation[model.GenesisPort]{
		mutex:     sync.Mutex{},
		lastSeen:  lastSeen,
		dataStore: dataStore,
	}
}

func NewNetworkPlatformDataOperation(orgID int, dataList []model.GenesisNetwork) *GenesisSyncTypeOperation[model.GenesisNetwork] {
	lastSeen := map[int]map[string]time.Time{}
	tMap := map[string]time.Time{}
	lastSeen[orgID] = tMap
	dataStore := map[int]map[string]model.GenesisNetwork{}
	vMap := map[string]model.GenesisNetwork{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	dataStore[orgID] = vMap
	return &GenesisSyncTypeOperation[model.GenesisNetwork]{
		mutex:     sync.Mutex{},
		lastSeen:  lastSeen,
		dataStore: dataStore,
	}
}

func NewVinterfacePlatformDataOperation(orgID int, dataList []model.GenesisVinterface) *GenesisSyncTypeOperation[model.GenesisVinterface] {
	lastSeen := map[int]map[string]time.Time{}
	tMap := map[string]time.Time{}
	lastSeen[orgID] = tMap
	dataStore := map[int]map[string]model.GenesisVinterface{}
	vMap := map[string]model.GenesisVinterface{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	dataStore[orgID] = vMap
	return &GenesisSyncTypeOperation[model.GenesisVinterface]{
		mutex:     sync.Mutex{},
		lastSeen:  lastSeen,
		dataStore: dataStore,
	}
}

func NewIPLastSeenPlatformDataOperation(orgID int, dataList []model.GenesisIP) *GenesisSyncTypeOperation[model.GenesisIP] {
	lastSeen := map[int]map[string]time.Time{}
	tMap := map[string]time.Time{}
	lastSeen[orgID] = tMap
	dataStore := map[int]map[string]model.GenesisIP{}
	vMap := map[string]model.GenesisIP{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	dataStore[orgID] = vMap
	return &GenesisSyncTypeOperation[model.GenesisIP]{
		mutex:     sync.Mutex{},
		lastSeen:  lastSeen,
		dataStore: dataStore,
	}
}

func NewLldpInfoPlatformDataOperation(orgID int, dataList []model.GenesisLldp) *GenesisSyncTypeOperation[model.GenesisLldp] {
	lastSeen := map[int]map[string]time.Time{}
	tMap := map[string]time.Time{}
	lastSeen[orgID] = tMap
	dataStore := map[int]map[string]model.GenesisLldp{}
	vMap := map[string]model.GenesisLldp{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	dataStore[orgID] = vMap
	return &GenesisSyncTypeOperation[model.GenesisLldp]{
		mutex:     sync.Mutex{},
		lastSeen:  lastSeen,
		dataStore: dataStore,
	}
}

func NewProcessPlatformDataOperation(orgID int, dataList []model.GenesisProcess) *GenesisSyncTypeOperation[model.GenesisProcess] {
	lastSeen := map[int]map[string]time.Time{}
	tMap := map[string]time.Time{}
	lastSeen[orgID] = tMap
	dataStore := map[int]map[string]model.GenesisProcess{}
	vMap := map[string]model.GenesisProcess{}
	for _, data := range dataList {
		vMap[data.Lcuuid] = data
	}
	dataStore[orgID] = vMap
	return &GenesisSyncTypeOperation[model.GenesisProcess]{
		mutex:     sync.Mutex{},
		lastSeen:  lastSeen,
		dataStore: dataStore,
	}
}
