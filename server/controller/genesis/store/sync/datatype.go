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
	"fmt"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	mmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/genesis/common"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

type GenesisSyncDataOperation struct {
	IPlastseens *GenesisSyncTypeOperation[model.GenesisIP]
	VIPs        *GenesisSyncTypeOperation[model.GenesisVIP]
	VMs         *GenesisSyncTypeOperation[model.GenesisVM]
	VPCs        *GenesisSyncTypeOperation[model.GenesisVPC]
	Hosts       *GenesisSyncTypeOperation[model.GenesisHost]
	Lldps       *GenesisSyncTypeOperation[model.GenesisLldp]
	Ports       *GenesisSyncTypeOperation[model.GenesisPort]
	Networks    *GenesisSyncTypeOperation[model.GenesisNetwork]
	Vinterfaces *GenesisSyncTypeOperation[model.GenesisVinterface]
	Processes   *GenesisSyncTypeOperation[model.GenesisProcess]
}

type GenesisSyncTypeOperation[T common.GenesisSyncType] struct {
	mutex      sync.Mutex
	lastSeen   map[int]map[string]time.Time
	dataStore  map[int]map[string]T
	dataStore2 map[int]map[string][]T
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
	for orgID, dataMap := range g.dataStore2 {
		for _, d := range dataMap {
			result[orgID] = append(result[orgID], d...)
		}
	}

	return result
}

func (g *GenesisSyncTypeOperation[T]) Renew(orgID int, key string, timestamp time.Time, items []T) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if key == "" {
		for _, item := range items {
			if oLastSeen, ok := g.lastSeen[orgID]; ok {
				oLastSeen[item.GetLcuuid()] = timestamp
			}
		}
	} else {
		g.lastSeen[orgID][key] = timestamp
		g.dataStore2[orgID][key] = items
	}
}

func (g *GenesisSyncTypeOperation[T]) Update(orgID int, key string, timestamp time.Time, items []T) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if key == "" {
		for _, item := range items {
			itemLcuuid := item.GetLcuuid()
			if oLastSeen, ok := g.lastSeen[orgID]; ok {
				oLastSeen[itemLcuuid] = timestamp
			} else {
				g.lastSeen[orgID] = map[string]time.Time{itemLcuuid: timestamp}
			}
			if _, ok := g.dataStore[orgID]; ok {
				g.dataStore[orgID][itemLcuuid] = item
			} else {
				g.dataStore[orgID] = map[string]T{itemLcuuid: item}
			}
		}
	} else {
		if _, ok := g.lastSeen[orgID]; ok {
			g.lastSeen[orgID][key] = timestamp
		} else {
			g.lastSeen[orgID] = map[string]time.Time{key: timestamp}
		}
		if _, ok := g.dataStore2[orgID]; ok {
			g.dataStore2[orgID][key] = items
		} else {
			g.dataStore2[orgID] = map[string][]T{key: items}
		}
	}
}

func (g *GenesisSyncTypeOperation[T]) Age(timestamp time.Time, timeout time.Duration) bool {
	var removed bool
	ageTimestamp := timestamp.Add(-timeout)

	g.mutex.Lock()
	defer g.mutex.Unlock()
	for orgID, dataMap := range g.dataStore {
		for dataLcuuid := range dataMap {
			lastSeenMap, ok := g.lastSeen[orgID]
			if !ok || lastSeenMap == nil {
				continue
			}
			lastSeenTime, exists := lastSeenMap[dataLcuuid]
			if !exists {
				continue
			}
			if !ageTimestamp.After(lastSeenTime) {
				continue
			}
			removed = true
			delete(g.dataStore[orgID], dataLcuuid)
			delete(g.lastSeen[orgID], dataLcuuid)
		}
	}

	for orgID, dataMap := range g.dataStore2 {
		for key := range dataMap {
			if ageTimestamp.After(g.lastSeen[orgID][key]) {
				removed = true
				delete(g.dataStore2[orgID], key)
				delete(g.lastSeen[orgID], key)
			}
		}
	}

	return removed
}

func (g *GenesisSyncTypeOperation[T]) Load(nodeIP string) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	for _, db := range mysql.GetDBs().All() {
		storages := []model.GenesisStorage{}
		err := db.Where("node_ip = ?", nodeIP).Find(&storages).Error
		if err != nil {
			log.Errorf("get node (%s) storage failed:%s", nodeIP, err.Error(), logger.NewORGPrefix(db.ORGID))
			continue
		}
		lastSeen := map[string]time.Time{}
		dataStore2 := map[string][]T{}
		for _, storage := range storages {
			var items []T
			err = db.Where("node_ip = ?", nodeIP).Where("vtap_id = ?", storage.VtapID).Find(&items).Error
			if err != nil {
				log.Errorf("get vtap (%d) data failed:%s", storage.VtapID, err.Error(), logger.NewORGPrefix(db.ORGID))
				continue
			}
			var vtap mmodel.VTap
			err = db.Where("id = ?", storage.VtapID).First(&vtap).Error
			if err != nil {
				log.Errorf("get vtap (%d) failed:%s", storage.VtapID, err.Error(), logger.NewORGPrefix(db.ORGID))
				continue
			}
			key := fmt.Sprintf("%s-%s", vtap.CtrlIP, vtap.CtrlMac)
			lastSeen[key] = time.Now()
			dataStore2[key] = items
		}
		g.lastSeen[db.ORGID] = lastSeen
		g.dataStore2[db.ORGID] = dataStore2
	}

}

func (g *GenesisSyncTypeOperation[T]) Save(nodeIP string) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	for _, db := range mysql.GetDBs().All() {
		// get effective vtap ids in current controller
		var storages []model.GenesisStorage
		err := db.Where("node_ip = ?", nodeIP).Find(&storages).Error
		if err != nil {
			log.Errorf("get node (%s) storage data failed: %s", nodeIP, err.Error(), logger.NewORGPrefix(db.ORGID))
			continue
		}

		// current memory data
		var items []T
		vtapIDMap := map[uint32]int{0: 0}
		dataMap := g.dataStore2[db.ORGID]
		for _, storage := range storages {
			vtapIDMap[storage.VtapID] = 0
			if len(dataMap) == 0 {
				log.Debugf("not found org (%d) data of dataStroe2", db.ORGID)
				continue
			}
			var vtap mmodel.VTap
			err = db.Where("id = ?", storage.VtapID).First(&vtap).Error
			if err != nil {
				log.Warningf("get vtap id (%d) failed: %s", storage.VtapID, err.Error(), logger.NewORGPrefix(db.ORGID))
				continue
			}
			data, ok := dataMap[fmt.Sprintf("%s-%s", vtap.CtrlIP, vtap.CtrlMac)]
			if !ok {
				log.Debugf("not found vtap id (%d) data of dataStore2", storage.VtapID)
				continue
			}
			items = append(items, data...)
		}

		for _, data := range g.dataStore[db.ORGID] {
			if _, ok := vtapIDMap[data.GetVtapID()]; !ok {
				continue
			}
			items = append(items, data)
		}

		err = db.Transaction(func(tx *gorm.DB) error {
			// delete old data
			var dataType T
			if err := tx.Where("node_ip = ?", nodeIP).Delete(&dataType).Error; err != nil {
				return err
			}
			// create new data
			if len(items) > 0 {
				if err := tx.CreateInBatches(items, 100).Error; err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			log.Errorf("save data failed: %s", err.Error(), logger.NewORGPrefix(db.ORGID))
			continue
		}
	}
}

func NewHostPlatformDataOperation() *GenesisSyncTypeOperation[model.GenesisHost] {
	return &GenesisSyncTypeOperation[model.GenesisHost]{
		mutex:      sync.Mutex{},
		lastSeen:   map[int]map[string]time.Time{},
		dataStore:  map[int]map[string]model.GenesisHost{},
		dataStore2: map[int]map[string][]model.GenesisHost{},
	}
}

func NewVMPlatformDataOperation() *GenesisSyncTypeOperation[model.GenesisVM] {
	return &GenesisSyncTypeOperation[model.GenesisVM]{
		mutex:      sync.Mutex{},
		lastSeen:   map[int]map[string]time.Time{},
		dataStore:  map[int]map[string]model.GenesisVM{},
		dataStore2: map[int]map[string][]model.GenesisVM{},
	}
}

func NewVIPPlatformDataOperation() *GenesisSyncTypeOperation[model.GenesisVIP] {
	return &GenesisSyncTypeOperation[model.GenesisVIP]{
		mutex:      sync.Mutex{},
		lastSeen:   map[int]map[string]time.Time{},
		dataStore:  map[int]map[string]model.GenesisVIP{},
		dataStore2: map[int]map[string][]model.GenesisVIP{},
	}
}

func NewVpcPlatformDataOperation() *GenesisSyncTypeOperation[model.GenesisVPC] {
	return &GenesisSyncTypeOperation[model.GenesisVPC]{
		mutex:      sync.Mutex{},
		lastSeen:   map[int]map[string]time.Time{},
		dataStore:  map[int]map[string]model.GenesisVPC{},
		dataStore2: map[int]map[string][]model.GenesisVPC{},
	}
}

func NewPortPlatformDataOperation() *GenesisSyncTypeOperation[model.GenesisPort] {
	return &GenesisSyncTypeOperation[model.GenesisPort]{
		mutex:      sync.Mutex{},
		lastSeen:   map[int]map[string]time.Time{},
		dataStore:  map[int]map[string]model.GenesisPort{},
		dataStore2: map[int]map[string][]model.GenesisPort{},
	}
}

func NewNetworkPlatformDataOperation() *GenesisSyncTypeOperation[model.GenesisNetwork] {
	return &GenesisSyncTypeOperation[model.GenesisNetwork]{
		mutex:      sync.Mutex{},
		lastSeen:   map[int]map[string]time.Time{},
		dataStore:  map[int]map[string]model.GenesisNetwork{},
		dataStore2: map[int]map[string][]model.GenesisNetwork{},
	}
}

func NewVinterfacePlatformDataOperation() *GenesisSyncTypeOperation[model.GenesisVinterface] {
	return &GenesisSyncTypeOperation[model.GenesisVinterface]{
		mutex:      sync.Mutex{},
		lastSeen:   map[int]map[string]time.Time{},
		dataStore:  map[int]map[string]model.GenesisVinterface{},
		dataStore2: map[int]map[string][]model.GenesisVinterface{},
	}
}

func NewIPLastSeenPlatformDataOperation() *GenesisSyncTypeOperation[model.GenesisIP] {
	return &GenesisSyncTypeOperation[model.GenesisIP]{
		mutex:      sync.Mutex{},
		lastSeen:   map[int]map[string]time.Time{},
		dataStore:  map[int]map[string]model.GenesisIP{},
		dataStore2: map[int]map[string][]model.GenesisIP{},
	}
}

func NewLldpInfoPlatformDataOperation() *GenesisSyncTypeOperation[model.GenesisLldp] {
	return &GenesisSyncTypeOperation[model.GenesisLldp]{
		mutex:      sync.Mutex{},
		lastSeen:   map[int]map[string]time.Time{},
		dataStore:  map[int]map[string]model.GenesisLldp{},
		dataStore2: map[int]map[string][]model.GenesisLldp{},
	}
}

func NewProcessPlatformDataOperation() *GenesisSyncTypeOperation[model.GenesisProcess] {
	return &GenesisSyncTypeOperation[model.GenesisProcess]{
		mutex:      sync.Mutex{},
		lastSeen:   map[int]map[string]time.Time{},
		dataStore:  map[int]map[string]model.GenesisProcess{},
		dataStore2: map[int]map[string][]model.GenesisProcess{},
	}
}
