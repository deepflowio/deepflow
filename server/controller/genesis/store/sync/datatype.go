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

	mysql "github.com/deepflowio/deepflow/server/controller/db/metadb"
	mmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/genesis/common"
	"github.com/deepflowio/deepflow/server/controller/genesis/config"
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
	cfg        config.GenesisConfig
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
		if orgLastSeen, ok := g.lastSeen[orgID]; ok {
			orgLastSeen[key] = timestamp
		} else {
			g.lastSeen[orgID] = map[string]time.Time{key: timestamp}
		}
		if orgDataStore2, ok := g.dataStore2[orgID]; ok {
			orgDataStore2[key] = items
		} else {
			g.dataStore2[orgID] = map[string][]T{key: items}
		}
	}
}

func (g *GenesisSyncTypeOperation[T]) Update(orgID int, key string, timestamp time.Time, items []T) {
	log.Infof("update %T vtap (%s) entries: %d", items, key, len(items), logger.NewORGPrefix(orgID))

	g.mutex.Lock()
	defer g.mutex.Unlock()

	if key == "" {
		for _, item := range items {
			itemLcuuid := item.GetLcuuid()
			if orgLastSeen, ok := g.lastSeen[orgID]; ok {
				orgLastSeen[itemLcuuid] = timestamp
			} else {
				g.lastSeen[orgID] = map[string]time.Time{itemLcuuid: timestamp}
			}
			if orgDataStore, ok := g.dataStore[orgID]; ok {
				_, existed := orgDataStore[itemLcuuid]
				orgDataStore[itemLcuuid] = item
				if !g.cfg.LogDetailEnabled {
					continue
				}
				if !existed && item.GetVtapID() != 0 {
					log.Infof("sync add (%#+v)", item.GetInfo(), logger.NewORGPrefix(orgID))
				}
			} else {
				g.dataStore[orgID] = map[string]T{itemLcuuid: item}
				if item.GetVtapID() == 0 {
					continue
				}
				if !g.cfg.LogDetailEnabled {
					continue
				}
				log.Infof("sync add (%#+v)", item, logger.NewORGPrefix(orgID))
			}
		}
	} else {
		if orgLastSeen, ok := g.lastSeen[orgID]; ok {
			orgLastSeen[key] = timestamp
		} else {
			g.lastSeen[orgID] = map[string]time.Time{key: timestamp}
		}
		if orgDataStore2, ok := g.dataStore2[orgID]; ok {
			orgItems, itemExists := orgDataStore2[key]
			orgDataStore2[key] = items
			if !g.cfg.LogDetailEnabled {
				return
			}
			if itemExists {
				newData := map[string]T{}
				for _, item := range items {
					newData[item.GetLcuuid()] = item
				}

				curData := map[string]T{}
				for _, item := range orgItems {
					curData[item.GetLcuuid()] = item
				}

				// add
				for lcuuid, data := range newData {
					_, ok := curData[lcuuid]
					if ok || data.GetVtapID() == 0 {
						continue
					}
					log.Infof("sync (%s) add (%#+v)", key, data.GetInfo(), logger.NewORGPrefix(orgID))
				}

				// delete
				for lcuuid, data := range curData {
					_, ok := newData[lcuuid]
					if ok || data.GetVtapID() == 0 {
						continue
					}
					log.Infof("sync (%s) delete (%#+v)", key, data.GetInfo(), logger.NewORGPrefix(orgID))
				}
			}
		} else {
			g.dataStore2[orgID] = map[string][]T{key: items}
			if !g.cfg.LogDetailEnabled {
				return
			}
			for _, item := range items {
				if item.GetVtapID() == 0 {
					continue
				}
				log.Infof("sync (%s) add (%#+v)", key, item, logger.NewORGPrefix(orgID))
			}
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

			if g.cfg.LogDetailEnabled {
				log.Infof("aging data (%s)", dataMap[dataLcuuid].GetInfo(), logger.NewORGPrefix(orgID))
			}

			delete(g.dataStore[orgID], dataLcuuid)
			delete(g.lastSeen[orgID], dataLcuuid)
		}
	}

	for orgID, dataMap := range g.dataStore2 {
		for key := range dataMap {
			if ageTimestamp.After(g.lastSeen[orgID][key]) {
				removed = true

				if g.cfg.LogDetailEnabled {
					for _, item := range dataMap[key] {
						log.Infof("aging (%s) data (%s)", key, item.GetInfo(), logger.NewORGPrefix(orgID))
					}
				}

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
			var vtap mmodel.VTap
			err = db.Where("id = ?", storage.VtapID).First(&vtap).Error
			if err != nil {
				log.Errorf("get vtap (%d) failed:%s", storage.VtapID, err.Error(), logger.NewORGPrefix(db.ORGID))
				continue
			}
			var items []T
			err = db.Where("node_ip = ?", nodeIP).Where("vtap_id = ?", storage.VtapID).Find(&items).Error
			if err != nil {
				log.Errorf("get vtap (%d) data failed:%s", storage.VtapID, err.Error(), logger.NewORGPrefix(db.ORGID))
				continue
			}

			if len(items) == 0 {
				continue
			}

			key := fmt.Sprintf("%s-%s", vtap.CtrlIP, vtap.CtrlMac)
			if g.cfg.LogDetailEnabled {
				for _, item := range items {
					log.Infof("genesis load %T vtap (%s) data (%s)", item, key, item.GetInfo(), logger.NewORGPrefix(db.ORGID))
				}
			}
			lastSeen[key] = time.Now()
			dataStore2[key] = items

			log.Infof("genesis load %T vtap (%s) %d entries", items[0], key, len(items), logger.NewORGPrefix(db.ORGID))
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

		var vtaps []mmodel.VTap
		err = db.Find(&vtaps).Error
		if err != nil {
			log.Warning("get vtaps failed: %s", err.Error(), logger.NewORGPrefix(db.ORGID))
			continue
		}
		vtapIDs := map[int]mmodel.VTap{}
		for _, vtap := range vtaps {
			vtapIDs[vtap.ID] = vtap
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

			vtap, ok := vtapIDs[int(storage.VtapID)]
			if !ok {
				log.Debugf("vtap (%d) not found", storage.VtapID, logger.NewORGPrefix(db.ORGID))
				continue
			}

			data, ok := dataMap[fmt.Sprintf("%s-%s", vtap.CtrlIP, vtap.CtrlMac)]
			if !ok {
				log.Debugf("not found vtap id (%d) data of dataStore2", storage.VtapID, logger.NewORGPrefix(db.ORGID))
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

func NewHostPlatformDataOperation(cfg config.GenesisConfig) *GenesisSyncTypeOperation[model.GenesisHost] {
	return &GenesisSyncTypeOperation[model.GenesisHost]{
		cfg:        cfg,
		mutex:      sync.Mutex{},
		lastSeen:   map[int]map[string]time.Time{},
		dataStore:  map[int]map[string]model.GenesisHost{},
		dataStore2: map[int]map[string][]model.GenesisHost{},
	}
}

func NewVMPlatformDataOperation(cfg config.GenesisConfig) *GenesisSyncTypeOperation[model.GenesisVM] {
	return &GenesisSyncTypeOperation[model.GenesisVM]{
		cfg:        cfg,
		mutex:      sync.Mutex{},
		lastSeen:   map[int]map[string]time.Time{},
		dataStore:  map[int]map[string]model.GenesisVM{},
		dataStore2: map[int]map[string][]model.GenesisVM{},
	}
}

func NewVIPPlatformDataOperation(cfg config.GenesisConfig) *GenesisSyncTypeOperation[model.GenesisVIP] {
	return &GenesisSyncTypeOperation[model.GenesisVIP]{
		cfg:        cfg,
		mutex:      sync.Mutex{},
		lastSeen:   map[int]map[string]time.Time{},
		dataStore:  map[int]map[string]model.GenesisVIP{},
		dataStore2: map[int]map[string][]model.GenesisVIP{},
	}
}

func NewVpcPlatformDataOperation(cfg config.GenesisConfig) *GenesisSyncTypeOperation[model.GenesisVPC] {
	return &GenesisSyncTypeOperation[model.GenesisVPC]{
		cfg:        cfg,
		mutex:      sync.Mutex{},
		lastSeen:   map[int]map[string]time.Time{},
		dataStore:  map[int]map[string]model.GenesisVPC{},
		dataStore2: map[int]map[string][]model.GenesisVPC{},
	}
}

func NewPortPlatformDataOperation(cfg config.GenesisConfig) *GenesisSyncTypeOperation[model.GenesisPort] {
	return &GenesisSyncTypeOperation[model.GenesisPort]{
		cfg:        cfg,
		mutex:      sync.Mutex{},
		lastSeen:   map[int]map[string]time.Time{},
		dataStore:  map[int]map[string]model.GenesisPort{},
		dataStore2: map[int]map[string][]model.GenesisPort{},
	}
}

func NewNetworkPlatformDataOperation(cfg config.GenesisConfig) *GenesisSyncTypeOperation[model.GenesisNetwork] {
	return &GenesisSyncTypeOperation[model.GenesisNetwork]{
		cfg:        cfg,
		mutex:      sync.Mutex{},
		lastSeen:   map[int]map[string]time.Time{},
		dataStore:  map[int]map[string]model.GenesisNetwork{},
		dataStore2: map[int]map[string][]model.GenesisNetwork{},
	}
}

func NewVinterfacePlatformDataOperation(cfg config.GenesisConfig) *GenesisSyncTypeOperation[model.GenesisVinterface] {
	return &GenesisSyncTypeOperation[model.GenesisVinterface]{
		cfg:        cfg,
		mutex:      sync.Mutex{},
		lastSeen:   map[int]map[string]time.Time{},
		dataStore:  map[int]map[string]model.GenesisVinterface{},
		dataStore2: map[int]map[string][]model.GenesisVinterface{},
	}
}

func NewIPLastSeenPlatformDataOperation(cfg config.GenesisConfig) *GenesisSyncTypeOperation[model.GenesisIP] {
	return &GenesisSyncTypeOperation[model.GenesisIP]{
		cfg:        cfg,
		mutex:      sync.Mutex{},
		lastSeen:   map[int]map[string]time.Time{},
		dataStore:  map[int]map[string]model.GenesisIP{},
		dataStore2: map[int]map[string][]model.GenesisIP{},
	}
}

func NewLldpInfoPlatformDataOperation(cfg config.GenesisConfig) *GenesisSyncTypeOperation[model.GenesisLldp] {
	return &GenesisSyncTypeOperation[model.GenesisLldp]{
		cfg:        cfg,
		mutex:      sync.Mutex{},
		lastSeen:   map[int]map[string]time.Time{},
		dataStore:  map[int]map[string]model.GenesisLldp{},
		dataStore2: map[int]map[string][]model.GenesisLldp{},
	}
}

func NewProcessPlatformDataOperation(cfg config.GenesisConfig) *GenesisSyncTypeOperation[model.GenesisProcess] {
	return &GenesisSyncTypeOperation[model.GenesisProcess]{
		cfg:        cfg,
		mutex:      sync.Mutex{},
		lastSeen:   map[int]map[string]time.Time{},
		dataStore:  map[int]map[string]model.GenesisProcess{},
		dataStore2: map[int]map[string][]model.GenesisProcess{},
	}
}
