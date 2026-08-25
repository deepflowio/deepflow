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

package mysql

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"

	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	mmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/genesis/common"
	cfg "github.com/deepflowio/deepflow/server/controller/genesis/config"
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
	nodeIP string
	config cfg.GenesisConfig
	store  *cache.Cache
}

func (gs *GenesisSyncTypeOperation[T]) formatKey(orgID int, vtapID uint32, vtapKey string) string {
	return fmt.Sprintf("%d-%d-%s", orgID, vtapID, vtapKey)
}

func (gs *GenesisSyncTypeOperation[T]) Fetch() map[int][]T {
	result := map[int][]T{}
	for key, item := range gs.store.Items() {
		orgID, err := strconv.Atoi(strings.Split(key, "-")[0])
		if err != nil {
			log.Errorf("parse org ID failed: %s", err.Error())
			continue
		}
		result[orgID] = append(result[orgID], item.Object.([]T)...)
	}

	return result
}

func (gs *GenesisSyncTypeOperation[T]) Renew(orgID int, vtapID uint32, vtapKey string, items []T) {
	if len(items) == 0 {
		return
	}

	gs.store.SetDefault(gs.formatKey(orgID, vtapID, vtapKey), items)
}

func (gs *GenesisSyncTypeOperation[T]) Update(orgID int, vtapID uint32, vtapKey string, items []T) {
	if len(items) == 0 {
		return
	}

	log.Infof("update %T vtap (%s) entries: %d", items, vtapKey, len(items), logger.NewORGPrefix(orgID))

	db, err := metadb.GetDB(orgID)
	if err != nil {
		log.Errorf("get metadb session failed: %s", err.Error(), logger.NewORGPrefix(orgID))
		return
	}

	key := gs.formatKey(orgID, vtapID, vtapKey)
	if gs.config.LogDetailEnabled && vtapID != 0 {
		newData := map[string]T{}
		for _, item := range items {
			newData[item.GetLcuuid()] = item
		}

		curData := map[string]T{}
		storeData, ok := gs.store.Get(key)
		if ok {
			for _, item := range storeData.([]T) {
				curData[item.GetLcuuid()] = item
			}
		}

		// add
		for lcuuid, data := range newData {
			_, ok := curData[lcuuid]
			if ok || data.GetVtapID() == 0 {
				continue
			}
			log.Infof("sync (%s) add (%s)", key, data.GetInfo(), logger.NewORGPrefix(orgID))
		}

		// delete
		for lcuuid, data := range curData {
			_, ok := newData[lcuuid]
			if ok || data.GetVtapID() == 0 {
				continue
			}
			log.Infof("sync (%s) delete (%s)", key, data.GetInfo(), logger.NewORGPrefix(orgID))
		}
	}

	gs.store.SetDefault(key, items)

	if vtapID == 0 {
		return
	}

	var toDelete T
	err = db.Where("vtap_id = ?", vtapID).Where("node_ip = ?", gs.nodeIP).Delete(&toDelete).Error
	if err != nil {
		log.Warningf("delete vtap (%d) old data failed: %s", vtapID, err.Error(), logger.NewORGPrefix(orgID))
	}

	err = db.CreateInBatches(items, 100).Error
	if err != nil {
		log.Warningf("create vtap (%s) new data failed: %s", vtapKey, err.Error(), logger.NewORGPrefix(orgID))
	}
}

func (gs *GenesisSyncTypeOperation[T]) Load() {
	orgIDs, err := metadb.GetORGIDs()
	if err != nil {
		log.Errorf("get org ids failed: %s", err.Error())
		return
	}
	for _, orgID := range orgIDs {
		db, err := metadb.GetDB(orgID)
		if err != nil {
			log.Errorf("get metadb session failed: %s", err.Error(), logger.NewORGPrefix(orgID))
			continue
		}
		storages := []model.GenesisStorage{}
		err = db.Where("node_ip = ?", gs.nodeIP).Find(&storages).Error
		if err != nil {
			log.Errorf("get node (%s) storage failed:%s", gs.nodeIP, err.Error(), logger.NewORGPrefix(orgID))
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

		activeVtapIDs := []uint32{}
		for _, storage := range storages {
			var items []T
			err = db.Where("node_ip = ?", gs.nodeIP).Where("vtap_id = ?", storage.VtapID).Find(&items).Error
			if err != nil {
				log.Errorf("get vtap (%d) data failed:%s", storage.VtapID, err.Error(), logger.NewORGPrefix(orgID))
				continue
			}
			vtap, ok := vtapIDs[int(storage.VtapID)]
			if !ok {
				log.Debugf("vtap (%d) not found", storage.VtapID, logger.NewORGPrefix(db.ORGID))
				continue
			}
			if len(items) == 0 {
				continue
			}
			key := gs.formatKey(orgID, storage.VtapID, vtap.CtrlIP+"-"+vtap.CtrlMac)
			if gs.config.LogDetailEnabled {
				for _, item := range items {
					log.Infof("genesis load %T vtap (%s) data (%s)", item, key, item.GetInfo(), logger.NewORGPrefix(db.ORGID))
				}
			}
			gs.store.SetDefault(key, items)
			activeVtapIDs = append(activeVtapIDs, storage.VtapID)
			log.Infof("genesis load %T vtap (%s) entries: %d", items, key, len(items), logger.NewORGPrefix(db.ORGID))
		}
		var inactive T
		err = db.Where("node_ip = ?", gs.nodeIP).Where("vtap_id NOT IN (?)", activeVtapIDs).Delete(&inactive).Error
		if err != nil {
			log.Errorf("delete (%s) inactive data failed:%s", gs.nodeIP, err.Error(), logger.NewORGPrefix(orgID))
		}
	}
}

func (gs *GenesisSyncTypeOperation[T]) SetOnEvicted(f func(k string, v interface{})) {
	gs.store.OnEvicted(f)
}

func NewHostPlatformDataOperation(nodeIP string, expired, interval int, config cfg.GenesisConfig) *GenesisSyncTypeOperation[model.GenesisHost] {
	return &GenesisSyncTypeOperation[model.GenesisHost]{
		nodeIP: nodeIP,
		config: config,
		store: cache.New(
			time.Duration(expired)*time.Second,
			time.Duration(interval)*time.Second,
		),
	}
}

func NewVMPlatformDataOperation(nodeIP string, expired, interval int, config cfg.GenesisConfig) *GenesisSyncTypeOperation[model.GenesisVM] {
	return &GenesisSyncTypeOperation[model.GenesisVM]{
		nodeIP: nodeIP,
		config: config,
		store: cache.New(
			time.Duration(expired)*time.Second,
			time.Duration(interval)*time.Second,
		),
	}
}

func NewVIPPlatformDataOperation(nodeIP string, expired, interval int, config cfg.GenesisConfig) *GenesisSyncTypeOperation[model.GenesisVIP] {
	return &GenesisSyncTypeOperation[model.GenesisVIP]{
		nodeIP: nodeIP,
		config: config,
		store: cache.New(
			time.Duration(expired)*time.Second,
			time.Duration(interval)*time.Second,
		),
	}
}

func NewVpcPlatformDataOperation(nodeIP string, expired, interval int, config cfg.GenesisConfig) *GenesisSyncTypeOperation[model.GenesisVPC] {
	return &GenesisSyncTypeOperation[model.GenesisVPC]{
		nodeIP: nodeIP,
		config: config,
		store: cache.New(
			time.Duration(expired)*time.Second,
			time.Duration(interval)*time.Second,
		),
	}
}

func NewPortPlatformDataOperation(nodeIP string, expired, interval int, config cfg.GenesisConfig) *GenesisSyncTypeOperation[model.GenesisPort] {
	return &GenesisSyncTypeOperation[model.GenesisPort]{
		nodeIP: nodeIP,
		config: config,
		store: cache.New(
			time.Duration(expired)*time.Second,
			time.Duration(interval)*time.Second,
		),
	}
}

func NewNetworkPlatformDataOperation(nodeIP string, expired, interval int, config cfg.GenesisConfig) *GenesisSyncTypeOperation[model.GenesisNetwork] {
	return &GenesisSyncTypeOperation[model.GenesisNetwork]{
		nodeIP: nodeIP,
		config: config,
		store: cache.New(
			time.Duration(expired)*time.Second,
			time.Duration(interval)*time.Second,
		),
	}
}

func NewVinterfacePlatformDataOperation(nodeIP string, expired, interval int, config cfg.GenesisConfig) *GenesisSyncTypeOperation[model.GenesisVinterface] {
	return &GenesisSyncTypeOperation[model.GenesisVinterface]{
		nodeIP: nodeIP,
		config: config,
		store: cache.New(
			time.Duration(expired)*time.Second,
			time.Duration(interval)*time.Second,
		),
	}
}

func NewIPLastSeenPlatformDataOperation(nodeIP string, expired, interval int, config cfg.GenesisConfig) *GenesisSyncTypeOperation[model.GenesisIP] {
	return &GenesisSyncTypeOperation[model.GenesisIP]{
		nodeIP: nodeIP,
		config: config,
		store: cache.New(
			time.Duration(expired)*time.Second,
			time.Duration(interval)*time.Second,
		),
	}
}

func NewLldpInfoPlatformDataOperation(nodeIP string, expired, interval int, config cfg.GenesisConfig) *GenesisSyncTypeOperation[model.GenesisLldp] {
	return &GenesisSyncTypeOperation[model.GenesisLldp]{
		nodeIP: nodeIP,
		config: config,
		store: cache.New(
			time.Duration(expired)*time.Second,
			time.Duration(interval)*time.Second,
		),
	}
}

func NewProcessPlatformDataOperation(nodeIP string, expired, interval int, config cfg.GenesisConfig) *GenesisSyncTypeOperation[model.GenesisProcess] {
	return &GenesisSyncTypeOperation[model.GenesisProcess]{
		nodeIP: nodeIP,
		config: config,
		store: cache.New(
			time.Duration(expired)*time.Second,
			time.Duration(interval)*time.Second,
		),
	}
}
