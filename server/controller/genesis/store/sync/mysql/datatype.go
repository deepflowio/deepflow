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
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
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
	nodeIP string
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
			log.Error(err.Error())
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

	db, err := metadb.GetDB(orgID)
	if err != nil {
		log.Errorf("get metadb session failed: %s", err.Error(), logger.NewORGPrefix(orgID))
		return
	}

	gs.store.SetDefault(gs.formatKey(orgID, vtapID, vtapKey), items)

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
		log.Error("get org ids failed")
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

		activeVtapIDs := []uint32{}
		for _, storage := range storages {
			var items []T
			err = db.Where("node_ip = ?", gs.nodeIP).Where("vtap_id = ?", storage.VtapID).Find(&items).Error
			if err != nil {
				log.Errorf("get vtap (%d) data failed:%s", storage.VtapID, err.Error(), logger.NewORGPrefix(orgID))
				continue
			}
			var vtap metadbmodel.VTap
			err = db.Where("id = ?", storage.VtapID).First(&vtap).Error
			if err != nil {
				log.Warningf("get vtap (%d) failed:%s", storage.VtapID, err.Error(), logger.NewORGPrefix(orgID))
				continue
			}
			if len(items) == 0 {
				continue
			}
			gs.store.SetDefault(gs.formatKey(orgID, storage.VtapID, vtap.CtrlIP+"-"+vtap.CtrlMac), items)
			activeVtapIDs = append(activeVtapIDs, storage.VtapID)
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

func NewHostPlatformDataOperation(nodeIP string, expired, interval int) *GenesisSyncTypeOperation[model.GenesisHost] {
	return &GenesisSyncTypeOperation[model.GenesisHost]{
		nodeIP: nodeIP,
		store: cache.New(
			time.Duration(expired)*time.Second,
			time.Duration(interval)*time.Second,
		),
	}
}

func NewVMPlatformDataOperation(nodeIP string, expired, interval int) *GenesisSyncTypeOperation[model.GenesisVM] {
	return &GenesisSyncTypeOperation[model.GenesisVM]{
		nodeIP: nodeIP,
		store: cache.New(
			time.Duration(expired)*time.Second,
			time.Duration(interval)*time.Second,
		),
	}
}

func NewVIPPlatformDataOperation(nodeIP string, expired, interval int) *GenesisSyncTypeOperation[model.GenesisVIP] {
	return &GenesisSyncTypeOperation[model.GenesisVIP]{
		nodeIP: nodeIP,
		store: cache.New(
			time.Duration(expired)*time.Second,
			time.Duration(interval)*time.Second,
		),
	}
}

func NewVpcPlatformDataOperation(nodeIP string, expired, interval int) *GenesisSyncTypeOperation[model.GenesisVPC] {
	return &GenesisSyncTypeOperation[model.GenesisVPC]{
		nodeIP: nodeIP,
		store: cache.New(
			time.Duration(expired)*time.Second,
			time.Duration(interval)*time.Second,
		),
	}
}

func NewPortPlatformDataOperation(nodeIP string, expired, interval int) *GenesisSyncTypeOperation[model.GenesisPort] {
	return &GenesisSyncTypeOperation[model.GenesisPort]{
		nodeIP: nodeIP,
		store: cache.New(
			time.Duration(expired)*time.Second,
			time.Duration(interval)*time.Second,
		),
	}
}

func NewNetworkPlatformDataOperation(nodeIP string, expired, interval int) *GenesisSyncTypeOperation[model.GenesisNetwork] {
	return &GenesisSyncTypeOperation[model.GenesisNetwork]{
		nodeIP: nodeIP,
		store: cache.New(
			time.Duration(expired)*time.Second,
			time.Duration(interval)*time.Second,
		),
	}
}

func NewVinterfacePlatformDataOperation(nodeIP string, expired, interval int) *GenesisSyncTypeOperation[model.GenesisVinterface] {
	return &GenesisSyncTypeOperation[model.GenesisVinterface]{
		nodeIP: nodeIP,
		store: cache.New(
			time.Duration(expired)*time.Second,
			time.Duration(interval)*time.Second,
		),
	}
}

func NewIPLastSeenPlatformDataOperation(nodeIP string, expired, interval int) *GenesisSyncTypeOperation[model.GenesisIP] {
	return &GenesisSyncTypeOperation[model.GenesisIP]{
		nodeIP: nodeIP,
		store: cache.New(
			time.Duration(expired)*time.Second,
			time.Duration(interval)*time.Second,
		),
	}
}

func NewLldpInfoPlatformDataOperation(nodeIP string, expired, interval int) *GenesisSyncTypeOperation[model.GenesisLldp] {
	return &GenesisSyncTypeOperation[model.GenesisLldp]{
		nodeIP: nodeIP,
		store: cache.New(
			time.Duration(expired)*time.Second,
			time.Duration(interval)*time.Second,
		),
	}
}

func NewProcessPlatformDataOperation(nodeIP string, expired, interval int) *GenesisSyncTypeOperation[model.GenesisProcess] {
	return &GenesisSyncTypeOperation[model.GenesisProcess]{
		nodeIP: nodeIP,
		store: cache.New(
			time.Duration(expired)*time.Second,
			time.Duration(interval)*time.Second,
		),
	}
}
