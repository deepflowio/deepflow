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
	"context"
	"os"
	"sync"
	"time"

	"gorm.io/gorm/clause"

	ccommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/genesis/common"
	"github.com/deepflowio/deepflow/server/controller/genesis/config"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

type SyncStorage struct {
	nodeIP          string
	cfg             config.GenesisConfig
	sCtx            context.Context
	sCancel         context.CancelFunc
	channel         chan common.GenesisSyncData
	dirty           bool
	mutex           sync.Mutex
	genesisSyncInfo GenesisSyncDataOperation
}

func NewSyncStorage(ctx context.Context, cfg config.GenesisConfig, sChan chan common.GenesisSyncData) *SyncStorage {
	sCtx, sCancel := context.WithCancel(ctx)
	return &SyncStorage{
		nodeIP:          os.Getenv(ccommon.NODE_IP_KEY),
		cfg:             cfg,
		sCtx:            sCtx,
		sCancel:         sCancel,
		channel:         sChan,
		dirty:           false,
		mutex:           sync.Mutex{},
		genesisSyncInfo: GenesisSyncDataOperation{},
	}
}

func (s *SyncStorage) Renew(orgID int, vtapID uint32, key string, refresh, wrEnabled bool, data common.GenesisSyncDataResponse) {
	now := time.Now()
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.genesisSyncInfo.VIPs.Renew(orgID, key, now, data.VIPs)
	s.genesisSyncInfo.Processes.Renew(orgID, key, now, data.Processes)
	s.genesisSyncInfo.Vinterfaces.Renew(orgID, key, now, data.Vinterfaces)
	if wrEnabled {
		s.genesisSyncInfo.VMs.Renew(orgID, key, now, data.VMs)
		s.genesisSyncInfo.VPCs.Renew(orgID, key, now, data.VPCs)
		s.genesisSyncInfo.Hosts.Renew(orgID, key, now, data.Hosts)
		s.genesisSyncInfo.Lldps.Renew(orgID, key, now, data.Lldps)
		s.genesisSyncInfo.Ports.Renew(orgID, key, now, data.Ports)
		s.genesisSyncInfo.Networks.Renew(orgID, key, now, data.Networks)
		s.genesisSyncInfo.IPlastseens.Renew(orgID, key, now, data.IPLastSeens)
	}

	if !refresh {
		return
	}
	db, err := mysql.GetDB(orgID)
	if err != nil {
		log.Errorf("get mysql session failed: %s", logger.NewORGPrefix(orgID))
		return
	}
	err = db.Model(&model.GenesisStorage{}).Where("vtap_id = ? AND node_ip <> ?", vtapID, s.nodeIP).Update("node_ip", s.nodeIP).Error
	if err != nil {
		log.Warningf("vtap id (%d) refresh storage to node (%s) failed: %s", vtapID, s.nodeIP, err.Error(), logger.NewORGPrefix(orgID))
	}
}

func (s *SyncStorage) Update(orgID int, vtapID uint32, key string, data common.GenesisSyncDataResponse) {
	now := time.Now()

	updateFlag := false
	s.mutex.Lock()
	if len(data.VIPs) != 0 {
		updateFlag = true
		s.genesisSyncInfo.VIPs.Update(orgID, key, now, data.VIPs)
	}
	if len(data.VMs) != 0 {
		updateFlag = true
		s.genesisSyncInfo.VMs.Update(orgID, key, now, data.VMs)
	}
	if len(data.VPCs) != 0 {
		updateFlag = true
		s.genesisSyncInfo.VPCs.Update(orgID, key, now, data.VPCs)
	}
	if len(data.Hosts) != 0 {
		updateFlag = true
		s.genesisSyncInfo.Hosts.Update(orgID, key, now, data.Hosts)
	}
	if len(data.Lldps) != 0 {
		updateFlag = true
		s.genesisSyncInfo.Lldps.Update(orgID, key, now, data.Lldps)
	}
	if len(data.Ports) != 0 {
		updateFlag = true
		s.genesisSyncInfo.Ports.Update(orgID, key, now, data.Ports)
	}
	if len(data.Networks) != 0 {
		updateFlag = true
		s.genesisSyncInfo.Networks.Update(orgID, key, now, data.Networks)
	}
	if len(data.IPLastSeens) != 0 {
		updateFlag = true
		s.genesisSyncInfo.IPlastseens.Update(orgID, key, now, data.IPLastSeens)
	}
	if len(data.Vinterfaces) != 0 {
		updateFlag = true
		s.genesisSyncInfo.Vinterfaces.Update(orgID, key, now, data.Vinterfaces)
	}
	if len(data.Processes) != 0 {
		updateFlag = true
		s.genesisSyncInfo.Processes.Update(orgID, key, now, data.Processes)
	}
	s.mutex.Unlock()

	if updateFlag && vtapID != 0 {
		// push immediately after update
		s.fetch()

		db, err := mysql.GetDB(orgID)
		if err != nil {
			log.Errorf("get mysql session failed: %s", err.Error(), logger.NewORGPrefix(orgID))
			return
		}
		db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "vtap_id"}},
			DoUpdates: clause.Assignments(map[string]interface{}{"node_ip": s.nodeIP}),
		}).Create(&model.GenesisStorage{
			VtapID: vtapID,
			NodeIP: s.nodeIP,
		})
	}
	s.dirty = true
}

func (s *SyncStorage) fetch() {
	s.channel <- common.GenesisSyncData{
		VIPs:        s.genesisSyncInfo.VIPs.Fetch(),
		VMs:         s.genesisSyncInfo.VMs.Fetch(),
		VPCs:        s.genesisSyncInfo.VPCs.Fetch(),
		Hosts:       s.genesisSyncInfo.Hosts.Fetch(),
		Ports:       s.genesisSyncInfo.Ports.Fetch(),
		Lldps:       s.genesisSyncInfo.Lldps.Fetch(),
		IPLastSeens: s.genesisSyncInfo.IPlastseens.Fetch(),
		Networks:    s.genesisSyncInfo.Networks.Fetch(),
		Vinterfaces: s.genesisSyncInfo.Vinterfaces.Fetch(),
		Processes:   s.genesisSyncInfo.Processes.Fetch(),
	}
}

func (s *SyncStorage) loadFromDatabase() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.genesisSyncInfo.VIPs = NewVIPPlatformDataOperation()
	s.genesisSyncInfo.VIPs.Load(s.nodeIP)

	s.genesisSyncInfo.VMs = NewVMPlatformDataOperation()
	s.genesisSyncInfo.VMs.Load(s.nodeIP)

	s.genesisSyncInfo.VPCs = NewVpcPlatformDataOperation()
	s.genesisSyncInfo.VPCs.Load(s.nodeIP)

	s.genesisSyncInfo.Hosts = NewHostPlatformDataOperation()
	s.genesisSyncInfo.Hosts.Load(s.nodeIP)

	s.genesisSyncInfo.Ports = NewPortPlatformDataOperation()
	s.genesisSyncInfo.Ports.Load(s.nodeIP)

	s.genesisSyncInfo.Lldps = NewLldpInfoPlatformDataOperation()
	s.genesisSyncInfo.Lldps.Load(s.nodeIP)

	s.genesisSyncInfo.IPlastseens = NewIPLastSeenPlatformDataOperation()
	s.genesisSyncInfo.IPlastseens.Load(s.nodeIP)

	s.genesisSyncInfo.Networks = NewNetworkPlatformDataOperation()
	s.genesisSyncInfo.Networks.Load(s.nodeIP)

	s.genesisSyncInfo.Vinterfaces = NewVinterfacePlatformDataOperation()
	s.genesisSyncInfo.Vinterfaces.Load(s.nodeIP)

	s.genesisSyncInfo.Processes = NewProcessPlatformDataOperation()
	s.genesisSyncInfo.Processes.Load(s.nodeIP)

	s.fetch()
}

func (s *SyncStorage) storeToDatabase() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.genesisSyncInfo.VIPs.Save(s.nodeIP)
	s.genesisSyncInfo.VMs.Save(s.nodeIP)
	s.genesisSyncInfo.VPCs.Save(s.nodeIP)
	s.genesisSyncInfo.Hosts.Save(s.nodeIP)
	s.genesisSyncInfo.Ports.Save(s.nodeIP)
	s.genesisSyncInfo.Lldps.Save(s.nodeIP)
	s.genesisSyncInfo.IPlastseens.Save(s.nodeIP)
	s.genesisSyncInfo.Networks.Save(s.nodeIP)
	s.genesisSyncInfo.Vinterfaces.Save(s.nodeIP)
	s.genesisSyncInfo.Processes.Save(s.nodeIP)
}

func (s *SyncStorage) refreshDatabase() {
	ticker := time.NewTicker(time.Duration(s.cfg.AgingTime) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// clean genesis storage invalid data
		orgIDs, err := mysql.GetORGIDs()
		if err != nil {
			log.Errorf("get org ids failed: %s", err.Error())
			return
		}
		for _, orgID := range orgIDs {
			db, err := mysql.GetDB(orgID)
			if err != nil {
				log.Errorf("get mysql session failed: %s", err.Error(), logger.NewORGPrefix(orgID))
				continue
			}
			vTaps := []mysqlmodel.VTap{}
			vTapIDs := map[int]bool{}
			storages := []model.GenesisStorage{}
			invalidStorages := []model.GenesisStorage{}
			db.Find(&vTaps)
			db.Where("node_ip = ?", s.nodeIP).Find(&storages)
			for _, v := range vTaps {
				vTapIDs[v.ID] = false
			}
			for _, s := range storages {
				if _, ok := vTapIDs[int(s.VtapID)]; !ok {
					invalidStorages = append(invalidStorages, s)
				}
			}
			if len(invalidStorages) > 0 {
				err := db.Delete(&invalidStorages).Error
				if err != nil {
					log.Errorf("node (%s) clean genesis storage invalid data failed: %s", s.nodeIP, err.Error(), logger.NewORGPrefix(orgID))
				} else {
					log.Infof("node (%s) clean genesis storage invalid data success", s.nodeIP, logger.NewORGPrefix(orgID))
				}
			}
		}

		s.dirty = true
	}
}

func (s *SyncStorage) run() {
	s.loadFromDatabase()

	ageTime := time.Duration(s.cfg.AgingTime) * time.Second
	for {
		time.Sleep(time.Duration(s.cfg.DataPersistenceInterval) * time.Second)
		now := time.Now()
		hasChange := false
		s.mutex.Lock()
		hasChange = hasChange || s.genesisSyncInfo.VIPs.Age(now, ageTime)
		hasChange = hasChange || s.genesisSyncInfo.VMs.Age(now, ageTime)
		hasChange = hasChange || s.genesisSyncInfo.VPCs.Age(now, ageTime)
		hasChange = hasChange || s.genesisSyncInfo.Lldps.Age(now, ageTime)
		hasChange = hasChange || s.genesisSyncInfo.Ports.Age(now, ageTime)
		hasChange = hasChange || s.genesisSyncInfo.Networks.Age(now, ageTime)
		hasChange = hasChange || s.genesisSyncInfo.IPlastseens.Age(now, ageTime)
		hasChange = hasChange || s.genesisSyncInfo.Processes.Age(now, ageTime)
		hasChange = hasChange || s.genesisSyncInfo.Vinterfaces.Age(now, time.Duration(s.cfg.VinterfaceAgingTime)*time.Second)
		hasChange = hasChange || s.dirty
		s.dirty = false
		s.mutex.Unlock()
		if hasChange {
			s.storeToDatabase()
			s.fetch()
		}
	}
}

func (s *SyncStorage) Start() {
	go s.refreshDatabase()
	go s.run()
}

func (s *SyncStorage) Stop() {
	if s.sCancel != nil {
		s.sCancel()
	}
}
