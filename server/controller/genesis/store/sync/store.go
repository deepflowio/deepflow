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
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	mcommon "github.com/deepflowio/deepflow/server/controller/db/metadb/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/genesis/common"
	"github.com/deepflowio/deepflow/server/controller/genesis/config"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

type SyncStorage struct {
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
		cfg:             cfg,
		sCtx:            sCtx,
		sCancel:         sCancel,
		channel:         sChan,
		dirty:           false,
		mutex:           sync.Mutex{},
		genesisSyncInfo: GenesisSyncDataOperation{},
	}
}

func (s *SyncStorage) Renew(orgID int, vtapID uint32, refresh bool, data common.GenesisSyncDataResponse) {
	now := time.Now()
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.genesisSyncInfo.VIPs.Renew(orgID, now, data.VIPs)
	s.genesisSyncInfo.VMs.Renew(orgID, now, data.VMs)
	s.genesisSyncInfo.VPCs.Renew(orgID, now, data.VPCs)
	s.genesisSyncInfo.Hosts.Renew(orgID, now, data.Hosts)
	s.genesisSyncInfo.Lldps.Renew(orgID, now, data.Lldps)
	s.genesisSyncInfo.Ports.Renew(orgID, now, data.Ports)
	s.genesisSyncInfo.Networks.Renew(orgID, now, data.Networks)
	s.genesisSyncInfo.IPlastseens.Renew(orgID, now, data.IPLastSeens)
	s.genesisSyncInfo.Vinterfaces.Renew(orgID, now, data.Vinterfaces)
	s.genesisSyncInfo.Processes.Renew(orgID, now, data.Processes)

	if !refresh {
		return
	}
	db, err := metadb.GetDB(orgID)
	if err != nil {
		log.Error("get metadb session failed", logger.NewORGPrefix(orgID))
		return
	}
	nodeIP := os.Getenv(ccommon.NODE_IP_KEY)
	err = db.Model(&model.GenesisStorage{}).Where("vtap_id = ? AND node_ip <> ?", vtapID, nodeIP).Update("node_ip", nodeIP).Error
	if err != nil {
		log.Warningf("vtap id (%d) refresh storage to node (%s) failed: %s", vtapID, nodeIP, err, logger.NewORGPrefix(orgID))
	}
}

func (s *SyncStorage) Update(orgID int, vtapID uint32, data common.GenesisSyncDataResponse) {
	now := time.Now()
	s.mutex.Lock()
	defer s.mutex.Unlock()

	updateFlag := false
	if len(data.VIPs) != 0 {
		updateFlag = true
		s.genesisSyncInfo.VIPs.Update(orgID, now, data.VIPs)
	}
	if len(data.VMs) != 0 {
		updateFlag = true
		s.genesisSyncInfo.VMs.Update(orgID, now, data.VMs)
	}
	if len(data.VPCs) != 0 {
		updateFlag = true
		s.genesisSyncInfo.VPCs.Update(orgID, now, data.VPCs)
	}
	if len(data.Hosts) != 0 {
		updateFlag = true
		s.genesisSyncInfo.Hosts.Update(orgID, now, data.Hosts)
	}
	if len(data.Lldps) != 0 {
		updateFlag = true
		s.genesisSyncInfo.Lldps.Update(orgID, now, data.Lldps)
	}
	if len(data.Ports) != 0 {
		updateFlag = true
		s.genesisSyncInfo.Ports.Update(orgID, now, data.Ports)
	}
	if len(data.Networks) != 0 {
		updateFlag = true
		s.genesisSyncInfo.Networks.Update(orgID, now, data.Networks)
	}
	if len(data.IPLastSeens) != 0 {
		updateFlag = true
		s.genesisSyncInfo.IPlastseens.Update(orgID, now, data.IPLastSeens)
	}
	if len(data.Vinterfaces) != 0 {
		updateFlag = true
		s.genesisSyncInfo.Vinterfaces.Update(orgID, now, data.Vinterfaces)
	}
	if len(data.Processes) != 0 {
		updateFlag = true
		s.genesisSyncInfo.Processes.Update(orgID, now, data.Processes)
	}
	if updateFlag && vtapID != 0 {
		// push immediately after update
		s.fetch()

		db, err := metadb.GetDB(orgID)
		if err != nil {
			log.Error("get metadb session failed", logger.NewORGPrefix(orgID))
			return
		}
		nodeIP := os.Getenv(ccommon.NODE_IP_KEY)
		db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "vtap_id"}},
			DoUpdates: clause.Assignments(map[string]interface{}{"node_ip": nodeIP}),
		}).Create(&model.GenesisStorage{
			VtapID: vtapID,
			NodeIP: nodeIP,
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

func (s *SyncStorage) loadFromDatabase(ageTime time.Duration) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	now := time.Now()
	s.genesisSyncInfo = GenesisSyncDataOperation{}
	var vips []model.GenesisVIP
	var vms []model.GenesisVM
	var vpcs []model.GenesisVpc
	var hosts []model.GenesisHost
	var ports []model.GenesisPort
	var lldps []model.GenesisLldp
	var ipLastSeens []model.GenesisIP
	var networks []model.GenesisNetwork
	var vinterfaces []model.GenesisVinterface
	var processes []model.GenesisProcess

	s.genesisSyncInfo.VIPs = NewVIPPlatformDataOperation(mcommon.DEFAULT_ORG_ID, vips)
	s.genesisSyncInfo.VIPs.Load(now, ageTime)

	s.genesisSyncInfo.VMs = NewVMPlatformDataOperation(mcommon.DEFAULT_ORG_ID, vms)
	s.genesisSyncInfo.VMs.Load(now, ageTime)

	s.genesisSyncInfo.VPCs = NewVpcPlatformDataOperation(mcommon.DEFAULT_ORG_ID, vpcs)
	s.genesisSyncInfo.VPCs.Load(now, ageTime)

	s.genesisSyncInfo.Hosts = NewHostPlatformDataOperation(mcommon.DEFAULT_ORG_ID, hosts)
	s.genesisSyncInfo.Hosts.Load(now, ageTime)

	s.genesisSyncInfo.Ports = NewPortPlatformDataOperation(mcommon.DEFAULT_ORG_ID, ports)
	s.genesisSyncInfo.Ports.Load(now, ageTime)

	s.genesisSyncInfo.Lldps = NewLldpInfoPlatformDataOperation(mcommon.DEFAULT_ORG_ID, lldps)
	s.genesisSyncInfo.Lldps.Load(now, ageTime)

	s.genesisSyncInfo.IPlastseens = NewIPLastSeenPlatformDataOperation(mcommon.DEFAULT_ORG_ID, ipLastSeens)
	s.genesisSyncInfo.IPlastseens.Load(now, ageTime)

	s.genesisSyncInfo.Networks = NewNetworkPlatformDataOperation(mcommon.DEFAULT_ORG_ID, networks)
	s.genesisSyncInfo.Networks.Load(now, ageTime)

	s.genesisSyncInfo.Vinterfaces = NewVinterfacePlatformDataOperation(mcommon.DEFAULT_ORG_ID, vinterfaces)
	s.genesisSyncInfo.Vinterfaces.Load(now, ageTime)

	s.genesisSyncInfo.Processes = NewProcessPlatformDataOperation(mcommon.DEFAULT_ORG_ID, processes)
	s.genesisSyncInfo.Processes.Load(now, ageTime)

	s.fetch()
}

func (s *SyncStorage) storeToDatabase() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.genesisSyncInfo.VIPs.Save()
	s.genesisSyncInfo.VMs.Save()
	s.genesisSyncInfo.VPCs.Save()
	s.genesisSyncInfo.Hosts.Save()
	s.genesisSyncInfo.Ports.Save()
	s.genesisSyncInfo.Lldps.Save()
	s.genesisSyncInfo.IPlastseens.Save()
	s.genesisSyncInfo.Networks.Save()
	s.genesisSyncInfo.Vinterfaces.Save()
	s.genesisSyncInfo.Processes.Save()
}

func (s *SyncStorage) refreshDatabase() {
	ticker := time.NewTicker(time.Duration(s.cfg.AgingTime) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// clean genesis storage invalid data
		orgIDs, err := metadb.GetORGIDs()
		if err != nil {
			log.Error("get org ids failed")
			return
		}
		nodeIP := os.Getenv(ccommon.NODE_IP_KEY)
		for _, orgID := range orgIDs {
			db, err := metadb.GetDB(orgID)
			if err != nil {
				log.Error("get metadb session failed", logger.NewORGPrefix(orgID))
				continue
			}
			vTaps := []metadbmodel.VTap{}
			vTapIDs := map[int]bool{}
			storages := []model.GenesisStorage{}
			invalidStorages := []model.GenesisStorage{}
			db.Select("id").Find(&vTaps)
			db.Where("node_ip = ?", nodeIP).Find(&storages)
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
					log.Errorf("node (%s) clean genesis storage invalid data failed: %s", nodeIP, err, logger.NewORGPrefix(orgID))
				} else {
					log.Infof("node (%s) clean genesis storage invalid data success", nodeIP, logger.NewORGPrefix(orgID))
				}
			}
		}

		s.dirty = true
	}
}

func (s *SyncStorage) run() {
	ageTime := time.Duration(s.cfg.AgingTime) * time.Second
	s.loadFromDatabase(ageTime)

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
