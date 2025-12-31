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
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm/clause"

	ccommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/genesis/common"
	"github.com/deepflowio/deepflow/server/controller/genesis/config"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

type SyncStorage struct {
	nodeIP  string
	cfg     config.GenesisConfig
	sCtx    context.Context
	sCancel context.CancelFunc
	data    GenesisSyncDataOperation
	channel chan common.GenesisSyncData
}

func NewSyncStorage(ctx context.Context, cfg config.GenesisConfig, sChan chan common.GenesisSyncData) *SyncStorage {
	sCtx, sCancel := context.WithCancel(ctx)
	return &SyncStorage{
		nodeIP:  os.Getenv(ccommon.NODE_IP_KEY),
		cfg:     cfg,
		sCtx:    sCtx,
		sCancel: sCancel,
		channel: sChan,
		data:    GenesisSyncDataOperation{},
	}
}

func (s *SyncStorage) Renew(orgID int, vtapID uint32, vtapKey string, refresh, wrEnabled bool, items common.GenesisSyncDataResponse) {
	s.data.VIPs.Renew(orgID, vtapID, vtapKey, items.VIPs)
	s.data.Processes.Renew(orgID, vtapID, vtapKey, items.Processes)
	s.data.Vinterfaces.Renew(orgID, vtapID, vtapKey, items.Vinterfaces)
	if wrEnabled {
		s.data.VMs.Renew(orgID, vtapID, vtapKey, items.VMs)
		s.data.VPCs.Renew(orgID, vtapID, vtapKey, items.VPCs)
		s.data.Hosts.Renew(orgID, vtapID, vtapKey, items.Hosts)
		s.data.Lldps.Renew(orgID, vtapID, vtapKey, items.Lldps)
		s.data.Ports.Renew(orgID, vtapID, vtapKey, items.Ports)
		s.data.Networks.Renew(orgID, vtapID, vtapKey, items.Networks)
		s.data.IPlastseens.Renew(orgID, vtapID, vtapKey, items.IPLastSeens)
	}

	if !refresh {
		return
	}
	db, err := metadb.GetDB(orgID)
	if err != nil {
		log.Errorf("get metadb session failed", logger.NewORGPrefix(orgID))
		return
	}
	err = db.Model(&model.GenesisStorage{}).Where("vtap_id = ? AND node_ip <> ?", vtapID, s.nodeIP).Update("node_ip", s.nodeIP).Error
	if err != nil {
		log.Warningf("vtap id (%d) refresh storage to node (%s) failed: %s", vtapID, s.nodeIP, err, logger.NewORGPrefix(orgID))
	}
}

func (s *SyncStorage) Update(orgID int, vtapID uint32, vtapKey string, items common.GenesisSyncDataResponse) {
	s.data.VIPs.Update(orgID, vtapID, vtapKey, items.VIPs)
	s.data.VMs.Update(orgID, vtapID, vtapKey, items.VMs)
	s.data.VPCs.Update(orgID, vtapID, vtapKey, items.VPCs)
	s.data.Hosts.Update(orgID, vtapID, vtapKey, items.Hosts)
	s.data.Lldps.Update(orgID, vtapID, vtapKey, items.Lldps)
	s.data.Ports.Update(orgID, vtapID, vtapKey, items.Ports)
	s.data.Networks.Update(orgID, vtapID, vtapKey, items.Networks)
	s.data.IPlastseens.Update(orgID, vtapID, vtapKey, items.IPLastSeens)
	s.data.Vinterfaces.Update(orgID, vtapID, vtapKey, items.Vinterfaces)
	s.data.Processes.Update(orgID, vtapID, vtapKey, items.Processes)

	// push immediately after update
	s.fetch()

	if vtapID == 0 {
		return
	}
	db, err := metadb.GetDB(orgID)
	if err != nil {
		log.Errorf("get metadb session failed: %s", err.Error(), logger.NewORGPrefix(orgID))
		return
	}
	err = db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "vtap_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"node_ip"}),
	}).Create(&model.GenesisStorage{
		VtapID: vtapID,
		NodeIP: s.nodeIP,
	}).Error
	if err != nil {
		log.Errorf("update storage (vtap_id:%d/node_ip:%s) failed: %s", vtapID, s.nodeIP, err.Error(), logger.NewORGPrefix(orgID))
		return
	}
}

func (s *SyncStorage) fetch() {
	s.channel <- common.GenesisSyncData{
		VIPs:        s.data.VIPs.Fetch(),
		VMs:         s.data.VMs.Fetch(),
		VPCs:        s.data.VPCs.Fetch(),
		Hosts:       s.data.Hosts.Fetch(),
		Ports:       s.data.Ports.Fetch(),
		Lldps:       s.data.Lldps.Fetch(),
		IPLastSeens: s.data.IPlastseens.Fetch(),
		Networks:    s.data.Networks.Fetch(),
		Vinterfaces: s.data.Vinterfaces.Fetch(),
		Processes:   s.data.Processes.Fetch(),
	}
}

func (s *SyncStorage) loadFromDatabase() {
	expired := int(s.cfg.AgingTime)
	interval := int(s.cfg.DataPersistenceInterval)
	s.data.VIPs = NewVIPPlatformDataOperation(s.nodeIP, expired, interval)
	s.data.VIPs.Load()

	s.data.VMs = NewVMPlatformDataOperation(s.nodeIP, expired, interval)
	s.data.VMs.Load()

	s.data.VPCs = NewVpcPlatformDataOperation(s.nodeIP, expired, interval)
	s.data.VPCs.Load()

	s.data.Hosts = NewHostPlatformDataOperation(s.nodeIP, expired, interval)
	s.data.Hosts.Load()

	s.data.Ports = NewPortPlatformDataOperation(s.nodeIP, expired, interval)
	s.data.Ports.Load()

	s.data.Lldps = NewLldpInfoPlatformDataOperation(s.nodeIP, expired, interval)
	s.data.Lldps.Load()

	s.data.IPlastseens = NewIPLastSeenPlatformDataOperation(s.nodeIP, expired, interval)
	s.data.IPlastseens.Load()

	s.data.Networks = NewNetworkPlatformDataOperation(s.nodeIP, expired, interval)
	s.data.Networks.Load()

	s.data.Vinterfaces = NewVinterfacePlatformDataOperation(s.nodeIP, expired, interval)
	s.data.Vinterfaces.Load()

	s.data.Processes = NewProcessPlatformDataOperation(s.nodeIP, expired, interval)
	s.data.Processes.Load()

	s.fetch()
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
		for _, orgID := range orgIDs {
			db, err := metadb.GetDB(orgID)
			if err != nil {
				log.Errorf("get metadb session failed: %s", err.Error(), logger.NewORGPrefix(orgID))
				continue
			}
			vTaps := []metadbmodel.VTap{}
			vTapIDs := map[int]bool{}
			storages := []model.GenesisStorage{}
			invalidStorages := []model.GenesisStorage{}
			db.Select("id").Find(&vTaps)
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
					log.Errorf("node (%s) clean genesis storage invalid data failed: %s", s.nodeIP, err, logger.NewORGPrefix(orgID))
				} else {
					log.Infof("node (%s) clean genesis storage invalid data success", s.nodeIP, logger.NewORGPrefix(orgID))
				}
			}
		}
	}
}

func (s *SyncStorage) onEvicted(k string, v interface{}) {
	s.fetch()

	keys := strings.Split(k, "-")
	orgID, err := strconv.Atoi(keys[0])
	if err != nil {
		log.Error(err.Error())
		return
	}
	db, err := metadb.GetDB(orgID)
	if err != nil {
		log.Errorf("get metadb session failed: %s", err.Error(), logger.NewORGPrefix(orgID))
		return
	}
	err = db.Delete(&v).Error
	if err != nil {
		log.Errorf("delete vtap (%s) stale data (%#v) failed: %s", k, v, err.Error(), logger.NewORGPrefix(orgID))
	}
}

func (s *SyncStorage) run() {
	s.loadFromDatabase()

	s.data.VMs.SetOnEvicted(s.onEvicted)
	s.data.VIPs.SetOnEvicted(s.onEvicted)
	s.data.VPCs.SetOnEvicted(s.onEvicted)
	s.data.Hosts.SetOnEvicted(s.onEvicted)
	s.data.Lldps.SetOnEvicted(s.onEvicted)
	s.data.Ports.SetOnEvicted(s.onEvicted)
	s.data.Networks.SetOnEvicted(s.onEvicted)
	s.data.Processes.SetOnEvicted(s.onEvicted)
	s.data.Vinterfaces.SetOnEvicted(s.onEvicted)
	s.data.IPlastseens.SetOnEvicted(s.onEvicted)
}

func (s *SyncStorage) Start() {
	go s.refreshDatabase()
	s.run()
}

func (s *SyncStorage) Stop() {
	if s.sCancel != nil {
		s.sCancel()
	}
}
