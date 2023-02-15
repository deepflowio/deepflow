/*
 * Copyright (c) 2022 Yunshan Networks
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
	"context"
	"os"
	"sync"
	"time"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/genesis/config"
	"github.com/deepflowio/deepflow/server/controller/model"
)

type SyncStorage struct {
	cfg             config.GenesisConfig
	vCtx            context.Context
	vCancel         context.CancelFunc
	channel         chan GenesisSyncData
	dirty           bool
	mutex           sync.Mutex
	genesisSyncInfo GenesisSyncDataOperation
}

func NewSyncStorage(cfg config.GenesisConfig, sChan chan GenesisSyncData, ctx context.Context) *SyncStorage {
	vCtx, vCancel := context.WithCancel(ctx)
	return &SyncStorage{
		cfg:             cfg,
		vCtx:            vCtx,
		vCancel:         vCancel,
		channel:         sChan,
		dirty:           false,
		mutex:           sync.Mutex{},
		genesisSyncInfo: GenesisSyncDataOperation{},
	}
}

func (s *SyncStorage) Renew(data GenesisSyncDataOperation) {
	now := time.Now()
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if data.VMs != nil {
		s.genesisSyncInfo.VMs.Renew(data.VMs.Fetch(), now)
	}
	if data.VPCs != nil {
		s.genesisSyncInfo.VPCs.Renew(data.VPCs.Fetch(), now)
	}
	if data.Hosts != nil {
		s.genesisSyncInfo.Hosts.Renew(data.Hosts.Fetch(), now)
	}
	if data.Lldps != nil {
		s.genesisSyncInfo.Lldps.Renew(data.Lldps.Fetch(), now)
	}
	if data.Ports != nil {
		s.genesisSyncInfo.Ports.Renew(data.Ports.Fetch(), now)
	}
	if data.Networks != nil {
		s.genesisSyncInfo.Networks.Renew(data.Networks.Fetch(), now)
	}
	if data.IPlastseens != nil {
		s.genesisSyncInfo.IPlastseens.Renew(data.IPlastseens.Fetch(), now)
	}
	if data.Vinterfaces != nil {
		s.genesisSyncInfo.Vinterfaces.Renew(data.Vinterfaces.Fetch(), now)
	}
	if data.Processes != nil {
		s.genesisSyncInfo.Processes.Renew(data.Processes.Fetch(), now)
	}
}

func (s *SyncStorage) Update(data GenesisSyncDataOperation, vtapID uint32) {
	now := time.Now()
	s.mutex.Lock()
	defer s.mutex.Unlock()

	updateFlag := false
	if data.VMs != nil {
		updateFlag = true
		s.genesisSyncInfo.VMs.Update(data.VMs.Fetch(), now)
	}
	if data.VPCs != nil {
		updateFlag = true
		s.genesisSyncInfo.VPCs.Update(data.VPCs.Fetch(), now)
	}
	if data.Hosts != nil {
		updateFlag = true
		s.genesisSyncInfo.Hosts.Update(data.Hosts.Fetch(), now)
	}
	if data.Lldps != nil {
		updateFlag = true
		s.genesisSyncInfo.Lldps.Update(data.Lldps.Fetch(), now)
	}
	if data.Ports != nil {
		updateFlag = true
		s.genesisSyncInfo.Ports.Update(data.Ports.Fetch(), now)
	}
	if data.Networks != nil {
		updateFlag = true
		s.genesisSyncInfo.Networks.Update(data.Networks.Fetch(), now)
	}
	if data.IPlastseens != nil {
		updateFlag = true
		s.genesisSyncInfo.IPlastseens.Update(data.IPlastseens.Fetch(), now)
	}
	if data.Vinterfaces != nil {
		updateFlag = true
		s.genesisSyncInfo.Vinterfaces.Update(data.Vinterfaces.Fetch(), now)
	}
	if data.Processes != nil {
		updateFlag = true
		s.genesisSyncInfo.Processes.Update(data.Processes.Fetch(), now)
	}
	if updateFlag && vtapID != 0 {
		// push immediately after update
		s.fetch()

		var storages []model.GenesisStorage
		mysql.Db.Where("vtap_id = ?", vtapID).Find(&storages)
		if len(storages) > 0 {
			mysql.Db.Model(&model.GenesisStorage{}).Where("vtap_id = ?", vtapID).Update("node_ip", os.Getenv(common.NODE_IP_KEY))
		} else {
			mysql.Db.Create(&model.GenesisStorage{VtapID: vtapID, NodeIP: os.Getenv(common.NODE_IP_KEY)})
		}
	}
	s.dirty = true
}

func (s *SyncStorage) fetch() {
	s.channel <- GenesisSyncData{
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
	var vms []model.GenesisVM
	var vpcs []model.GenesisVpc
	var hosts []model.GenesisHost
	var ports []model.GenesisPort
	var lldps []model.GenesisLldp
	var ipLastSeens []model.GenesisIP
	var networks []model.GenesisNetwork
	var vinterfaces []model.GenesisVinterface
	var processes []model.GenesisProcess

	s.genesisSyncInfo.VMs = NewVMPlatformDataOperation(vms)
	s.genesisSyncInfo.VMs.Load(now, ageTime)

	s.genesisSyncInfo.VPCs = NewVpcPlatformDataOperation(vpcs)
	s.genesisSyncInfo.VPCs.Load(now, ageTime)

	s.genesisSyncInfo.Hosts = NewHostPlatformDataOperation(hosts)
	s.genesisSyncInfo.Hosts.Load(now, ageTime)

	s.genesisSyncInfo.Ports = NewPortPlatformDataOperation(ports)
	s.genesisSyncInfo.Ports.Load(now, ageTime)

	s.genesisSyncInfo.Lldps = NewLldpInfoPlatformDataOperation(lldps)
	s.genesisSyncInfo.Lldps.Load(now, ageTime)

	s.genesisSyncInfo.IPlastseens = NewIPLastSeenPlatformDataOperation(ipLastSeens)
	s.genesisSyncInfo.IPlastseens.Load(now, ageTime)

	s.genesisSyncInfo.Networks = NewNetworkPlatformDataOperation(networks)
	s.genesisSyncInfo.Networks.Load(now, ageTime)

	s.genesisSyncInfo.Vinterfaces = NewVinterfacePlatformDataOperation(vinterfaces)
	s.genesisSyncInfo.Vinterfaces.Load(now, ageTime)

	s.genesisSyncInfo.Processes = NewProcessPlatformDataOperation(processes)
	s.genesisSyncInfo.Processes.Load(now, ageTime)

	s.fetch()
}

func (s *SyncStorage) storeToDatabase() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

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

func (s *SyncStorage) refreshDatabase(ageTime time.Duration) {
	for {
		// clean genesis storage invalid data
		vTaps := []mysql.VTap{}
		vTapIDs := map[int]bool{}
		storages := []model.GenesisStorage{}
		invalidStorages := []model.GenesisStorage{}
		mysql.Db.Find(&vTaps)
		mysql.Db.Where("node_ip = ?", os.Getenv(common.NODE_IP_KEY)).Find(&storages)
		for _, v := range vTaps {
			vTapIDs[v.ID] = false
		}
		for _, s := range storages {
			if _, ok := vTapIDs[int(s.VtapID)]; !ok {
				invalidStorages = append(invalidStorages, s)
			}
		}
		if len(invalidStorages) > 0 {
			err := mysql.Db.Delete(&invalidStorages).Error
			if err != nil {
				log.Errorf("clean genesis storage invalid data failed: %s", err)
			} else {
				log.Info("clean genesis storage invalid data success")
			}
		}

		time.Sleep(ageTime)
		s.dirty = true
	}
}

func (s *SyncStorage) run() {
	ageTime := time.Duration(s.cfg.AgingTime) * time.Second
	// 启动时先从数据库恢复数据
	s.loadFromDatabase(ageTime)
	// 每个老化周期刷新一次数据库
	go s.refreshDatabase(ageTime)

	for {
		time.Sleep(time.Duration(s.cfg.DataPersistenceInterval) * time.Second)
		now := time.Now()
		hasChange := false
		s.mutex.Lock()
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
	go s.run()
}

func (s *SyncStorage) Stop() {
	if s.vCancel != nil {
		s.vCancel()
	}
}

type KubernetesStorage struct {
	cfg            config.GenesisConfig
	kCtx           context.Context
	kCancel        context.CancelFunc
	channel        chan map[string]KubernetesInfo
	kubernetesData map[string]KubernetesInfo
	mutex          sync.Mutex
}

func NewKubernetesStorage(cfg config.GenesisConfig, kChan chan map[string]KubernetesInfo, ctx context.Context) *KubernetesStorage {
	kCtx, kCancel := context.WithCancel(ctx)
	return &KubernetesStorage{
		cfg:            cfg,
		kCtx:           kCtx,
		kCancel:        kCancel,
		channel:        kChan,
		kubernetesData: map[string]KubernetesInfo{},
		mutex:          sync.Mutex{},
	}
}

func (k *KubernetesStorage) Clear() {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	k.kubernetesData = map[string]KubernetesInfo{}
}

func (k *KubernetesStorage) Add(k8sInfo KubernetesInfo) {
	k.mutex.Lock()
	kInfo, ok := k.kubernetesData[k8sInfo.ClusterID]
	// trident上报消息中version未变化时，只更新epoch和error_msg
	if ok && kInfo.Version == k8sInfo.Version {
		kInfo.Epoch = time.Now()
		kInfo.ErrorMSG = k8sInfo.ErrorMSG
		k.kubernetesData[k8sInfo.ClusterID] = kInfo
	} else {
		k.kubernetesData[k8sInfo.ClusterID] = k8sInfo
	}
	k.mutex.Unlock()

	result, err := k.fetch()
	if err == nil {
		k.channel <- result
	}
}

func (k *KubernetesStorage) fetch() (map[string]KubernetesInfo, error) {
	return k.kubernetesData, nil
}

func (k *KubernetesStorage) run() {
	for {
		time.Sleep(time.Duration(k.cfg.DataPersistenceInterval) * time.Second)
		now := time.Now()
		k.mutex.Lock()
		for key, s := range k.kubernetesData {
			if now.Sub(s.Epoch) <= time.Duration(k.cfg.AgingTime)*time.Second {
				continue
			}
			delete(k.kubernetesData, key)
		}
		k.mutex.Unlock()
		result, err := k.fetch()
		if err == nil {
			k.channel <- result
		}
	}
}

func (k *KubernetesStorage) Start() {
	go k.run()
}

func (k *KubernetesStorage) Stop() {
	if k.kCancel != nil {
		k.kCancel()
	}
}
