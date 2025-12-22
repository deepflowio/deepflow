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

package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	ccommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/genesis/common"
	"github.com/deepflowio/deepflow/server/controller/genesis/config"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/libs/logger"
	"gorm.io/gorm/clause"
)

type KubernetesStorage struct {
	nodeIP         string
	listenPort     int
	listenNodePort int
	cfg            config.GenesisConfig
	kCtx           context.Context
	kCancel        context.CancelFunc
	channel        chan common.KubernetesInfo
	kubernetesData map[string]common.KubernetesInfo
	mutex          sync.RWMutex
}

func NewKubernetesStorage(ctx context.Context, port, nPort int, cfg config.GenesisConfig, kChan chan common.KubernetesInfo) *KubernetesStorage {
	kCtx, kCancel := context.WithCancel(ctx)
	return &KubernetesStorage{
		nodeIP:         os.Getenv(ccommon.NODE_IP_KEY),
		listenPort:     port,
		listenNodePort: nPort,
		cfg:            cfg,
		kCtx:           kCtx,
		kCancel:        kCancel,
		channel:        kChan,
		kubernetesData: map[string]common.KubernetesInfo{},
		mutex:          sync.RWMutex{},
	}
}

func (k *KubernetesStorage) Clear() {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	k.kubernetesData = map[string]common.KubernetesInfo{}
}

func (k *KubernetesStorage) formatKey(orgID int, clusterID string) string {
	return fmt.Sprintf("%d-%s", orgID, clusterID)
}

func (k *KubernetesStorage) CheckVersion(orgID int, clusterID string, version uint64) bool {
	k.mutex.RLock()
	defer k.mutex.RUnlock()

	key := k.formatKey(orgID, clusterID)
	data, ok := k.kubernetesData[key]
	if !ok {
		return false
	}
	return data.Version == version
}

func (k *KubernetesStorage) Add(orgID int, newData common.KubernetesInfo) {
	k.mutex.Lock()
	key := k.formatKey(orgID, newData.ClusterID)
	unTriggerFlag := false
	data, ok := k.kubernetesData[key]
	// when version unchanged in the reported message, only update epoch and error_msg
	if ok && data.Version == newData.Version {
		unTriggerFlag = true
		data.Epoch = newData.Epoch
		data.ErrorMSG = newData.ErrorMSG
		k.kubernetesData[key] = data
	} else {
		k.kubernetesData[key] = newData
	}
	k.mutex.Unlock()

	k.fetch()

	db, err := metadb.GetDB(orgID)
	if err != nil {
		log.Errorf("get metadb session failed: %s", err.Error(), logger.NewORGPrefix(orgID))
		return
	}
	err = db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"node_ip"}),
	}).Create(&model.GenesisCluster{
		ID:     newData.ClusterID,
		NodeIP: k.nodeIP,
	}).Error
	if err != nil {
		log.Errorf("update cluster (id:%s/node_ip:%s) failed: %s", newData.ClusterID, k.nodeIP, err.Error(), logger.NewORGPrefix(orgID))
		return
	}

	if !unTriggerFlag {
		err = k.triggerCloudRefresh(orgID, newData.ClusterID, newData.Version)
		if err != nil {
			log.Warning(fmt.Sprintf("trigger cloud kubernetes refresh failed: (%s)", err.Error()), logger.NewORGPrefix(orgID))
		}
	}
}

func (k *KubernetesStorage) fetch() {
	k.mutex.RLock()
	defer k.mutex.RUnlock()
	for _, data := range k.kubernetesData {
		k.channel <- data
	}
}

func (k *KubernetesStorage) triggerCloudRefresh(orgID int, clusterID string, version uint64) error {
	var controllerIP, domainLcuuid, subDomainLcuuid string

	db, err := metadb.GetDB(orgID)
	if err != nil {
		log.Errorf("get metadb session failed: %s", err.Error(), logger.NewORGPrefix(orgID))
		return err
	}

	var subDomains []metadbmodel.SubDomain
	err = db.Where("cluster_id = ?", clusterID).Find(&subDomains).Error
	if err != nil {
		return err
	}
	var domain metadbmodel.Domain
	switch len(subDomains) {
	case 0:
		err = db.Where("cluster_id = ? AND type = ?", clusterID, ccommon.KUBERNETES).First(&domain).Error
		if err != nil {
			return err
		}
		controllerIP = domain.ControllerIP
		domainLcuuid = domain.Lcuuid
		subDomainLcuuid = domain.Lcuuid
	case 1:
		err = db.Where("lcuuid = ?", subDomains[0].Domain).First(&domain).Error
		if err != nil {
			return err
		}
		controllerIP = domain.ControllerIP
		domainLcuuid = domain.Lcuuid
		subDomainLcuuid = subDomains[0].Lcuuid
	default:
		return errors.New(fmt.Sprintf("cluster_id (%s) is not unique in metadb table sub_domain", clusterID))
	}

	var controller metadbmodel.Controller
	err = db.Where("ip = ? AND state <> ?", controllerIP, ccommon.CONTROLLER_STATE_EXCEPTION).First(&controller).Error
	if err != nil {
		return err
	}
	requestIP := controllerIP
	requestPort := k.listenNodePort
	if controller.PodIP != "" {
		requestIP = controller.PodIP
		requestPort = k.listenPort
	}

	requestUrl := "http://" + net.JoinHostPort(requestIP, strconv.Itoa(requestPort)) + "/v1/kubernetes-refresh/"
	queryStrings := map[string]string{
		"domain_lcuuid":     domainLcuuid,
		"sub_domain_lcuuid": subDomainLcuuid,
		"version":           strconv.Itoa(int(version)),
	}

	log.Debugf("trigger cloud (%s) kubernetes (%s) refresh version (%d)", requestUrl, clusterID, version, logger.NewORGPrefix(orgID))

	return common.RequestGet(requestUrl, 30, queryStrings)
}

func (k *KubernetesStorage) run() {
	for {
		time.Sleep(time.Duration(k.cfg.DataPersistenceInterval) * time.Second)

		now := time.Now()
		k.mutex.RLock()
		toDeleteKeys := []string{}
		for key, data := range k.kubernetesData {
			if now.Sub(data.Epoch) <= time.Duration(k.cfg.AgingTime)*time.Second {
				continue
			}
			toDeleteKeys = append(toDeleteKeys, key)
		}
		k.mutex.RUnlock()

		k.mutex.Lock()
		for _, key := range toDeleteKeys {
			delete(k.kubernetesData, key)
		}
		k.mutex.Unlock()

		k.fetch()
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
