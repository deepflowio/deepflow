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
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
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
	nodeIP           string
	listenPort       int
	listenNodePort   int
	cfg              config.GenesisConfig
	kCtx             context.Context
	kCancel          context.CancelFunc
	channel          chan common.KubernetesInfo
	kubernetesData   map[string]common.KubernetesInfo
	clusterDestCache map[string]common.ClusterDest
	mutex            sync.RWMutex
	cacheMutex       sync.RWMutex
	cacheRunning     atomic.Bool
}

func NewKubernetesStorage(ctx context.Context, port, nPort int, cfg config.GenesisConfig, kChan chan common.KubernetesInfo) *KubernetesStorage {
	kCtx, kCancel := context.WithCancel(ctx)
	return &KubernetesStorage{
		nodeIP:           os.Getenv(ccommon.NODE_IP_KEY),
		listenPort:       port,
		listenNodePort:   nPort,
		cfg:              cfg,
		kCtx:             kCtx,
		kCancel:          kCancel,
		channel:          kChan,
		kubernetesData:   map[string]common.KubernetesInfo{},
		clusterDestCache: map[string]common.ClusterDest{},
		mutex:            sync.RWMutex{},
		cacheMutex:       sync.RWMutex{},
		cacheRunning:     atomic.Bool{},
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
	} else {
		data = newData
	}
	k.kubernetesData[key] = data

	k.mutex.Unlock()

	k.channel <- data

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
			log.Warningf("trigger cloud kubernetes refresh failed: (%s)", err.Error(), logger.NewORGPrefix(orgID))
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
	dest, ok := k.getDest(orgID, clusterID)
	if !ok {
		return fmt.Errorf("not found cluster (%s) dest info", clusterID)
	}

	requestUrl := "http://" + dest.Endpoint + "/v1/kubernetes-refresh/"
	queryStrings := map[string]string{
		"domain_lcuuid":     dest.DomainLcuuid,
		"sub_domain_lcuuid": dest.SubDomainLcuuid,
		"version":           fmt.Sprintf("%d", version),
	}

	log.Debugf("trigger cloud (%s) kubernetes (%s) refresh version (%d)", requestUrl, clusterID, version, logger.NewORGPrefix(orgID))

	return common.RequestGet(requestUrl, 30, queryStrings)
}

func (k *KubernetesStorage) getDest(orgID int, clusterID string) (common.ClusterDest, bool) {
	clusterKey := k.formatKey(orgID, clusterID)
	k.cacheMutex.RLock()
	dest, ok := k.clusterDestCache[clusterKey]
	k.cacheMutex.RUnlock()
	if ok {
		return dest, true
	}

	k.generateCache()

	k.cacheMutex.RLock()
	dest, ok = k.clusterDestCache[clusterKey]
	k.cacheMutex.RUnlock()
	return dest, ok
}

func (k *KubernetesStorage) generateCache() {
	if k.cacheRunning.Load() {
		return
	}

	k.cacheRunning.Swap(true)
	defer k.cacheRunning.Swap(false)

	cacheMap := map[string]common.ClusterDest{}
	for _, db := range metadb.GetDBs().All() {
		var controllers []metadbmodel.Controller
		err := db.Where("state <> ?", ccommon.CONTROLLER_STATE_EXCEPTION).Find(&controllers).Error
		if err != nil {
			log.Errorf("get controller failed: %s", err.Error(), logger.NewORGPrefix(db.ORGID))
			return
		}
		controllerIPToPodIP := map[string]string{}
		for _, controller := range controllers {
			if controller.PodIP == "" {
				log.Warningf("not found controller (%s) pod ip", controller.IP, logger.NewORGPrefix(db.ORGID))
			}
			controllerIPToPodIP[controller.IP] = controller.PodIP
		}

		var domains []metadbmodel.Domain
		err = db.Find(&domains).Error
		if err != nil {
			log.Errorf("get domain failed: %s", err.Error(), logger.NewORGPrefix(db.ORGID))
			return
		}
		lcuuidToDomain := map[string]metadbmodel.Domain{}
		for _, domain := range domains {
			if domain.Type != ccommon.KUBERNETES {
				lcuuidToDomain[domain.Lcuuid] = domain
				continue
			}
			var endpoint string
			podIP, ok := controllerIPToPodIP[domain.ControllerIP]
			if !ok {
				log.Warningf("domain (%s) controller ip (%s) not in controllers", domain.Name, domain.ControllerIP, logger.NewORGPrefix(db.ORGID))
				continue
			}
			if podIP != "" {
				endpoint = net.JoinHostPort(podIP, strconv.Itoa(k.listenPort))
			} else {
				endpoint = net.JoinHostPort(domain.ControllerIP, strconv.Itoa(k.listenNodePort))
			}
			cacheMap[k.formatKey(db.ORGID, domain.ClusterID)] = common.ClusterDest{
				Endpoint:        endpoint,
				DomainLcuuid:    domain.Lcuuid,
				SubDomainLcuuid: domain.Lcuuid,
			}
		}

		var subDomains []metadbmodel.SubDomain
		err = db.Find(&subDomains).Error
		if err != nil {
			log.Errorf("get subdomain failed: %s", err.Error(), logger.NewORGPrefix(db.ORGID))
			return
		}
		for _, subDomain := range subDomains {
			domain, ok := lcuuidToDomain[subDomain.Domain]
			if !ok {
				log.Warningf("subdomain (%s) not found domain", subDomain.Name, logger.NewORGPrefix(db.ORGID))
				continue
			}
			var endpoint string
			podIP, ok := controllerIPToPodIP[domain.ControllerIP]
			if !ok {
				log.Warningf("subdomain (%s) controller ip (%s) not in controllers", subDomain.Name, domain.ControllerIP, logger.NewORGPrefix(db.ORGID))
				continue
			}
			if podIP != "" {
				endpoint = net.JoinHostPort(podIP, strconv.Itoa(k.listenPort))
			} else {
				endpoint = net.JoinHostPort(domain.ControllerIP, strconv.Itoa(k.listenNodePort))
			}
			cacheMap[k.formatKey(db.ORGID, domain.ClusterID)] = common.ClusterDest{
				Endpoint:        endpoint,
				DomainLcuuid:    domain.Lcuuid,
				SubDomainLcuuid: subDomain.Lcuuid,
			}
		}
	}

	k.cacheMutex.Lock()
	k.clusterDestCache = cacheMap
	k.cacheMutex.Unlock()
}

func (k *KubernetesStorage) run() {
	ticker := time.NewTicker(time.Duration(k.cfg.DataPersistenceInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			go k.generateCache()

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

			if len(toDeleteKeys) == 0 {
				continue
			}

			k.mutex.Lock()
			for _, key := range toDeleteKeys {
				delete(k.kubernetesData, key)
			}
			k.mutex.Unlock()

			k.fetch()
		case <-k.kCtx.Done():
			return
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
