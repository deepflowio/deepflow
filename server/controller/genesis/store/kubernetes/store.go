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
	"strconv"
	"sync"
	"time"

	ccommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/genesis/common"
	"github.com/deepflowio/deepflow/server/controller/genesis/config"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

type KubernetesStorage struct {
	listenPort     int
	listenNodePort int
	cfg            config.GenesisConfig
	kCtx           context.Context
	kCancel        context.CancelFunc
	channel        chan common.KubernetesInfo
	kubernetesData map[int]map[string]common.KubernetesInfo
	mutex          sync.Mutex
}

func NewKubernetesStorage(ctx context.Context, port, nPort int, cfg config.GenesisConfig, kChan chan common.KubernetesInfo) *KubernetesStorage {
	kCtx, kCancel := context.WithCancel(ctx)
	return &KubernetesStorage{
		listenPort:     port,
		listenNodePort: nPort,
		cfg:            cfg,
		kCtx:           kCtx,
		kCancel:        kCancel,
		channel:        kChan,
		kubernetesData: map[int]map[string]common.KubernetesInfo{},
		mutex:          sync.Mutex{},
	}
}

func (k *KubernetesStorage) Clear() {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	k.kubernetesData = map[int]map[string]common.KubernetesInfo{}
}

func (k *KubernetesStorage) Add(orgID int, newInfo common.KubernetesInfo) {
	k.mutex.Lock()
	unTriggerFlag := false
	kubernetesData, ok := k.kubernetesData[orgID]
	if ok {
		// 上报消息中version未变化时，只更新epoch和error_msg
		if oldInfo, ok := kubernetesData[newInfo.ClusterID]; ok && oldInfo.Version == newInfo.Version {
			unTriggerFlag = true
			oldInfo.Epoch = newInfo.Epoch
			oldInfo.ErrorMSG = newInfo.ErrorMSG
			kubernetesData[newInfo.ClusterID] = oldInfo
		} else {
			kubernetesData[newInfo.ClusterID] = newInfo
		}
	} else {
		k.kubernetesData[orgID] = map[string]common.KubernetesInfo{
			newInfo.ClusterID: newInfo,
		}
	}
	k.fetch()
	k.mutex.Unlock()

	if !unTriggerFlag {
		err := k.triggerCloudRrefresh(orgID, newInfo.ClusterID, newInfo.Version)
		if err != nil {
			log.Warning(fmt.Sprintf("trigger cloud kubernetes refresh failed: (%s)", err.Error()), logger.NewORGPrefix(orgID))
		}
	}
}

func (k *KubernetesStorage) fetch() {
	for _, k8sDatas := range k.kubernetesData {
		for _, kData := range k8sDatas {
			k.channel <- kData
		}
	}
}

func (k *KubernetesStorage) triggerCloudRrefresh(orgID int, clusterID string, version uint64) error {
	var controllerIP, domainLcuuid, subDomainLcuuid string

	db, err := metadb.GetDB(orgID)
	if err != nil {
		log.Error("get metadb session failed", logger.NewORGPrefix(orgID))
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
		err = db.Where("lcuuid = ? AND type = ?", subDomains[0].Domain, ccommon.KUBERNETES).First(&domain).Error
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
		k.mutex.Lock()
		for _, kubernetesData := range k.kubernetesData {
			for key, s := range kubernetesData {
				if now.Sub(s.Epoch) <= time.Duration(k.cfg.AgingTime)*time.Second {
					continue
				}
				delete(kubernetesData, key)
			}
		}
		k.fetch()
		k.mutex.Unlock()
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
