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

package kubernetes

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/op/go-logging"
	"gorm.io/gorm"

	. "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	models "github.com/deepflowio/deepflow/server/controller/db/mysql"
	resourceservice "github.com/deepflowio/deepflow/server/controller/http/service/resource"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/config"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/dbmgr"
)

var log = logging.MustGetLogger("trisolaris.kubernetes")

type KubernetesInfo struct {
	mutex                sync.RWMutex
	clusterIDToDomain    map[string]string
	clusterIDToSubDomain map[string]string
	db                   *gorm.DB
	cfg                  *config.Config
}

func NewKubernetesInfo(db *gorm.DB, cfg *config.Config) *KubernetesInfo {
	return &KubernetesInfo{
		cfg:                  cfg,
		db:                   db,
		clusterIDToDomain:    make(map[string]string),
		clusterIDToSubDomain: make(map[string]string),
	}
}

func (k *KubernetesInfo) TimedRefreshClusterID() {
	ticker := time.NewTicker(time.Duration(60) * time.Second).C
	for {
		k.refresh()
		select {
		case <-ticker:
			k.refresh()
		}
	}
}

func (k *KubernetesInfo) refresh() {
	log.Infof("refresh cache cluster_id started")
	k.mutex.Lock()
	defer k.mutex.Unlock()
	domainMgr := dbmgr.DBMgr[models.Domain](k.db)
	dbDomains, _ := domainMgr.GetBatchFromTypes([]int{KUBERNETES})
	clusterIDToDomain := make(map[string]string)
	for _, dbDomain := range dbDomains {
		clusterIDToDomain[dbDomain.ClusterID] = dbDomain.Lcuuid
	}
	k.clusterIDToDomain = clusterIDToDomain

	subDomainMgr := dbmgr.DBMgr[models.SubDomain](k.db)
	subDomains, _ := subDomainMgr.Gets()
	clusterIDToSubDomain := make(map[string]string)
	for _, sd := range subDomains {
		clusterIDToSubDomain[sd.ClusterID] = sd.Lcuuid
	}
	k.clusterIDToSubDomain = clusterIDToSubDomain
	log.Infof("refresh cache cluster_id completed")
	log.Debugf("cluster_id domain map: %v, sub_domain map: %v", k.clusterIDToDomain, k.clusterIDToSubDomain)
	return
}

func (k *KubernetesInfo) CreateDomainIfClusterIDNotExists(clusterID, clusterName string) (exists bool) {
	ok, err := k.CheckClusterID(clusterID)
	if err != nil {
		log.Errorf("check cluster_id: %s failed: %s", clusterID, err)
		return true
	}
	if !ok {
		k.CacheClusterID(clusterID, clusterName)
		return false
	}
	return true
}

func (k *KubernetesInfo) CheckClusterID(clusterID string) (bool, error) {
	k.mutex.Lock()
	defer k.mutex.Unlock()
	_, dok := k.clusterIDToDomain[clusterID]
	_, sdok := k.clusterIDToSubDomain[clusterID]
	ok := dok || sdok
	if !ok {
		log.Warningf("cluster_id: %s not found in cache, domain map: %v, sub_domain map: %v", clusterID, k.clusterIDToDomain, k.clusterIDToSubDomain)
		var domain mysql.Domain
		dResult := k.db.Where("cluster_id = ?", clusterID).Find(&domain)
		if dResult.RowsAffected > 0 {
			k.clusterIDToDomain[clusterID] = domain.Lcuuid
			return true, nil
		}
		if dResult.Error != nil {
			return false, errors.New(fmt.Sprintf("query domain from db failed: %s", dResult.Error.Error()))
		}

		var subDomain mysql.SubDomain
		sdResult := k.db.Where("cluster_id = ?", clusterID).Find(&subDomain)
		if sdResult.RowsAffected > 0 {
			k.clusterIDToSubDomain[clusterID] = subDomain.Lcuuid
			return true, nil
		}
		if sdResult.Error != nil {
			return false, errors.New(fmt.Sprintf("query sub_domain from db failed: %s", sdResult.Error.Error()))
		}
		log.Warningf("cluster_id: %s not found in db", clusterID)
	}
	return ok, nil
}

func (k *KubernetesInfo) CacheClusterID(clusterID, clusterName string) {
	log.Infof("start cache cluster_id: %s, cluster_name: %s", clusterID, clusterName)
	k.mutex.Lock()
	defer k.mutex.Unlock()
	_, ok := k.clusterIDToDomain[clusterID]
	if !ok {
		k.clusterIDToDomain[clusterID] = ""
		log.Infof("cache cluster_id: %s, cluster_name: %s", clusterID, clusterName)
		go func() {
			for k.clusterIDToDomain[clusterID] == "" {
				domainLcuuid, err := k.createDomain(clusterID, clusterName)
				if err != nil {
					log.Errorf("auto create domain failed: %s, try again after 3s", err.Error())
					time.Sleep(time.Second * 3)
				} else {
					k.clusterIDToDomain[clusterID] = domainLcuuid
				}
			}
		}()
	}
	return
}

func (k *KubernetesInfo) createDomain(clusterID, clusterName string) (domainLcuuid string, err error) {
	log.Infof("auto create domain with cluster_id: %s, cluster_name: %s", clusterID, clusterName)
	azConMgr := dbmgr.DBMgr[models.AZControllerConnection](k.db)
	azConn, err := azConMgr.GetFromControllerIP(k.cfg.NodeIP)
	if err != nil {
		log.Errorf("get az controller connection (node_ip: %s) from db failed: %s", k.cfg.NodeIP, err.Error())
		return "", err
	}
	domainConf := map[string]interface{}{
		"controller_ip":              k.cfg.NodeIP,
		"pod_net_ipv4_cidr_max_mask": 16,
		"pod_net_ipv6_cidr_max_mask": 64,
		"port_name_regex":            DEFAULT_PORT_NAME_REGEX,
		"region_uuid":                azConn.Region,
		"vtap_id":                    "",
	}
	var name string
	if clusterName != "" {
		name = clusterName
	} else {
		name = "k8s-" + clusterID
	}
	domainCreate := model.DomainCreate{
		Name:                name,
		Type:                KUBERNETES,
		KubernetesClusterID: clusterID,
		ControllerIP:        k.cfg.NodeIP,
		Config:              domainConf,
		// icon id value only for enterprise edition
		IconID: DomainTypeToIconID[KUBERNETES],
	}
	domain, err := resourceservice.CreateDomain(domainCreate, nil)
	if err != nil {
		log.Errorf("create domain failed: %s", err.Error())
		return "", err
	}
	return domain.Lcuuid, nil
}
