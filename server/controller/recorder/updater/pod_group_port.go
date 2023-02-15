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

package updater

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
)

type PodGroupPort struct {
	UpdaterBase[cloudmodel.PodGroupPort, mysql.PodGroupPort, *cache.PodGroupPort]
}

func NewPodGroupPort(wholeCache *cache.Cache, cloudData []cloudmodel.PodGroupPort) *PodGroupPort {
	updater := &PodGroupPort{
		UpdaterBase[cloudmodel.PodGroupPort, mysql.PodGroupPort, *cache.PodGroupPort]{
			cache:        wholeCache,
			dbOperator:   db.NewPodGroupPort(),
			diffBaseData: wholeCache.PodGroupPorts,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (p *PodGroupPort) getDiffBaseByCloudItem(cloudItem *cloudmodel.PodGroupPort) (diffBase *cache.PodGroupPort, exists bool) {
	diffBase, exists = p.diffBaseData[cloudItem.Lcuuid]
	return
}

func (p *PodGroupPort) generateDBItemToAdd(cloudItem *cloudmodel.PodGroupPort) (*mysql.PodGroupPort, bool) {
	podGroupID, exists := p.cache.ToolDataSet.GetPodGroupIDByLcuuid(cloudItem.PodGroupLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_POD_GROUP_EN, cloudItem.PodGroupLcuuid,
			common.RESOURCE_TYPE_POD_GROUP_PORT_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	podServiceID, exists := p.cache.ToolDataSet.GetPodServiceIDByLcuuid(cloudItem.PodServiceLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_POD_SERVICE_EN, cloudItem.PodServiceLcuuid,
			common.RESOURCE_TYPE_POD_GROUP_PORT_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}

	dbItem := &mysql.PodGroupPort{
		Name:         cloudItem.Name,
		Protocol:     cloudItem.Protocol,
		Port:         cloudItem.Port,
		PodServiceID: podServiceID,
		PodGroupID:   podGroupID,
		SubDomain:    cloudItem.SubDomainLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (p *PodGroupPort) generateUpdateInfo(diffBase *cache.PodGroupPort, cloudItem *cloudmodel.PodGroupPort) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	return updateInfo, len(updateInfo) > 0
}

func (p *PodGroupPort) addCache(dbItems []*mysql.PodGroupPort) {
	p.cache.AddPodGroupPorts(dbItems)
}

func (p *PodGroupPort) updateCache(cloudItem *cloudmodel.PodGroupPort, diffBase *cache.PodGroupPort) {
	diffBase.Update(cloudItem)
}

func (p *PodGroupPort) deleteCache(lcuuids []string) {
	p.cache.DeletePodGroupPorts(lcuuids)
}
