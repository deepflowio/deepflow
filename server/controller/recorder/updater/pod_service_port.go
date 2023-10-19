/*
 * Copyright (c) 2023 Yunshan Networks
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
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
)

type PodServicePort struct {
	UpdaterBase[cloudmodel.PodServicePort, mysql.PodServicePort, *cache.PodServicePort]
}

func NewPodServicePort(wholeCache *cache.Cache, cloudData []cloudmodel.PodServicePort) *PodServicePort {
	updater := &PodServicePort{
		UpdaterBase[cloudmodel.PodServicePort, mysql.PodServicePort, *cache.PodServicePort]{
			resourceType: ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_PORT_EN,
			cache:        wholeCache,
			dbOperator:   db.NewPodServicePort(),
			diffBaseData: wholeCache.PodServicePorts,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (s *PodServicePort) getDiffBaseByCloudItem(cloudItem *cloudmodel.PodServicePort) (diffBase *cache.PodServicePort, exists bool) {
	diffBase, exists = s.diffBaseData[cloudItem.Lcuuid]
	return
}

func (p *PodServicePort) generateDBItemToAdd(cloudItem *cloudmodel.PodServicePort) (*mysql.PodServicePort, bool) {
	podServiceID, exists := p.cache.ToolDataSet.GetPodServiceIDByLcuuid(cloudItem.PodServiceLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, cloudItem.PodServiceLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_PORT_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}

	dbItem := &mysql.PodServicePort{
		Name:         cloudItem.Name,
		Protocol:     cloudItem.Protocol,
		Port:         cloudItem.Port,
		TargetPort:   cloudItem.TargetPort,
		NodePort:     cloudItem.NodePort,
		PodServiceID: podServiceID,
		SubDomain:    cloudItem.SubDomainLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (p *PodServicePort) generateUpdateInfo(diffBase *cache.PodServicePort, cloudItem *cloudmodel.PodServicePort) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
