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
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type PodGroupPort struct {
	UpdaterBase[
		cloudmodel.PodGroupPort,
		mysql.PodGroupPort,
		*diffbase.PodGroupPort,
		*message.PodGroupPortAdd,
		message.PodGroupPortAdd,
		*message.PodGroupPortUpdate,
		message.PodGroupPortUpdate,
		*message.PodGroupPortFieldsUpdate,
		message.PodGroupPortFieldsUpdate,
		*message.PodGroupPortDelete,
		message.PodGroupPortDelete]
}

func NewPodGroupPort(wholeCache *cache.Cache, cloudData []cloudmodel.PodGroupPort) *PodGroupPort {
	updater := &PodGroupPort{
		newUpdaterBase[
			cloudmodel.PodGroupPort,
			mysql.PodGroupPort,
			*diffbase.PodGroupPort,
			*message.PodGroupPortAdd,
			message.PodGroupPortAdd,
			*message.PodGroupPortUpdate,
			message.PodGroupPortUpdate,
			*message.PodGroupPortFieldsUpdate,
			message.PodGroupPortFieldsUpdate,
			*message.PodGroupPortDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN,
			wholeCache,
			db.NewPodGroupPort(),
			wholeCache.DiffBaseDataSet.PodGroupPorts,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (p *PodGroupPort) getDiffBaseByCloudItem(cloudItem *cloudmodel.PodGroupPort) (diffBase *diffbase.PodGroupPort, exists bool) {
	diffBase, exists = p.diffBaseData[cloudItem.Lcuuid]
	return
}

func (p *PodGroupPort) generateDBItemToAdd(cloudItem *cloudmodel.PodGroupPort) (*mysql.PodGroupPort, bool) {
	podGroupID, exists := p.cache.ToolDataSet.GetPodGroupIDByLcuuid(cloudItem.PodGroupLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, cloudItem.PodGroupLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	podServiceID, exists := p.cache.ToolDataSet.GetPodServiceIDByLcuuid(cloudItem.PodServiceLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, cloudItem.PodServiceLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN, cloudItem.Lcuuid,
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

func (p *PodGroupPort) generateUpdateInfo(diffBase *diffbase.PodGroupPort, cloudItem *cloudmodel.PodGroupPort) (*message.PodGroupPortFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.PodGroupPortFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	return structInfo, mapInfo, len(mapInfo) > 0
}
