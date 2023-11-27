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

type PodIngress struct {
	UpdaterBase[
		cloudmodel.PodIngress,
		mysql.PodIngress,
		*diffbase.PodIngress,
		*message.PodIngressAdd,
		message.PodIngressAdd,
		*message.PodIngressUpdate,
		message.PodIngressUpdate,
		*message.PodIngressFieldsUpdate,
		message.PodIngressFieldsUpdate,
		*message.PodIngressDelete,
		message.PodIngressDelete]
}

func NewPodIngress(wholeCache *cache.Cache, cloudData []cloudmodel.PodIngress) *PodIngress {
	updater := &PodIngress{
		newUpdaterBase[
			cloudmodel.PodIngress,
			mysql.PodIngress,
			*diffbase.PodIngress,
			*message.PodIngressAdd,
			message.PodIngressAdd,
			*message.PodIngressUpdate,
			message.PodIngressUpdate,
			*message.PodIngressFieldsUpdate,
			message.PodIngressFieldsUpdate,
			*message.PodIngressDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN,
			wholeCache,
			db.NewPodIngress(),
			wholeCache.DiffBaseDataSet.PodIngresses,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (i *PodIngress) getDiffBaseByCloudItem(cloudItem *cloudmodel.PodIngress) (diffBase *diffbase.PodIngress, exists bool) {
	diffBase, exists = i.diffBaseData[cloudItem.Lcuuid]
	return
}

func (i *PodIngress) generateDBItemToAdd(cloudItem *cloudmodel.PodIngress) (*mysql.PodIngress, bool) {
	podNamespaceID, exists := i.cache.ToolDataSet.GetPodNamespaceIDByLcuuid(cloudItem.PodNamespaceLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, cloudItem.PodNamespaceLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	podClusterID, exists := i.cache.ToolDataSet.GetPodClusterIDByLcuuid(cloudItem.PodClusterLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, cloudItem.PodClusterLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	dbItem := &mysql.PodIngress{
		Name:           cloudItem.Name,
		PodNamespaceID: podNamespaceID,
		PodClusterID:   podClusterID,
		SubDomain:      cloudItem.SubDomainLcuuid,
		Domain:         i.cache.DomainLcuuid,
		Region:         cloudItem.RegionLcuuid,
		AZ:             cloudItem.AZLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (i *PodIngress) generateUpdateInfo(diffBase *diffbase.PodIngress, cloudItem *cloudmodel.PodIngress) (*message.PodIngressFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.PodIngressFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		mapInfo["region"] = cloudItem.RegionLcuuid
		structInfo.RegionLcuuid.Set(diffBase.RegionLcuuid, cloudItem.RegionLcuuid)
	}
	if diffBase.AZLcuuid != cloudItem.AZLcuuid {
		mapInfo["az"] = cloudItem.AZLcuuid
		structInfo.AZLcuuid.Set(diffBase.AZLcuuid, cloudItem.AZLcuuid)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
