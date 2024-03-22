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

type PodService struct {
	UpdaterBase[
		cloudmodel.PodService,
		mysql.PodService,
		*diffbase.PodService,
		*message.PodServiceAdd,
		message.PodServiceAdd,
		*message.PodServiceUpdate,
		message.PodServiceUpdate,
		*message.PodServiceFieldsUpdate,
		message.PodServiceFieldsUpdate,
		*message.PodServiceDelete,
		message.PodServiceDelete]
}

func NewPodService(wholeCache *cache.Cache, cloudData []cloudmodel.PodService) *PodService {
	updater := &PodService{
		newUpdaterBase[
			cloudmodel.PodService,
			mysql.PodService,
			*diffbase.PodService,
			*message.PodServiceAdd,
			message.PodServiceAdd,
			*message.PodServiceUpdate,
			message.PodServiceUpdate,
			*message.PodServiceFieldsUpdate,
			message.PodServiceFieldsUpdate,
			*message.PodServiceDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN,
			wholeCache,
			db.NewPodService().SetORG(wholeCache.GetORG()),
			wholeCache.DiffBaseDataSet.PodServices,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (s *PodService) getDiffBaseByCloudItem(cloudItem *cloudmodel.PodService) (diffBase *diffbase.PodService, exists bool) {
	diffBase, exists = s.diffBaseData[cloudItem.Lcuuid]
	return
}

func (s *PodService) generateDBItemToAdd(cloudItem *cloudmodel.PodService) (*mysql.PodService, bool) {
	vpcID, exists := s.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	podNamespaceID, exists := s.cache.ToolDataSet.GetPodNamespaceIDByLcuuid(cloudItem.PodNamespaceLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, cloudItem.PodNamespaceLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, cloudItem.Lcuuid,
		))
	}
	podClusterID, exists := s.cache.ToolDataSet.GetPodClusterIDByLcuuid(cloudItem.PodClusterLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, cloudItem.PodClusterLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	var podIngressID int
	if cloudItem.PodIngressLcuuid != "" {
		podIngressID, exists = s.cache.ToolDataSet.GetPodIngressIDByLcuuid(cloudItem.PodIngressLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, cloudItem.PodIngressLcuuid,
				ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, cloudItem.Lcuuid,
			))
			return nil, false
		}
	}
	dbItem := &mysql.PodService{
		Name:             cloudItem.Name,
		Label:            cloudItem.Label,
		Annotation:       cloudItem.Annotation,
		Type:             cloudItem.Type,
		Selector:         cloudItem.Selector,
		ServiceClusterIP: cloudItem.ServiceClusterIP,
		PodIngressID:     podIngressID,
		PodNamespaceID:   podNamespaceID,
		PodClusterID:     podClusterID,
		SubDomain:        cloudItem.SubDomainLcuuid,
		Domain:           s.cache.DomainLcuuid,
		Region:           cloudItem.RegionLcuuid,
		AZ:               cloudItem.AZLcuuid,
		VPCID:            vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (s *PodService) generateUpdateInfo(diffBase *diffbase.PodService, cloudItem *cloudmodel.PodService) (*message.PodServiceFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.PodServiceFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.PodIngressLcuuid != cloudItem.PodIngressLcuuid {
		var podIngressID int
		if cloudItem.PodIngressLcuuid != "" {
			var exists bool
			podIngressID, exists = s.cache.ToolDataSet.GetPodIngressIDByLcuuid(cloudItem.PodIngressLcuuid)
			if !exists {
				log.Errorf(resourceAForResourceBNotFound(
					ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, cloudItem.PodIngressLcuuid,
					ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, cloudItem.Lcuuid,
				))
				return nil, nil, false
			}
		}
		mapInfo["pod_ingress_id"] = podIngressID
		structInfo.PodIngressID.SetNew(podIngressID)
		structInfo.PodIngressLcuuid.Set(diffBase.PodIngressLcuuid, cloudItem.PodIngressLcuuid)
	}
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	if diffBase.Label != cloudItem.Label {
		mapInfo["label"] = cloudItem.Label
		structInfo.Label.Set(diffBase.Label, cloudItem.Label)
	}
	if diffBase.Annotation != cloudItem.Annotation {
		mapInfo["annotation"] = cloudItem.Annotation
		structInfo.Annotation.Set(diffBase.Annotation, cloudItem.Annotation)
	}
	if diffBase.Selector != cloudItem.Selector {
		mapInfo["selector"] = cloudItem.Selector
		structInfo.Selector.Set(diffBase.Selector, cloudItem.Selector)
	}
	if diffBase.ServiceClusterIP != cloudItem.ServiceClusterIP {
		mapInfo["service_cluster_ip"] = cloudItem.ServiceClusterIP
		structInfo.ServiceClusterIP.Set(diffBase.ServiceClusterIP, cloudItem.ServiceClusterIP)
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
