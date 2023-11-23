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
)

type PodService struct {
	UpdaterBase[cloudmodel.PodService, mysql.PodService, *diffbase.PodService]
}

func NewPodService(wholeCache *cache.Cache, cloudData []cloudmodel.PodService) *PodService {
	updater := &PodService{
		UpdaterBase[cloudmodel.PodService, mysql.PodService, *diffbase.PodService]{
			resourceType: ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN,
			cache:        wholeCache,
			dbOperator:   db.NewPodService(),
			diffBaseData: wholeCache.DiffBaseDataSet.PodServices,
			cloudData:    cloudData,
		},
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

func (s *PodService) generateUpdateInfo(diffBase *diffbase.PodService, cloudItem *cloudmodel.PodService) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
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
				return nil, false
			}
		}
		updateInfo["pod_ingress_id"] = podIngressID
	}
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.Label != cloudItem.Label {
		updateInfo["label"] = cloudItem.Label
	}
	if diffBase.Annotation != cloudItem.Annotation {
		updateInfo["annotation"] = cloudItem.Annotation
	}
	if diffBase.Selector != cloudItem.Selector {
		updateInfo["selector"] = cloudItem.Selector
	}
	if diffBase.ServiceClusterIP != cloudItem.ServiceClusterIP {
		updateInfo["service_cluster_ip"] = cloudItem.ServiceClusterIP
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		updateInfo["region"] = cloudItem.RegionLcuuid
	}
	if diffBase.AZLcuuid != cloudItem.AZLcuuid {
		updateInfo["az"] = cloudItem.AZLcuuid
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
