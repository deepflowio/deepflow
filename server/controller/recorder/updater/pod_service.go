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
	"sigs.k8s.io/yaml"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type PodService struct {
	UpdaterBase[
		cloudmodel.PodService,
		*diffbase.PodService,
		*metadbmodel.PodService,
		metadbmodel.PodService,
		*message.AddedPodServices,
		message.AddedPodServices,
		message.AddNoneAddition,
		*message.UpdatedPodService,
		message.UpdatedPodService,
		*message.UpdatedPodServiceFields,
		message.UpdatedPodServiceFields,
		*message.DeletedPodServices,
		message.DeletedPodServices,
		message.DeleteNoneAddition]
}

func NewPodService(wholeCache *cache.Cache, cloudData []cloudmodel.PodService) *PodService {
	updater := &PodService{
		newUpdaterBase[
			cloudmodel.PodService,
			*diffbase.PodService,
			*metadbmodel.PodService,
			metadbmodel.PodService,
			*message.AddedPodServices,
			message.AddedPodServices,
			message.AddNoneAddition,
			*message.UpdatedPodService,
			message.UpdatedPodService,
			*message.UpdatedPodServiceFields,
			message.UpdatedPodServiceFields,
			*message.DeletedPodServices,
			message.DeletedPodServices,
			message.DeleteNoneAddition,
		](
			ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN,
			wholeCache,
			db.NewPodService().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.PodServices,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	updater.toLoggable = true
	return updater
}

func (s *PodService) generateDBItemToAdd(cloudItem *cloudmodel.PodService) (*metadbmodel.PodService, bool) {
	vpcID, exists := s.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, cloudItem.Lcuuid,
		), s.metadata.LogPrefixes)
		return nil, false
	}
	podNamespaceID, exists := s.cache.ToolDataSet.GetPodNamespaceIDByLcuuid(cloudItem.PodNamespaceLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, cloudItem.PodNamespaceLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, cloudItem.Lcuuid,
		), s.metadata.LogPrefixes)
	}
	podClusterID, exists := s.cache.ToolDataSet.GetPodClusterIDByLcuuid(cloudItem.PodClusterLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, cloudItem.PodClusterLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, cloudItem.Lcuuid,
		), s.metadata.LogPrefixes)
		return nil, false
	}
	var podIngressID int
	if cloudItem.PodIngressLcuuid != "" {
		podIngressID, exists = s.cache.ToolDataSet.GetPodIngressIDByLcuuid(cloudItem.PodIngressLcuuid)
		if !exists {
			log.Error(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, cloudItem.PodIngressLcuuid,
				ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, cloudItem.Lcuuid,
			), s.metadata.LogPrefixes)
			return nil, false
		}
	}
	yamlMetadata, err := yaml.JSONToYAML([]byte(cloudItem.Metadata))
	if err != nil {
		log.Errorf("failed to convert %s metadata JSON to YAML: %s", s.resourceType, cloudItem.Metadata, s.metadata.LogPrefixes)
		return nil, false
	}
	yamlSpec, err := yaml.JSONToYAML([]byte(cloudItem.Spec))
	if err != nil {
		log.Errorf("failed to convert %s spec JSON to YAML: %s", s.resourceType, cloudItem.Spec, s.metadata.LogPrefixes)
		return nil, false
	}

	dbItem := &metadbmodel.PodService{
		Name:             cloudItem.Name,
		Label:            cloudItem.Label,
		Annotation:       cloudItem.Annotation,
		Type:             cloudItem.Type,
		Selector:         cloudItem.Selector,
		ExternalIP:       cloudItem.ExternalIP,
		ServiceClusterIP: cloudItem.ServiceClusterIP,
		Metadata:         yamlMetadata,
		MetadataHash:     cloudItem.MetadataHash,
		Spec:             yamlSpec,
		SpecHash:         cloudItem.SpecHash,
		PodIngressID:     podIngressID,
		PodNamespaceID:   podNamespaceID,
		PodClusterID:     podClusterID,
		SubDomain:        cloudItem.SubDomainLcuuid,
		Domain:           s.metadata.GetDomainLcuuid(),
		Region:           cloudItem.RegionLcuuid,
		AZ:               cloudItem.AZLcuuid,
		VPCID:            vpcID,
		UID:              ctrlrcommon.GenerateResourceShortUUID(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN),
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (s *PodService) generateUpdateInfo(diffBase *diffbase.PodService, cloudItem *cloudmodel.PodService) (*message.UpdatedPodServiceFields, map[string]interface{}, bool) {
	structInfo := new(message.UpdatedPodServiceFields)
	mapInfo := make(map[string]interface{})
	if diffBase.PodIngressLcuuid != cloudItem.PodIngressLcuuid {
		var podIngressID int
		if cloudItem.PodIngressLcuuid != "" {
			var exists bool
			podIngressID, exists = s.cache.ToolDataSet.GetPodIngressIDByLcuuid(cloudItem.PodIngressLcuuid)
			if !exists {
				log.Error(resourceAForResourceBNotFound(
					ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, cloudItem.PodIngressLcuuid,
					ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, cloudItem.Lcuuid,
				), s.metadata.LogPrefixes)
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
	if diffBase.ExternalIP != cloudItem.ExternalIP {
		mapInfo["external_ip"] = cloudItem.ExternalIP
		structInfo.ExternalIP.Set(diffBase.ExternalIP, cloudItem.ExternalIP)
	}
	if diffBase.ServiceClusterIP != cloudItem.ServiceClusterIP {
		mapInfo["service_cluster_ip"] = cloudItem.ServiceClusterIP
		structInfo.ServiceClusterIP.Set(diffBase.ServiceClusterIP, cloudItem.ServiceClusterIP)
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		mapInfo["region"] = cloudItem.RegionLcuuid
		structInfo.RegionLcuuid.Set(diffBase.RegionLcuuid, cloudItem.RegionLcuuid)
	}
	if diffBase.MetadataHash != cloudItem.MetadataHash {
		mapInfo["metadata_hash"] = cloudItem.MetadataHash

		yamlMetadataBytes, err := yaml.JSONToYAML([]byte(cloudItem.Metadata))
		if err != nil {
			log.Errorf("failed to convert %s metadata JSON (data: %v) to YAML: %s", s.resourceType, cloudItem.Metadata, s.metadata.LogPrefixes)
			return nil, nil, false
		}
		if compressedBytes, err := metadbmodel.AutoCompressedBytes(yamlMetadataBytes).Value(); err != nil {
			log.Errorf("failed to compress %s YAML data: %v: %s", s.resourceType, yamlMetadataBytes, err.Error(), s.metadata.LogPrefixes)
			return nil, nil, false
		} else {
			mapInfo["compressed_metadata"] = compressedBytes
		}
		structInfo.Metadata.Set(diffBase.Metadata, string(yamlMetadataBytes))
	} else {
		structInfo.Metadata.Set(diffBase.Metadata, diffBase.Metadata) // set for resource event, because it publish combined config of metadata and spec
	}
	if diffBase.SpecHash != cloudItem.SpecHash {
		mapInfo["spec_hash"] = cloudItem.SpecHash

		yamlSpecBytes, err := yaml.JSONToYAML([]byte(cloudItem.Spec))
		if err != nil {
			log.Errorf("failed to convert %s spec JSON (data: %v) to YAML: %s", s.resourceType, cloudItem.Spec, s.metadata.LogPrefixes)
			return nil, nil, false
		}
		if compressedBytes, err := metadbmodel.AutoCompressedBytes(yamlSpecBytes).Value(); err != nil {
			log.Errorf("failed to compress %s YAML data: %v: %s", s.resourceType, yamlSpecBytes, err.Error(), s.metadata.LogPrefixes)
			return nil, nil, false
		} else {
			mapInfo["compressed_spec"] = compressedBytes
		}
		structInfo.Spec.Set(diffBase.Spec, string(yamlSpecBytes))
	} else {
		structInfo.Spec.Set(diffBase.Spec, diffBase.Spec) // set for resource event, because it publish combined config of metadata and spec
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
