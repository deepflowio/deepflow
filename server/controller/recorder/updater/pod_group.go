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

type PodGroup struct {
	UpdaterBase[
		cloudmodel.PodGroup,
		*diffbase.PodGroup,
		*metadbmodel.PodGroup,
		metadbmodel.PodGroup,
		*message.PodGroupAdd,
		message.PodGroupAdd,
		message.AddNoneAddition,
		*message.PodGroupUpdate,
		message.PodGroupUpdate,
		*message.PodGroupFieldsUpdate,
		message.PodGroupFieldsUpdate,
		*message.PodGroupDelete,
		message.PodGroupDelete,
		message.DeleteNoneAddition]
}

func NewPodGroup(wholeCache *cache.Cache, cloudData []cloudmodel.PodGroup) *PodGroup {
	updater := &PodGroup{
		newUpdaterBase[
			cloudmodel.PodGroup,
			*diffbase.PodGroup,
			*metadbmodel.PodGroup,
			metadbmodel.PodGroup,
			*message.PodGroupAdd,
			message.PodGroupAdd,
			message.AddNoneAddition,
			*message.PodGroupUpdate,
			message.PodGroupUpdate,
			*message.PodGroupFieldsUpdate,
			message.PodGroupFieldsUpdate,
			*message.PodGroupDelete,
			message.PodGroupDelete,
			message.DeleteNoneAddition,
		](
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN,
			wholeCache,
			db.NewPodGroup().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.PodGroups,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (p *PodGroup) getDiffBaseByCloudItem(cloudItem *cloudmodel.PodGroup) (diffBase *diffbase.PodGroup, exists bool) {
	diffBase, exists = p.diffBaseData[cloudItem.Lcuuid]
	return
}

func (p *PodGroup) generateDBItemToAdd(cloudItem *cloudmodel.PodGroup) (*metadbmodel.PodGroup, bool) {
	podNamespaceID, exists := p.cache.ToolDataSet.GetPodNamespaceIDByLcuuid(cloudItem.PodNamespaceLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, cloudItem.PodNamespaceLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, cloudItem.Lcuuid,
		), p.metadata.LogPrefixes)
		return nil, false
	}
	podClusterID, exists := p.cache.ToolDataSet.GetPodClusterIDByLcuuid(cloudItem.PodClusterLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, cloudItem.PodClusterLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, cloudItem.Lcuuid,
		), p.metadata.LogPrefixes)
		return nil, false
	}
	yamlMetadata, err := yaml.JSONToYAML([]byte(cloudItem.Metadata))
	if err != nil {
		log.Errorf("failed to convert %s metadata JSON to YAML: %s", p.resourceType, cloudItem.Metadata, p.metadata.LogPrefixes)
		return nil, false
	}
	yamlSpec, err := yaml.JSONToYAML([]byte(cloudItem.Spec))
	if err != nil {
		log.Errorf("failed to convert %s spec JSON to YAML: %s", p.resourceType, cloudItem.Spec, p.metadata.LogPrefixes)
		return nil, false
	}
	dbItem := &metadbmodel.PodGroup{
		Name:           cloudItem.Name,
		Type:           cloudItem.Type,
		Label:          cloudItem.Label,
		Metadata:       string(yamlMetadata),
		MetadataHash:   cloudItem.MetadataHash,
		Spec:           string(yamlSpec),
		SpecHash:       cloudItem.SpecHash,
		PodNum:         cloudItem.PodNum,
		PodNamespaceID: podNamespaceID,
		PodClusterID:   podClusterID,
		SubDomain:      cloudItem.SubDomainLcuuid,
		Domain:         p.metadata.Domain.Lcuuid,
		Region:         cloudItem.RegionLcuuid,
		AZ:             cloudItem.AZLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (p *PodGroup) generateUpdateInfo(diffBase *diffbase.PodGroup, cloudItem *cloudmodel.PodGroup) (*message.PodGroupFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.PodGroupFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
		structInfo.Type.SetNew(cloudItem.Type)
	}
	if diffBase.Type != cloudItem.Type {
		mapInfo["type"] = cloudItem.Type
		structInfo.Type.Set(diffBase.Type, cloudItem.Type)
	}
	if diffBase.PodNum != cloudItem.PodNum {
		mapInfo["pod_num"] = cloudItem.PodNum
		structInfo.PodNum.Set(diffBase.PodNum, cloudItem.PodNum)
	}
	if diffBase.Label != cloudItem.Label {
		mapInfo["label"] = cloudItem.Label
		structInfo.Label.Set(diffBase.Label, cloudItem.Label)
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		mapInfo["region"] = cloudItem.RegionLcuuid
		structInfo.RegionLcuuid.Set(diffBase.RegionLcuuid, cloudItem.RegionLcuuid)
	}
	if diffBase.MetadataHash != cloudItem.MetadataHash {
		mapInfo["metadata_hash"] = cloudItem.MetadataHash

		yamlMetadata, err := yaml.JSONToYAML([]byte(cloudItem.Metadata))
		if err != nil {
			log.Errorf("failed to convert %s metadata JSON (data: %v) to YAML: %s", p.resourceType, cloudItem.Metadata, p.metadata.LogPrefixes)
			return nil, nil, false
		}
		mapInfo["metadata"] = string(yamlMetadata)
		structInfo.Metadata.Set(diffBase.Metadata, string(yamlMetadata))
	} else {
		structInfo.Metadata.Set(diffBase.Metadata, diffBase.Metadata) // set for resource event, because it publish combined config of metadata and spec
	}
	if diffBase.SpecHash != cloudItem.SpecHash {
		mapInfo["spec_hash"] = cloudItem.SpecHash

		yamlSpec, err := yaml.JSONToYAML([]byte(cloudItem.Spec))
		if err != nil {
			log.Errorf("failed to convert %s spec JSON (data: %v) to YAML: %s", p.resourceType, cloudItem.Spec, p.metadata.LogPrefixes)
			return nil, nil, false
		}
		mapInfo["spec"] = string(yamlSpec)
		structInfo.Spec.Set(diffBase.Spec, cloudItem.Spec)
	} else {
		structInfo.Spec.Set(diffBase.Spec, diffBase.Spec) // set for resource event, because it publish combined config of metadata and spec
	}
	return structInfo, mapInfo, len(mapInfo) > 0
}
