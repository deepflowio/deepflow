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
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/types"
)

// PodGroupMessageFactory defines the message factory for PodGroup
type PodGroupMessageFactory struct{}

func (f *PodGroupMessageFactory) CreateAddedMessage() types.Added {
	return &message.AddedPodGroups{}
}

func (f *PodGroupMessageFactory) CreateUpdatedMessage() types.Updated {
	return &message.UpdatedPodGroup{}
}

func (f *PodGroupMessageFactory) CreateDeletedMessage() types.Deleted {
	return &message.DeletedPodGroups{}
}

func (f *PodGroupMessageFactory) CreateUpdatedFields() types.UpdatedFields {
	return &message.UpdatedPodGroupFields{}
}

type PodGroup struct {
	UpdaterBase[
		cloudmodel.PodGroup,
		*diffbase.PodGroup,
		*metadbmodel.PodGroup,
		metadbmodel.PodGroup,
	]
}

func NewPodGroup(wholeCache *cache.Cache, cloudData []cloudmodel.PodGroup) *PodGroup {
	if !hasMessageFactory(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN) {
		RegisterMessageFactory(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, &PodGroupMessageFactory{})
	}

	updater := &PodGroup{
		UpdaterBase: newUpdaterBase(
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN,
			wholeCache,
			db.NewPodGroup().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.PodGroups,
			cloudData,
		),
	}
	updater.setDataGenerator(updater)
	updater.toLoggable = true
	return updater
}

// Implement DataGenerator interface

func (n *PodGroup) generateDBItemToAdd(cloudItem *cloudmodel.PodGroup) (*metadbmodel.PodGroup, bool) {
	podNamespaceID, exists := n.cache.ToolDataSet.GetPodNamespaceIDByLcuuid(cloudItem.PodNamespaceLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, cloudItem.PodNamespaceLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, cloudItem.Lcuuid,
		), n.metadata.LogPrefixes)
		return nil, false
	}
	podClusterID, exists := n.cache.ToolDataSet.GetPodClusterIDByLcuuid(cloudItem.PodClusterLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, cloudItem.PodClusterLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, cloudItem.Lcuuid,
		), n.metadata.LogPrefixes)
		return nil, false
	}
	yamlMetadata, err := yaml.JSONToYAML([]byte(cloudItem.Metadata))
	if err != nil {
		log.Errorf("failed to convert %s metadata JSON to YAML: %s", n.resourceType, cloudItem.Metadata, n.metadata.LogPrefixes)
		return nil, false
	}
	yamlSpec, err := yaml.JSONToYAML([]byte(cloudItem.Spec))
	if err != nil {
		log.Errorf("failed to convert %s spec JSON to YAML: %s", n.resourceType, cloudItem.Spec, n.metadata.LogPrefixes)
		return nil, false
	}

	dbItem := &metadbmodel.PodGroup{
		Name:           cloudItem.Name,
		Type:           cloudItem.Type,
		Label:          cloudItem.Label,
		NetworkMode:    cloudItem.NetworkMode,
		Metadata:       yamlMetadata,
		MetadataHash:   cloudItem.MetadataHash,
		Spec:           yamlSpec,
		SpecHash:       cloudItem.SpecHash,
		PodNum:         cloudItem.PodNum,
		PodNamespaceID: podNamespaceID,
		PodClusterID:   podClusterID,
		SubDomain:      cloudItem.SubDomainLcuuid,
		Domain:         n.metadata.GetDomainLcuuid(),
		Region:         cloudItem.RegionLcuuid,
		AZ:             cloudItem.AZLcuuid,
		UID:            ctrlrcommon.GenerateResourceShortUUID(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN),
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (n *PodGroup) generateUpdateInfo(diffBase *diffbase.PodGroup, cloudItem *cloudmodel.PodGroup) (types.UpdatedFields, map[string]interface{}, bool) {
	structInfo := &message.UpdatedPodGroupFields{}
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
	if diffBase.NetworkMode != cloudItem.NetworkMode {
		mapInfo["network_mode"] = cloudItem.NetworkMode
		structInfo.NetworkMode.Set(diffBase.NetworkMode, cloudItem.NetworkMode)
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		mapInfo["region"] = cloudItem.RegionLcuuid
		structInfo.RegionLcuuid.Set(diffBase.RegionLcuuid, cloudItem.RegionLcuuid)
	}
	if diffBase.AZLcuuid != cloudItem.AZLcuuid {
		mapInfo["az"] = cloudItem.AZLcuuid
		structInfo.AZLcuuid.Set(diffBase.AZLcuuid, cloudItem.AZLcuuid)
	}
	if diffBase.MetadataHash != cloudItem.MetadataHash {
		mapInfo["metadata_hash"] = cloudItem.MetadataHash

		yamlMetadataBytes, err := yaml.JSONToYAML([]byte(cloudItem.Metadata))
		if err != nil {
			log.Errorf("failed to convert %s metadata JSON (data: %v) to YAML: %s", n.resourceType, cloudItem.Metadata, n.metadata.LogPrefixes)
			return nil, nil, false
		}
		if compressedBytes, err := metadbmodel.AutoCompressedBytes(yamlMetadataBytes).Value(); err != nil {
			log.Errorf("failed to compress %s YAML data: %v: %s", n.resourceType, yamlMetadataBytes, err.Error(), n.metadata.LogPrefixes)
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
			log.Errorf("failed to convert %s spec JSON (data: %v) to YAML: %s", n.resourceType, cloudItem.Spec, n.metadata.LogPrefixes)
			return nil, nil, false
		}
		if compressedBytes, err := metadbmodel.AutoCompressedBytes(yamlSpecBytes).Value(); err != nil {
			log.Errorf("failed to compress %s YAML data: %v: %s", n.resourceType, yamlSpecBytes, err.Error(), n.metadata.LogPrefixes)
			return nil, nil, false
		} else {
			mapInfo["compressed_spec"] = compressedBytes
		}
		structInfo.Spec.Set(diffBase.Spec, string(yamlSpecBytes))
	} else {
		structInfo.Spec.Set(diffBase.Spec, diffBase.Spec) // set for resource event, because it publish combined config of metadata and spec
	}

	// 返回接口类型
	return structInfo, mapInfo, len(mapInfo) > 0
}
