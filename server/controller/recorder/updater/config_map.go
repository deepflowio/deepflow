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
	"time"

	"sigs.k8s.io/yaml"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ConfigMap struct {
	UpdaterBase[
		cloudmodel.ConfigMap,
		*diffbase.ConfigMap,
		*metadbmodel.ConfigMap,
		metadbmodel.ConfigMap,
		*message.AddedConfigMaps,
		message.AddedConfigMaps,
		message.AddNoneAddition,
		*message.UpdatedConfigMap,
		message.UpdatedConfigMap,
		*message.UpdatedConfigMapFields,
		message.UpdatedConfigMapFields,
		*message.DeletedConfigMaps,
		message.DeletedConfigMaps,
		message.DeleteNoneAddition]
}

func NewConfigMap(wholeCache *cache.Cache, cloudData []cloudmodel.ConfigMap) *ConfigMap {
	updater := &ConfigMap{
		newUpdaterBase[
			cloudmodel.ConfigMap,
			*diffbase.ConfigMap,
			*metadbmodel.ConfigMap,
			metadbmodel.ConfigMap,
			*message.AddedConfigMaps,
			message.AddedConfigMaps,
			message.AddNoneAddition,
			*message.UpdatedConfigMap,
			message.UpdatedConfigMap,
			*message.UpdatedConfigMapFields,
			message.UpdatedConfigMapFields,
			*message.DeletedConfigMaps,
			message.DeletedConfigMaps,
			message.DeleteNoneAddition,
		](
			ctrlrcommon.RESOURCE_TYPE_CONFIG_MAP_EN,
			wholeCache,
			db.NewConfigMap().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.ConfigMaps,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	updater.toLoggable = true
	return updater
}

func (h *ConfigMap) generateDBItemToAdd(cloudItem *cloudmodel.ConfigMap) (*metadbmodel.ConfigMap, bool) {
	podClusterID, exists := h.cache.ToolDataSet.GetPodClusterIDByLcuuid(cloudItem.PodClusterLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, cloudItem.PodClusterLcuuid,
			ctrlrcommon.RESOURCE_TYPE_CONFIG_MAP_EN, cloudItem.Lcuuid,
		), h.metadata.LogPrefixes)
		return nil, false
	}
	podNamespaceID, exists := h.cache.ToolDataSet.GetPodNamespaceIDByLcuuid(cloudItem.PodNamespaceLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, cloudItem.PodNamespaceLcuuid,
			ctrlrcommon.RESOURCE_TYPE_CONFIG_MAP_EN, cloudItem.Lcuuid,
		), h.metadata.LogPrefixes)
		return nil, false
	}
	vpcID, exists := h.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_CONFIG_MAP_EN, cloudItem.Lcuuid,
		), h.metadata.LogPrefixes)
		return nil, false
	}
	yamlData, err := yaml.JSONToYAML([]byte(cloudItem.Data))
	if err != nil {
		log.Errorf("failed to convert %s JSON to YAML: %s", h.resourceType, h.metadata.LogPrefixes)
		return nil, false
	}
	dbItem := &metadbmodel.ConfigMap{
		Name:           cloudItem.Name,
		Data:           yamlData,
		DataHash:       cloudItem.DataHash,
		PodNamespaceID: podNamespaceID,
		PodClusterID:   podClusterID,
		VPCID:          vpcID,
		AZ:             cloudItem.AZLcuuid,
		Region:         cloudItem.RegionLcuuid,
		Domain:         h.metadata.GetDomainLcuuid(),
		SubDomain:      h.metadata.GetSubDomainLcuuid(),
		SyncedAt:       time.Now(),
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (h *ConfigMap) generateUpdateInfo(diffBase *diffbase.ConfigMap, cloudItem *cloudmodel.ConfigMap) (*message.UpdatedConfigMapFields, map[string]interface{}, bool) {
	structInfo := new(message.UpdatedConfigMapFields)
	mapInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(cloudItem.Name, diffBase.Name)
	}
	if diffBase.DataHash != cloudItem.DataHash {
		mapInfo["data_hash"] = cloudItem.DataHash

		yamlDataBytes, err := yaml.JSONToYAML([]byte(cloudItem.Data))
		if err != nil {
			log.Errorf("failed to convert %s JSON data: %v to YAML: %s", h.resourceType, cloudItem.Data, h.metadata.LogPrefixes)
			return nil, nil, false
		}

		if compressedData, err := metadbmodel.AutoCompressedBytes(yamlDataBytes).Value(); err != nil {
			log.Errorf("failed to compress %s YAML data: %v: %s", h.resourceType, yamlDataBytes, h.metadata.LogPrefixes)
			return nil, nil, false
		} else {
			mapInfo["compressed_data"] = compressedData
			structInfo.Data.Set(diffBase.Data, string(yamlDataBytes))
		}
	}
	return structInfo, mapInfo, len(mapInfo) > 0
}
