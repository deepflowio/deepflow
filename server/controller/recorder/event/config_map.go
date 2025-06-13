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

package event

import (
	"sigs.k8s.io/yaml"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type ConfigMap struct {
	EventManagerBase
}

func NewConfigMap(toolDS *tool.DataSet, eq *queue.OverwriteQueue) *ConfigMap {
	mng := &ConfigMap{
		newEventManagerBase(
			ctrlrcommon.RESOURCE_TYPE_CONFIG_MAP_EN,
			toolDS,
			eq,
		),
	}
	return mng
}

func (p *ConfigMap) ProduceByAdd(items []*mysqlmodel.ConfigMap) {
	for _, item := range items {
		opts := []eventapi.TagFieldOption{
			eventapi.TagConfigMapID(uint32(item.ID)),
			eventapi.TagPodNSID(item.PodNamespaceID),
			eventapi.TagPodClusterID(item.PodClusterID),
			eventapi.TagVPCID(item.VPCID),
			eventapi.TagAttributes(
				[]string{eventapi.AttributeNameConfigName},
				[]string{item.Name}),
		}

		p.enqueueIfInsertIntoMySQLFailed(
			item.Lcuuid, item.Domain, eventapi.RESOURCE_EVENT_TYPE_ATTACH_CONFIG_MAP, opts...,
		)
	}
}

func (p *ConfigMap) ProduceByUpdate(cloudItem *cloudmodel.ConfigMap, diffBase *diffbase.ConfigMap) {
	if cloudItem.DataHash == diffBase.DataHash {
		return
	}

	newData, err := yaml.JSONToYAML([]byte(cloudItem.Data))
	if err != nil {
		log.Errorf("failed to convert JSON data: %v to YAML: %s", cloudItem.Data, p.metadata.LogPrefixes)
		return
	}
	diff := CompareConfig(
		diffBase.Data, string(newData), int(p.metadata.Config.EventCfg.ConfigDiffContext),
	)

	configMapInfo, ok := p.ToolDataSet.GetConfigMapInfoByLcuuid(cloudItem.Lcuuid)
	if !ok {
		log.Errorf("config map info not found for lcuuid: %s", cloudItem.Lcuuid, p.metadata.LogPrefixes)
		return
	}

	opts := []eventapi.TagFieldOption{
		eventapi.TagConfigMapID(uint32(configMapInfo.ID)),
		eventapi.TagAttributes(
			[]string{eventapi.AttributeNameConfigName, eventapi.AttributeNameConfig, eventapi.AttributeNameConfigDiff},
			[]string{diffBase.Name, diffBase.Data, diff}),
	}

	p.enqueueIfInsertIntoMySQLFailed(
		diffBase.Lcuuid, configMapInfo.DomainLcuuid, eventapi.RESOURCE_EVENT_TYPE_MODIFY_CONFIG_MAP, opts...,
	)
}

func (p *ConfigMap) ProduceByDelete(dbItems []*mysqlmodel.ConfigMap) {
	for _, item := range dbItems {
		opts := []eventapi.TagFieldOption{
			eventapi.TagConfigMapID(uint32(item.ID)),
			eventapi.TagPodNSID(item.PodNamespaceID),
			eventapi.TagPodClusterID(item.PodClusterID),
			eventapi.TagVPCID(item.VPCID),
			eventapi.TagAttributes(
				[]string{eventapi.AttributeNameConfigName},
				[]string{item.Name}),
		}

		p.enqueueIfInsertIntoMySQLFailed(
			item.Lcuuid, item.Domain, eventapi.RESOURCE_EVENT_TYPE_DETACH_CONFIG_MAP, opts...,
		)
	}
}
