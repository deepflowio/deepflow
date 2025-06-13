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
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type PodGroupConfigMapConnection struct {
	EventManagerBase
}

func NewPodGroupConfigMapConnection(toolDS *tool.DataSet, eq *queue.OverwriteQueue) *PodGroupConfigMapConnection {
	mng := &PodGroupConfigMapConnection{
		newEventManagerBase(
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_CONFIG_MAP_CONNECTION_EN,
			toolDS,
			eq,
		),
	}
	return mng
}

func (p *PodGroupConfigMapConnection) ProduceByAdd(items []*mysqlmodel.PodGroupConfigMapConnection) {
	for _, item := range items {
		configMapName, ok := p.ToolDataSet.GetNameByConfigMapID(item.ConfigMapID)
		if !ok {
			log.Errorf("config map name %d not found", item.ConfigMapID, p.metadata.LogPrefixes)
		}

		opts := []eventapi.TagFieldOption{
			eventapi.TagPodGroupID(item.PodGroupID),
			eventapi.TagConfigMapID(uint32(item.ConfigMapID)),
			eventapi.TagAttributes(
				[]string{eventapi.AttributeNameConfigName},
				[]string{configMapName}),
		}

		p.enqueueIfInsertIntoMySQLFailed(
			item.Lcuuid, item.Domain, eventapi.RESOURCE_EVENT_TYPE_ATTACH_CONFIG_MAP, opts...,
		)
	}
}

func (p *PodGroupConfigMapConnection) ProduceByUpdate(cloudItem *cloudmodel.PodGroupConfigMapConnection, diffBase *diffbase.PodGroupConfigMapConnection) {
}

func (p *PodGroupConfigMapConnection) ProduceByDelete(items []*mysqlmodel.PodGroupConfigMapConnection) {
	for _, item := range items {
		configMapName, ok := p.ToolDataSet.GetNameByConfigMapID(item.ConfigMapID)
		if !ok {
			log.Errorf("config map name %d not found", item.ConfigMapID, p.metadata.LogPrefixes)
		}
		opts := []eventapi.TagFieldOption{
			eventapi.TagPodGroupID(item.PodGroupID),
			eventapi.TagConfigMapID(uint32(item.ConfigMapID)),
			eventapi.TagAttributes(
				[]string{eventapi.AttributeNameConfigName},
				[]string{configMapName}),
		}

		p.enqueueIfInsertIntoMySQLFailed(
			item.Lcuuid, item.Domain, eventapi.RESOURCE_EVENT_TYPE_DETACH_CONFIG_MAP, opts...,
		)
	}
}
