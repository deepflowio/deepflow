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
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbModel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type PodGroupConfigMapConnection struct {
	ManagerComponent
	CUDSubscriberComponent
}

func NewPodGroupConfigMapConnection(q *queue.OverwriteQueue) *PodGroupConfigMapConnection {
	mng := &PodGroupConfigMapConnection{
		newManagerComponent(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_CONFIG_MAP_CONNECTION_EN, q),
		newCUDSubscriberComponent(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_CONFIG_MAP_CONNECTION_EN),
	}
	mng.SetSubscriberSelf(mng)
	return mng
}

func (p *PodGroupConfigMapConnection) OnResourceBatchAdded(md *message.Metadata, msg interface{}) {
	for _, item := range msg.([]*metadbModel.PodGroupConfigMapConnection) {
		configMapName, ok := md.GetToolDataSet().GetNameByConfigMapID(item.ConfigMapID)
		if !ok {
			log.Errorf("config map name %d not found", item.ConfigMapID, md.LogPrefixes)
		}

		opts := []eventapi.TagFieldOption{
			eventapi.TagPodGroupID(item.PodGroupID),
			eventapi.TagConfigMapID(uint32(item.ConfigMapID)),
			eventapi.TagAttributes(
				[]string{eventapi.AttributeNameConfigName},
				[]string{configMapName}),
		}

		p.enqueueIfInsertIntoMySQLFailed(
			md, item.Lcuuid, item.Domain, eventapi.RESOURCE_EVENT_TYPE_ATTACH_CONFIG_MAP, opts...,
		)
	}
}

func (p *PodGroupConfigMapConnection) OnResourceBatchDeleted(md *message.Metadata, msg interface{}) {
	for _, item := range msg.([]*metadbModel.PodGroupConfigMapConnection) {
		configMapName, ok := md.GetToolDataSet().GetNameByConfigMapID(item.ConfigMapID)
		if !ok {
			log.Errorf("config map name %d not found", item.ConfigMapID, md.LogPrefixes)
		}
		opts := []eventapi.TagFieldOption{
			eventapi.TagPodGroupID(item.PodGroupID),
			eventapi.TagConfigMapID(uint32(item.ConfigMapID)),
			eventapi.TagAttributes(
				[]string{eventapi.AttributeNameConfigName},
				[]string{configMapName}),
		}

		p.enqueueIfInsertIntoMySQLFailed(
			md, item.Lcuuid, item.Domain, eventapi.RESOURCE_EVENT_TYPE_DETACH_CONFIG_MAP, opts...,
		)
	}
}
