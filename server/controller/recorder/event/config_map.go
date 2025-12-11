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
	ctrlCommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbModel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/event/config"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type ConfigMap struct {
	ManagerComponent
	CUDSubscriberComponent
	cfg config.Config
}

func NewConfigMap(cfg config.Config, q *queue.OverwriteQueue) *ConfigMap {
	mng := &ConfigMap{
		newManagerComponent(ctrlCommon.RESOURCE_TYPE_CONFIG_MAP_EN, q),
		newCUDSubscriberComponent(ctrlCommon.RESOURCE_TYPE_CONFIG_MAP_EN, SubTopic(pubsub.TopicResourceUpdatedFull)),
		cfg,
	}
	mng.SetSubscriberSelf(mng)
	return mng
}

func (c *ConfigMap) OnResourceBatchAdded(md *message.Metadata, msg interface{}) {
	for _, item := range msg.([]*metadbModel.ConfigMap) {
		opts := []eventapi.TagFieldOption{
			eventapi.TagConfigMapID(uint32(item.ID)),
			eventapi.TagPodNSID(item.PodNamespaceID),
			eventapi.TagPodClusterID(item.PodClusterID),
			eventapi.TagVPCID(item.VPCID),
			eventapi.TagAttributes(
				[]string{eventapi.AttributeNameConfigName},
				[]string{item.Name}),
		}

		c.enqueueIfInsertIntoMetadbFailed(
			md, item.Lcuuid, item.Domain, eventapi.RESOURCE_EVENT_TYPE_ATTACH_CONFIG_MAP, opts...,
		)
	}
}

func (c *ConfigMap) OnResourceUpdated(md *message.Metadata, msg interface{}) {
	fields := msg.(*message.UpdatedConfigMap).GetFields().(*message.UpdatedConfigMapFields)
	if !fields.Data.IsDifferent() {
		return
	}
	item := msg.(*message.UpdatedConfigMap).GetNewMetadbItem().(*metadbModel.ConfigMap)

	diff := CompareConfig(fields.Data.GetOld(), fields.Data.GetNew(), int(c.cfg.ConfigDiffContext))

	opts := []eventapi.TagFieldOption{
		eventapi.TagConfigMapID(uint32(item.ID)),
		eventapi.TagPodNSID(item.PodNamespaceID),
		eventapi.TagPodClusterID(item.PodClusterID),
		eventapi.TagVPCID(item.VPCID),
		eventapi.TagAttributes(
			[]string{eventapi.AttributeNameConfigName, eventapi.AttributeNameConfig, eventapi.AttributeNameConfigDiff},
			[]string{item.Name, string(item.Data), diff}),
	}

	c.enqueueIfInsertIntoMetadbFailed(
		md, item.Lcuuid, item.Domain, eventapi.RESOURCE_EVENT_TYPE_MODIFY_CONFIG_MAP, opts...,
	)
}

func (c *ConfigMap) OnResourceBatchDeleted(md *message.Metadata, msg interface{}) {
	for _, item := range msg.([]*metadbModel.ConfigMap) {
		opts := []eventapi.TagFieldOption{
			eventapi.TagConfigMapID(uint32(item.ID)),
			eventapi.TagPodNSID(item.PodNamespaceID),
			eventapi.TagPodClusterID(item.PodClusterID),
			eventapi.TagVPCID(item.VPCID),
			eventapi.TagAttributes(
				[]string{eventapi.AttributeNameConfigName},
				[]string{item.Name}),
		}
		c.enqueueIfInsertIntoMetadbFailed(
			md, item.Lcuuid, item.Domain, eventapi.RESOURCE_EVENT_TYPE_DETACH_CONFIG_MAP, opts...,
		)
	}
}
