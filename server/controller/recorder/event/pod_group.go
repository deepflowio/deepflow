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
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/event/config"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type PodGroup struct {
	ManagerComponent
	CUDSubscriberComponent
	cfg config.Config
}

func NewPodGroup(cfg config.Config, q *queue.OverwriteQueue) *PodGroup {
	mng := &PodGroup{
		newManagerComponent(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, q),
		newCUDSubscriberComponent(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, SubTopic(pubsub.TopicResourceUpdatedFull)),
		cfg,
	}
	mng.SetSubscriberSelf(mng)
	return mng
}

func (p *PodGroup) OnResourceBatchAdded(md *message.Metadata, msg interface{}) {
	// TODO remove
}

func (c *PodGroup) OnResourceUpdated(md *message.Metadata, msg interface{}) {
	updatedFull := msg.(*message.UpdatedPodGroup)
	newDBItem := updatedFull.GetNewMetadbItem().(*metadbmodel.PodGroup)
	fields := updatedFull.GetFields().(*message.UpdatedPodGroupFields)
	if !fields.Metadata.IsDifferent() && !fields.Spec.IsDifferent() {
		return
	}
	eventType := eventapi.RESOURCE_EVENT_TYPE_MODIFY
	var opts []eventapi.TagFieldOption

	old := JoinMetadataAndSpec(fields.Metadata.GetOld(), fields.Spec.GetOld())
	new := JoinMetadataAndSpec(fields.Metadata.GetNew(), fields.Spec.GetNew())
	if old == "" || new == "" {
		return
	} else {
		diff := CompareConfig(old, new, int(c.cfg.ConfigDiffContext))

		opts = []eventapi.TagFieldOption{
			eventapi.TagPodGroupID(fields.GetID()),
			// We need to provide pod group type information for ingester to recognize auto_service classification
			eventapi.TagPodGroupType(uint32(ctrlrcommon.RESOURCE_POD_GROUP_TYPE_MAP[newDBItem.Type])),
			// Provide instance type to fill in auto_instance information
			// Pod group itself does not have an instance type, but its changes essentially affect pods,
			// so the type is set to pod; since it affects many pods, the auto instance id remains 0
			eventapi.TagInstanceType(uint32(ctrlrcommon.VIF_DEVICE_TYPE_POD)),
			eventapi.TagAttributes(
				[]string{eventapi.AttributeNameConfig, eventapi.AttributeNameConfigDiff},
				[]string{new, diff}),
		}
	}
	c.createAndEnqueue(md, fields.GetLcuuid(), eventType, opts...)
}

func (p *PodGroup) OnResourceBatchDeleted(md *message.Metadata, msg interface{}) {
	// TODO remove
}
