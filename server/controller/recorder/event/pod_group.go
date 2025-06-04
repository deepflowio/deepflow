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
		newCUDSubscriberComponent(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, SubTopic(pubsub.TopicResourceUpdatedFields)),
		cfg,
	}
	mng.SetSubscriberSelf(mng)
	return mng
}

func (p *PodGroup) OnResourceBatchAdded(md *message.Metadata, msg interface{}) {
	// TODO remove
}

func (c *PodGroup) OnResourceUpdated(md *message.Metadata, msg interface{}) {
	fields := msg.(*message.PodGroupFieldsUpdate)
	if !fields.Metadata.IsDifferent() && !fields.Spec.IsDifferent() {
		return
	}
	eventType := eventapi.RESOURCE_EVENT_TYPE_UPDATE_CONFIG
	var opts []eventapi.TagFieldOption

	old := fields.Metadata.GetOld() + "\n" + fields.Spec.GetOld()
	new := fields.Metadata.GetNew() + "\n" + fields.Spec.GetNew()
	if old == "" {
		eventType = eventapi.RESOURCE_EVENT_TYPE_ADD_CONFIG
	} else if new == "" {
		eventType = eventapi.RESOURCE_EVENT_TYPE_DELETE_CONFIG
	} else {
		diff := CompareConfig(old, new, int(c.cfg.ConfigDiffContext))

		opts = []eventapi.TagFieldOption{
			eventapi.TagPodGroupID(fields.GetID()),
			eventapi.TagAttributes([]string{eventapi.AttributeNameConfig}, []string{diff}),
		}
	}
	c.createAndEnqueue(md, fields.GetLcuuid(), eventType, opts...)
}

func (p *PodGroup) OnResourceBatchDeleted(md *message.Metadata, msg interface{}) {
	// TODO remove
}
