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

type PodService struct {
	ManagerComponent
	CUDSubscriberComponent
	cfg        config.Config
	deviceType int
}

func NewPodService(cfg config.Config, q *queue.OverwriteQueue) *PodService {
	mng := &PodService{
		newManagerComponent(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, q),
		newCUDSubscriberComponent(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, SubTopic(pubsub.TopicResourceUpdatedFields)),
		cfg,
		ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE,
	}
	mng.SetSubscriberSelf(mng)
	return mng
}

func (p *PodService) OnResourceBatchAdded(md *message.Metadata, msg interface{}) {
	for _, item := range msg.([]*metadbmodel.PodService) {
		var opts []eventapi.TagFieldOption
		info, err := md.GetToolDataSet().GetPodServiceInfoByID(item.ID)
		if err != nil {
			log.Error(err)
		} else {
			opts = append(opts, []eventapi.TagFieldOption{
				eventapi.TagAZID(info.AZID),
				eventapi.TagRegionID(info.RegionID),
			}...)
		}
		opts = append(opts, []eventapi.TagFieldOption{
			eventapi.TagPodServiceID(item.ID),
			eventapi.TagVPCID(item.VPCID),
			eventapi.TagL3DeviceType(p.deviceType),
			eventapi.TagL3DeviceID(item.ID),
			eventapi.TagPodClusterID(item.PodClusterID),
			eventapi.TagPodNSID(item.PodNamespaceID),
		}...)

		p.createInstanceAndEnqueue(md,
			item.Lcuuid,
			eventapi.RESOURCE_EVENT_TYPE_CREATE,
			item.Name,
			p.deviceType,
			item.ID,
			opts...,
		)
	}
}

func (c *PodService) OnResourceUpdated(md *message.Metadata, msg interface{}) {
	fields := msg.(*message.PodServiceFieldsUpdate)
	if !fields.Metadata.IsDifferent() && !fields.Spec.IsDifferent() {
		return
	}
	eventType := eventapi.RESOURCE_EVENT_TYPE_MODIFY
	var opts []eventapi.TagFieldOption

	old := fields.Metadata.GetOld() + "\n" + fields.Spec.GetOld()
	new := fields.Metadata.GetNew() + "\n" + fields.Spec.GetNew()
	if old == "\n" || new == "\n" {
		return
	} else {
		diff := CompareConfig(old, new, int(c.cfg.ConfigDiffContext))

		opts = []eventapi.TagFieldOption{
			eventapi.TagPodServiceID(fields.GetID()),
			eventapi.TagAttributes(
				[]string{eventapi.AttributeNameConfig, eventapi.AttributeNameConfigDiff},
				[]string{new, diff}),
		}
	}
	c.createAndEnqueue(md, fields.GetLcuuid(), eventType, opts...)
}

func (p *PodService) OnResourceBatchDeleted(md *message.Metadata, msg interface{}) {
	for _, item := range msg.([]*metadbmodel.PodService) {
		p.createInstanceAndEnqueue(md, item.Lcuuid, eventapi.RESOURCE_EVENT_TYPE_DELETE, item.Name, p.deviceType, item.ID)
	}
}
