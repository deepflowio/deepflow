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
	"fmt"

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/metadata"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type Pod struct {
	ManagerComponent
	CUDSubscriberComponent
	deviceType int
	tool       *IPTool
}

func NewPod(q *queue.OverwriteQueue) *Pod {
	mng := &Pod{
		newManagerComponent(ctrlrcommon.RESOURCE_TYPE_POD_EN, q),
		newCUDSubscriberComponent(ctrlrcommon.RESOURCE_TYPE_POD_EN, SubTopic(pubsub.TopicResourceUpdatedFields)),
		ctrlrcommon.VIF_DEVICE_TYPE_POD,
		newTool(),
	}
	mng.SetSubscriberSelf(mng)
	return mng
}

func (p *Pod) OnResourceBatchAdded(md *message.Metadata, msg interface{}) {
	for _, item := range msg.([]*metadbmodel.Pod) {
		var opts []eventapi.TagFieldOption
		var domainLcuuid string
		info, err := md.GetToolDataSet().GetPodInfoByID(item.ID)
		if err != nil {
			log.Error(err)
		} else {
			opts = append(opts, []eventapi.TagFieldOption{
				eventapi.TagAZID(info.AZID),
				eventapi.TagRegionID(info.RegionID),
			}...)
			domainLcuuid = info.DomainLcuuid
		}
		podGroupType, ok := md.GetToolDataSet().GetPodGroupTypeByID(item.PodGroupID)
		if !ok {
			log.Errorf("db pod_group type(id: %d) not found", item.PodGroupID, md.LogPrefixORGID)
		}

		opts = append(opts, []eventapi.TagFieldOption{
			eventapi.TagPodID(item.ID),
			eventapi.TagVPCID(item.VPCID),
			eventapi.TagPodClusterID(item.PodClusterID),
			eventapi.TagPodGroupID(item.PodGroupID),
			eventapi.TagPodGroupType(metadata.PodGroupTypeMap[podGroupType]),
			eventapi.TagPodServiceID(item.PodServiceID),
			eventapi.TagPodNodeID(item.PodNodeID),
			eventapi.TagPodNSID(item.PodNamespaceID),
		}...)

		l3DeviceOpts, ok := p.tool.getL3DeviceOptionsByPodNodeID(md, item.PodNodeID)
		if ok {
			opts = append(opts, l3DeviceOpts...)
			p.createAndEnqueue(md,
				item.Lcuuid,
				eventapi.RESOURCE_EVENT_TYPE_CREATE,
				item.Name,
				p.deviceType,
				item.ID,
				opts...,
			)
		} else {
			p.enqueueIfInsertIntoMySQLFailed(
				md,
				item.Lcuuid,
				domainLcuuid,
				eventapi.RESOURCE_EVENT_TYPE_CREATE,
				item.Name,
				p.deviceType,
				item.ID,
				opts...,
			)
		}
	}
}

func (p *Pod) OnResourceUpdated(md *message.Metadata, msg interface{}) {
	updatedFields := msg.(*message.PodFieldsUpdate)
	if updatedFields.CreatedAt.IsDifferent() && updatedFields.PodNodeID.IsDifferent() {
		var (
			err error
		)
		id := updatedFields.GetID()
		name := updatedFields.Name.GetNew()

		oldPodNodeName, err := md.GetToolDataSet().GetPodNodeNameByID(updatedFields.PodNodeID.GetOld())
		if err != nil {
			log.Errorf("%v, %v", nameByIDNotFound(p.resourceType, id), err, md.LogPrefixORGID)
		}

		newPodNodeName, err := md.GetToolDataSet().GetPodNodeNameByID(updatedFields.PodNodeID.GetNew())
		if err != nil {
			log.Errorf("%v, %v", nameByIDNotFound(p.resourceType, id), err, md.LogPrefixORGID)
		}

		nIDs, ips := p.getIPNetworksByID(md, id)
		var domainLcuuid string
		info, err := md.GetToolDataSet().GetPodInfoByID(id)
		if err != nil {
			log.Error(err)
		} else {
			domainLcuuid = info.DomainLcuuid
		}
		opts := []eventapi.TagFieldOption{
			eventapi.TagDescription(fmt.Sprintf(DESCRecreateFormat, name, oldPodNodeName, newPodNodeName)),
			eventapi.TagAttributeSubnetIDs(nIDs),
			eventapi.TagAttributeIPs(ips),
		}
		if len(nIDs) > 0 {
			opts = append(opts, eventapi.TagSubnetID(nIDs[0]))
		}
		if len(ips) > 0 {
			opts = append(opts, eventapi.TagIP(ips[0]))
		}
		p.enqueueIfInsertIntoMySQLFailed(
			md,
			updatedFields.GetLcuuid(),
			domainLcuuid,
			eventapi.RESOURCE_EVENT_TYPE_RECREATE,
			name,
			p.deviceType,
			id,
			opts...,
		)
	}
}

func (p *Pod) OnResourceBatchDeleted(md *message.Metadata, msg interface{}) {
	for _, lcuuid := range msg.([]*metadbmodel.Pod) {
		p.createAndEnqueue(md, lcuuid.Lcuuid, eventapi.RESOURCE_EVENT_TYPE_DELETE, lcuuid.Name, p.deviceType, lcuuid.ID)
	}
}

func (p *Pod) getIPNetworksByID(md *message.Metadata, id int) (networkIDs []uint32, ips []string) {
	ipNetworkMap, _ := md.GetToolDataSet().EventDataSet.GetPodIPNetworkMapByID(id)
	for ip, nID := range ipNetworkMap {
		networkIDs = append(networkIDs, uint32(nID))
		ips = append(ips, ip.IP)
	}
	return
}
