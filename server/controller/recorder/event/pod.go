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

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/metadata"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type Pod struct {
	EventManagerBase
	deviceType int
	tool       *IPTool
}

func NewPod(toolDS *tool.DataSet, eq *queue.OverwriteQueue) *Pod {
	mng := &Pod{
		newEventManagerBase(
			ctrlrcommon.RESOURCE_TYPE_POD_EN,
			toolDS,
			eq,
		),
		ctrlrcommon.VIF_DEVICE_TYPE_POD,
		newTool(toolDS),
	}
	return mng
}

func (p *Pod) ProduceByAdd(items []*mysql.Pod) {
	for _, item := range items {
		var opts []eventapi.TagFieldOption
		var domainLcuuid string
		info, err := p.ToolDataSet.GetPodInfoByID(item.ID)
		if err != nil {
			log.Error(err)
		} else {
			opts = append(opts, []eventapi.TagFieldOption{
				eventapi.TagAZID(info.AZID),
				eventapi.TagRegionID(info.RegionID),
			}...)
			domainLcuuid = info.DomainLcuuid
		}
		podGroupType, ok := p.ToolDataSet.GetPodGroupTypeByID(item.PodGroupID)
		if !ok {
			log.Error(p.metadata.LogPre(fmt.Sprintf("db pod_group type(id: %d) not found", item.PodGroupID)))
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

		l3DeviceOpts, ok := p.tool.getL3DeviceOptionsByPodNodeID(item.PodNodeID)
		if ok {
			opts = append(opts, l3DeviceOpts...)
			p.createAndEnqueue(
				item.Lcuuid,
				eventapi.RESOURCE_EVENT_TYPE_CREATE,
				item.Name,
				p.deviceType,
				item.ID,
				opts...,
			)
		} else {
			p.enqueueIfInsertIntoMySQLFailed(
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

func (p *Pod) ProduceByUpdate(cloudItem *cloudmodel.Pod, diffBase *diffbase.Pod) {
	if diffBase.CreatedAt != cloudItem.CreatedAt {
		var (
			id   int
			name string
			err  error
		)
		id, ok := p.ToolDataSet.GetPodIDByLcuuid(diffBase.Lcuuid)
		if ok {
			name, err = p.ToolDataSet.GetPodNameByID(id)
			if err != nil {
				log.Error(p.metadata.LogPre("%v, %v", idByLcuuidNotFound(p.resourceType, diffBase.Lcuuid), err))
			}
		} else {
			log.Error(nameByIDNotFound(p.resourceType, id))
		}

		var oldPodNodeName string
		oldPodNodeID := p.ToolDataSet.GetPodNodeIDByLcuuid(diffBase.PodNodeLcuuid)
		if oldPodNodeID != 0 {
			oldPodNodeName, err = p.ToolDataSet.GetPodNodeNameByID(oldPodNodeID)
			if err != nil {
				log.Error(p.metadata.LogPre("%v, %v", idByLcuuidNotFound(p.resourceType, diffBase.PodNodeLcuuid), err))
			}
		}

		var newPodNodeName string
		newPodNodeID := p.ToolDataSet.GetPodNodeIDByLcuuid(cloudItem.PodNodeLcuuid)
		if newPodNodeID != 0 {
			newPodNodeName, err = p.ToolDataSet.GetPodNodeNameByID(newPodNodeID)
			if err != nil {
				log.Error(p.metadata.LogPre("%v, %v", idByLcuuidNotFound(p.resourceType, cloudItem.PodNodeLcuuid), err))
			}
		}

		nIDs, ips := p.getIPNetworksByID(id)
		var domainLcuuid string
		info, err := p.ToolDataSet.GetPodInfoByID(id)
		if err != nil {
			log.Error(err)
		} else {
			domainLcuuid = info.DomainLcuuid
		}
		opts := []eventapi.TagFieldOption{
			eventapi.TagDescription(fmt.Sprintf(DESCRecreateFormat, cloudItem.Name, oldPodNodeName, newPodNodeName)),
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
			cloudItem.Lcuuid,
			domainLcuuid,
			eventapi.RESOURCE_EVENT_TYPE_RECREATE,
			name,
			p.deviceType,
			id,
			opts...,
		)
	}
}

func (p *Pod) ProduceByDelete(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		var (
			id   int
			name string
			err  error
		)
		id, ok := p.ToolDataSet.GetPodIDByLcuuid(lcuuid)
		if ok {
			name, err = p.ToolDataSet.GetPodNameByID(id)
			if err != nil {
				log.Error(p.metadata.LogPre("%v, %v", idByLcuuidNotFound(p.resourceType, lcuuid), err))
			}
		} else {
			log.Error(nameByIDNotFound(p.resourceType, id))
		}

		p.createAndEnqueue(lcuuid, eventapi.RESOURCE_EVENT_TYPE_DELETE, name, p.deviceType, id)
	}
}

func (p *Pod) getIPNetworksByID(id int) (networkIDs []uint32, ips []string) {
	ipNetworkMap, _ := p.ToolDataSet.EventDataSet.GetPodIPNetworkMapByID(id)
	for ip, nID := range ipNetworkMap {
		networkIDs = append(networkIDs, uint32(nID))
		ips = append(ips, ip.IP)
	}
	return
}
