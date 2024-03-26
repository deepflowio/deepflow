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
	"encoding/json"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type SubDomain struct {
	domainLcuuid    string
	subDomainLcuuid string
	EventManagerBase
	tool *IPTool
}

func NewSubDomain(domainLcuuid, subDomainLcuuid string, toolDS *tool.DataSet, eq *queue.OverwriteQueue) *SubDomain {
	return &SubDomain{
		domainLcuuid,
		subDomainLcuuid,
		newEventManagerBase(
			common.RESOURCE_TYPE_SUB_DOMAIN_EN,
			toolDS,
			eq,
		),
		newTool(toolDS),
	}
}

// After all updaters are processed, fill the information of resource events stored in the db and put them to the queue.
// If the population fails, incomplete resource events are also written to the queue.
func (r *SubDomain) ProduceFromMySQL() {
	var dbItems []mysql.ResourceEvent
	err := r.org.DB.Where("domain = ? AND sub_domain = ?", r.domainLcuuid, r.subDomainLcuuid).Find(&dbItems).Error
	if err != nil {
		log.Error(r.org.LogPre("db query resource_event failed:%s", err.Error()))
		return
	}
	for _, item := range dbItems {
		var event *eventapi.ResourceEvent
		err = json.Unmarshal([]byte(item.Content), &event)
		if err != nil {
			log.Error(r.org.LogPre("json marshal event (detail: %#v) failed: %s", item, err.Error()))
			r.org.DB.Delete(&item)
			continue
		}

		if event.Type == eventapi.RESOURCE_EVENT_TYPE_RECREATE {
			r.fillRecreatePodEvent(event)
		} else if common.Contains([]string{eventapi.RESOURCE_EVENT_TYPE_CREATE, eventapi.RESOURCE_EVENT_TYPE_ADD_IP}, event.Type) {
			r.fillL3DeviceInfo(event)
		}
		r.convertAndEnqueue(item.ResourceLcuuid, event)
		r.org.DB.Delete(&item)
	}
}

func (r *SubDomain) fillRecreatePodEvent(event *eventapi.ResourceEvent) {
	var networkIDs []uint32
	var ips []string
	ipNetworkMap, _ := r.ToolDataSet.EventDataSet.GetPodIPNetworkMapByID(int(event.InstanceID))
	for ip, nID := range ipNetworkMap {
		networkIDs = append(networkIDs, uint32(nID))
		ips = append(ips, ip.IP)
	}
	event.AttributeSubnetIDs = networkIDs
	event.AttributeIPs = ips
}

func (r *SubDomain) fillL3DeviceInfo(event *eventapi.ResourceEvent) bool {
	var podNodeID int
	if event.InstanceType == common.VIF_DEVICE_TYPE_POD_NODE {
		podNodeID = int(event.InstanceID)
	} else if event.InstanceType == common.VIF_DEVICE_TYPE_POD {
		podInfo, err := r.ToolDataSet.GetPodInfoByID(int(event.InstanceID))
		if err != nil {
			log.Error(r.org.LogPre("get pod (id: %d) pod node ID failed: %s", event.InstanceID, err.Error()))
			return false
		}
		podNodeID = podInfo.PodNodeID
	}
	l3DeviceOpts, ok := r.tool.getL3DeviceOptionsByPodNodeID(podNodeID)
	if ok {
		for _, option := range l3DeviceOpts {
			option(event)
		}
	}
	return true
}
