/*
 * Copyright (c) 2022 Yunshan Networks
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
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type SubDomain struct {
	domainLcuuid    string
	subDomainLcuuid string
	EventManagerBase
}

func NewSubDomain(domainLcuuid, subDomainLcuuid string, toolDS *cache.ToolDataSet, eq *queue.OverwriteQueue) *SubDomain {
	return &SubDomain{
		domainLcuuid,
		subDomainLcuuid,
		EventManagerBase{
			ToolDataSet: toolDS,
			Queue:       eq,
		},
	}
}

// After all updaters are processed, fill the information of resource events stored in the db and put them to the queue.
// If the population fails, incomplete resource events are also written to the queue.
func (r *SubDomain) ProduceFromMySQL() {
	var dbItems []mysql.ResourceEvent
	err := mysql.Db.Where("domain = ? AND sub_domain = ?", r.domainLcuuid, r.subDomainLcuuid).Find(&dbItems).Error
	if err != nil {
		log.Errorf("db query resource_event failed:%s", err.Error())
		return
	}
	for _, item := range dbItems {
		var event *eventapi.ResourceEvent
		err = json.Unmarshal([]byte(item.Content), &event)
		if err != nil {
			log.Errorf("json marshal event (detail: %#v) failed: %s", item, err.Error())
			mysql.Db.Delete(&item)
			continue
		}

		if event.Type == eventapi.RESOURCE_EVENT_TYPE_RECREATE {
			r.fillRecreatePodEvent(event)
		} else if common.Contains([]string{eventapi.RESOURCE_EVENT_TYPE_CREATE, eventapi.RESOURCE_EVENT_TYPE_ADD_IP}, event.Type) {
			r.fillL3DeviceInfo(event)
		}
		r.convertAndEnqueue(item.ResourceLcuuid, event)
		mysql.Db.Delete(&item)
	}
}

func (r *SubDomain) fillRecreatePodEvent(event *eventapi.ResourceEvent) {
	var networkIDs []uint32
	var ips []string
	ipNetworkMap, _ := r.ToolDataSet.EventToolDataSet.GetPodIPNetworkMapByID(int(event.InstanceID))
	for ip, nID := range ipNetworkMap {
		networkIDs = append(networkIDs, uint32(nID))
		ips = append(ips, ip.IP)
	}
	event.SubnetIDs = networkIDs
	event.IPs = ips
}

func (r *SubDomain) fillL3DeviceInfo(event *eventapi.ResourceEvent) bool {
	var podNodeID int
	if event.InstanceType == common.VIF_DEVICE_TYPE_POD_NODE {
		podNodeID = int(event.InstanceID)
	} else if event.InstanceType == common.VIF_DEVICE_TYPE_POD {
		podInfo, err := r.ToolDataSet.GetPodInfoByID(int(event.InstanceID))
		if err != nil {
			log.Errorf("get pod (id: %d) pod node ID failed: %s", event.InstanceID, err.Error())
			return false
		}
		podNodeID = podInfo.PodNodeID
	}
	l3DeviceOpts, ok := getL3DeviceOptionsByPodNodeID(r.ToolDataSet, podNodeID)
	if ok {
		for _, option := range l3DeviceOpts {
			option(event)
		}
	}
	return true
}
