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
	"slices"

	"github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type WholeSubDomain struct {
	ManagerComponent
	ChangedSubscriberComponent
	tool *IPTool
}

func NewWholeSubDomain(q *queue.OverwriteQueue) *WholeSubDomain {
	mng := &WholeSubDomain{
		newManagerComponent(common.RESOURCE_TYPE_SUB_DOMAIN_EN, q),
		newChangedSubscriberComponent(pubsub.PubSubTypeWholeSubDomain),
		newTool(),
	}
	mng.SetSubscriberSelf(mng)
	return mng
}

// After all updaters are processed, fill the information of resource events stored in the db and put them to the queue.
// If the population fails, incomplete resource events are also written to the queue.
func (r *WholeSubDomain) OnAnyChanged(md *message.Metadata) {
	var dbItems []metadbmodel.ResourceEvent // TODO use domain_id, sub_domain_id
	err := md.GetDB().Where(map[string]interface{}{"domain": md.GetDomainLcuuid(), "sub_domain": md.GetSubDomainLcuuid()}).Find(&dbItems).Error
	if err != nil {
		log.Errorf("db query resource_event failed: %s", err.Error(), md.LogPrefixes)
		return
	}
	for _, item := range dbItems {
		var event *eventapi.ResourceEvent
		err = json.Unmarshal([]byte(item.Content), &event)
		if err != nil {
			log.Errorf("json marshal event (detail: %#v) failed: %s", item, err, md.LogPrefixes)
			md.GetDB().Delete(&item)
			continue
		}

		if event.Type == eventapi.RESOURCE_EVENT_TYPE_RECREATE {
			r.fillRecreatePodEvent(md, event)
			r.convertAndEnqueue(md, item.ResourceLcuuid, event)
		} else if slices.Contains([]string{eventapi.RESOURCE_EVENT_TYPE_CREATE, eventapi.RESOURCE_EVENT_TYPE_ATTACH_IP}, event.Type) {
			r.fillL3DeviceInfo(md, event)
			r.convertAndEnqueue(md, item.ResourceLcuuid, event)
		} else if slices.Contains([]string{
			eventapi.RESOURCE_EVENT_TYPE_ATTACH_CONFIG_MAP,
			eventapi.RESOURCE_EVENT_TYPE_MODIFY_CONFIG_MAP,
			eventapi.RESOURCE_EVENT_TYPE_DETACH_CONFIG_MAP}, event.Type) {
			podGroupIDs := md.GetToolDataSet().GetPodGroupIDsByConfigMapID(int(event.ConfigMapID))
			if len(podGroupIDs) != 0 {
				log.Infof("pod group ids: %v connected to config map (id: %d)", podGroupIDs, event.ConfigMapID, md.LogPrefixes)
			}
			for _, podGroupID := range podGroupIDs {
				event.PodGroupID = uint32(podGroupID)
				r.convertAndEnqueue(md, item.ResourceLcuuid, event)
			}
		}
		md.GetDB().Delete(&item)
	}
}

func (r *WholeSubDomain) fillRecreatePodEvent(md *message.Metadata, event *eventapi.ResourceEvent) {
	var networkIDs []uint32
	var ips []string
	ipNetworkMap, _ := md.GetToolDataSet().EventDataSet.GetPodIPNetworkMapByID(int(event.InstanceID))
	for ip, nID := range ipNetworkMap {
		networkIDs = append(networkIDs, uint32(nID))
		ips = append(ips, ip.IP)
	}
	event.AttributeSubnetIDs = networkIDs
	event.AttributeIPs = ips
}

func (r *WholeSubDomain) fillL3DeviceInfo(md *message.Metadata, event *eventapi.ResourceEvent) bool {
	var podNodeID int
	if event.InstanceType == common.VIF_DEVICE_TYPE_POD_NODE {
		podNodeID = int(event.InstanceID)
	} else if event.InstanceType == common.VIF_DEVICE_TYPE_POD {
		podInfo, err := md.GetToolDataSet().GetPodInfoByID(int(event.InstanceID))
		if err != nil {
			log.Errorf("get pod (id: %d) pod node ID failed: %s", event.InstanceID, err.Error(), md.LogPrefixes)
			return false
		}
		podNodeID = podInfo.PodNodeID
	}
	l3DeviceOpts, ok := r.tool.getL3DeviceOptionsByPodNodeID(md, podNodeID)
	if ok {
		for _, option := range l3DeviceOpts {
			option(event)
		}
	}
	return true
}
