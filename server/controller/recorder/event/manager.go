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
	"time"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	. "github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type EventManagerBase struct {
	resourceType string
	ToolDataSet  *cache.ToolDataSet
	Queue        *queue.OverwriteQueue
}

type ResourceEventToMySQL struct {
	eventapi.ResourceEvent
}

func (e *EventManagerBase) createAndEnqueue(
	resourceLcuuid, eventType, instanceName string, instanceType, instanceID int, options ...eventapi.TagFieldOption) {
	// use interface in eventapi to create ResourceEvent instance which will be enqueued, because we need to manually free instance memory
	event := eventapi.AcquireResourceEvent()
	e.fillEvent(event, eventType, instanceName, instanceType, instanceID, options...)
	e.enqueue(resourceLcuuid, event)
}

func (e *EventManagerBase) createProcessAndEnqueue(
	resourceLcuuid, eventType, instanceName string, instanceType, instanceID int, options ...eventapi.TagFieldOption) {
	// use interface in eventapi to create ResourceEvent instance which will be enqueued, because we need to manually free instance memory
	event := eventapi.AcquireResourceEvent()
	e.fillEvent(event, eventType, instanceName, instanceType, instanceID, options...)
	// add process info
	event.GProcessID = uint32(instanceID)
	event.GProcessName = instanceName
	e.enqueue(resourceLcuuid, event)
}

func (e EventManagerBase) fillEvent(
	event *eventapi.ResourceEvent,
	eventType, instanceName string, instanceType, instanceID int, options ...eventapi.TagFieldOption,
) {
	event.Time = time.Now().Unix()
	event.TimeMilli = time.Now().UnixMilli()
	event.Type = eventType
	event.InstanceType = uint32(instanceType)
	event.InstanceID = uint32(instanceID)
	event.InstanceName = instanceName
	event.IfNeedTagged = true
	if eventType == eventapi.RESOURCE_EVENT_TYPE_CREATE || eventType == eventapi.RESOURCE_EVENT_TYPE_ADD_IP {
		event.IfNeedTagged = false
	}
	for _, option := range options {
		option(event)
	}
}

func (e *EventManagerBase) enqueue(resourceLcuuid string, event *eventapi.ResourceEvent) {
	rt := e.resourceType
	if rt == "" {
		rt = DEVICE_TYPE_INT_TO_STR[int(event.InstanceType)]
	}
	log.Infof("put %s event (lcuuid: %s): %+v into shared queue", rt, resourceLcuuid, event)
	err := e.Queue.Put(event)
	if err != nil {
		log.Error(putEventIntoQueueFailed(rt, err))
	}
}

// Due to the fixed sequence of resource learning, some data required by resource change events can only be obtained after the completion of subsequent resource learning.
// Therefore, we need to store the change event temporarily until all resources are learned and the required data is filled before the queue is added
// Such change events include:
// - PodNode's/POD's create event, PodNode's/POD's add-ip event, fill in the L3Device information and HostID as required
// - POD's recreate event, requires real-time IPs information
func (e *EventManagerBase) enqueueIfInsertIntoMySQLFailed(
	resourceLcuuid, domainLcuuid string, eventType, instanceName string, instanceType, instanceID int, options ...eventapi.TagFieldOption,
) {
	// use struct to create ResourceEvent instance if it will be stored in MySQL
	event := &eventapi.ResourceEvent{}
	e.fillEvent(event, eventType, instanceName, instanceType, instanceID, options...)
	content, err := json.Marshal(event)
	if err != nil {
		log.Errorf("json marshal event (detail: %#v) failed: %s", event, err.Error())
	} else {
		dbItem := mysql.ResourceEvent{
			Domain:  domainLcuuid,
			Content: string(content),
		}
		err = mysql.Db.Create(&dbItem).Error
		if err != nil {
			log.Errorf("add resource_event (detail: %#v) failed: %s", dbItem, err.Error())
		} else {
			log.Infof("create resource_event (detail: %#v) success", dbItem)
			return
		}
	}

	e.convertAndEnqueue(resourceLcuuid, event)
}

func (e *EventManagerBase) convertAndEnqueue(resourceLcuuid string, ev *eventapi.ResourceEvent) {
	event := e.convertToEventBeEnqueued(ev)
	e.enqueue(resourceLcuuid, event)
}

func (e *EventManagerBase) convertToEventBeEnqueued(ev *eventapi.ResourceEvent) *eventapi.ResourceEvent {
	event := eventapi.AcquireResourceEvent()
	event.Time = ev.Time
	event.TimeMilli = ev.TimeMilli
	event.Type = ev.Type
	event.InstanceType = ev.InstanceType
	event.InstanceName = ev.InstanceName
	event.InstanceID = ev.InstanceID
	event.SubnetIDs = ev.SubnetIDs
	event.IPs = ev.IPs
	event.IfNeedTagged = ev.IfNeedTagged
	event.RegionID = ev.RegionID
	event.AZID = ev.AZID
	event.VPCID = ev.VPCID
	event.L3DeviceType = ev.L3DeviceType
	event.L3DeviceID = ev.L3DeviceID
	event.HostID = ev.HostID
	event.PodClusterID = ev.PodClusterID
	event.PodNSID = ev.PodNSID
	event.PodNodeID = ev.PodNodeID
	event.PodServiceID = ev.PodServiceID
	event.PodGroupID = ev.PodGroupID
	event.PodID = ev.PodID
	event.Description = ev.Description
	return event
}
