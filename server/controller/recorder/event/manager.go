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
	"reflect"
	"slices"
	"time"

	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type ManagerComponent struct {
	resourceType string
	Queue        *queue.OverwriteQueue
}

func newManagerComponent(rt string, q *queue.OverwriteQueue) ManagerComponent {
	return ManagerComponent{
		resourceType: rt,
		Queue:        q,
	}
}

// TODO remove
func (e *ManagerComponent) createInstanceAndEnqueue(
	md *message.Metadata,
	resourceLcuuid, eventType, instanceName string, instanceType, instanceID int, options ...eventapi.TagFieldOption) {
	options = append(
		options,
		eventapi.TagInstanceType(uint32(instanceType)),
		eventapi.TagInstanceID(uint32(instanceID)),
		eventapi.TagInstanceName(instanceName))

	e.createAndEnqueue(md, resourceLcuuid, eventType, options...)
}

func (e *ManagerComponent) createAndEnqueue(
	md *message.Metadata, resourceLcuuid, eventType string, options ...eventapi.TagFieldOption) {
	// use interface in eventapi to create ResourceEvent instance which will be enqueued, because we need to manually free instance memory
	event := eventapi.AcquireResourceEvent()
	e.fillEvent(md, event, eventType, options...)
	e.enqueue(md, resourceLcuuid, event)
}

func (e ManagerComponent) fillEvent(
	md *message.Metadata,
	event *eventapi.ResourceEvent,
	eventType string, options ...eventapi.TagFieldOption,
) {
	event.ORGID = uint16(md.GetORGID())
	event.TeamID = uint16(md.GetTeamID())
	event.Time = time.Now().Unix()
	event.TimeMilli = time.Now().UnixMilli()
	event.Type = eventType
	event.IfNeedTagged = true
	if slices.Contains([]string{
		eventapi.RESOURCE_EVENT_TYPE_CREATE,
		eventapi.RESOURCE_EVENT_TYPE_ATTACH_IP,
		eventapi.RESOURCE_EVENT_TYPE_MODIFY,
		eventapi.RESOURCE_EVENT_TYPE_ATTACH_CONFIG_MAP,
		eventapi.RESOURCE_EVENT_TYPE_MODIFY_CONFIG_MAP,
		eventapi.RESOURCE_EVENT_TYPE_DETACH_CONFIG_MAP,
	}, eventType) {
		event.IfNeedTagged = false
	}
	for _, option := range options {
		option(event)
	}
}

func (e *ManagerComponent) enqueue(md *message.Metadata, resourceLcuuid string, event *eventapi.ResourceEvent) {
	rt := e.resourceType
	if rt == "" {
		rt = common.DEVICE_TYPE_INT_TO_STR[int(event.InstanceType)]
	}
	log.Infof("put %s event (lcuuid: %s): %+v into shared queue", rt, resourceLcuuid, event, md.LogPrefixes)
	err := e.Queue.Put(event)
	if err != nil {
		log.Error(putEventIntoQueueFailed(rt, err), md.LogPrefixes)
	}
}

func (e *ManagerComponent) enqueueInstanceIfInsertIntoMySQLFailed(
	md *message.Metadata,
	resourceLcuuid, domainLcuuid, eventType, instanceName string, instanceType, instanceID int, options ...eventapi.TagFieldOption,
) {
	options = append(
		options,
		eventapi.TagInstanceType(uint32(instanceType)),
		eventapi.TagInstanceID(uint32(instanceID)),
		eventapi.TagInstanceName(instanceName))

	e.enqueueIfInsertIntoMySQLFailed(md, resourceLcuuid, domainLcuuid, eventType, options...)
}

// Due to the fixed sequence of resource learning, some data required by resource change events can only be obtained after the completion of subsequent resource learning.
// Therefore, we need to store the change event temporarily until all resources are learned and the required data is filled before the queue is added.
// Such change events include:
// - PodNode's/POD's create event, PodNode's/POD's add-ip event, fill in the L3Device information and HostID as required
// - POD's recreate event, requires real-time IPs information
// - ConfigMap's create event, ConfigMap's update event, ConfigMap's delete event, requires real-time PodGroup-ConfigMap connection information
// If the event is not stored in MySQL, it will be directly enqueued.
func (e *ManagerComponent) enqueueIfInsertIntoMySQLFailed(
	md *message.Metadata,
	resourceLcuuid, domainLcuuid, eventType string, options ...eventapi.TagFieldOption,
) {
	// use struct to create ResourceEvent instance if it will be stored in MySQL
	event := &eventapi.ResourceEvent{}
	e.fillEvent(md, event, eventType, options...)
	content, err := json.Marshal(event)
	if err != nil {
		log.Errorf("json marshal event (detail: %#v) failed: %s", event, err.Error(), md.LogPrefixes)
	} else {
		dbItem := metadbmodel.ResourceEvent{
			Domain:  domainLcuuid,
			Content: string(content),
		}
		if err = md.GetDB().Create(&dbItem).Error; err == nil {
			log.Infof("create resource_event (detail: %#v) success", dbItem, md.LogPrefixes)
			return
		}
		log.Errorf("add resource_event (detail: %#v) failed: %s", dbItem, err.Error(), md.LogPrefixes)
	}

	e.convertAndEnqueue(md, resourceLcuuid, event)
}

func (e *ManagerComponent) convertAndEnqueue(md *message.Metadata, resourceLcuuid string, ev *eventapi.ResourceEvent) {
	event := e.convertToEventBeEnqueued(ev)
	// log.Infof("TODO: put event (lcuuid: %s): %#v into shared queue", resourceLcuuid, event, md.LogPrefixes)
	e.enqueue(md, resourceLcuuid, event)
}

func (e *ManagerComponent) convertToEventBeEnqueued(ev *eventapi.ResourceEvent) *eventapi.ResourceEvent {
	event := eventapi.AcquireResourceEvent()
	if ev == nil {
		return event
	}

	src := reflect.ValueOf(ev).Elem()
	dst := reflect.ValueOf(event).Elem()
	for i := 0; i < src.NumField(); i++ {
		dst.Field(i).Set(src.Field(i))
	}

	return event
}
