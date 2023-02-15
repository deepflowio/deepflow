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

package decoder

import (
	"net"

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/message/trident"
	ingestercommon "github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/event/common"
	"github.com/deepflowio/deepflow/server/ingester/event/config"
	"github.com/deepflowio/deepflow/server/ingester/event/dbwriter"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("event.decoder")

const (
	BUFFER_SIZE = 1024
)

type Counter struct {
	InCount    int64 `statsd:"in-count"`
	OutCount   int64 `statsd:"out-count"`
	ErrorCount int64 `statsd:"err-count"`
}

type Decoder struct {
	eventType         common.EventType
	resourceInfoTable *ResourceInfoTable
	inQueue           queue.QueueReader
	eventWriter       *dbwriter.EventWriter
	debugEnabled      bool
	config            *config.Config

	counter *Counter
	utils.Closable
}

func NewDecoder(
	eventType common.EventType,
	inQueue queue.QueueReader,
	eventWriter *dbwriter.EventWriter,
	config *config.Config,
) *Decoder {
	controllers := make([]net.IP, len(config.Base.ControllerIPs))
	for i, ipString := range config.Base.ControllerIPs {
		controllers[i] = net.ParseIP(ipString)
		if controllers[i].To4() != nil {
			controllers[i] = controllers[i].To4()
		}
	}
	resourceInfoTable := NewResourceInfoTable(controllers, int(config.Base.ControllerPort), config.Base.GrpcBufferSize)
	return &Decoder{
		eventType:         eventType,
		resourceInfoTable: resourceInfoTable,
		inQueue:           inQueue,
		debugEnabled:      log.IsEnabledFor(logging.DEBUG),
		eventWriter:       eventWriter,
		config:            config,
		counter:           &Counter{},
	}
}

func (d *Decoder) GetCounter() interface{} {
	var counter *Counter
	counter, d.counter = d.counter, &Counter{}
	return counter
}

func (d *Decoder) Run() {
	log.Infof("event(%s) decoder run", d.eventType)
	d.resourceInfoTable.Start()
	ingestercommon.RegisterCountableForIngester("decoder", d, stats.OptionStatTags{
		"event_type": d.eventType.String()})
	buffer := make([]interface{}, BUFFER_SIZE)
	for {
		n := d.inQueue.Gets(buffer)
		for i := 0; i < n; i++ {
			if buffer[i] == nil {
				continue
			}
			d.counter.InCount++
			switch d.eventType {
			case common.RESOURCE_EVENT:
				event, ok := buffer[i].(*eventapi.ResourceEvent)
				if !ok {
					log.Warning("get decode queue data type wrong")
				} else {
					d.handleResourceEvent(event)
					event.Release()
				}
			default:
				log.Warningf("unknown event type %d", d.eventType)
			}
		}
	}
}

func (d *Decoder) handleResourceEvent(event *eventapi.ResourceEvent) {
	eventStore := dbwriter.AcquireEventStore()
	eventStore.Time = uint32(event.Time)

	eventStore.InstanceType = event.InstanceType
	eventStore.InstanceID = event.InstanceID
	eventStore.InstanceName = event.InstanceName

	eventStore.EventType = event.Type
	eventStore.EventDescription = event.Description

	eventStore.SubnetIDs = append(eventStore.SubnetIDs, event.SubnetIDs...)
	eventStore.IPs = append(eventStore.IPs, event.IPs...)
	eventStore.GProcessID = event.GProcessID

	if event.IfNeedTagged {
		eventStore.Tagged = 1
		resourceInfo := d.resourceInfoTable.QueryResourceInfo(event.InstanceType, event.InstanceID)
		if resourceInfo != nil {
			eventStore.RegionID = uint16(resourceInfo.RegionID)
			eventStore.AZID = uint16(resourceInfo.AZID)
			eventStore.L3EpcID = resourceInfo.L3EpcID
			eventStore.HostID = uint16(resourceInfo.HostID)
			eventStore.PodID = resourceInfo.PodID
			eventStore.PodNodeID = resourceInfo.PodNodeID
			eventStore.PodNSID = uint16(resourceInfo.PodNSID)
			eventStore.PodClusterID = uint16(resourceInfo.PodClusterID)
			eventStore.PodGroupID = resourceInfo.PodGroupID
			eventStore.L3DeviceType = uint8(resourceInfo.L3DeviceType)
			eventStore.L3DeviceID = resourceInfo.L3DeviceID
		}
	} else {
		eventStore.Tagged = 0
		eventStore.RegionID = uint16(event.RegionID)
		eventStore.AZID = uint16(event.AZID)
		if event.VPCID == 0 {
			eventStore.L3EpcID = -2
		} else {
			eventStore.L3EpcID = int32(event.VPCID)
		}
		eventStore.HostID = uint16(event.HostID)
		eventStore.PodID = event.PodID
		eventStore.PodNodeID = event.PodNodeID
		eventStore.PodNSID = uint16(event.PodNSID)
		eventStore.PodClusterID = uint16(event.PodClusterID)
		eventStore.PodGroupID = event.PodGroupID
		eventStore.L3DeviceType = uint8(event.L3DeviceType)
		eventStore.L3DeviceID = event.L3DeviceID

	}
	if event.InstanceType == uint32(trident.DeviceType_DEVICE_TYPE_POD_SERVICE) {
		eventStore.ServiceID = event.InstanceID
	}

	d.eventWriter.Write(eventStore)
}
