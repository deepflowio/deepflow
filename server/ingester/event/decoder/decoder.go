/*
 * Copyright (c) 2023 Yunshan Networks
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
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/message/trident"
	ingestercommon "github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/event/common"
	"github.com/deepflowio/deepflow/server/ingester/event/config"
	"github.com/deepflowio/deepflow/server/ingester/event/dbwriter"
	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
	"github.com/deepflowio/deepflow/server/libs/zerodoc/pb"
)

var log = logging.MustGetLogger("event.decoder")

const (
	BUFFER_SIZE = 1024
	SEPARATOR   = ", "
)

type Counter struct {
	InCount    int64 `statsd:"in-count"`
	OutCount   int64 `statsd:"out-count"`
	ErrorCount int64 `statsd:"err-count"`
}

type Decoder struct {
	eventType         common.EventType
	resourceInfoTable *ResourceInfoTable
	platformData      *grpc.PlatformInfoTable
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
	platformData *grpc.PlatformInfoTable,
	config *config.Config,
) *Decoder {
	controllers := make([]net.IP, len(config.Base.ControllerIPs))
	for i, ipString := range config.Base.ControllerIPs {
		controllers[i] = net.ParseIP(ipString)
		if controllers[i].To4() != nil {
			controllers[i] = controllers[i].To4()
		}
	}
	var resourceInfoTable *ResourceInfoTable
	if eventType == common.RESOURCE_EVENT {
		resourceInfoTable = NewResourceInfoTable(controllers, int(config.Base.ControllerPort), config.Base.GrpcBufferSize)
	}
	return &Decoder{
		eventType:         eventType,
		resourceInfoTable: resourceInfoTable,
		platformData:      platformData,
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
	if d.resourceInfoTable != nil {
		d.resourceInfoTable.Start()
	}
	ingestercommon.RegisterCountableForIngester("decoder", d, stats.OptionStatTags{
		"event_type": d.eventType.String()})
	buffer := make([]interface{}, BUFFER_SIZE)
	decoder := &codec.SimpleDecoder{}
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
					continue
				}
				d.handleResourceEvent(event)
				event.Release()
			case common.PROC_EVENT:
				if buffer[i] == nil {
					continue
				}
				d.counter.InCount++
				recvBytes, ok := buffer[i].(*receiver.RecvBuffer)
				if !ok {
					log.Warning("get decode queue data type wrong")
					continue
				}
				decoder.Init(recvBytes.Buffer[recvBytes.Begin:recvBytes.End])
				d.handleProcEvent(recvBytes.VtapID, decoder)
				receiver.ReleaseRecvBuffer(recvBytes)
			}
		}
	}
}

func (d *Decoder) WriteProcEvent(vtapId uint16, e *pb.ProcEvent) {
	eventStore := dbwriter.AcquireEventStore()
	eventStore.HasMetrics = true
	eventStore.Time = uint32(time.Duration(e.StartTime) / time.Second)
	eventStore.StartTime = int64(time.Duration(e.StartTime) / time.Microsecond)
	eventStore.EndTime = int64(time.Duration(e.EndTime) / time.Microsecond)
	eventStore.Duration = uint64(e.EndTime - e.StartTime)

	if e.EventType == pb.EventType_IoEvent {
		eventStore.SignalSource = uint8(dbwriter.SIGNAL_SOURCE_IO)
	} else {
		eventStore.SignalSource = uint8(e.EventType)
	}

	if e.IoEventData != nil {
		ioData := e.IoEventData
		eventStore.EventType = strings.ToLower(ioData.Operation.String())
		eventStore.EventDescription = fmt.Sprintf("process %s (%d) %s %d bytes and took %dms", string(e.ProcessKname), e.Pid, eventStore.EventType, ioData.BytesCount, ioData.Latency/uint64(time.Millisecond))
		eventStore.AttributeNames = append(eventStore.AttributeNames, "file_name", "thread_id", "coroutine_id")
		eventStore.AttributeValues = append(eventStore.AttributeValues, string(ioData.Filename), strconv.Itoa(int(e.ThreadId)), strconv.Itoa(int(e.CoroutineId)))
		eventStore.Bytes = ioData.BytesCount
		eventStore.Duration = uint64(eventStore.EndTime - eventStore.StartTime)
	}
	eventStore.VTAPID = vtapId
	eventStore.L3EpcID = d.platformData.QueryVtapEpc0(uint32(vtapId))
	if baseInfo := d.platformData.QueryEpcIDBaseInfo(eventStore.L3EpcID); baseInfo != nil {
		eventStore.RegionID = uint16(baseInfo.RegionID)
	}
	eventStore.AppInstance = strconv.Itoa(int(e.Pid))

	d.eventWriter.Write(eventStore)
}

func (d *Decoder) handleProcEvent(vtapId uint16, decoder *codec.SimpleDecoder) {
	for !decoder.IsEnd() {
		bytes := decoder.ReadBytes()
		if decoder.Failed() {
			if d.counter.ErrorCount == 0 {
				log.Errorf("proc event decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			}
			d.counter.ErrorCount++
			return
		}
		pbProcEvent := &pb.ProcEvent{}
		if err := pbProcEvent.Unmarshal(bytes); err != nil {
			if d.counter.ErrorCount == 0 {
				log.Errorf("proc event unmarshal failed, err: %s", err)
			}
			d.counter.ErrorCount++
			continue
		}
		d.WriteProcEvent(vtapId, pbProcEvent)
	}
}

func uint32ArrayToStr(u32s []uint32) string {
	sb := &strings.Builder{}
	for i, u32 := range u32s {
		sb.WriteString(strconv.Itoa(int(u32)))
		if i < len(u32s)-1 {
			sb.WriteString(SEPARATOR)
		}
	}
	return sb.String()
}

func getAutoInstance(instanceID, instanceType, GProcessID uint32) (uint32, uint8) {
	if GProcessID == 0 || instanceType == ingestercommon.PodType {
		return instanceID, uint8(instanceType)
	}
	return GProcessID, ingestercommon.ProcessType
}

func (d *Decoder) handleResourceEvent(event *eventapi.ResourceEvent) {
	eventStore := dbwriter.AcquireEventStore()
	eventStore.HasMetrics = false
	eventStore.Time = uint32(event.Time)
	eventStore.StartTime = event.TimeMilli * 1000 // convert to microsecond
	eventStore.EndTime = eventStore.StartTime

	eventStore.SignalSource = uint8(dbwriter.SIGNAL_SOURCE_RESOURCE)
	eventStore.EventType = event.Type
	eventStore.EventDescription = event.Description

	eventStore.GProcessID = event.GProcessID

	if len(event.AttributeSubnetIDs) > 0 {
		eventStore.AttributeNames = append(eventStore.AttributeNames, "subnet_ids")
		eventStore.AttributeValues = append(eventStore.AttributeValues,
			uint32ArrayToStr(event.AttributeSubnetIDs))
	}
	if len(event.AttributeIPs) > 0 {
		eventStore.AttributeNames = append(eventStore.AttributeNames, "ips")
		eventStore.AttributeValues = append(eventStore.AttributeValues,
			strings.Join(event.AttributeIPs, SEPARATOR))

	}

	podGroupType := uint8(0)
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
			podGroupType = resourceInfo.PodGroupType
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
		podGroupType = event.PodGroupType
		eventStore.L3DeviceType = uint8(event.L3DeviceType)
		eventStore.L3DeviceID = event.L3DeviceID
	}
	eventStore.SubnetID = uint16(event.SubnetID)
	eventStore.IsIPv4 = true
	if ip := net.ParseIP(event.IP); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			eventStore.IP4 = utils.IpToUint32(ip4)
		} else {
			eventStore.IsIPv4 = false
			eventStore.IP6 = ip
		}
	}
	eventStore.AutoInstanceID, eventStore.AutoInstanceType =
		ingestercommon.GetAutoInstance(
			eventStore.PodID,
			eventStore.GProcessID,
			eventStore.PodNodeID,
			eventStore.L3DeviceID,
			eventStore.L3DeviceType,
			eventStore.L3EpcID,
		)
	// if resource information is not matched, it will be filled with event(InstanceID, InstanceType, GProcessID) information
	if eventStore.AutoInstanceID == 0 {
		eventStore.AutoInstanceID, eventStore.AutoInstanceType = getAutoInstance(event.InstanceID, event.InstanceType, event.GProcessID)
	}

	if event.InstanceType == uint32(trident.DeviceType_DEVICE_TYPE_POD_SERVICE) {
		eventStore.ServiceID = event.InstanceID
	}
	eventStore.AutoServiceID, eventStore.AutoServiceType =
		ingestercommon.GetAutoService(
			eventStore.ServiceID,
			eventStore.PodGroupID,
			eventStore.GProcessID,
			eventStore.PodNodeID,
			eventStore.L3DeviceID,
			eventStore.L3DeviceType,
			podGroupType,
			eventStore.L3EpcID,
		)

	d.eventWriter.Write(eventStore)
}
