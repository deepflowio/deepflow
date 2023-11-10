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

	"github.com/deepflowio/deepflow/message/alarm_event"
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
	"github.com/deepflowio/deepflow/server/libs/zerodoc"
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
					log.Warning("get resoure event decode queue data type wrong")
					continue
				}
				d.handleResourceEvent(event)
				event.Release()
			case common.PERF_EVENT:
				if buffer[i] == nil {
					continue
				}
				recvBytes, ok := buffer[i].(*receiver.RecvBuffer)
				if !ok {
					log.Warning("get proc event decode queue data type wrong")
					continue
				}
				decoder.Init(recvBytes.Buffer[recvBytes.Begin:recvBytes.End])
				d.handlePerfEvent(recvBytes.VtapID, decoder)
				receiver.ReleaseRecvBuffer(recvBytes)
			case common.ALARM_EVENT:
				if buffer[i] == nil {
					continue
				}
				recvBytes, ok := buffer[i].(*receiver.RecvBuffer)
				if !ok {
					log.Warning("get alarm event decode queue data type wrong")
					continue
				}
				decoder.Init(recvBytes.Buffer[recvBytes.Begin:recvBytes.End])
				d.handleAlarmEvent(decoder)
				receiver.ReleaseRecvBuffer(recvBytes)
			}
		}
	}
}

func (d *Decoder) WritePerfEvent(vtapId uint16, e *pb.ProcEvent) {
	s := dbwriter.AcquireEventStore()
	s.HasMetrics = true
	s.Time = uint32(time.Duration(e.StartTime) / time.Second)
	s.StartTime = int64(time.Duration(e.StartTime) / time.Microsecond)
	s.EndTime = int64(time.Duration(e.EndTime) / time.Microsecond)
	s.Duration = uint64(e.EndTime - e.StartTime)
	s.PodID = e.PodId

	if e.EventType == pb.EventType_IoEvent {
		s.SignalSource = uint8(dbwriter.SIGNAL_SOURCE_IO)
	} else {
		s.SignalSource = uint8(e.EventType)
	}

	s.GProcessID = d.platformData.QueryProcessInfo(uint32(vtapId), e.Pid)
	if e.IoEventData != nil {
		ioData := e.IoEventData
		s.EventType = strings.ToLower(ioData.Operation.String())
		s.EventDescription = fmt.Sprintf("process %s (%d) %s %d bytes and took %dms", string(e.ProcessKname), e.Pid, s.EventType, ioData.BytesCount, ioData.Latency/uint64(time.Millisecond))
		s.AttributeNames = append(s.AttributeNames, "file_name", "thread_id", "coroutine_id")
		s.AttributeValues = append(s.AttributeValues, string(ioData.Filename), strconv.Itoa(int(e.ThreadId)), strconv.Itoa(int(e.CoroutineId)))
		s.Bytes = ioData.BytesCount
		s.Duration = uint64(s.EndTime - s.StartTime)
	}
	s.VTAPID = vtapId
	s.L3EpcID = d.platformData.QueryVtapEpc0(uint32(vtapId))

	var info *grpc.Info
	if e.PodId != 0 {
		info = d.platformData.QueryEpcIDPodInfo(int32(s.VTAPID), e.PodId)
	}
	podGroupType := uint8(0)
	if info != nil {
		s.RegionID = uint16(info.RegionID)
		s.AZID = uint16(info.AZID)
		s.L3EpcID = info.EpcID
		s.HostID = uint16(info.HostID)
		s.PodID = info.PodID
		s.PodNodeID = info.PodNodeID
		s.PodNSID = uint16(info.PodNSID)
		s.PodClusterID = uint16(info.PodClusterID)
		s.PodGroupID = info.PodGroupID
		podGroupType = info.PodGroupType
		s.L3DeviceType = uint8(info.DeviceType)
		s.L3DeviceID = info.DeviceID
		s.SubnetID = uint16(info.SubnetID)
		s.IsIPv4 = info.IsIPv4
		s.IP4 = info.IP4
		s.IP6 = info.IP6
		// if it is just Pod Node, there is no need to match the service
		if ingestercommon.IsPodServiceIP(zerodoc.DeviceType(s.L3DeviceType), s.PodID, 0) {
			s.ServiceID = d.platformData.QueryService(
				s.PodID, s.PodNodeID, uint32(s.PodClusterID), s.PodGroupID, s.L3EpcID, !s.IsIPv4, s.IP4, s.IP6, 0, 0)
		}
	} else if baseInfo := d.platformData.QueryEpcIDBaseInfo(s.L3EpcID); baseInfo != nil {
		s.RegionID = uint16(baseInfo.RegionID)
	}

	s.AutoInstanceID, s.AutoInstanceType = ingestercommon.GetAutoInstance(s.PodID, s.GProcessID, s.PodNodeID, s.L3DeviceID, uint8(s.L3DeviceType), s.L3EpcID)
	s.AutoServiceID, s.AutoServiceType = ingestercommon.GetAutoService(s.ServiceID, s.PodGroupID, s.GProcessID, s.PodNodeID, s.L3DeviceID, uint8(s.L3DeviceType), podGroupType, s.L3EpcID)

	s.AppInstance = strconv.Itoa(int(e.Pid))

	d.eventWriter.Write(s)
}

func (d *Decoder) handlePerfEvent(vtapId uint16, decoder *codec.SimpleDecoder) {
	for !decoder.IsEnd() {
		bytes := decoder.ReadBytes()
		if decoder.Failed() {
			if d.counter.ErrorCount == 0 {
				log.Errorf("proc event decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			}
			d.counter.ErrorCount++
			return
		}
		pbPerfEvent := &pb.ProcEvent{}
		if err := pbPerfEvent.Unmarshal(bytes); err != nil {
			if d.counter.ErrorCount == 0 {
				log.Errorf("proc event unmarshal failed, err: %s", err)
			}
			d.counter.ErrorCount++
			continue
		}
		d.counter.OutCount++
		d.WritePerfEvent(vtapId, pbPerfEvent)
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
	s := dbwriter.AcquireEventStore()
	s.HasMetrics = false
	s.Time = uint32(event.Time)
	s.StartTime = event.TimeMilli * 1000 // convert to microsecond
	s.EndTime = s.StartTime

	s.SignalSource = uint8(dbwriter.SIGNAL_SOURCE_RESOURCE)
	s.EventType = event.Type
	s.EventDescription = event.Description

	s.GProcessID = event.GProcessID

	if len(event.AttributeSubnetIDs) > 0 {
		s.AttributeNames = append(s.AttributeNames, "subnet_ids")
		s.AttributeValues = append(s.AttributeValues,
			uint32ArrayToStr(event.AttributeSubnetIDs))
	}
	if len(event.AttributeIPs) > 0 {
		s.AttributeNames = append(s.AttributeNames, "ips")
		s.AttributeValues = append(s.AttributeValues,
			strings.Join(event.AttributeIPs, SEPARATOR))

	}

	podGroupType := uint8(0)
	if event.IfNeedTagged {
		s.Tagged = 1
		resourceInfo := d.resourceInfoTable.QueryResourceInfo(event.InstanceType, event.InstanceID)
		if resourceInfo != nil {
			s.RegionID = uint16(resourceInfo.RegionID)
			s.AZID = uint16(resourceInfo.AZID)
			s.L3EpcID = resourceInfo.L3EpcID
			s.HostID = uint16(resourceInfo.HostID)
			s.PodID = resourceInfo.PodID
			s.PodNodeID = resourceInfo.PodNodeID
			s.PodNSID = uint16(resourceInfo.PodNSID)
			s.PodClusterID = uint16(resourceInfo.PodClusterID)
			s.PodGroupID = resourceInfo.PodGroupID
			podGroupType = resourceInfo.PodGroupType
			s.L3DeviceType = uint8(resourceInfo.L3DeviceType)
			s.L3DeviceID = resourceInfo.L3DeviceID
		}
	} else {
		s.Tagged = 0
		s.RegionID = uint16(event.RegionID)
		s.AZID = uint16(event.AZID)
		if event.VPCID == 0 {
			s.L3EpcID = -2
		} else {
			s.L3EpcID = int32(event.VPCID)
		}
		s.HostID = uint16(event.HostID)
		s.PodID = event.PodID
		s.PodNodeID = event.PodNodeID
		s.PodNSID = uint16(event.PodNSID)
		s.PodClusterID = uint16(event.PodClusterID)
		s.PodGroupID = event.PodGroupID
		podGroupType = event.PodGroupType
		s.L3DeviceType = uint8(event.L3DeviceType)
		s.L3DeviceID = event.L3DeviceID

	}
	s.SubnetID = uint16(event.SubnetID)
	s.IsIPv4 = true
	if ip := net.ParseIP(event.IP); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			s.IP4 = utils.IpToUint32(ip4)
		} else {
			s.IsIPv4 = false
			s.IP6 = ip
		}
	}
	s.AutoInstanceID, s.AutoInstanceType =
		ingestercommon.GetAutoInstance(
			s.PodID,
			s.GProcessID,
			s.PodNodeID,
			s.L3DeviceID,
			s.L3DeviceType,
			s.L3EpcID,
		)
	// if resource information is not matched, it will be filled with event(InstanceID, InstanceType, GProcessID) information
	if s.AutoInstanceID == 0 {
		s.AutoInstanceID, s.AutoInstanceType = getAutoInstance(event.InstanceID, event.InstanceType, event.GProcessID)
	}

	if event.InstanceType == uint32(trident.DeviceType_DEVICE_TYPE_POD_SERVICE) {
		s.ServiceID = event.InstanceID
	}
	s.AutoServiceID, s.AutoServiceType =
		ingestercommon.GetAutoService(
			s.ServiceID,
			s.PodGroupID,
			s.GProcessID,
			s.PodNodeID,
			s.L3DeviceID,
			s.L3DeviceType,
			podGroupType,
			s.L3EpcID,
		)

	d.counter.OutCount++
	d.eventWriter.Write(s)
}

func (d *Decoder) handleAlarmEvent(decoder *codec.SimpleDecoder) {
	for !decoder.IsEnd() {
		bytes := decoder.ReadBytes()
		if decoder.Failed() {
			if d.counter.ErrorCount == 0 {
				log.Errorf("alarm event decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			}
			d.counter.ErrorCount++
			return
		}
		pbAlarmEvent := &alarm_event.AlarmEvent{}
		if err := pbAlarmEvent.Unmarshal(bytes); err != nil {
			if d.counter.ErrorCount == 0 {
				log.Errorf("alarm event unmarshal failed, err: %s", err)
			}
			d.counter.ErrorCount++
			continue
		}
		d.counter.OutCount++
		d.writeAlarmEvent(pbAlarmEvent)
	}
}

func (d *Decoder) writeAlarmEvent(event *alarm_event.AlarmEvent) {
	s := dbwriter.AcquireAlarmEventStore()
	s.Time = event.GetTimestamp()
	s.Lcuuid = event.GetLcuuid()
	s.User = event.GetUser()
	s.UserId = event.GetUserId()

	s.PolicyId = event.GetPolicyId()
	s.PolicyName = event.GetPolicyName()
	s.PolicyLevel = event.GetPolicyLevel()
	s.PolicyAppType = event.GetPolicyAppType()
	s.PolicySubType = event.GetPolicySubType()
	s.PolicyContrastType = event.GetPolicyContrastType()
	s.PolicyDataLevel = event.GetPolicyDataLevel()
	s.PolicyTargetUid = event.GetPolicyTargetUid()
	s.PolicyTargetName = event.GetPolicyTargetName()
	s.PolicyGoTo = event.GetPolicyGoTo()
	s.PolicyTargetField = event.GetPolicyTargetField()
	s.PolicyEndpoints = event.GetPolicyEndpoints()
	s.TriggerCondition = event.GetTriggerCondition()
	s.TriggerValue = event.GetTriggerValue()
	s.ValueUnit = event.GetValueUnit()
	s.EventLevel = event.GetEventLevel()
	s.AlarmTarget = event.GetAlarmTarget()
	s.RegionId = uint16(d.platformData.QueryRegionID())
	s.PolicyQueryUrl = event.GetPolicyQueryUrl()
	s.PolicyQueryConditions = event.GetPolicyQueryConditions()
	s.PolicyThresholdCritical = event.GetPolicyThresholdCritical()
	s.PolicyThresholdError = event.GetPolicyThresholdError()
	s.PolicyThresholdWarning = event.GetPolicyThresholdWarning()

	d.eventWriter.WriteAlarmEvent(s)
}
