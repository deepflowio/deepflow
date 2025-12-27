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

package decoder

import (
	"net"
	"strconv"
	"strings"
	"time"

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/message/alert_event"
	"github.com/deepflowio/deepflow/message/trident"
	ingestercommon "github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/event/common"
	"github.com/deepflowio/deepflow/server/ingester/event/config"
	"github.com/deepflowio/deepflow/server/ingester/event/dbwriter"
	"github.com/deepflowio/deepflow/server/ingester/exporters"
	exporterscommon "github.com/deepflowio/deepflow/server/ingester/exporters/common"
	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	flow_metrics "github.com/deepflowio/deepflow/server/libs/flow-metrics"
	"github.com/deepflowio/deepflow/server/libs/flow-metrics/pb"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
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
	index        int
	eventType    common.EventType
	platformData *grpc.PlatformInfoTable
	inQueue      queue.QueueReader
	eventWriter  *dbwriter.EventWriter
	exporters    *exporters.Exporters
	debugEnabled bool
	config       *config.Config

	orgId, teamId uint16

	counter *Counter
	utils.Closable
}

func NewDecoder(
	index int,
	eventType common.EventType,
	inQueue queue.QueueReader,
	eventWriter *dbwriter.EventWriter,
	platformData *grpc.PlatformInfoTable,
	exporters *exporters.Exporters,
	config *config.Config,
) *Decoder {
	controllers := make([]net.IP, len(config.Base.ControllerIPs))
	for i, ipString := range config.Base.ControllerIPs {
		controllers[i] = net.ParseIP(ipString)
		if controllers[i].To4() != nil {
			controllers[i] = controllers[i].To4()
		}
	}
	return &Decoder{
		index:        index,
		eventType:    eventType,
		platformData: platformData,
		inQueue:      inQueue,
		debugEnabled: log.IsEnabledFor(logging.DEBUG),
		eventWriter:  eventWriter,
		exporters:    exporters,
		config:       config,
		counter:      &Counter{},
	}
}

func (d *Decoder) GetCounter() interface{} {
	var counter *Counter
	counter, d.counter = d.counter, &Counter{}
	return counter
}

func (d *Decoder) Run() {
	log.Infof("event (%s) decoder run", d.eventType)
	ingestercommon.RegisterCountableForIngester("decoder", d, stats.OptionStatTags{
		"index": strconv.Itoa(d.index), "event_type": d.eventType.String()})
	buffer := make([]interface{}, BUFFER_SIZE)
	decoder := &codec.SimpleDecoder{}
	for {
		n := d.inQueue.Gets(buffer)
		for i := 0; i < n; i++ {
			if buffer[i] == nil {
				d.export(nil)
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
			case common.FILE_EVENT:
				recvBytes, ok := buffer[i].(*receiver.RecvBuffer)
				if !ok {
					log.Warning("get file event decode queue data type wrong")
					continue
				}
				decoder.Init(recvBytes.Buffer[recvBytes.Begin:recvBytes.End])
				d.orgId, d.teamId = uint16(recvBytes.OrgID), uint16(recvBytes.TeamID)
				d.handleFileEvent(recvBytes.VtapID, decoder)
				receiver.ReleaseRecvBuffer(recvBytes)
			case common.ALERT_EVENT:
				recvBytes, ok := buffer[i].(*receiver.RecvBuffer)
				if !ok {
					log.Warning("get alert event decode queue data type wrong")
					continue
				}
				decoder.Init(recvBytes.Buffer[recvBytes.Begin:recvBytes.End])
				d.handleAlertEvent(decoder)
				receiver.ReleaseRecvBuffer(recvBytes)
			case common.K8S_EVENT:
				recvBytes, ok := buffer[i].(*receiver.RecvBuffer)
				if !ok {
					log.Warning("get k8s event decode queue data type wrong")
					continue
				}
				decoder.Init(recvBytes.Buffer[recvBytes.Begin:recvBytes.End])
				d.orgId, d.teamId = uint16(recvBytes.OrgID), uint16(recvBytes.TeamID)
				d.handleK8sEvent(recvBytes.VtapID, decoder)
				receiver.ReleaseRecvBuffer(recvBytes)
			}
		}
	}
}

func (d *Decoder) WriteFileEvent(vtapId uint16, e *pb.ProcEvent) {
	s := dbwriter.AcquireEventStore()
	s.IsFileEvent = true
	s.Time = uint32(time.Duration(e.StartTime) / time.Second)
	s.SetId(s.Time, d.platformData.QueryAnalyzerID())
	s.StartTime = int64(time.Duration(e.StartTime) / time.Microsecond)
	s.EndTime = int64(time.Duration(e.EndTime) / time.Microsecond)
	s.Duration = uint64(e.EndTime - e.StartTime)
	s.PodID = e.PodId
	s.OrgId, s.TeamID = d.orgId, d.teamId

	if e.EventType == pb.EventType_IoEvent {
		s.SignalSource = uint8(dbwriter.SIGNAL_SOURCE_IO)
	} else {
		s.SignalSource = uint8(e.EventType)
	}

	s.GProcessID = d.platformData.QueryProcessInfo(s.OrgId, vtapId, e.Pid)
	if e.IoEventData != nil {
		ioData := e.IoEventData
		s.EventType = strings.ToLower(ioData.Operation.String())
		s.ProcessKName = string(e.ProcessKname)
		s.FileName = string(ioData.Filename)
		s.Offset = ioData.OffBytes
		s.SyscallThread = e.ThreadId
		s.SyscallCoroutine = e.CoroutineId
		s.FileType = uint8(ioData.FileType)
		s.FileDir = string(ioData.FileDir)
		s.MountSource = string(ioData.MountSource)
		s.MountPoint = string(ioData.MountPoint)
		s.Bytes = ioData.BytesCount
		s.Duration = uint64(s.EndTime - s.StartTime)
	}
	s.VTAPID = vtapId
	s.L3EpcID = d.platformData.QueryVtapEpc0(s.OrgId, vtapId)

	var info *grpc.Info
	if e.PodId != 0 {
		info = d.platformData.QueryPodIdInfo(s.OrgId, e.PodId)
	}

	// if platformInfo cannot be obtained from PodId, finally fill with Vtap's platformInfo
	if info == nil {
		vtapInfo := d.platformData.QueryVtapInfo(s.OrgId, vtapId)
		if vtapInfo != nil {
			vtapIP := net.ParseIP(vtapInfo.Ip)
			if vtapIP != nil {
				if ip4 := vtapIP.To4(); ip4 != nil {
					s.IsIPv4 = true
					s.IP4 = utils.IpToUint32(ip4)
					info = d.platformData.QueryIPV4Infos(s.OrgId, vtapInfo.EpcId, s.IP4)
				} else {
					s.IP6 = vtapIP
					info = d.platformData.QueryIPV6Infos(s.OrgId, vtapInfo.EpcId, s.IP6)
				}
			}
		}
	}

	podGroupType := uint8(0)
	if info != nil {
		s.RegionID = uint16(info.RegionID)
		s.AZID = uint16(info.AZID)
		s.L3EpcID = info.EpcID
		s.HostID = uint16(info.HostID)
		if s.PodID == 0 {
			s.PodID = info.PodID
		}
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
		if ingestercommon.IsPodServiceIP(flow_metrics.DeviceType(s.L3DeviceType), s.PodID, 0) {
			s.ServiceID = d.platformData.QueryPodService(s.OrgId,
				s.PodID, s.PodNodeID, uint32(s.PodClusterID), s.PodGroupID, s.L3EpcID, !s.IsIPv4, s.IP4, s.IP6, 0, 0)
		}
	} else if baseInfo := d.platformData.QueryEpcIDBaseInfo(s.OrgId, s.L3EpcID); baseInfo != nil {
		s.RegionID = uint16(baseInfo.RegionID)
	}

	s.AutoInstanceID, s.AutoInstanceType = ingestercommon.GetAutoInstance(s.PodID, s.GProcessID, s.PodNodeID, s.L3DeviceID, uint32(s.SubnetID), uint8(s.L3DeviceType), s.L3EpcID)
	customServiceID := d.platformData.QueryCustomService(s.OrgId, s.L3EpcID, !s.IsIPv4, s.IP4, s.IP6, 0, s.ServiceID, s.PodGroupID, s.L3DeviceID, s.PodID, uint8(s.L3DeviceType))
	s.AutoServiceID, s.AutoServiceType = ingestercommon.GetAutoService(customServiceID, s.ServiceID, s.PodGroupID, s.GProcessID, uint32(s.PodClusterID), s.L3DeviceID, uint32(s.SubnetID), uint8(s.L3DeviceType), podGroupType, s.L3EpcID)

	s.AppInstance = strconv.Itoa(int(e.Pid))

	d.export(s)
	d.eventWriter.Write(s)
}

func (d *Decoder) export(item exporterscommon.ExportItem) {
	if d.exporters == nil {
		return
	}
	d.exporters.Put(d.eventType.DataSource(), d.index, item)
}

func (d *Decoder) handleFileEvent(vtapId uint16, decoder *codec.SimpleDecoder) {
	for !decoder.IsEnd() {
		bytes := decoder.ReadBytes()
		if decoder.Failed() {
			if d.counter.ErrorCount == 0 {
				log.Errorf("proc event decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			}
			d.counter.ErrorCount++
			return
		}
		pbFileEvent := &pb.ProcEvent{}
		if err := pbFileEvent.Unmarshal(bytes); err != nil {
			if d.counter.ErrorCount == 0 {
				log.Errorf("proc event unmarshal failed, err: %s", err)
			}
			d.counter.ErrorCount++
			continue
		}
		d.counter.OutCount++
		d.WriteFileEvent(vtapId, pbFileEvent)
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
	if GProcessID == 0 || instanceType == uint32(ingestercommon.PodType) {
		return instanceID, uint8(instanceType)
	}
	return GProcessID, ingestercommon.ProcessType
}

func (d *Decoder) handleResourceEvent(event *eventapi.ResourceEvent) {
	s := dbwriter.AcquireEventStore()
	s.IsFileEvent = false
	s.Time = uint32(event.Time)
	s.SetId(s.Time, d.platformData.QueryAnalyzerID())
	s.StartTime = event.TimeMilli * 1000 // convert to microsecond
	s.EndTime = s.StartTime

	s.SignalSource = uint8(dbwriter.SIGNAL_SOURCE_RESOURCE)
	s.EventType = event.Type
	s.EventDescription = event.Description

	s.OrgId = event.ORGID
	s.TeamID = event.TeamID

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
	s.AttributeNames = append(s.AttributeNames, event.AttributeNames...)
	s.AttributeValues = append(s.AttributeValues, event.AttributeValues...)

	podGroupType := uint8(0)
	if event.IfNeedTagged {
		s.Tagged = 1
		resourceInfo := d.platformData.QueryResourceInfo(s.OrgId, event.InstanceType, event.InstanceID, event.PodID)
		if resourceInfo != nil {
			s.RegionID = uint16(resourceInfo.RegionID)
			s.AZID = uint16(resourceInfo.AZID)
			s.L3EpcID = resourceInfo.EpcID
			s.HostID = uint16(resourceInfo.HostID)
			s.PodID = resourceInfo.PodID
			s.PodNodeID = resourceInfo.PodNodeID
			s.PodNSID = uint16(resourceInfo.PodNSID)
			s.PodClusterID = uint16(resourceInfo.PodClusterID)
			s.PodGroupID = resourceInfo.PodGroupID
			podGroupType = resourceInfo.PodGroupType
			s.L3DeviceType = uint8(resourceInfo.DeviceType)
			s.L3DeviceID = resourceInfo.DeviceID
		}
	} else {
		s.Tagged = 0
		s.RegionID = uint16(event.RegionID)
		s.AZID = uint16(event.AZID)
		s.L3EpcID = int32(event.VPCID)
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
			uint32(s.SubnetID),
			s.L3DeviceType,
			s.L3EpcID,
		)
	// if resource information is not matched, it will be filled with event(InstanceID, InstanceType, GProcessID) information
	if s.AutoInstanceID == 0 {
		s.AutoInstanceID, s.AutoInstanceType = getAutoInstance(event.InstanceID, event.InstanceType, event.GProcessID)
	}

	if event.InstanceType == uint32(trident.DeviceType_DEVICE_TYPE_POD_SERVICE) {
		s.ServiceID = event.InstanceID
	} else if ingestercommon.IsPodServiceIP(flow_metrics.DeviceType(s.L3DeviceType), s.PodID, 0) {
		s.ServiceID = d.platformData.QueryPodService(s.OrgId, s.PodID, s.PodNodeID, uint32(s.PodClusterID), s.PodGroupID, s.L3EpcID, !s.IsIPv4, s.IP4, s.IP6, 0, 0)
	}

	customServiceID := d.platformData.QueryCustomService(s.OrgId, s.L3EpcID, !s.IsIPv4, s.IP4, s.IP6, 0, s.ServiceID, s.PodGroupID, s.L3DeviceID, s.PodID, uint8(s.L3DeviceType))
	s.AutoServiceID, s.AutoServiceType =
		ingestercommon.GetAutoService(
			customServiceID,
			s.ServiceID,
			s.PodGroupID,
			s.GProcessID,
			uint32(s.PodClusterID),
			s.L3DeviceID,
			uint32(s.SubnetID),
			s.L3DeviceType,
			podGroupType,
			s.L3EpcID,
		)

	d.counter.OutCount++
	d.eventWriter.Write(s)
}

func (d *Decoder) handleAlertEvent(decoder *codec.SimpleDecoder) {
	for !decoder.IsEnd() {
		bytes := decoder.ReadBytes()
		if decoder.Failed() {
			if d.counter.ErrorCount == 0 {
				log.Errorf("alert event decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			}
			d.counter.ErrorCount++
			return
		}
		pbAlertEvent := &alert_event.AlertEvent{}
		if err := pbAlertEvent.Unmarshal(bytes); err != nil {
			if d.counter.ErrorCount == 0 {
				log.Errorf("alert event unmarshal failed, err: %s", err)
			}
			d.counter.ErrorCount++
			continue
		}
		d.counter.OutCount++
		d.writeAlertEvent(pbAlertEvent)
	}
}

func (d *Decoder) writeAlertEvent(event *alert_event.AlertEvent) {
	s := dbwriter.AcquireAlertEventStore()
	s.Time = event.GetTime()
	s.SetId(s.Time, d.platformData.QueryAnalyzerID())

	s.PolicyId = event.GetPolicyId()
	s.PolicyType = uint8(event.GetPolicyType())
	s.AlertPolicy = event.GetAlertPolicy()
	s.MetricValue = event.GetMetricValue()
	s.MetricValueStr = event.GetMetricValueStr()
	s.EventLevel = uint8(event.GetEventLevel())
	s.TargetTags = event.GetTargetTags()

	s.TagStrKeys = event.GetTagStrKeys()
	s.TagStrValues = event.GetTagStrValues()
	s.TagIntKeys = event.GetTagIntKeys()
	s.TagIntValues = event.GetTagIntValues()
	s.TriggerThreshold = event.GetTriggerThreshold()
	s.MetricUnit = event.GetMetricUnit()
	s.XTargetUid = event.GetXTargetUid()
	s.XQueryRegion = event.GetXQueryRegion()

	s.OrgId = uint16(event.GetOrgId())
	s.TeamID = uint16(event.GetTeamId())
	s.UserId = event.GetUserId()

	d.eventWriter.WriteAlertEvent(s)
}
