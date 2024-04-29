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
	"strings"
	"time"

	pb "github.com/deepflowio/deepflow/message/k8s_event"
	ingestercommon "github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/event/dbwriter"
	"github.com/deepflowio/deepflow/server/libs/codec"
	flow_metrics "github.com/deepflowio/deepflow/server/libs/flow-metrics"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

func (d *Decoder) WriteK8sEvent(vtapId uint16, e *pb.KubernetesEvent) {
	s := dbwriter.AcquireEventStore()
	s.HasMetrics = false
	s.Time = uint32(time.Duration(e.FirstTimestamp) / time.Millisecond) // us -> s
	s.SetId(s.Time, d.platformData.QueryAnalyzerID())
	s.StartTime = int64(e.FirstTimestamp)
	s.EndTime = int64(e.FirstTimestamp)
	s.EventType = strings.ToLower(e.Type.String())

	io := e.InvolvedObject
	if io != nil {
		s.AppInstance = io.GetKind() + "/" + io.GetName()
		fieldPath := io.GetFieldPath()
		if fieldPath != "" {
			s.AttributeNames = append(s.AttributeNames, "sub_object")
			s.AttributeValues = append(s.AttributeValues, fieldPath)
		}
	}
	s.EventDescription = e.GetMessage()

	reason := e.GetReason()
	if reason != "" {
		s.AttributeNames = append(s.AttributeNames, "reason")
		s.AttributeValues = append(s.AttributeValues, reason)
	}
	source := e.Source
	if source != nil && source.GetComponent() != "" {
		s.AttributeNames = append(s.AttributeNames, "source.component")
		s.AttributeValues = append(s.AttributeValues, source.GetComponent())
	}
	s.SignalSource = uint8(dbwriter.SIGNAL_SOURCE_K8S)

	s.VTAPID = vtapId
	s.L3EpcID = d.platformData.QueryVtapEpc0(vtapId)

	var info *grpc.Info
	vtapInfo := d.platformData.QueryVtapInfo(vtapId)
	if vtapInfo != nil {
		vtapIP := net.ParseIP(vtapInfo.Ip)
		if vtapIP != nil {
			if ip4 := vtapIP.To4(); ip4 != nil {
				s.IsIPv4 = true
				s.IP4 = utils.IpToUint32(ip4)
				info = d.platformData.QueryIPV4Infos(vtapInfo.EpcId, s.IP4)
			} else {
				s.IP6 = vtapIP
				info = d.platformData.QueryIPV6Infos(vtapInfo.EpcId, s.IP6)
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
			s.ServiceID = d.platformData.QueryService(
				s.PodID, s.PodNodeID, uint32(s.PodClusterID), s.PodGroupID, s.L3EpcID, !s.IsIPv4, s.IP4, s.IP6, 0, 0)
		}
	} else if baseInfo := d.platformData.QueryEpcIDBaseInfo(s.L3EpcID); baseInfo != nil {
		s.RegionID = uint16(baseInfo.RegionID)
	}

	s.AutoInstanceID, s.AutoInstanceType = ingestercommon.GetAutoInstance(s.PodID, s.GProcessID, s.PodNodeID, s.L3DeviceID, uint8(s.L3DeviceType), s.L3EpcID)
	s.AutoServiceID, s.AutoServiceType = ingestercommon.GetAutoService(s.ServiceID, s.PodGroupID, s.GProcessID, s.PodNodeID, s.L3DeviceID, uint8(s.L3DeviceType), podGroupType, s.L3EpcID)

	d.eventWriter.Write(s)
}

func (d *Decoder) handleK8sEvent(vtapId uint16, decoder *codec.SimpleDecoder) {
	for !decoder.IsEnd() {
		bytes := decoder.ReadBytes()
		if decoder.Failed() {
			if d.counter.ErrorCount == 0 {
				log.Errorf("proc event decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			}
			d.counter.ErrorCount++
			return
		}
		pbK8sEvent := &pb.KubernetesEvent{}
		if err := pbK8sEvent.Unmarshal(bytes); err != nil {
			if d.counter.ErrorCount == 0 {
				log.Errorf("proc event unmarshal failed, err: %s", err)
			}
			d.counter.ErrorCount++
			continue
		}
		d.counter.OutCount++
		d.WriteK8sEvent(vtapId, pbK8sEvent)
	}
}
