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
package dbwriter

import (
	"unsafe"

	"github.com/ClickHouse/ch-go/proto"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/datatype"
)

type ExtMetricsBlock struct {
	MsgType               datatype.MessageType
	ColTime               proto.ColDateTime
	ColAzId               proto.ColUInt16
	ColGprocessId         proto.ColUInt32
	ColHostId             proto.ColUInt16
	ColIp4                proto.ColIPv4
	ColIp6                proto.ColIPv6
	ColIsIpv4             proto.ColUInt8
	ColL3DeviceId         proto.ColUInt32
	ColL3DeviceType       proto.ColUInt8
	ColL3EpcId            proto.ColInt32
	ColPodClusterId       proto.ColUInt16
	ColPodGroupId         proto.ColUInt32
	ColPodId              proto.ColUInt32
	ColPodNodeId          proto.ColUInt32
	ColPodNsId            proto.ColUInt16
	ColRegionId           proto.ColUInt16
	ColAutoInstanceId     proto.ColUInt32
	ColAutoInstanceType   proto.ColUInt8
	ColAutoServiceId      proto.ColUInt32
	ColAutoServiceType    proto.ColUInt8
	ColServiceId          proto.ColUInt32
	ColSubnetId           proto.ColUInt16
	ColAgentId            proto.ColUInt16
	ColVirtualTableName   *proto.ColLowCardinality[string]
	ColTeamId             proto.ColUInt16
	ColTagNames           *proto.ColArr[string]
	ColTagValues          *proto.ColArr[string]
	ColMetricsFloatNames  *proto.ColArr[string]
	ColMetricsFloatValues *proto.ColArr[float64]
}

func (b *ExtMetricsBlock) Reset() {
	b.ColTime.Reset()
	if b.MsgType != datatype.MESSAGE_TYPE_DFSTATS && b.MsgType != datatype.MESSAGE_TYPE_SERVER_DFSTATS {
		b.ColAzId.Reset()
		b.ColGprocessId.Reset()
		b.ColHostId.Reset()
		b.ColIp4.Reset()
		b.ColIp6.Reset()
		b.ColIsIpv4.Reset()
		b.ColL3DeviceId.Reset()
		b.ColL3DeviceType.Reset()
		b.ColL3EpcId.Reset()
		b.ColPodClusterId.Reset()
		b.ColPodGroupId.Reset()
		b.ColPodId.Reset()
		b.ColPodNodeId.Reset()
		b.ColPodNsId.Reset()
		b.ColRegionId.Reset()
		b.ColAutoInstanceId.Reset()
		b.ColAutoInstanceType.Reset()
		b.ColAutoServiceId.Reset()
		b.ColAutoServiceType.Reset()
		b.ColServiceId.Reset()
		b.ColSubnetId.Reset()
		b.ColAgentId.Reset()
	}
	b.ColVirtualTableName.Reset()
	b.ColTeamId.Reset()
	b.ColTagNames.Reset()
	b.ColTagValues.Reset()
	b.ColMetricsFloatNames.Reset()
	b.ColMetricsFloatValues.Reset()
}

func (b *ExtMetricsBlock) ToInput(input proto.Input) proto.Input {
	input = append(input,
		proto.InputColumn{Name: ckdb.COLUMN_TIME, Data: &b.ColTime},
		proto.InputColumn{Name: ckdb.COLUMN_VIRTUAL_TABLE_NAME, Data: b.ColVirtualTableName},
		proto.InputColumn{Name: ckdb.COLUMN_TEAM_ID, Data: &b.ColTeamId},
		proto.InputColumn{Name: ckdb.COLUMN_TAG_NAMES, Data: b.ColTagNames},
		proto.InputColumn{Name: ckdb.COLUMN_TAG_VALUES, Data: b.ColTagValues},
		proto.InputColumn{Name: ckdb.COLUMN_METRICS_FLOAT_NAMES, Data: b.ColMetricsFloatNames},
		proto.InputColumn{Name: ckdb.COLUMN_METRICS_FLOAT_VALUES, Data: b.ColMetricsFloatValues},
	)
	if b.MsgType != datatype.MESSAGE_TYPE_DFSTATS && b.MsgType != datatype.MESSAGE_TYPE_SERVER_DFSTATS {
		input = append(input,
			proto.InputColumn{Name: ckdb.COLUMN_AZ_ID, Data: &b.ColAzId},
			proto.InputColumn{Name: ckdb.COLUMN_GPROCESS_ID, Data: &b.ColGprocessId},
			proto.InputColumn{Name: ckdb.COLUMN_HOST_ID, Data: &b.ColHostId},
			proto.InputColumn{Name: ckdb.COLUMN_IP4, Data: &b.ColIp4},
			proto.InputColumn{Name: ckdb.COLUMN_IP6, Data: &b.ColIp6},
			proto.InputColumn{Name: ckdb.COLUMN_IS_IPV4, Data: &b.ColIsIpv4},
			proto.InputColumn{Name: ckdb.COLUMN_L3_DEVICE_ID, Data: &b.ColL3DeviceId},
			proto.InputColumn{Name: ckdb.COLUMN_L3_DEVICE_TYPE, Data: &b.ColL3DeviceType},
			proto.InputColumn{Name: ckdb.COLUMN_L3_EPC_ID, Data: &b.ColL3EpcId},
			proto.InputColumn{Name: ckdb.COLUMN_POD_CLUSTER_ID, Data: &b.ColPodClusterId},
			proto.InputColumn{Name: ckdb.COLUMN_POD_GROUP_ID, Data: &b.ColPodGroupId},
			proto.InputColumn{Name: ckdb.COLUMN_POD_ID, Data: &b.ColPodId},
			proto.InputColumn{Name: ckdb.COLUMN_POD_NODE_ID, Data: &b.ColPodNodeId},
			proto.InputColumn{Name: ckdb.COLUMN_POD_NS_ID, Data: &b.ColPodNsId},
			proto.InputColumn{Name: ckdb.COLUMN_REGION_ID, Data: &b.ColRegionId},
			proto.InputColumn{Name: ckdb.COLUMN_AUTO_INSTANCE_ID, Data: &b.ColAutoInstanceId},
			proto.InputColumn{Name: ckdb.COLUMN_AUTO_INSTANCE_TYPE, Data: &b.ColAutoInstanceType},
			proto.InputColumn{Name: ckdb.COLUMN_AUTO_SERVICE_ID, Data: &b.ColAutoServiceId},
			proto.InputColumn{Name: ckdb.COLUMN_AUTO_SERVICE_TYPE, Data: &b.ColAutoServiceType},
			proto.InputColumn{Name: ckdb.COLUMN_SERVICE_ID, Data: &b.ColServiceId},
			proto.InputColumn{Name: ckdb.COLUMN_SUBNET_ID, Data: &b.ColSubnetId},
			proto.InputColumn{Name: ckdb.COLUMN_AGENT_ID, Data: &b.ColAgentId},
		)
	}
	return input
}

func (n *ExtMetrics) NewColumnBlock() ckdb.CKColumnBlock {
	return &ExtMetricsBlock{
		MsgType:               n.MsgType,
		ColVirtualTableName:   new(proto.ColStr).LowCardinality(),
		ColTagNames:           new(proto.ColStr).LowCardinality().Array(),
		ColTagValues:          new(proto.ColStr).Array(),
		ColMetricsFloatNames:  new(proto.ColStr).LowCardinality().Array(),
		ColMetricsFloatValues: new(proto.ColFloat64).Array(),
	}
}

func (n *ExtMetrics) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*ExtMetricsBlock)
	ckdb.AppendColDateTime(&block.ColTime, n.Timestamp)

	if n.MsgType != datatype.MESSAGE_TYPE_DFSTATS && n.MsgType != datatype.MESSAGE_TYPE_SERVER_DFSTATS {
		t := &n.UniversalTag
		block.ColAzId.Append(t.AZID)
		block.ColGprocessId.Append(t.GPID)
		block.ColHostId.Append(t.HostID)
		block.ColIp4.Append(proto.IPv4(t.IP))
		ckdb.AppendIPv6(&block.ColIp6, t.IP6)
		block.ColIsIpv4.Append(1 - *(*uint8)(unsafe.Pointer(&t.IsIPv6)))
		block.ColL3DeviceId.Append(t.L3DeviceID)
		block.ColL3DeviceType.Append(uint8(t.L3DeviceType))
		block.ColL3EpcId.Append(t.L3EpcID)
		block.ColPodClusterId.Append(t.PodClusterID)
		block.ColPodGroupId.Append(t.PodGroupID)
		block.ColPodId.Append(t.PodID)
		block.ColPodNodeId.Append(t.PodNodeID)
		block.ColPodNsId.Append(t.PodNSID)
		block.ColRegionId.Append(t.RegionID)
		block.ColAutoInstanceId.Append(t.AutoInstanceID)
		block.ColAutoInstanceType.Append(t.AutoInstanceType)
		block.ColAutoServiceId.Append(t.AutoServiceID)
		block.ColAutoServiceType.Append(t.AutoServiceType)
		block.ColServiceId.Append(t.ServiceID)
		block.ColSubnetId.Append(t.SubnetID)
		block.ColAgentId.Append(t.VTAPID)
	}

	block.ColVirtualTableName.Append(n.VTableName)
	block.ColTeamId.Append(n.TeamID)
	block.ColTagNames.Append(n.TagNames)
	block.ColTagValues.Append(n.TagValues)
	block.ColMetricsFloatNames.Append(n.MetricsFloatNames)
	block.ColMetricsFloatValues.Append(n.MetricsFloatValues)
}
