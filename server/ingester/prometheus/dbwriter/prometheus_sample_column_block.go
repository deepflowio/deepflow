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
)

type PrometheusSampleMiniBlock struct {
	AppLabelLen         int
	ColTime             proto.ColDateTime
	ColMetricId         proto.ColUInt32
	ColTargetId         proto.ColUInt32
	ColTeamId           proto.ColUInt16
	ColAppLabelValueIds [ckdb.MAX_APP_LABEL_COLUMN_INDEX + 1]proto.ColUInt32
	ColValue            proto.ColFloat64
}

func (b *PrometheusSampleMiniBlock) Reset() {
	b.ColTime.Reset()
	b.ColMetricId.Reset()
	b.ColTargetId.Reset()
	b.ColTeamId.Reset()
	for i := 1; i < b.AppLabelLen; i++ {
		b.ColAppLabelValueIds[i].Reset()
	}
	b.ColValue.Reset()
}

func (b *PrometheusSampleMiniBlock) ToInput(input proto.Input) proto.Input {
	input = append(input,
		proto.InputColumn{Name: ckdb.COLUMN_TIME, Data: &b.ColTime},
		proto.InputColumn{Name: ckdb.COLUMN_METRIC_ID, Data: &b.ColMetricId},
		proto.InputColumn{Name: ckdb.COLUMN_TARGET_ID, Data: &b.ColTargetId},
		proto.InputColumn{Name: ckdb.COLUMN_TEAM_ID, Data: &b.ColTeamId},
		proto.InputColumn{Name: ckdb.COLUMN_VALUE, Data: &b.ColValue},
	)
	for i := 1; i < b.AppLabelLen; i++ {
		input = append(input, proto.InputColumn{Name: ckdb.COLUMN_APP_LABEL_VALUE_IDs[i], Data: &b.ColAppLabelValueIds[i]})
	}
	return input
}

func (n *PrometheusSampleMini) NewColumnBlock() ckdb.CKColumnBlock {
	return &PrometheusSampleMiniBlock{
		AppLabelLen: n.AppLabelLen(),
	}
}

func (n *PrometheusSampleMini) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*PrometheusSampleMiniBlock)
	ckdb.AppendColDateTime(&block.ColTime, n.Timestamp)
	block.ColMetricId.Append(n.MetricID)
	block.ColTargetId.Append(n.TargetID)
	block.ColTeamId.Append(n.TeamID)
	appLabelLen := n.AppLabelLen()
	if block.AppLabelLen < appLabelLen {
		block.AppLabelLen = appLabelLen
	}
	for i := 1; i < block.AppLabelLen; i++ {
		block.ColAppLabelValueIds[i].Append(n.AppLabelValueIDs[i])
	}
	block.ColValue.Append(n.Value)
}

type PrometheusSampleBlock struct {
	*PrometheusSampleMiniBlock
	ColAzId             proto.ColUInt16
	ColGprocessId       proto.ColUInt32
	ColHostId           proto.ColUInt16
	ColIp4              proto.ColIPv4
	ColIp6              proto.ColIPv6
	ColIsIpv4           proto.ColUInt8
	ColL3DeviceId       proto.ColUInt32
	ColL3DeviceType     proto.ColUInt8
	ColL3EpcId          proto.ColInt32
	ColPodClusterId     proto.ColUInt16
	ColPodGroupId       proto.ColUInt32
	ColPodId            proto.ColUInt32
	ColPodNodeId        proto.ColUInt32
	ColPodNsId          proto.ColUInt16
	ColRegionId         proto.ColUInt16
	ColAutoInstanceId   proto.ColUInt32
	ColAutoInstanceType proto.ColUInt8
	ColAutoServiceId    proto.ColUInt32
	ColAutoServiceType  proto.ColUInt8
	ColServiceId        proto.ColUInt32
	ColSubnetId         proto.ColUInt16
	ColAgentId          proto.ColUInt16
}

func (b *PrometheusSampleBlock) Reset() {
	b.PrometheusSampleMiniBlock.Reset()
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

func (b *PrometheusSampleBlock) ToInput(input proto.Input) proto.Input {
	input = b.PrometheusSampleMiniBlock.ToInput(input)
	return append(input,
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

func (n *PrometheusSample) NewColumnBlock() ckdb.CKColumnBlock {
	return &PrometheusSampleBlock{
		PrometheusSampleMiniBlock: n.PrometheusSampleMini.NewColumnBlock().(*PrometheusSampleMiniBlock),
	}
}

func (n *PrometheusSample) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*PrometheusSampleBlock)
	n.PrometheusSampleMini.AppendToColumnBlock(block.PrometheusSampleMiniBlock)
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
