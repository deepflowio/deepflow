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
package flow_metrics

import (
	"unsafe"

	"github.com/ClickHouse/ch-go/proto"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
)

type TagBlock struct {
	Code
	ColTime                 proto.ColDateTime
	ColTid                  proto.ColUInt8
	ColAclGid               proto.ColUInt16
	ColAzId                 proto.ColUInt16
	ColAzId0                proto.ColUInt16
	ColAzId1                proto.ColUInt16
	ColRole                 proto.ColUInt8
	ColGprocessId           proto.ColUInt32
	ColGprocessId0          proto.ColUInt32
	ColGprocessId1          proto.ColUInt32
	ColHostId               proto.ColUInt16
	ColHostId0              proto.ColUInt16
	ColHostId1              proto.ColUInt16
	ColIp4                  proto.ColIPv4
	ColIp6                  proto.ColIPv6
	ColIsIpv4               proto.ColUInt8
	ColTagSource            proto.ColUInt8
	ColIp40                 proto.ColIPv4
	ColIp41                 proto.ColIPv4
	ColIp60                 proto.ColIPv6
	ColIp61                 proto.ColIPv6
	ColTagSource0           proto.ColUInt8
	ColTagSource1           proto.ColUInt8
	ColIsKeyService         proto.ColUInt8
	ColL3DeviceId           proto.ColUInt32
	ColL3DeviceType         proto.ColUInt8
	ColL3DeviceId0          proto.ColUInt32
	ColL3DeviceId1          proto.ColUInt32
	ColL3DeviceType0        proto.ColUInt8
	ColL3DeviceType1        proto.ColUInt8
	ColL3EpcId              proto.ColInt32
	ColL3EpcId0             proto.ColInt32
	ColL3EpcId1             proto.ColInt32
	ColL7Protocol           proto.ColUInt8
	ColAppService           *proto.ColLowCardinality[string]
	ColAppInstance          *proto.ColLowCardinality[string]
	ColEndpoint             proto.ColStr
	ColBizType              proto.ColUInt8
	ColPodClusterId         proto.ColUInt16
	ColPodClusterId0        proto.ColUInt16
	ColPodClusterId1        proto.ColUInt16
	ColPodGroupId           proto.ColUInt32
	ColPodGroupId0          proto.ColUInt32
	ColPodGroupId1          proto.ColUInt32
	ColPodId                proto.ColUInt32
	ColPodId0               proto.ColUInt32
	ColPodId1               proto.ColUInt32
	ColPodNodeId            proto.ColUInt32
	ColPodNodeId0           proto.ColUInt32
	ColPodNodeId1           proto.ColUInt32
	ColPodNsId              proto.ColUInt16
	ColPodNsId0             proto.ColUInt16
	ColPodNsId1             proto.ColUInt16
	ColProtocol             proto.ColUInt8
	ColRegionId             proto.ColUInt16
	ColRegionId0            proto.ColUInt16
	ColRegionId1            proto.ColUInt16
	ColAutoInstanceId       proto.ColUInt32
	ColAutoInstanceType     proto.ColUInt8
	ColAutoServiceId        proto.ColUInt32
	ColAutoServiceType      proto.ColUInt8
	ColAutoInstanceId0      proto.ColUInt32
	ColAutoInstanceType0    proto.ColUInt8
	ColAutoServiceId0       proto.ColUInt32
	ColAutoServiceType0     proto.ColUInt8
	ColAutoInstanceId1      proto.ColUInt32
	ColAutoInstanceType1    proto.ColUInt8
	ColAutoServiceId1       proto.ColUInt32
	ColAutoServiceType1     proto.ColUInt8
	ColSignalSource         proto.ColUInt16
	ColServiceId            proto.ColUInt32
	ColServiceId0           proto.ColUInt32
	ColServiceId1           proto.ColUInt32
	ColServerPort           proto.ColUInt16
	ColSubnetId             proto.ColUInt16
	ColSubnetId0            proto.ColUInt16
	ColSubnetId1            proto.ColUInt16
	ColTunnelIpId           proto.ColUInt16
	ColCaptureNicType       proto.ColUInt8
	ColTunnelType           proto.ColUInt8
	ColCaptureNic           proto.ColUInt32
	ColNatSource            proto.ColUInt8
	ColObservationPoint     *proto.ColLowCardinality[string]
	ColCaptureNetworkTypeId proto.ColUInt8
	ColAgentId              proto.ColUInt16
	ColTeamId               proto.ColUInt16
}

func (b *TagBlock) Reset() {
	code := b.Code
	b.ColTime.Reset()
	b.ColTid.Reset()
	if code&ACLGID != 0 {
		b.ColAclGid.Reset()
	}
	if code&AZID != 0 {
		b.ColAzId.Reset()
	}
	if code&AZIDPath != 0 {
		b.ColAzId0.Reset()
		b.ColAzId1.Reset()
	}
	if code&Direction != 0 {
		b.ColRole.Reset()
	}
	if code&GPID != 0 {
		b.ColGprocessId.Reset()
	}
	if code&GPIDPath != 0 {
		b.ColGprocessId0.Reset()
		b.ColGprocessId1.Reset()
	}
	if code&HostID != 0 {
		b.ColHostId.Reset()
	}
	if code&HostIDPath != 0 {
		b.ColHostId0.Reset()
		b.ColHostId1.Reset()
	}
	if code&IP != 0 {
		b.ColIp4.Reset()
		b.ColIp6.Reset()
		b.ColIsIpv4.Reset()
		b.ColTagSource.Reset()
	}
	if code&IPPath != 0 {
		b.ColIp40.Reset()
		b.ColIp41.Reset()
		b.ColIp60.Reset()
		b.ColIp61.Reset()
		b.ColIsIpv4.Reset()
		b.ColTagSource0.Reset()
		b.ColTagSource1.Reset()
	}
	if code&IsKeyService != 0 {
		b.ColIsKeyService.Reset()
	}
	if code&L3Device != 0 {
		b.ColL3DeviceId.Reset()
		b.ColL3DeviceType.Reset()
	}
	if code&L3DevicePath != 0 {
		b.ColL3DeviceId0.Reset()
		b.ColL3DeviceId1.Reset()
		b.ColL3DeviceType0.Reset()
		b.ColL3DeviceType1.Reset()
	}
	if code&L3EpcID != 0 {
		b.ColL3EpcId.Reset()
	}
	if code&L3EpcIDPath != 0 {
		b.ColL3EpcId0.Reset()
		b.ColL3EpcId1.Reset()
	}
	if code&L7Protocol != 0 {
		b.ColL7Protocol.Reset()
		b.ColAppService.Reset()
		b.ColAppInstance.Reset()
		b.ColEndpoint.Reset()
		b.ColBizType.Reset()
	}
	if code&PodClusterID != 0 {
		b.ColPodClusterId.Reset()
	}
	if code&PodClusterIDPath != 0 {
		b.ColPodClusterId0.Reset()
		b.ColPodClusterId1.Reset()
	}
	if code&PodGroupID != 0 {
		b.ColPodGroupId.Reset()
	}
	if code&PodGroupIDPath != 0 {
		b.ColPodGroupId0.Reset()
		b.ColPodGroupId1.Reset()
	}
	if code&PodID != 0 {
		b.ColPodId.Reset()
	}
	if code&PodIDPath != 0 {
		b.ColPodId0.Reset()
		b.ColPodId1.Reset()
	}
	if code&PodNodeID != 0 {
		b.ColPodNodeId.Reset()
	}
	if code&PodNodeIDPath != 0 {
		b.ColPodNodeId0.Reset()
		b.ColPodNodeId1.Reset()
	}
	if code&PodNSID != 0 {
		b.ColPodNsId.Reset()
	}
	if code&PodNSIDPath != 0 {
		b.ColPodNsId0.Reset()
		b.ColPodNsId1.Reset()
	}
	if code&Protocol != 0 {
		b.ColProtocol.Reset()
	}
	if code&RegionID != 0 {
		b.ColRegionId.Reset()
	}
	if code&RegionIDPath != 0 {
		b.ColRegionId0.Reset()
		b.ColRegionId1.Reset()
	}
	if code&Resource != 0 {
		b.ColAutoInstanceId.Reset()
		b.ColAutoInstanceType.Reset()
		b.ColAutoServiceId.Reset()
		b.ColAutoServiceType.Reset()
	}
	if code&ResourcePath != 0 {
		b.ColAutoInstanceId0.Reset()
		b.ColAutoInstanceType0.Reset()
		b.ColAutoServiceId0.Reset()
		b.ColAutoServiceType0.Reset()
		b.ColAutoInstanceId1.Reset()
		b.ColAutoInstanceType1.Reset()
		b.ColAutoServiceId1.Reset()
		b.ColAutoServiceType1.Reset()
	}
	if code&SignalSource != 0 {
		b.ColSignalSource.Reset()
	}
	if code&ServiceID != 0 {
		b.ColServiceId.Reset()
	}
	if code&ServiceIDPath != 0 {
		b.ColServiceId0.Reset()
		b.ColServiceId1.Reset()
	}
	if code&ServerPort != 0 {
		b.ColServerPort.Reset()
	}
	if code&SubnetID != 0 {
		b.ColSubnetId.Reset()
	}
	if code&SubnetIDPath != 0 {
		b.ColSubnetId0.Reset()
		b.ColSubnetId1.Reset()
	}
	if code&TunnelIPID != 0 {
		b.ColTunnelIpId.Reset()
	}
	if code&TAPPort != 0 {
		b.ColCaptureNicType.Reset()
		b.ColTunnelType.Reset()
		b.ColCaptureNic.Reset()
		b.ColNatSource.Reset()
	}
	if code&TAPSide != 0 {
		b.ColObservationPoint.Reset()
	}
	if code&TAPType != 0 {
		b.ColCaptureNetworkTypeId.Reset()
	}
	if code&VTAPID != 0 {
		b.ColAgentId.Reset()
		b.ColTeamId.Reset()
	}
}

func (b *TagBlock) ToInput(input proto.Input) proto.Input {
	code := b.Code
	input = append(input,
		proto.InputColumn{Name: ckdb.COLUMN_TIME, Data: &b.ColTime},
		proto.InputColumn{Name: ckdb.COLUMN__TID, Data: &b.ColTid},
	)
	if code&ACLGID != 0 {
		input = append(input, proto.InputColumn{Name: ckdb.COLUMN_ACL_GID, Data: &b.ColAclGid})
	}
	if code&AZID != 0 {
		input = append(input, proto.InputColumn{Name: ckdb.COLUMN_AZ_ID, Data: &b.ColAzId})
	}
	if code&AZIDPath != 0 {
		input = append(input,
			proto.InputColumn{Name: ckdb.COLUMN_AZ_ID_0, Data: &b.ColAzId0},
			proto.InputColumn{Name: ckdb.COLUMN_AZ_ID_1, Data: &b.ColAzId1},
		)
	}
	if code&Direction != 0 {
		input = append(input, proto.InputColumn{Name: ckdb.COLUMN_ROLE, Data: &b.ColRole})
	}
	if code&GPID != 0 {
		input = append(input, proto.InputColumn{Name: ckdb.COLUMN_GPROCESS_ID, Data: &b.ColGprocessId})
	}
	if code&GPIDPath != 0 {
		input = append(input,
			proto.InputColumn{Name: ckdb.COLUMN_GPROCESS_ID_0, Data: &b.ColGprocessId0},
			proto.InputColumn{Name: ckdb.COLUMN_GPROCESS_ID_1, Data: &b.ColGprocessId1},
		)
	}
	if code&HostID != 0 {
		input = append(input, proto.InputColumn{Name: ckdb.COLUMN_HOST_ID, Data: &b.ColHostId})
	}
	if code&HostIDPath != 0 {
		input = append(input,
			proto.InputColumn{Name: ckdb.COLUMN_HOST_ID_0, Data: &b.ColHostId0},
			proto.InputColumn{Name: ckdb.COLUMN_HOST_ID_1, Data: &b.ColHostId1},
		)
	}
	if code&IP != 0 {
		input = append(input,
			proto.InputColumn{Name: ckdb.COLUMN_IP4, Data: &b.ColIp4},
			proto.InputColumn{Name: ckdb.COLUMN_IP6, Data: &b.ColIp6},
			proto.InputColumn{Name: ckdb.COLUMN_IS_IPV4, Data: &b.ColIsIpv4},
			proto.InputColumn{Name: ckdb.COLUMN_TAG_SOURCE, Data: &b.ColTagSource},
		)
	}
	if code&IPPath != 0 {
		input = append(input,
			proto.InputColumn{Name: ckdb.COLUMN_IP4_0, Data: &b.ColIp40},
			proto.InputColumn{Name: ckdb.COLUMN_IP4_1, Data: &b.ColIp41},
			proto.InputColumn{Name: ckdb.COLUMN_IP6_0, Data: &b.ColIp60},
			proto.InputColumn{Name: ckdb.COLUMN_IP6_1, Data: &b.ColIp61},
			proto.InputColumn{Name: ckdb.COLUMN_IS_IPV4, Data: &b.ColIsIpv4},
			proto.InputColumn{Name: ckdb.COLUMN_TAG_SOURCE_0, Data: &b.ColTagSource0},
			proto.InputColumn{Name: ckdb.COLUMN_TAG_SOURCE_1, Data: &b.ColTagSource1},
		)
	}
	if code&IsKeyService != 0 {
		input = append(input, proto.InputColumn{Name: ckdb.COLUMN_IS_KEY_SERVICE, Data: &b.ColIsKeyService})
	}
	if code&L3Device != 0 {
		input = append(input,
			proto.InputColumn{Name: ckdb.COLUMN_L3_DEVICE_ID, Data: &b.ColL3DeviceId},
			proto.InputColumn{Name: ckdb.COLUMN_L3_DEVICE_TYPE, Data: &b.ColL3DeviceType},
		)
	}
	if code&L3DevicePath != 0 {
		input = append(input,
			proto.InputColumn{Name: ckdb.COLUMN_L3_DEVICE_ID_0, Data: &b.ColL3DeviceId0},
			proto.InputColumn{Name: ckdb.COLUMN_L3_DEVICE_ID_1, Data: &b.ColL3DeviceId1},
			proto.InputColumn{Name: ckdb.COLUMN_L3_DEVICE_TYPE_0, Data: &b.ColL3DeviceType0},
			proto.InputColumn{Name: ckdb.COLUMN_L3_DEVICE_TYPE_1, Data: &b.ColL3DeviceType1},
		)
	}
	if code&L3EpcID != 0 {
		input = append(input,
			proto.InputColumn{Name: ckdb.COLUMN_L3_EPC_ID, Data: &b.ColL3EpcId},
		)
	}
	if code&L3EpcIDPath != 0 {
		input = append(input,
			proto.InputColumn{Name: ckdb.COLUMN_L3_EPC_ID_0, Data: &b.ColL3EpcId0},
			proto.InputColumn{Name: ckdb.COLUMN_L3_EPC_ID_1, Data: &b.ColL3EpcId1},
		)
	}
	if code&L7Protocol != 0 {
		input = append(input,
			proto.InputColumn{Name: ckdb.COLUMN_L7_PROTOCOL, Data: &b.ColL7Protocol},
			proto.InputColumn{Name: ckdb.COLUMN_APP_SERVICE, Data: b.ColAppService},
			proto.InputColumn{Name: ckdb.COLUMN_APP_INSTANCE, Data: b.ColAppInstance},
			proto.InputColumn{Name: ckdb.COLUMN_ENDPOINT, Data: &b.ColEndpoint},
			proto.InputColumn{Name: ckdb.COLUMN_BIZ_TYPE, Data: &b.ColBizType},
		)
	}
	if code&PodClusterID != 0 {
		input = append(input, proto.InputColumn{Name: ckdb.COLUMN_POD_CLUSTER_ID, Data: &b.ColPodClusterId})
	}
	if code&PodClusterIDPath != 0 {
		input = append(input,
			proto.InputColumn{Name: ckdb.COLUMN_POD_CLUSTER_ID_0, Data: &b.ColPodClusterId0},
			proto.InputColumn{Name: ckdb.COLUMN_POD_CLUSTER_ID_1, Data: &b.ColPodClusterId1},
		)
	}
	if code&PodGroupID != 0 {
		input = append(input, proto.InputColumn{Name: ckdb.COLUMN_POD_GROUP_ID, Data: &b.ColPodGroupId})
	}
	if code&PodGroupIDPath != 0 {
		input = append(input,
			proto.InputColumn{Name: ckdb.COLUMN_POD_GROUP_ID_0, Data: &b.ColPodGroupId0},
			proto.InputColumn{Name: ckdb.COLUMN_POD_GROUP_ID_1, Data: &b.ColPodGroupId1},
		)
	}
	if code&PodID != 0 {
		input = append(input, proto.InputColumn{Name: ckdb.COLUMN_POD_ID, Data: &b.ColPodId})
	}
	if code&PodIDPath != 0 {
		input = append(input,
			proto.InputColumn{Name: ckdb.COLUMN_POD_ID_0, Data: &b.ColPodId0},
			proto.InputColumn{Name: ckdb.COLUMN_POD_ID_1, Data: &b.ColPodId1},
		)
	}
	if code&PodNodeID != 0 {
		input = append(input, proto.InputColumn{Name: ckdb.COLUMN_POD_NODE_ID, Data: &b.ColPodNodeId})
	}
	if code&PodNodeIDPath != 0 {
		input = append(input,
			proto.InputColumn{Name: ckdb.COLUMN_POD_NODE_ID_0, Data: &b.ColPodNodeId0},
			proto.InputColumn{Name: ckdb.COLUMN_POD_NODE_ID_1, Data: &b.ColPodNodeId1},
		)
	}
	if code&PodNSID != 0 {
		input = append(input, proto.InputColumn{Name: ckdb.COLUMN_POD_NS_ID, Data: &b.ColPodNsId})
	}
	if code&PodNSIDPath != 0 {
		input = append(input,
			proto.InputColumn{Name: ckdb.COLUMN_POD_NS_ID_0, Data: &b.ColPodNsId0},
			proto.InputColumn{Name: ckdb.COLUMN_POD_NS_ID_1, Data: &b.ColPodNsId1},
		)
	}
	if code&Protocol != 0 {
		input = append(input, proto.InputColumn{Name: ckdb.COLUMN_PROTOCOL, Data: &b.ColProtocol})
	}
	if code&RegionID != 0 {
		input = append(input, proto.InputColumn{Name: ckdb.COLUMN_REGION_ID, Data: &b.ColRegionId})
	}
	if code&RegionIDPath != 0 {
		input = append(input,
			proto.InputColumn{Name: ckdb.COLUMN_REGION_ID_0, Data: &b.ColRegionId0},
			proto.InputColumn{Name: ckdb.COLUMN_REGION_ID_1, Data: &b.ColRegionId1},
		)
	}
	if code&Resource != 0 {
		input = append(input,
			proto.InputColumn{Name: ckdb.COLUMN_AUTO_INSTANCE_ID, Data: &b.ColAutoInstanceId},
			proto.InputColumn{Name: ckdb.COLUMN_AUTO_INSTANCE_TYPE, Data: &b.ColAutoInstanceType},
			proto.InputColumn{Name: ckdb.COLUMN_AUTO_SERVICE_ID, Data: &b.ColAutoServiceId},
			proto.InputColumn{Name: ckdb.COLUMN_AUTO_SERVICE_TYPE, Data: &b.ColAutoServiceType},
		)
	}
	if code&ResourcePath != 0 {
		input = append(input,
			proto.InputColumn{Name: ckdb.COLUMN_AUTO_INSTANCE_ID_0, Data: &b.ColAutoInstanceId0},
			proto.InputColumn{Name: ckdb.COLUMN_AUTO_INSTANCE_TYPE_0, Data: &b.ColAutoInstanceType0},
			proto.InputColumn{Name: ckdb.COLUMN_AUTO_SERVICE_ID_0, Data: &b.ColAutoServiceId0},
			proto.InputColumn{Name: ckdb.COLUMN_AUTO_SERVICE_TYPE_0, Data: &b.ColAutoServiceType0},
			proto.InputColumn{Name: ckdb.COLUMN_AUTO_INSTANCE_ID_1, Data: &b.ColAutoInstanceId1},
			proto.InputColumn{Name: ckdb.COLUMN_AUTO_INSTANCE_TYPE_1, Data: &b.ColAutoInstanceType1},
			proto.InputColumn{Name: ckdb.COLUMN_AUTO_SERVICE_ID_1, Data: &b.ColAutoServiceId1},
			proto.InputColumn{Name: ckdb.COLUMN_AUTO_SERVICE_TYPE_1, Data: &b.ColAutoServiceType1},
		)
	}
	if code&SignalSource != 0 {
		input = append(input, proto.InputColumn{Name: ckdb.COLUMN_SIGNAL_SOURCE, Data: &b.ColSignalSource})
	}
	if code&ServiceID != 0 {
		input = append(input, proto.InputColumn{Name: ckdb.COLUMN_SERVICE_ID, Data: &b.ColServiceId})
	}
	if code&ServiceIDPath != 0 {
		input = append(input,
			proto.InputColumn{Name: ckdb.COLUMN_SERVICE_ID_0, Data: &b.ColServiceId0},
			proto.InputColumn{Name: ckdb.COLUMN_SERVICE_ID_1, Data: &b.ColServiceId1},
		)
	}
	if code&ServerPort != 0 {
		input = append(input, proto.InputColumn{Name: ckdb.COLUMN_SERVER_PORT, Data: &b.ColServerPort})
	}
	if code&SubnetID != 0 {
		input = append(input, proto.InputColumn{Name: ckdb.COLUMN_SUBNET_ID, Data: &b.ColSubnetId})
	}
	if code&SubnetIDPath != 0 {
		input = append(input,
			proto.InputColumn{Name: ckdb.COLUMN_SUBNET_ID_0, Data: &b.ColSubnetId0},
			proto.InputColumn{Name: ckdb.COLUMN_SUBNET_ID_1, Data: &b.ColSubnetId1},
		)
	}
	if code&TunnelIPID != 0 {
		input = append(input, proto.InputColumn{Name: ckdb.COLUMN_TUNNEL_IP_ID, Data: &b.ColTunnelIpId})
	}
	if code&TAPPort != 0 {
		input = append(input,
			proto.InputColumn{Name: ckdb.COLUMN_CAPTURE_NIC_TYPE, Data: &b.ColCaptureNicType},
			proto.InputColumn{Name: ckdb.COLUMN_TUNNEL_TYPE, Data: &b.ColTunnelType},
			proto.InputColumn{Name: ckdb.COLUMN_CAPTURE_NIC, Data: &b.ColCaptureNic},
			proto.InputColumn{Name: ckdb.COLUMN_NAT_SOURCE, Data: &b.ColNatSource},
		)
	}
	if code&TAPSide != 0 {
		input = append(input, proto.InputColumn{Name: ckdb.COLUMN_OBSERVATION_POINT, Data: b.ColObservationPoint})
	}
	if code&TAPType != 0 {
		input = append(input, proto.InputColumn{Name: ckdb.COLUMN_CAPTURE_NETWORK_TYPE_ID, Data: &b.ColCaptureNetworkTypeId})
	}
	if code&VTAPID != 0 {
		input = append(input,
			proto.InputColumn{Name: ckdb.COLUMN_AGENT_ID, Data: &b.ColAgentId},
			proto.InputColumn{Name: ckdb.COLUMN_TEAM_ID, Data: &b.ColTeamId},
		)
	}
	return input
}

func (n *Tag) NewColumnBlock() ckdb.CKColumnBlock {
	return &TagBlock{
		Code:                n.Code,
		ColAppService:       new(proto.ColStr).LowCardinality(),
		ColAppInstance:      new(proto.ColStr).LowCardinality(),
		ColObservationPoint: new(proto.ColStr).LowCardinality(),
	}
}

func (n *Tag) AppendToColumnBlock(b ckdb.CKColumnBlock, time uint32) {
	block := b.(*TagBlock)
	ckdb.AppendColDateTime(&block.ColTime, time)
	block.ColTid.Append(n.GlobalThreadID)
	code := n.Code
	if code&ACLGID != 0 {
		block.ColAclGid.Append(n.ACLGID)
	}

	if code&AZID != 0 {
		block.ColAzId.Append(n.AZID)
	}

	if code&AZIDPath != 0 {
		block.ColAzId0.Append(n.AZID)
		block.ColAzId1.Append(n.AZID1)
	}

	if code&Direction != 0 {
		block.ColRole.Append(n.Role)
	}

	if code&GPID != 0 {
		block.ColGprocessId.Append(n.GPID)
	}
	if code&GPIDPath != 0 {
		block.ColGprocessId0.Append(n.GPID)
		block.ColGprocessId1.Append(n.GPID1)
	}

	if code&HostID != 0 {
		block.ColHostId.Append(n.HostID)
	}

	if code&HostIDPath != 0 {
		block.ColHostId0.Append(n.HostID)
		block.ColHostId1.Append(n.HostID1)
	}

	if code&IP != 0 {
		block.ColIp4.Append(proto.IPv4(n.IP))
		ckdb.AppendIPv6(&block.ColIp6, n.IP6)
		block.ColIsIpv4.Append(*(*uint8)(unsafe.Pointer(&n.IsIPv4)))
		block.ColTagSource.Append(n.TagSource)
	}

	if code&IPPath != 0 {
		block.ColIp40.Append(proto.IPv4(n.IP))
		block.ColIp41.Append(proto.IPv4(n.IP1))
		ckdb.AppendIPv6(&block.ColIp60, n.IP6)
		ckdb.AppendIPv6(&block.ColIp61, n.IP61)
		block.ColIsIpv4.Append(*(*uint8)(unsafe.Pointer(&n.IsIPv4)))
		block.ColTagSource0.Append(n.TagSource)
		block.ColTagSource1.Append(n.TagSource1)
	}

	if code&IsKeyService != 0 {
		block.ColIsKeyService.Append(n.IsKeyService)
	}

	if code&L3Device != 0 {
		block.ColL3DeviceId.Append(n.L3DeviceID)
		block.ColL3DeviceType.Append(uint8(n.L3DeviceType))
	}

	if code&L3DevicePath != 0 {
		block.ColL3DeviceId0.Append(n.L3DeviceID)
		block.ColL3DeviceId1.Append(n.L3DeviceID1)
		block.ColL3DeviceType0.Append(uint8(n.L3DeviceType))
		block.ColL3DeviceType1.Append(uint8(n.L3DeviceType1))
	}
	if code&L3EpcID != 0 {
		block.ColL3EpcId.Append(n.L3EpcID)
	}
	if code&L3EpcIDPath != 0 {
		block.ColL3EpcId0.Append(n.L3EpcID)
		block.ColL3EpcId1.Append(n.L3EpcID1)
	}

	if code&L7Protocol != 0 {
		block.ColL7Protocol.Append(uint8(n.L7Protocol))
		block.ColAppService.Append(n.AppService)
		block.ColAppInstance.Append(n.AppInstance)
		block.ColEndpoint.Append(n.Endpoint)
		block.ColBizType.Append(n.BizType)
	}

	if code&PodClusterID != 0 {
		block.ColPodClusterId.Append(n.PodClusterID)
	}

	if code&PodClusterIDPath != 0 {
		block.ColPodClusterId0.Append(n.PodClusterID)
		block.ColPodClusterId1.Append(n.PodClusterID1)
	}

	if code&PodGroupID != 0 {
		block.ColPodGroupId.Append(n.PodGroupID)
	}

	if code&PodGroupIDPath != 0 {
		block.ColPodGroupId0.Append(n.PodGroupID)
		block.ColPodGroupId1.Append(n.PodGroupID1)
	}

	if code&PodID != 0 {
		block.ColPodId.Append(n.PodID)
	}
	if code&PodIDPath != 0 {
		block.ColPodId0.Append(n.PodID)
		block.ColPodId1.Append(n.PodID1)
	}
	if code&PodNodeID != 0 {
		block.ColPodNodeId.Append(n.PodNodeID)
	}
	if code&PodNodeIDPath != 0 {
		block.ColPodNodeId0.Append(n.PodNodeID)
		block.ColPodNodeId1.Append(n.PodNodeID1)
	}

	if code&PodNSID != 0 {
		block.ColPodNsId.Append(n.PodNSID)
	}
	if code&PodNSIDPath != 0 {
		block.ColPodNsId0.Append(n.PodNSID)
		block.ColPodNsId1.Append(n.PodNSID1)
	}

	if code&Protocol != 0 {
		block.ColProtocol.Append(uint8(n.Protocol))
	}

	if code&RegionID != 0 {
		block.ColRegionId.Append(n.RegionID)
	}
	if code&RegionIDPath != 0 {
		block.ColRegionId0.Append(n.RegionID)
		block.ColRegionId1.Append(n.RegionID1)
	}

	if code&Resource != 0 {
		block.ColAutoInstanceId.Append(n.AutoInstanceID)
		block.ColAutoInstanceType.Append(n.AutoInstanceType)
		block.ColAutoServiceId.Append(n.AutoServiceID)
		block.ColAutoServiceType.Append(n.AutoServiceType)
	}

	if code&ResourcePath != 0 {
		block.ColAutoInstanceId0.Append(n.AutoInstanceID)
		block.ColAutoInstanceType0.Append(n.AutoInstanceType)
		block.ColAutoServiceId0.Append(n.AutoServiceID)
		block.ColAutoServiceType0.Append(n.AutoServiceType)
		block.ColAutoInstanceId1.Append(n.AutoInstanceID1)
		block.ColAutoInstanceType1.Append(n.AutoInstanceType1)
		block.ColAutoServiceId1.Append(n.AutoServiceID1)
		block.ColAutoServiceType1.Append(n.AutoServiceType1)
	}

	if code&SignalSource != 0 {
		block.ColSignalSource.Append(n.SignalSource)
	}
	if code&ServiceID != 0 {
		block.ColServiceId.Append(n.ServiceID)
	}
	if code&ServiceIDPath != 0 {
		block.ColServiceId0.Append(n.ServiceID)
		block.ColServiceId1.Append(n.ServiceID1)
	}

	if code&ServerPort != 0 {
		block.ColServerPort.Append(n.ServerPort)
	}

	if code&SubnetID != 0 {
		block.ColSubnetId.Append(n.SubnetID)
	}

	if code&SubnetIDPath != 0 {
		block.ColSubnetId0.Append(n.SubnetID)
		block.ColSubnetId1.Append(n.SubnetID1)
	}
	if code&TunnelIPID != 0 {
		block.ColTunnelIpId.Append(n.TunnelIPID)
	}
	if code&TAPPort != 0 {
		block.ColCaptureNicType.Append(n.TapPortType)
		block.ColTunnelType.Append(uint8(n.TunnelType))
		block.ColCaptureNic.Append(n.TapPort)
		block.ColNatSource.Append(uint8(n.NatSource))
	}
	if code&TAPSide != 0 {
		block.ColObservationPoint.Append(n.TAPSide.String())
	}
	if code&TAPType != 0 {
		block.ColCaptureNetworkTypeId.Append(uint8(n.TAPType))
	}
	if code&VTAPID != 0 {
		block.ColAgentId.Append(n.VTAPID)
		block.ColTeamId.Append(n.TeamID)
	}
}
