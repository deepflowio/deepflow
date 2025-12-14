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

package log_data

import (
	"unsafe"

	"github.com/ClickHouse/ch-go/proto"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
)

type DataLinkLayerBlock struct {
	ColMac0    proto.ColUInt64
	ColMac1    proto.ColUInt64
	ColEthType proto.ColUInt16
	ColVlan    proto.ColUInt16
}

func (b *DataLinkLayerBlock) Reset() {
	b.ColMac0.Reset()
	b.ColMac1.Reset()
	b.ColEthType.Reset()
	b.ColVlan.Reset()
}

func (b *DataLinkLayerBlock) ToInput(input proto.Input) proto.Input {
	return append(input,
		proto.InputColumn{Name: ckdb.COLUMN_MAC_0, Data: &b.ColMac0},
		proto.InputColumn{Name: ckdb.COLUMN_MAC_1, Data: &b.ColMac1},
		proto.InputColumn{Name: ckdb.COLUMN_ETH_TYPE, Data: &b.ColEthType},
		proto.InputColumn{Name: ckdb.COLUMN_VLAN, Data: &b.ColVlan},
	)
}

func (n *DataLinkLayer) NewColumnBlock() ckdb.CKColumnBlock {
	return &DataLinkLayerBlock{}
}

func (n *DataLinkLayer) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*DataLinkLayerBlock)
	block.ColMac0.Append(n.MAC0)
	block.ColMac1.Append(n.MAC1)
	block.ColEthType.Append(n.EthType)
	block.ColVlan.Append(n.VLAN)
}

type NetworkLayerBlock struct {
	ColIp40         proto.ColIPv4
	ColIp41         proto.ColIPv4
	ColIp60         proto.ColIPv6
	ColIp61         proto.ColIPv6
	ColIsIpv4       proto.ColUInt8
	ColProtocol     proto.ColUInt8
	ColTunnelTier   proto.ColUInt8
	ColTunnelType   proto.ColUInt16
	ColTunnelTxId   proto.ColUInt32
	ColTunnelRxId   proto.ColUInt32
	ColTunnelTxIp40 proto.ColIPv4
	ColTunnelTxIp41 proto.ColIPv4
	ColTunnelRxIp40 proto.ColIPv4
	ColTunnelRxIp41 proto.ColIPv4
	ColTunnelTxIp60 proto.ColIPv6
	ColTunnelTxIp61 proto.ColIPv6
	ColTunnelRxIp60 proto.ColIPv6
	ColTunnelRxIp61 proto.ColIPv6
	ColTunnelIsIpv4 proto.ColUInt8
	ColTunnelTxMac0 proto.ColUInt32
	ColTunnelTxMac1 proto.ColUInt32
	ColTunnelRxMac0 proto.ColUInt32
	ColTunnelRxMac1 proto.ColUInt32
}

func (b *NetworkLayerBlock) Reset() {
	b.ColIp40.Reset()
	b.ColIp41.Reset()
	b.ColIp60.Reset()
	b.ColIp61.Reset()
	b.ColIsIpv4.Reset()
	b.ColProtocol.Reset()
	b.ColTunnelTier.Reset()
	b.ColTunnelType.Reset()
	b.ColTunnelTxId.Reset()
	b.ColTunnelRxId.Reset()
	b.ColTunnelTxIp40.Reset()
	b.ColTunnelTxIp41.Reset()
	b.ColTunnelRxIp40.Reset()
	b.ColTunnelRxIp41.Reset()
	b.ColTunnelTxIp60.Reset()
	b.ColTunnelTxIp61.Reset()
	b.ColTunnelRxIp60.Reset()
	b.ColTunnelRxIp61.Reset()
	b.ColTunnelIsIpv4.Reset()
	b.ColTunnelTxMac0.Reset()
	b.ColTunnelTxMac1.Reset()
	b.ColTunnelRxMac0.Reset()
	b.ColTunnelRxMac1.Reset()
}

func (b *NetworkLayerBlock) ToInput(input proto.Input) proto.Input {
	return append(input,
		proto.InputColumn{Name: ckdb.COLUMN_IP4_0, Data: &b.ColIp40},
		proto.InputColumn{Name: ckdb.COLUMN_IP4_1, Data: &b.ColIp41},
		proto.InputColumn{Name: ckdb.COLUMN_IP6_0, Data: &b.ColIp60},
		proto.InputColumn{Name: ckdb.COLUMN_IP6_1, Data: &b.ColIp61},
		proto.InputColumn{Name: ckdb.COLUMN_IS_IPV4, Data: &b.ColIsIpv4},
		proto.InputColumn{Name: ckdb.COLUMN_PROTOCOL, Data: &b.ColProtocol},
		proto.InputColumn{Name: ckdb.COLUMN_TUNNEL_TIER, Data: &b.ColTunnelTier},
		proto.InputColumn{Name: ckdb.COLUMN_TUNNEL_TYPE, Data: &b.ColTunnelType},
		proto.InputColumn{Name: ckdb.COLUMN_TUNNEL_TX_ID, Data: &b.ColTunnelTxId},
		proto.InputColumn{Name: ckdb.COLUMN_TUNNEL_RX_ID, Data: &b.ColTunnelRxId},
		proto.InputColumn{Name: ckdb.COLUMN_TUNNEL_TX_IP4_0, Data: &b.ColTunnelTxIp40},
		proto.InputColumn{Name: ckdb.COLUMN_TUNNEL_TX_IP4_1, Data: &b.ColTunnelTxIp41},
		proto.InputColumn{Name: ckdb.COLUMN_TUNNEL_RX_IP4_0, Data: &b.ColTunnelRxIp40},
		proto.InputColumn{Name: ckdb.COLUMN_TUNNEL_RX_IP4_1, Data: &b.ColTunnelRxIp41},
		proto.InputColumn{Name: ckdb.COLUMN_TUNNEL_TX_IP6_0, Data: &b.ColTunnelTxIp60},
		proto.InputColumn{Name: ckdb.COLUMN_TUNNEL_TX_IP6_1, Data: &b.ColTunnelTxIp61},
		proto.InputColumn{Name: ckdb.COLUMN_TUNNEL_RX_IP6_0, Data: &b.ColTunnelRxIp60},
		proto.InputColumn{Name: ckdb.COLUMN_TUNNEL_RX_IP6_1, Data: &b.ColTunnelRxIp61},
		proto.InputColumn{Name: ckdb.COLUMN_TUNNEL_IS_IPV4, Data: &b.ColTunnelIsIpv4},
		proto.InputColumn{Name: ckdb.COLUMN_TUNNEL_TX_MAC_0, Data: &b.ColTunnelTxMac0},
		proto.InputColumn{Name: ckdb.COLUMN_TUNNEL_TX_MAC_1, Data: &b.ColTunnelTxMac1},
		proto.InputColumn{Name: ckdb.COLUMN_TUNNEL_RX_MAC_0, Data: &b.ColTunnelRxMac0},
		proto.InputColumn{Name: ckdb.COLUMN_TUNNEL_RX_MAC_1, Data: &b.ColTunnelRxMac1},
	)
}

func (n *NetworkLayer) NewColumnBlock() ckdb.CKColumnBlock {
	return &NetworkLayerBlock{}
}

func (n *NetworkLayer) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*NetworkLayerBlock)
	block.ColIp40.Append(proto.IPv4(n.IP40))
	block.ColIp41.Append(proto.IPv4(n.IP41))
	ckdb.AppendIPv6(&block.ColIp60, n.IP60)
	ckdb.AppendIPv6(&block.ColIp61, n.IP61)
	block.ColProtocol.Append(n.Protocol)
	block.ColIsIpv4.Append(*(*uint8)(unsafe.Pointer(&n.IsIPv4)))

	block.ColTunnelTier.Append(n.TunnelTier)
	block.ColTunnelType.Append(n.TunnelType)
	block.ColTunnelTxId.Append(n.TunnelTxID)
	block.ColTunnelRxId.Append(n.TunnelRxID)
	block.ColTunnelTxIp40.Append(proto.IPv4(n.TunnelTxIP40))
	block.ColTunnelTxIp41.Append(proto.IPv4(n.TunnelTxIP41))
	block.ColTunnelRxIp40.Append(proto.IPv4(n.TunnelRxIP40))
	block.ColTunnelRxIp41.Append(proto.IPv4(n.TunnelRxIP41))
	ckdb.AppendIPv6(&block.ColTunnelTxIp60, n.TunnelTxIP60)
	ckdb.AppendIPv6(&block.ColTunnelTxIp61, n.TunnelTxIP61)
	ckdb.AppendIPv6(&block.ColTunnelRxIp60, n.TunnelRxIP60)
	ckdb.AppendIPv6(&block.ColTunnelRxIp61, n.TunnelRxIP61)

	block.ColTunnelIsIpv4.Append(*(*uint8)(unsafe.Pointer(&n.TunnelIsIPv4)))
	block.ColTunnelTxMac0.Append(n.TunnelTxMac0)
	block.ColTunnelTxMac1.Append(n.TunnelTxMac1)
	block.ColTunnelRxMac0.Append(n.TunnelRxMac0)
	block.ColTunnelRxMac1.Append(n.TunnelRxMac1)
}

type TransportLayerBlock struct {
	ColClientPort       proto.ColUInt16
	ColServerPort       proto.ColUInt16
	ColTcpFlagsBit0     proto.ColUInt16
	ColTcpFlagsBit1     proto.ColUInt16
	ColSynSeq           proto.ColUInt32
	ColSynAckSeq        proto.ColUInt32
	ColLastKeepaliveSeq proto.ColUInt32
	ColLastKeepaliveAck proto.ColUInt32
}

func (b *TransportLayerBlock) Reset() {
	b.ColClientPort.Reset()
	b.ColServerPort.Reset()
	b.ColTcpFlagsBit0.Reset()
	b.ColTcpFlagsBit1.Reset()
	b.ColSynSeq.Reset()
	b.ColSynAckSeq.Reset()
	b.ColLastKeepaliveSeq.Reset()
	b.ColLastKeepaliveAck.Reset()
}

func (b *TransportLayerBlock) ToInput(input proto.Input) proto.Input {
	return append(input,
		proto.InputColumn{Name: ckdb.COLUMN_CLIENT_PORT, Data: &b.ColClientPort},
		proto.InputColumn{Name: ckdb.COLUMN_SERVER_PORT, Data: &b.ColServerPort},
		proto.InputColumn{Name: ckdb.COLUMN_TCP_FLAGS_BIT_0, Data: &b.ColTcpFlagsBit0},
		proto.InputColumn{Name: ckdb.COLUMN_TCP_FLAGS_BIT_1, Data: &b.ColTcpFlagsBit1},
		proto.InputColumn{Name: ckdb.COLUMN_SYN_SEQ, Data: &b.ColSynSeq},
		proto.InputColumn{Name: ckdb.COLUMN_SYN_ACK_SEQ, Data: &b.ColSynAckSeq},
		proto.InputColumn{Name: ckdb.COLUMN_LAST_KEEPALIVE_SEQ, Data: &b.ColLastKeepaliveSeq},
		proto.InputColumn{Name: ckdb.COLUMN_LAST_KEEPALIVE_ACK, Data: &b.ColLastKeepaliveAck},
	)
}

func (n *TransportLayer) NewColumnBlock() ckdb.CKColumnBlock {
	return &TransportLayerBlock{}
}

func (n *TransportLayer) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*TransportLayerBlock)
	block.ColClientPort.Append(n.ClientPort)
	block.ColServerPort.Append(n.ServerPort)
	block.ColTcpFlagsBit0.Append(n.TCPFlagsBit0)
	block.ColTcpFlagsBit1.Append(n.TCPFlagsBit1)
	block.ColSynSeq.Append(n.SynSeq)
	block.ColSynAckSeq.Append(n.SynAckSeq)
	block.ColLastKeepaliveSeq.Append(n.LastKeepaliveSeq)
	block.ColLastKeepaliveAck.Append(n.LastKeepaliveAck)
}

type ApplicationLayerBlock struct {
	ColL7Protocol proto.ColUInt8
}

func (b *ApplicationLayerBlock) Reset() {
	b.ColL7Protocol.Reset()
}

func (b *ApplicationLayerBlock) ToInput(input proto.Input) proto.Input {
	return append(input,
		proto.InputColumn{Name: ckdb.COLUMN_L7_PROTOCOL, Data: &b.ColL7Protocol},
	)
}

func (n *ApplicationLayer) NewColumnBlock() ckdb.CKColumnBlock {
	return &ApplicationLayerBlock{}
}

func (n *ApplicationLayer) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*ApplicationLayerBlock)
	block.ColL7Protocol.Append(n.L7Protocol)
}

type InternetBlock struct {
	ColProvince0 *proto.ColLowCardinality[string]
	ColProvince1 *proto.ColLowCardinality[string]
}

func (b *InternetBlock) Reset() {
	b.ColProvince0.Reset()
	b.ColProvince1.Reset()
}

func (b *InternetBlock) ToInput(input proto.Input) proto.Input {
	return append(input,
		proto.InputColumn{Name: ckdb.COLUMN_PROVINCE_0, Data: b.ColProvince0},
		proto.InputColumn{Name: ckdb.COLUMN_PROVINCE_1, Data: b.ColProvince1},
	)
}

func (n *Internet) NewColumnBlock() ckdb.CKColumnBlock {
	return &InternetBlock{
		ColProvince0: new(proto.ColStr).LowCardinality(),
		ColProvince1: new(proto.ColStr).LowCardinality(),
	}
}

func (n *Internet) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*InternetBlock)
	block.ColProvince0.Append(n.Province0)
	block.ColProvince1.Append(n.Province1)
}

type KnowledgeGraphBlock struct {
	ColRegionId0         proto.ColUInt16
	ColRegionId1         proto.ColUInt16
	ColAzId0             proto.ColUInt16
	ColAzId1             proto.ColUInt16
	ColHostId0           proto.ColUInt16
	ColHostId1           proto.ColUInt16
	ColL3DeviceType0     proto.ColUInt8
	ColL3DeviceType1     proto.ColUInt8
	ColL3DeviceId0       proto.ColUInt32
	ColL3DeviceId1       proto.ColUInt32
	ColPodNodeId0        proto.ColUInt32
	ColPodNodeId1        proto.ColUInt32
	ColPodNsId0          proto.ColUInt16
	ColPodNsId1          proto.ColUInt16
	ColPodGroupId0       proto.ColUInt32
	ColPodGroupId1       proto.ColUInt32
	ColPodId0            proto.ColUInt32
	ColPodId1            proto.ColUInt32
	ColPodClusterId0     proto.ColUInt16
	ColPodClusterId1     proto.ColUInt16
	ColL3EpcId0          proto.ColInt32
	ColL3EpcId1          proto.ColInt32
	ColEpcId0            proto.ColInt32
	ColEpcId1            proto.ColInt32
	ColSubnetId0         proto.ColUInt16
	ColSubnetId1         proto.ColUInt16
	ColServiceId0        proto.ColUInt32
	ColServiceId1        proto.ColUInt32
	ColAutoInstanceId0   proto.ColUInt32
	ColAutoInstanceType0 proto.ColUInt8
	ColAutoServiceId0    proto.ColUInt32
	ColAutoServiceType0  proto.ColUInt8
	ColAutoInstanceId1   proto.ColUInt32
	ColAutoInstanceType1 proto.ColUInt8
	ColAutoServiceId1    proto.ColUInt32
	ColAutoServiceType1  proto.ColUInt8
	ColTagSource0        proto.ColUInt8
	ColTagSource1        proto.ColUInt8
	ColTeamId            proto.ColUInt16
}

func (b *KnowledgeGraphBlock) Reset() {
	b.ColRegionId0.Reset()
	b.ColRegionId1.Reset()
	b.ColAzId0.Reset()
	b.ColAzId1.Reset()
	b.ColHostId0.Reset()
	b.ColHostId1.Reset()
	b.ColL3DeviceType0.Reset()
	b.ColL3DeviceType1.Reset()
	b.ColL3DeviceId0.Reset()
	b.ColL3DeviceId1.Reset()
	b.ColPodNodeId0.Reset()
	b.ColPodNodeId1.Reset()
	b.ColPodNsId0.Reset()
	b.ColPodNsId1.Reset()
	b.ColPodGroupId0.Reset()
	b.ColPodGroupId1.Reset()
	b.ColPodId0.Reset()
	b.ColPodId1.Reset()
	b.ColPodClusterId0.Reset()
	b.ColPodClusterId1.Reset()
	b.ColL3EpcId0.Reset()
	b.ColL3EpcId1.Reset()
	b.ColEpcId0.Reset()
	b.ColEpcId1.Reset()
	b.ColSubnetId0.Reset()
	b.ColSubnetId1.Reset()
	b.ColServiceId0.Reset()
	b.ColServiceId1.Reset()
	b.ColAutoInstanceId0.Reset()
	b.ColAutoInstanceType0.Reset()
	b.ColAutoServiceId0.Reset()
	b.ColAutoServiceType0.Reset()
	b.ColAutoInstanceId1.Reset()
	b.ColAutoInstanceType1.Reset()
	b.ColAutoServiceId1.Reset()
	b.ColAutoServiceType1.Reset()
	b.ColTagSource0.Reset()
	b.ColTagSource1.Reset()
	b.ColTeamId.Reset()
}

func (b *KnowledgeGraphBlock) ToInput(input proto.Input) proto.Input {
	return append(input,
		proto.InputColumn{Name: ckdb.COLUMN_REGION_ID_0, Data: &b.ColRegionId0},
		proto.InputColumn{Name: ckdb.COLUMN_REGION_ID_1, Data: &b.ColRegionId1},
		proto.InputColumn{Name: ckdb.COLUMN_AZ_ID_0, Data: &b.ColAzId0},
		proto.InputColumn{Name: ckdb.COLUMN_AZ_ID_1, Data: &b.ColAzId1},
		proto.InputColumn{Name: ckdb.COLUMN_HOST_ID_0, Data: &b.ColHostId0},
		proto.InputColumn{Name: ckdb.COLUMN_HOST_ID_1, Data: &b.ColHostId1},
		proto.InputColumn{Name: ckdb.COLUMN_L3_DEVICE_TYPE_0, Data: &b.ColL3DeviceType0},
		proto.InputColumn{Name: ckdb.COLUMN_L3_DEVICE_TYPE_1, Data: &b.ColL3DeviceType1},
		proto.InputColumn{Name: ckdb.COLUMN_L3_DEVICE_ID_0, Data: &b.ColL3DeviceId0},
		proto.InputColumn{Name: ckdb.COLUMN_L3_DEVICE_ID_1, Data: &b.ColL3DeviceId1},
		proto.InputColumn{Name: ckdb.COLUMN_POD_NODE_ID_0, Data: &b.ColPodNodeId0},
		proto.InputColumn{Name: ckdb.COLUMN_POD_NODE_ID_1, Data: &b.ColPodNodeId1},
		proto.InputColumn{Name: ckdb.COLUMN_POD_NS_ID_0, Data: &b.ColPodNsId0},
		proto.InputColumn{Name: ckdb.COLUMN_POD_NS_ID_1, Data: &b.ColPodNsId1},
		proto.InputColumn{Name: ckdb.COLUMN_POD_GROUP_ID_0, Data: &b.ColPodGroupId0},
		proto.InputColumn{Name: ckdb.COLUMN_POD_GROUP_ID_1, Data: &b.ColPodGroupId1},
		proto.InputColumn{Name: ckdb.COLUMN_POD_ID_0, Data: &b.ColPodId0},
		proto.InputColumn{Name: ckdb.COLUMN_POD_ID_1, Data: &b.ColPodId1},
		proto.InputColumn{Name: ckdb.COLUMN_POD_CLUSTER_ID_0, Data: &b.ColPodClusterId0},
		proto.InputColumn{Name: ckdb.COLUMN_POD_CLUSTER_ID_1, Data: &b.ColPodClusterId1},
		proto.InputColumn{Name: ckdb.COLUMN_L3_EPC_ID_0, Data: &b.ColL3EpcId0},
		proto.InputColumn{Name: ckdb.COLUMN_L3_EPC_ID_1, Data: &b.ColL3EpcId1},
		proto.InputColumn{Name: ckdb.COLUMN_EPC_ID_0, Data: &b.ColEpcId0},
		proto.InputColumn{Name: ckdb.COLUMN_EPC_ID_1, Data: &b.ColEpcId1},
		proto.InputColumn{Name: ckdb.COLUMN_SUBNET_ID_0, Data: &b.ColSubnetId0},
		proto.InputColumn{Name: ckdb.COLUMN_SUBNET_ID_1, Data: &b.ColSubnetId1},
		proto.InputColumn{Name: ckdb.COLUMN_SERVICE_ID_0, Data: &b.ColServiceId0},
		proto.InputColumn{Name: ckdb.COLUMN_SERVICE_ID_1, Data: &b.ColServiceId1},
		proto.InputColumn{Name: ckdb.COLUMN_AUTO_INSTANCE_ID_0, Data: &b.ColAutoInstanceId0},
		proto.InputColumn{Name: ckdb.COLUMN_AUTO_INSTANCE_TYPE_0, Data: &b.ColAutoInstanceType0},
		proto.InputColumn{Name: ckdb.COLUMN_AUTO_SERVICE_ID_0, Data: &b.ColAutoServiceId0},
		proto.InputColumn{Name: ckdb.COLUMN_AUTO_SERVICE_TYPE_0, Data: &b.ColAutoServiceType0},
		proto.InputColumn{Name: ckdb.COLUMN_AUTO_INSTANCE_ID_1, Data: &b.ColAutoInstanceId1},
		proto.InputColumn{Name: ckdb.COLUMN_AUTO_INSTANCE_TYPE_1, Data: &b.ColAutoInstanceType1},
		proto.InputColumn{Name: ckdb.COLUMN_AUTO_SERVICE_ID_1, Data: &b.ColAutoServiceId1},
		proto.InputColumn{Name: ckdb.COLUMN_AUTO_SERVICE_TYPE_1, Data: &b.ColAutoServiceType1},
		proto.InputColumn{Name: ckdb.COLUMN_TAG_SOURCE_0, Data: &b.ColTagSource0},
		proto.InputColumn{Name: ckdb.COLUMN_TAG_SOURCE_1, Data: &b.ColTagSource1},
		proto.InputColumn{Name: ckdb.COLUMN_TEAM_ID, Data: &b.ColTeamId},
	)
}

func (n *KnowledgeGraph) NewColumnBlock() ckdb.CKColumnBlock {
	return &KnowledgeGraphBlock{}
}

func (n *KnowledgeGraph) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*KnowledgeGraphBlock)
	block.ColRegionId0.Append(n.RegionID0)
	block.ColRegionId1.Append(n.RegionID1)
	block.ColAzId0.Append(n.AZID0)
	block.ColAzId1.Append(n.AZID1)
	block.ColHostId0.Append(n.HostID0)
	block.ColHostId1.Append(n.HostID1)
	block.ColL3DeviceType0.Append(n.L3DeviceType0)
	block.ColL3DeviceType1.Append(n.L3DeviceType1)
	block.ColL3DeviceId0.Append(n.L3DeviceID0)
	block.ColL3DeviceId1.Append(n.L3DeviceID1)
	block.ColPodNodeId0.Append(n.PodNodeID0)
	block.ColPodNodeId1.Append(n.PodNodeID1)
	block.ColPodNsId0.Append(n.PodNSID0)
	block.ColPodNsId1.Append(n.PodNSID1)
	block.ColPodGroupId0.Append(n.PodGroupID0)
	block.ColPodGroupId1.Append(n.PodGroupID1)
	block.ColPodId0.Append(n.PodID0)
	block.ColPodId1.Append(n.PodID1)
	block.ColPodClusterId0.Append(n.PodClusterID0)
	block.ColPodClusterId1.Append(n.PodClusterID1)
	block.ColL3EpcId0.Append(n.L3EpcID0)
	block.ColL3EpcId1.Append(n.L3EpcID1)
	block.ColEpcId0.Append(n.EpcID0)
	block.ColEpcId1.Append(n.EpcID1)
	block.ColSubnetId0.Append(n.SubnetID0)
	block.ColSubnetId1.Append(n.SubnetID1)
	block.ColServiceId0.Append(n.ServiceID0)
	block.ColServiceId1.Append(n.ServiceID1)
	block.ColAutoInstanceId0.Append(n.AutoInstanceID0)
	block.ColAutoInstanceType0.Append(n.AutoInstanceType0)
	block.ColAutoServiceId0.Append(n.AutoServiceID0)
	block.ColAutoServiceType0.Append(n.AutoServiceType0)
	block.ColAutoInstanceId1.Append(n.AutoInstanceID1)
	block.ColAutoInstanceType1.Append(n.AutoInstanceType1)
	block.ColAutoServiceId1.Append(n.AutoServiceID1)
	block.ColAutoServiceType1.Append(n.AutoServiceType1)
	block.ColTagSource0.Append(n.TagSource0)
	block.ColTagSource1.Append(n.TagSource1)
	block.ColTeamId.Append(n.TeamID)
}

type FlowInfoBlock struct {
	ColTime                 proto.ColDateTime
	ColCloseType            proto.ColUInt16
	ColSignalSource         proto.ColUInt16
	ColFlowId               proto.ColUInt64
	ColAggregatedFlowIds    proto.ColStr
	ColInitIpid             proto.ColUInt32
	ColCaptureNetworkTypeId proto.ColUInt8
	ColNatSource            proto.ColUInt8
	ColCaptureNicType       proto.ColUInt8
	ColCaptureNic           proto.ColUInt32
	ColObservationPoint     *proto.ColLowCardinality[string]
	ColAgentId              proto.ColUInt16
	ColL2End0               proto.ColUInt8
	ColL2End1               proto.ColUInt8
	ColL3End0               proto.ColUInt8
	ColL3End1               proto.ColUInt8
	ColStartTime            proto.ColDateTime64
	ColEndTime              proto.ColDateTime64
	ColDuration             proto.ColUInt64
	ColIsNewFlow            proto.ColUInt8
	ColStatus               proto.ColUInt8
	ColAclGids              *proto.ColArr[uint16]
	ColGprocessId0          proto.ColUInt32
	ColGprocessId1          proto.ColUInt32
	ColNatRealIp40          proto.ColIPv4
	ColNatRealIp41          proto.ColIPv4
	ColNatRealPort0         proto.ColUInt16
	ColNatRealPort1         proto.ColUInt16
	ColDirectionScore       proto.ColUInt8
	ColRequestDomain        proto.ColStr
}

func (b *FlowInfoBlock) Reset() {
	b.ColTime.Reset()
	b.ColCloseType.Reset()
	b.ColSignalSource.Reset()
	b.ColFlowId.Reset()
	b.ColAggregatedFlowIds.Reset()
	b.ColInitIpid.Reset()
	b.ColCaptureNetworkTypeId.Reset()
	b.ColNatSource.Reset()
	b.ColCaptureNicType.Reset()
	b.ColCaptureNic.Reset()
	b.ColObservationPoint.Reset()
	b.ColAgentId.Reset()
	b.ColL2End0.Reset()
	b.ColL2End1.Reset()
	b.ColL3End0.Reset()
	b.ColL3End1.Reset()
	b.ColStartTime.Reset()
	b.ColEndTime.Reset()
	b.ColDuration.Reset()
	b.ColIsNewFlow.Reset()
	b.ColStatus.Reset()
	b.ColAclGids.Reset()
	b.ColGprocessId0.Reset()
	b.ColGprocessId1.Reset()
	b.ColNatRealIp40.Reset()
	b.ColNatRealIp41.Reset()
	b.ColNatRealPort0.Reset()
	b.ColNatRealPort1.Reset()
	b.ColDirectionScore.Reset()
	b.ColRequestDomain.Reset()
}

func (b *FlowInfoBlock) ToInput(input proto.Input) proto.Input {
	return append(input,
		proto.InputColumn{Name: ckdb.COLUMN_TIME, Data: &b.ColTime},
		proto.InputColumn{Name: ckdb.COLUMN_CLOSE_TYPE, Data: &b.ColCloseType},
		proto.InputColumn{Name: ckdb.COLUMN_SIGNAL_SOURCE, Data: &b.ColSignalSource},
		proto.InputColumn{Name: ckdb.COLUMN_FLOW_ID, Data: &b.ColFlowId},
		proto.InputColumn{Name: ckdb.COLUMN_AGGREGATED_FLOW_IDS, Data: &b.ColAggregatedFlowIds},
		proto.InputColumn{Name: ckdb.COLUMN_INIT_IPID, Data: &b.ColInitIpid},
		proto.InputColumn{Name: ckdb.COLUMN_CAPTURE_NETWORK_TYPE_ID, Data: &b.ColCaptureNetworkTypeId},
		proto.InputColumn{Name: ckdb.COLUMN_NAT_SOURCE, Data: &b.ColNatSource},
		proto.InputColumn{Name: ckdb.COLUMN_CAPTURE_NIC_TYPE, Data: &b.ColCaptureNicType},
		proto.InputColumn{Name: ckdb.COLUMN_CAPTURE_NIC, Data: &b.ColCaptureNic},
		proto.InputColumn{Name: ckdb.COLUMN_OBSERVATION_POINT, Data: b.ColObservationPoint},
		proto.InputColumn{Name: ckdb.COLUMN_AGENT_ID, Data: &b.ColAgentId},
		proto.InputColumn{Name: ckdb.COLUMN_L2_END_0, Data: &b.ColL2End0},
		proto.InputColumn{Name: ckdb.COLUMN_L2_END_1, Data: &b.ColL2End1},
		proto.InputColumn{Name: ckdb.COLUMN_L3_END_0, Data: &b.ColL3End0},
		proto.InputColumn{Name: ckdb.COLUMN_L3_END_1, Data: &b.ColL3End1},
		proto.InputColumn{Name: ckdb.COLUMN_START_TIME, Data: &b.ColStartTime},
		proto.InputColumn{Name: ckdb.COLUMN_END_TIME, Data: &b.ColEndTime},
		proto.InputColumn{Name: ckdb.COLUMN_DURATION, Data: &b.ColDuration},
		proto.InputColumn{Name: ckdb.COLUMN_IS_NEW_FLOW, Data: &b.ColIsNewFlow},
		proto.InputColumn{Name: ckdb.COLUMN_STATUS, Data: &b.ColStatus},
		proto.InputColumn{Name: ckdb.COLUMN_ACL_GIDS, Data: b.ColAclGids},
		proto.InputColumn{Name: ckdb.COLUMN_GPROCESS_ID_0, Data: &b.ColGprocessId0},
		proto.InputColumn{Name: ckdb.COLUMN_GPROCESS_ID_1, Data: &b.ColGprocessId1},
		proto.InputColumn{Name: ckdb.COLUMN_NAT_REAL_IP4_0, Data: &b.ColNatRealIp40},
		proto.InputColumn{Name: ckdb.COLUMN_NAT_REAL_IP4_1, Data: &b.ColNatRealIp41},
		proto.InputColumn{Name: ckdb.COLUMN_NAT_REAL_PORT_0, Data: &b.ColNatRealPort0},
		proto.InputColumn{Name: ckdb.COLUMN_NAT_REAL_PORT_1, Data: &b.ColNatRealPort1},
		proto.InputColumn{Name: ckdb.COLUMN_DIRECTION_SCORE, Data: &b.ColDirectionScore},
		proto.InputColumn{Name: ckdb.COLUMN_REQUEST_DOMAIN, Data: &b.ColRequestDomain},
	)
}

func (n *FlowInfo) NewColumnBlock() ckdb.CKColumnBlock {
	return &FlowInfoBlock{
		ColObservationPoint: new(proto.ColStr).LowCardinality(),
		ColAclGids:          new(proto.ColUInt16).Array(),
	}
}

func (n *FlowInfo) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*FlowInfoBlock)
	ckdb.AppendColDateTime(&block.ColTime, n.Time)
	block.ColCloseType.Append(n.CloseType)
	block.ColSignalSource.Append(n.SignalSource)
	block.ColFlowId.Append(n.FlowID)
	block.ColAggregatedFlowIds.Append(n.AggregatedFlowIDs)
	block.ColInitIpid.Append(n.InitIpid)
	block.ColCaptureNetworkTypeId.Append(n.TapType)
	block.ColNatSource.Append(n.NatSource)
	block.ColCaptureNicType.Append(n.TapPortType)
	block.ColCaptureNic.Append(n.TapPort)
	block.ColObservationPoint.Append(n.TapSide)
	block.ColAgentId.Append(n.VtapID)
	block.ColL2End0.Append(*(*uint8)(unsafe.Pointer(&n.L2End0)))
	block.ColL2End1.Append(*(*uint8)(unsafe.Pointer(&n.L2End1)))
	block.ColL3End0.Append(*(*uint8)(unsafe.Pointer(&n.L3End0)))
	block.ColL3End1.Append(*(*uint8)(unsafe.Pointer(&n.L3End1)))
	ckdb.AppendColDateTime64Micro(&block.ColStartTime, n.StartTime)
	ckdb.AppendColDateTime64Micro(&block.ColEndTime, n.EndTime)
	block.ColDuration.Append(n.Duration)
	block.ColIsNewFlow.Append(n.IsNewFlow)
	block.ColStatus.Append(n.Status)
	block.ColAclGids.Append(n.AclGids)
	block.ColGprocessId0.Append(n.GPID0)
	block.ColGprocessId1.Append(n.GPID1)
	block.ColNatRealIp40.Append(proto.IPv4(n.NatRealIP0))
	block.ColNatRealIp41.Append(proto.IPv4(n.NatRealIP1))
	block.ColNatRealPort0.Append(n.NatRealPort0)
	block.ColNatRealPort1.Append(n.NatRealPort1)
	block.ColDirectionScore.Append(n.DirectionScore)
	block.ColRequestDomain.Append(n.RequestDomain)
}

type MetricsBlock struct {
	ColPacketTx        proto.ColUInt64
	ColPacketRx        proto.ColUInt64
	ColByteTx          proto.ColUInt64
	ColByteRx          proto.ColUInt64
	ColL3ByteTx        proto.ColUInt64
	ColL3ByteRx        proto.ColUInt64
	ColL4ByteTx        proto.ColUInt64
	ColL4ByteRx        proto.ColUInt64
	ColTotalPacketTx   proto.ColUInt64
	ColTotalPacketRx   proto.ColUInt64
	ColTotalByteTx     proto.ColUInt64
	ColTotalByteRx     proto.ColUInt64
	ColL7Request       proto.ColUInt32
	ColL7Response      proto.ColUInt32
	ColL7ParseFailed   proto.ColUInt32
	ColRtt             proto.ColFloat64
	ColRttClient       proto.ColFloat64
	ColRttServer       proto.ColFloat64
	ColTlsRtt          proto.ColFloat64
	ColSrtSum          proto.ColFloat64
	ColArtSum          proto.ColFloat64
	ColRrtSum          proto.ColFloat64
	ColCitSum          proto.ColFloat64
	ColSrtCount        proto.ColUInt64
	ColArtCount        proto.ColUInt64
	ColRrtCount        proto.ColUInt64
	ColCitCount        proto.ColUInt64
	ColSrtMax          proto.ColUInt32
	ColArtMax          proto.ColUInt32
	ColRrtMax          proto.ColUInt32
	ColCitMax          proto.ColUInt32
	ColRetransTx       proto.ColUInt32
	ColRetransRx       proto.ColUInt32
	ColZeroWinTx       proto.ColUInt32
	ColZeroWinRx       proto.ColUInt32
	ColSynCount        proto.ColUInt32
	ColSynackCount     proto.ColUInt32
	ColRetransSyn      proto.ColUInt32
	ColRetransSynack   proto.ColUInt32
	ColL7ClientError   proto.ColUInt32
	ColL7ServerError   proto.ColUInt32
	ColL7ServerTimeout proto.ColUInt32
	ColL7Error         proto.ColUInt32
	ColOooTx           proto.ColUInt32
	ColOooRx           proto.ColUInt32
	ColFinCount        proto.ColUInt32
}

func (b *MetricsBlock) Reset() {
	b.ColPacketTx.Reset()
	b.ColPacketRx.Reset()
	b.ColByteTx.Reset()
	b.ColByteRx.Reset()
	b.ColL3ByteTx.Reset()
	b.ColL3ByteRx.Reset()
	b.ColL4ByteTx.Reset()
	b.ColL4ByteRx.Reset()
	b.ColTotalPacketTx.Reset()
	b.ColTotalPacketRx.Reset()
	b.ColTotalByteTx.Reset()
	b.ColTotalByteRx.Reset()
	b.ColL7Request.Reset()
	b.ColL7Response.Reset()
	b.ColL7ParseFailed.Reset()
	b.ColRtt.Reset()
	b.ColRttClient.Reset()
	b.ColRttServer.Reset()
	b.ColTlsRtt.Reset()
	b.ColSrtSum.Reset()
	b.ColArtSum.Reset()
	b.ColRrtSum.Reset()
	b.ColCitSum.Reset()
	b.ColSrtCount.Reset()
	b.ColArtCount.Reset()
	b.ColRrtCount.Reset()
	b.ColCitCount.Reset()
	b.ColSrtMax.Reset()
	b.ColArtMax.Reset()
	b.ColRrtMax.Reset()
	b.ColCitMax.Reset()
	b.ColRetransTx.Reset()
	b.ColRetransRx.Reset()
	b.ColZeroWinTx.Reset()
	b.ColZeroWinRx.Reset()
	b.ColSynCount.Reset()
	b.ColSynackCount.Reset()
	b.ColRetransSyn.Reset()
	b.ColRetransSynack.Reset()
	b.ColL7ClientError.Reset()
	b.ColL7ServerError.Reset()
	b.ColL7ServerTimeout.Reset()
	b.ColL7Error.Reset()
	b.ColOooTx.Reset()
	b.ColOooRx.Reset()
	b.ColFinCount.Reset()
}

func (b *MetricsBlock) ToInput(input proto.Input) proto.Input {
	return append(input,
		proto.InputColumn{Name: ckdb.COLUMN_PACKET_TX, Data: &b.ColPacketTx},
		proto.InputColumn{Name: ckdb.COLUMN_PACKET_RX, Data: &b.ColPacketRx},
		proto.InputColumn{Name: ckdb.COLUMN_BYTE_TX, Data: &b.ColByteTx},
		proto.InputColumn{Name: ckdb.COLUMN_BYTE_RX, Data: &b.ColByteRx},
		proto.InputColumn{Name: ckdb.COLUMN_L3_BYTE_TX, Data: &b.ColL3ByteTx},
		proto.InputColumn{Name: ckdb.COLUMN_L3_BYTE_RX, Data: &b.ColL3ByteRx},
		proto.InputColumn{Name: ckdb.COLUMN_L4_BYTE_TX, Data: &b.ColL4ByteTx},
		proto.InputColumn{Name: ckdb.COLUMN_L4_BYTE_RX, Data: &b.ColL4ByteRx},
		proto.InputColumn{Name: ckdb.COLUMN_TOTAL_PACKET_TX, Data: &b.ColTotalPacketTx},
		proto.InputColumn{Name: ckdb.COLUMN_TOTAL_PACKET_RX, Data: &b.ColTotalPacketRx},
		proto.InputColumn{Name: ckdb.COLUMN_TOTAL_BYTE_TX, Data: &b.ColTotalByteTx},
		proto.InputColumn{Name: ckdb.COLUMN_TOTAL_BYTE_RX, Data: &b.ColTotalByteRx},
		proto.InputColumn{Name: ckdb.COLUMN_L7_REQUEST, Data: &b.ColL7Request},
		proto.InputColumn{Name: ckdb.COLUMN_L7_RESPONSE, Data: &b.ColL7Response},
		proto.InputColumn{Name: ckdb.COLUMN_L7_PARSE_FAILED, Data: &b.ColL7ParseFailed},
		proto.InputColumn{Name: ckdb.COLUMN_RTT, Data: &b.ColRtt},
		proto.InputColumn{Name: ckdb.COLUMN_RTT_CLIENT, Data: &b.ColRttClient},
		proto.InputColumn{Name: ckdb.COLUMN_RTT_SERVER, Data: &b.ColRttServer},
		proto.InputColumn{Name: ckdb.COLUMN_TLS_RTT, Data: &b.ColTlsRtt},
		proto.InputColumn{Name: ckdb.COLUMN_SRT_SUM, Data: &b.ColSrtSum},
		proto.InputColumn{Name: ckdb.COLUMN_ART_SUM, Data: &b.ColArtSum},
		proto.InputColumn{Name: ckdb.COLUMN_RRT_SUM, Data: &b.ColRrtSum},
		proto.InputColumn{Name: ckdb.COLUMN_CIT_SUM, Data: &b.ColCitSum},
		proto.InputColumn{Name: ckdb.COLUMN_SRT_COUNT, Data: &b.ColSrtCount},
		proto.InputColumn{Name: ckdb.COLUMN_ART_COUNT, Data: &b.ColArtCount},
		proto.InputColumn{Name: ckdb.COLUMN_RRT_COUNT, Data: &b.ColRrtCount},
		proto.InputColumn{Name: ckdb.COLUMN_CIT_COUNT, Data: &b.ColCitCount},
		proto.InputColumn{Name: ckdb.COLUMN_SRT_MAX, Data: &b.ColSrtMax},
		proto.InputColumn{Name: ckdb.COLUMN_ART_MAX, Data: &b.ColArtMax},
		proto.InputColumn{Name: ckdb.COLUMN_RRT_MAX, Data: &b.ColRrtMax},
		proto.InputColumn{Name: ckdb.COLUMN_CIT_MAX, Data: &b.ColCitMax},
		proto.InputColumn{Name: ckdb.COLUMN_RETRANS_TX, Data: &b.ColRetransTx},
		proto.InputColumn{Name: ckdb.COLUMN_RETRANS_RX, Data: &b.ColRetransRx},
		proto.InputColumn{Name: ckdb.COLUMN_ZERO_WIN_TX, Data: &b.ColZeroWinTx},
		proto.InputColumn{Name: ckdb.COLUMN_ZERO_WIN_RX, Data: &b.ColZeroWinRx},
		proto.InputColumn{Name: ckdb.COLUMN_SYN_COUNT, Data: &b.ColSynCount},
		proto.InputColumn{Name: ckdb.COLUMN_SYNACK_COUNT, Data: &b.ColSynackCount},
		proto.InputColumn{Name: ckdb.COLUMN_RETRANS_SYN, Data: &b.ColRetransSyn},
		proto.InputColumn{Name: ckdb.COLUMN_RETRANS_SYNACK, Data: &b.ColRetransSynack},
		proto.InputColumn{Name: ckdb.COLUMN_L7_CLIENT_ERROR, Data: &b.ColL7ClientError},
		proto.InputColumn{Name: ckdb.COLUMN_L7_SERVER_ERROR, Data: &b.ColL7ServerError},
		proto.InputColumn{Name: ckdb.COLUMN_L7_SERVER_TIMEOUT, Data: &b.ColL7ServerTimeout},
		proto.InputColumn{Name: ckdb.COLUMN_L7_ERROR, Data: &b.ColL7Error},
		proto.InputColumn{Name: ckdb.COLUMN_OOO_RX, Data: &b.ColOooRx},
		proto.InputColumn{Name: ckdb.COLUMN_OOO_TX, Data: &b.ColOooTx},
		proto.InputColumn{Name: ckdb.COLUMN_FIN_COUNT, Data: &b.ColFinCount},
	)
}

func (n *Metrics) NewColumnBlock() ckdb.CKColumnBlock {
	return &MetricsBlock{}
}

func (n *Metrics) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*MetricsBlock)
	block.ColPacketTx.Append(n.PacketTx)
	block.ColPacketRx.Append(n.PacketRx)
	block.ColByteTx.Append(n.ByteTx)
	block.ColByteRx.Append(n.ByteRx)
	block.ColL3ByteTx.Append(n.L3ByteTx)
	block.ColL3ByteRx.Append(n.L3ByteRx)
	block.ColL4ByteTx.Append(n.L4ByteTx)
	block.ColL4ByteRx.Append(n.L4ByteRx)
	block.ColTotalPacketTx.Append(n.TotalPacketTx)
	block.ColTotalPacketRx.Append(n.TotalPacketRx)
	block.ColTotalByteTx.Append(n.TotalByteTx)
	block.ColTotalByteRx.Append(n.TotalByteRx)
	block.ColL7Request.Append(n.L7Request)
	block.ColL7Response.Append(n.L7Response)
	block.ColL7ParseFailed.Append(n.L7ParseFailed)
	block.ColRtt.Append(float64(n.RTT))
	block.ColRttClient.Append(float64(n.RTTClient))
	block.ColRttServer.Append(float64(n.RTTServer))
	block.ColTlsRtt.Append(float64(n.TLSRTT))
	block.ColSrtSum.Append(float64(n.SRTSum))
	block.ColArtSum.Append(float64(n.ARTSum))
	block.ColRrtSum.Append(float64(n.RRTSum))
	block.ColCitSum.Append(float64(n.CITSum))
	block.ColSrtCount.Append(uint64(n.SRTCount))
	block.ColArtCount.Append(uint64(n.ARTCount))
	block.ColRrtCount.Append(uint64(n.RRTCount))
	block.ColCitCount.Append(uint64(n.CITCount))
	block.ColSrtMax.Append(n.SRTMax)
	block.ColArtMax.Append(n.ARTMax)
	block.ColRrtMax.Append(n.RRTMax)
	block.ColCitMax.Append(n.CITMax)
	block.ColRetransTx.Append(n.RetransTx)
	block.ColRetransRx.Append(n.RetransRx)
	block.ColZeroWinTx.Append(n.ZeroWinTx)
	block.ColZeroWinRx.Append(n.ZeroWinRx)
	block.ColSynCount.Append(n.SynCount)
	block.ColSynackCount.Append(n.SynackCount)
	block.ColRetransSyn.Append(n.RetransSyn)
	block.ColRetransSynack.Append(n.RetransSynack)
	block.ColL7ClientError.Append(n.L7ClientError)
	block.ColL7ServerError.Append(n.L7ServerError)
	block.ColL7ServerTimeout.Append(n.L7ServerTimeout)
	block.ColL7Error.Append(n.L7Error)
	block.ColOooTx.Append(n.OooTx)
	block.ColOooRx.Append(n.OooRx)
	block.ColFinCount.Append(n.FinCount)
}

type L4FlowLogBlock struct {
	Col_id proto.ColUInt64
	*DataLinkLayerBlock
	*NetworkLayerBlock
	*TransportLayerBlock
	*ApplicationLayerBlock
	*InternetBlock
	*KnowledgeGraphBlock
	*FlowInfoBlock
	*MetricsBlock
}

func (b *L4FlowLogBlock) Reset() {
	b.Col_id.Reset()
	b.DataLinkLayerBlock.Reset()
	b.NetworkLayerBlock.Reset()
	b.TransportLayerBlock.Reset()
	b.ApplicationLayerBlock.Reset()
	b.InternetBlock.Reset()
	b.KnowledgeGraphBlock.Reset()
	b.FlowInfoBlock.Reset()
	b.MetricsBlock.Reset()
}

func (b *L4FlowLogBlock) ToInput(input proto.Input) proto.Input {
	input = append(input, proto.InputColumn{Name: ckdb.COLUMN__ID, Data: &b.Col_id})
	input = b.DataLinkLayerBlock.ToInput(input)
	input = b.NetworkLayerBlock.ToInput(input)
	input = b.TransportLayerBlock.ToInput(input)
	input = b.ApplicationLayerBlock.ToInput(input)
	input = b.InternetBlock.ToInput(input)
	input = b.KnowledgeGraphBlock.ToInput(input)
	input = b.FlowInfoBlock.ToInput(input)
	input = b.MetricsBlock.ToInput(input)
	return input
}

func (n *L4FlowLog) NewColumnBlock() ckdb.CKColumnBlock {
	return &L4FlowLogBlock{
		DataLinkLayerBlock:    n.DataLinkLayer.NewColumnBlock().(*DataLinkLayerBlock),
		NetworkLayerBlock:     n.NetworkLayer.NewColumnBlock().(*NetworkLayerBlock),
		TransportLayerBlock:   n.TransportLayer.NewColumnBlock().(*TransportLayerBlock),
		ApplicationLayerBlock: n.ApplicationLayer.NewColumnBlock().(*ApplicationLayerBlock),
		InternetBlock:         n.Internet.NewColumnBlock().(*InternetBlock),
		KnowledgeGraphBlock:   n.KnowledgeGraph.NewColumnBlock().(*KnowledgeGraphBlock),
		FlowInfoBlock:         n.FlowInfo.NewColumnBlock().(*FlowInfoBlock),
		MetricsBlock:          n.Metrics.NewColumnBlock().(*MetricsBlock),
	}
}

func (f *L4FlowLog) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*L4FlowLogBlock)
	block.Col_id.Append(f._id)
	f.DataLinkLayer.AppendToColumnBlock(block.DataLinkLayerBlock)
	f.NetworkLayer.AppendToColumnBlock(block.NetworkLayerBlock)
	f.TransportLayer.AppendToColumnBlock(block.TransportLayerBlock)
	f.ApplicationLayer.AppendToColumnBlock(block.ApplicationLayerBlock)
	f.Internet.AppendToColumnBlock(block.InternetBlock)
	f.KnowledgeGraph.AppendToColumnBlock(block.KnowledgeGraphBlock)
	f.FlowInfo.AppendToColumnBlock(block.FlowInfoBlock)
	f.Metrics.AppendToColumnBlock(block.MetricsBlock)
}
