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

package log_data

import (
	"fmt"
	"math"
	"net"
	"sync/atomic"
	"time"

	"github.com/google/gopacket/layers"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/geo"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/datatype/pb"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/pool"
	"github.com/deepflowio/deepflow/server/libs/utils"
	"github.com/deepflowio/deepflow/server/libs/zerodoc"
)

const (
	US_TO_S_DEVISOR = 1000000 // 微秒转化为秒的除数
)

type L4FlowLog struct {
	pool.ReferenceCount
	_id uint64 // 用来标记全局(多节点)唯一的记录

	DataLinkLayer
	NetworkLayer
	TransportLayer
	ApplicationLayer
	Internet
	KnowledgeGraph
	FlowInfo
	Metrics
}

type DataLinkLayer struct {
	MAC0    uint64 `json:"mac_0"`
	MAC1    uint64 `json:"mac_1"`
	EthType uint16 `json:"eth_type"`
	VLAN    uint16 `json:"vlan,omitempty"`
}

var DataLinkLayerColumns = []*ckdb.Column{
	ckdb.NewColumn("mac_0", ckdb.UInt64),
	ckdb.NewColumn("mac_1", ckdb.UInt64),
	ckdb.NewColumn("eth_type", ckdb.UInt16).SetIndex(ckdb.IndexSet),
	ckdb.NewColumn("vlan", ckdb.UInt16).SetIndex(ckdb.IndexSet),
}

func (f *DataLinkLayer) WriteBlock(block *ckdb.Block) {
	block.Write(
		f.MAC0,
		f.MAC1,
		f.EthType,
		f.VLAN)
}

type NetworkLayer struct {
	IP40         uint32 `json:"ip4_0"`
	IP41         uint32 `json:"ip4_1"`
	IP60         net.IP `json:"ip6_0"`
	IP61         net.IP `json:"ip6_1"`
	IsIPv4       bool   `json:"is_ipv4"`
	Protocol     uint8  `json:"protocol"`
	TunnelTier   uint8  `json:"tunnel_tier,omitempty"`
	TunnelType   uint16 `json:"tunnel_type,omitempty"`
	TunnelTxID   uint32 `json:"tunnel_tx_id,omitempty"`
	TunnelRxID   uint32 `json:"tunnel_rx_id,omitempty"`
	TunnelTxIP40 uint32 `json:"tunnel_tx_ip4_0,omitempty"`
	TunnelTxIP41 uint32 `json:"tunnel_tx_ip4_1,omitempty"`
	TunnelRxIP40 uint32 `json:"tunnel_rx_ip4_0,omitempty"`
	TunnelRxIP41 uint32 `json:"tunnel_rx_ip4_1,omitempty"`
	TunnelTxIP60 net.IP `json:"tunnel_tx_ip6_0,omitempty"`
	TunnelTxIP61 net.IP `json:"tunnel_tx_ip6_1,omitempty"`
	TunnelRxIP60 net.IP `json:"tunnel_rx_ip6_0,omitempty"`
	TunnelRxIP61 net.IP `json:"tunnel_rx_ip6_1,omitempty"`
	TunnelIsIPv4 bool   `json:"tunnel_is_ipv4"`
	TunnelTxMac0 uint32 `json:"tunnel_tx_mac_0,omitempty"`
	TunnelTxMac1 uint32 `json:"tunnel_tx_mac_1,omitempty"`
	TunnelRxMac0 uint32 `json:"tunnel_rx_mac_0,omitempty"`
	TunnelRxMac1 uint32 `json:"tunnel_rx_mac_1,omitempty"`
}

var NetworkLayerColumns = []*ckdb.Column{
	ckdb.NewColumn("ip4_0", ckdb.IPv4),
	ckdb.NewColumn("ip4_1", ckdb.IPv4),
	ckdb.NewColumn("ip6_0", ckdb.IPv6),
	ckdb.NewColumn("ip6_1", ckdb.IPv6),
	ckdb.NewColumn("is_ipv4", ckdb.UInt8).SetIndex(ckdb.IndexMinmax),
	ckdb.NewColumn("protocol", ckdb.UInt8),
	ckdb.NewColumn("tunnel_tier", ckdb.UInt8),
	ckdb.NewColumn("tunnel_type", ckdb.UInt16),
	ckdb.NewColumn("tunnel_tx_id", ckdb.UInt32),
	ckdb.NewColumn("tunnel_rx_id", ckdb.UInt32),
	ckdb.NewColumn("tunnel_tx_ip4_0", ckdb.IPv4),
	ckdb.NewColumn("tunnel_tx_ip4_1", ckdb.IPv4),
	ckdb.NewColumn("tunnel_rx_ip4_0", ckdb.IPv4),
	ckdb.NewColumn("tunnel_rx_ip4_1", ckdb.IPv4),
	ckdb.NewColumn("tunnel_tx_ip6_0", ckdb.IPv6),
	ckdb.NewColumn("tunnel_tx_ip6_1", ckdb.IPv6),
	ckdb.NewColumn("tunnel_rx_ip6_0", ckdb.IPv6),
	ckdb.NewColumn("tunnel_rx_ip6_1", ckdb.IPv6),
	ckdb.NewColumn("tunnel_is_ipv4", ckdb.UInt8).SetIndex(ckdb.IndexMinmax),
	ckdb.NewColumn("tunnel_tx_mac_0", ckdb.UInt32),
	ckdb.NewColumn("tunnel_tx_mac_1", ckdb.UInt32),
	ckdb.NewColumn("tunnel_rx_mac_0", ckdb.UInt32),
	ckdb.NewColumn("tunnel_rx_mac_1", ckdb.UInt32),
}

func (n *NetworkLayer) WriteBlock(block *ckdb.Block) {
	block.WriteIPv4(n.IP40)
	block.WriteIPv4(n.IP41)
	block.WriteIPv6(n.IP60)
	block.WriteIPv6(n.IP61)
	block.WriteBool(n.IsIPv4)

	block.Write(
		n.Protocol,
		n.TunnelTier,
		n.TunnelType,
		n.TunnelTxID,
		n.TunnelRxID)

	block.WriteIPv4(n.TunnelTxIP40)
	block.WriteIPv4(n.TunnelTxIP41)
	block.WriteIPv4(n.TunnelRxIP40)
	block.WriteIPv4(n.TunnelRxIP41)

	block.WriteIPv6(n.TunnelTxIP60)
	block.WriteIPv6(n.TunnelTxIP61)
	block.WriteIPv6(n.TunnelRxIP60)
	block.WriteIPv6(n.TunnelRxIP61)
	block.WriteBool(n.TunnelIsIPv4)

	block.Write(
		n.TunnelTxMac0,
		n.TunnelTxMac1,
		n.TunnelRxMac0,
		n.TunnelRxMac1)
}

type TransportLayer struct {
	ClientPort       uint16 `json:"client_port"`
	ServerPort       uint16 `json:"server_port"`
	TCPFlagsBit0     uint16 `json:"tcp_flags_bit_0,omitempty"`
	TCPFlagsBit1     uint16 `json:"tcp_flags_bit_1,omitempty"`
	SynSeq           uint32 `json:"syn_seq"`
	SynAckSeq        uint32 `json:"syn_ack_seq"`
	LastKeepaliveSeq uint32 `json:"last_keepalive_seq"`
	LastKeepaliveAck uint32 `json:"last_keepalive_ack"`
}

var TransportLayerColumns = []*ckdb.Column{
	// 传输层
	ckdb.NewColumn("client_port", ckdb.UInt16),
	ckdb.NewColumn("server_port", ckdb.UInt16).SetIndex(ckdb.IndexSet),
	ckdb.NewColumn("tcp_flags_bit_0", ckdb.UInt16).SetIndex(ckdb.IndexNone),
	ckdb.NewColumn("tcp_flags_bit_1", ckdb.UInt16).SetIndex(ckdb.IndexNone),
	ckdb.NewColumn("syn_seq", ckdb.UInt32).SetComment("握手包的TCP SEQ序列号"),
	ckdb.NewColumn("syn_ack_seq", ckdb.UInt32).SetComment("握手回应包的TCP SEQ序列号"),
	ckdb.NewColumn("last_keepalive_seq", ckdb.UInt32),
	ckdb.NewColumn("last_keepalive_ack", ckdb.UInt32),
}

func (t *TransportLayer) WriteBlock(block *ckdb.Block) {
	block.Write(
		t.ClientPort,
		t.ServerPort,
		t.TCPFlagsBit0,
		t.TCPFlagsBit1,
		t.SynSeq,
		t.SynAckSeq,
		t.LastKeepaliveSeq,
		t.LastKeepaliveAck)
}

type ApplicationLayer struct {
	L7Protocol uint8 `json:"l7_protocol,omitempty"` // HTTP, DNS, others
}

var ApplicationLayerColumns = []*ckdb.Column{
	// 应用层
	ckdb.NewColumn("l7_protocol", ckdb.UInt8).SetIndex(ckdb.IndexMinmax),
}

func (a *ApplicationLayer) WriteBlock(block *ckdb.Block) {
	block.Write(a.L7Protocol)
}

type Internet struct {
	Province0 string `json:"province_0"`
	Province1 string `json:"province_1"`
}

var InternetColumns = []*ckdb.Column{
	// 广域网
	ckdb.NewColumn("province_0", ckdb.LowCardinalityString),
	ckdb.NewColumn("province_1", ckdb.LowCardinalityString),
}

func (i *Internet) WriteBlock(block *ckdb.Block) {
	block.Write(i.Province0, i.Province1)
}

type KnowledgeGraph struct {
	RegionID0     uint16 `json:"region_id_0"`
	RegionID1     uint16 `json:"region_id_1"`
	AZID0         uint16 `json:"az_id_0"`
	AZID1         uint16 `json:"az_id_1"`
	HostID0       uint16 `json:"host_id_0"`
	HostID1       uint16 `json:"host_id_1"`
	L3DeviceType0 uint8  `json:"l3_device_type_0"`
	L3DeviceType1 uint8  `json:"l3_device_type_1"`
	L3DeviceID0   uint32 `json:"l3_device_id_0"`
	L3DeviceID1   uint32 `json:"l3_device_id_1"`
	PodNodeID0    uint32 `json:"pod_node_id_0"`
	PodNodeID1    uint32 `json:"pod_node_id_1"`
	PodNSID0      uint16 `json:"pod_ns_id_0"`
	PodNSID1      uint16 `json:"pod_ns_id_1"`
	PodGroupID0   uint32 `json:"pod_group_id_0"`
	PodGroupID1   uint32 `json:"pod_group_id_1"`
	PodGroupType0 uint8  `json:"pod_group_type_0"` // no need to store
	PodGroupType1 uint8  `json:"pod_group_type_1"` // no need to store
	PodID0        uint32 `json:"pod_id_0"`
	PodID1        uint32 `json:"pod_id_1"`
	PodClusterID0 uint16 `json:"pod_cluster_id_0"`
	PodClusterID1 uint16 `json:"pod_cluster_id_1"`
	L3EpcID0      int32  `json:"l3_epc_id_0"`
	L3EpcID1      int32  `json:"l3_epc_id_1"`
	EpcID0        int32  `json:"epc_id_0"`
	EpcID1        int32  `json:"epc_id_1"`
	SubnetID0     uint16 `json:"subnet_id_0"`
	SubnetID1     uint16 `json:"subnet_id_1"`
	ServiceID0    uint32 `json:"service_id_0"`
	ServiceID1    uint32 `json:"service_id_1"`

	AutoInstanceID0   uint32
	AutoInstanceType0 uint8
	AutoServiceID0    uint32
	AutoServiceType0  uint8

	AutoInstanceID1   uint32
	AutoInstanceType1 uint8
	AutoServiceID1    uint32
	AutoServiceType1  uint8

	TagSource0 uint8
	TagSource1 uint8
}

var KnowledgeGraphColumns = []*ckdb.Column{
	// 知识图谱
	ckdb.NewColumn("region_id_0", ckdb.UInt16),
	ckdb.NewColumn("region_id_1", ckdb.UInt16),
	ckdb.NewColumn("az_id_0", ckdb.UInt16),
	ckdb.NewColumn("az_id_1", ckdb.UInt16),
	ckdb.NewColumn("host_id_0", ckdb.UInt16),
	ckdb.NewColumn("host_id_1", ckdb.UInt16),
	ckdb.NewColumn("l3_device_type_0", ckdb.UInt8),
	ckdb.NewColumn("l3_device_type_1", ckdb.UInt8),
	ckdb.NewColumn("l3_device_id_0", ckdb.UInt32),
	ckdb.NewColumn("l3_device_id_1", ckdb.UInt32),
	ckdb.NewColumn("pod_node_id_0", ckdb.UInt32),
	ckdb.NewColumn("pod_node_id_1", ckdb.UInt32),
	ckdb.NewColumn("pod_ns_id_0", ckdb.UInt16),
	ckdb.NewColumn("pod_ns_id_1", ckdb.UInt16),
	ckdb.NewColumn("pod_group_id_0", ckdb.UInt32),
	ckdb.NewColumn("pod_group_id_1", ckdb.UInt32),
	ckdb.NewColumn("pod_id_0", ckdb.UInt32),
	ckdb.NewColumn("pod_id_1", ckdb.UInt32),
	ckdb.NewColumn("pod_cluster_id_0", ckdb.UInt16),
	ckdb.NewColumn("pod_cluster_id_1", ckdb.UInt16),
	ckdb.NewColumn("l3_epc_id_0", ckdb.Int32),
	ckdb.NewColumn("l3_epc_id_1", ckdb.Int32),
	ckdb.NewColumn("epc_id_0", ckdb.Int32),
	ckdb.NewColumn("epc_id_1", ckdb.Int32),
	ckdb.NewColumn("subnet_id_0", ckdb.UInt16),
	ckdb.NewColumn("subnet_id_1", ckdb.UInt16),
	ckdb.NewColumn("service_id_0", ckdb.UInt32),
	ckdb.NewColumn("service_id_1", ckdb.UInt32),

	ckdb.NewColumn("auto_instance_id_0", ckdb.UInt32),
	ckdb.NewColumn("auto_instance_type_0", ckdb.UInt8),
	ckdb.NewColumn("auto_service_id_0", ckdb.UInt32),
	ckdb.NewColumn("auto_service_type_0", ckdb.UInt8),

	ckdb.NewColumn("auto_instance_id_1", ckdb.UInt32),
	ckdb.NewColumn("auto_instance_type_1", ckdb.UInt8),
	ckdb.NewColumn("auto_service_id_1", ckdb.UInt32),
	ckdb.NewColumn("auto_service_type_1", ckdb.UInt8),

	ckdb.NewColumn("tag_source_0", ckdb.UInt8),
	ckdb.NewColumn("tag_source_1", ckdb.UInt8),
}

func (k *KnowledgeGraph) WriteBlock(block *ckdb.Block) {
	block.Write(
		k.RegionID0,
		k.RegionID1,
		k.AZID0,
		k.AZID1,
		k.HostID0,
		k.HostID1,
		k.L3DeviceType0,
		k.L3DeviceType1,
		k.L3DeviceID0,
		k.L3DeviceID1,
		k.PodNodeID0,
		k.PodNodeID1,
		k.PodNSID0,
		k.PodNSID1,
		k.PodGroupID0,
		k.PodGroupID1,
		k.PodID0,
		k.PodID1,
		k.PodClusterID0,
		k.PodClusterID1,
		k.L3EpcID0,
		k.L3EpcID1,
		k.EpcID0,
		k.EpcID1,
		k.SubnetID0,
		k.SubnetID1,
		k.ServiceID0,
		k.ServiceID1,

		k.AutoInstanceID0,
		k.AutoInstanceType0,
		k.AutoServiceID0,
		k.AutoServiceType0,

		k.AutoInstanceID1,
		k.AutoInstanceType1,
		k.AutoServiceID1,
		k.AutoServiceType1,

		k.TagSource0,
		k.TagSource1,
	)
}

type FlowInfo struct {
	CloseType    uint16 `json:"close_type"`
	SignalSource uint16 `json:"signal_source"`
	FlowID       uint64 `json:"flow_id"`
	TapType      uint16 `json:"tap_type"`
	NatSource    uint8  `json:"nat_source"`
	TapPortType  uint8  `json:"tap_port_type"` // 0: MAC, 1: IPv4, 2:IPv6, 3: ID
	TapPort      uint32 `json:"tap_port"`
	TapSide      string `json:"tap_side"`
	VtapID       uint16 `json:"vtap_id"`
	L2End0       bool   `json:"l2_end_0"`
	L2End1       bool   `json:"l2_end_1"`
	L3End0       bool   `json:"l3_end_0"`
	L3End1       bool   `json:"l3_end_1"`
	StartTime    int64  `json:"start_time"` // us
	EndTime      int64  `json:"end_time"`   // us
	Duration     uint64 `json:"duration"`   // us
	IsNewFlow    uint8  `json:"is_new_flow"`
	Status       uint8  `json:"status"`
	AclGids      []uint16
	GPID0        uint32
	GPID1        uint32

	NatRealIP0   uint32
	NatRealIP1   uint32
	NatRealPort0 uint16
	NatRealPort1 uint16

	DirectionScore uint8
}

var FlowInfoColumns = []*ckdb.Column{
	// 流信息
	ckdb.NewColumn("time", ckdb.DateTime).SetComment("精度: 秒，等同end_time的秒精度"),
	ckdb.NewColumn("close_type", ckdb.UInt16).SetIndex(ckdb.IndexSet),
	ckdb.NewColumn("signal_source", ckdb.UInt16),
	ckdb.NewColumn("flow_id", ckdb.UInt64).SetIndex(ckdb.IndexMinmax),
	ckdb.NewColumn("tap_type", ckdb.UInt16),
	ckdb.NewColumn("nat_source", ckdb.UInt8),
	ckdb.NewColumn("tap_port_type", ckdb.UInt8),
	ckdb.NewColumn("tap_port", ckdb.UInt32),
	ckdb.NewColumn("tap_side", ckdb.LowCardinalityString),
	ckdb.NewColumn("vtap_id", ckdb.UInt16).SetIndex(ckdb.IndexSet),
	ckdb.NewColumn("l2_end_0", ckdb.UInt8).SetIndex(ckdb.IndexNone),
	ckdb.NewColumn("l2_end_1", ckdb.UInt8).SetIndex(ckdb.IndexNone),
	ckdb.NewColumn("l3_end_0", ckdb.UInt8).SetIndex(ckdb.IndexNone),
	ckdb.NewColumn("l3_end_1", ckdb.UInt8).SetIndex(ckdb.IndexNone),
	ckdb.NewColumn("start_time", ckdb.DateTime64us).SetComment("精度: 微秒"),
	ckdb.NewColumn("end_time", ckdb.DateTime64us).SetComment("精度: 微秒"),
	ckdb.NewColumn("duration", ckdb.UInt64).SetComment("单位: 微秒"),
	ckdb.NewColumn("is_new_flow", ckdb.UInt8),
	ckdb.NewColumn("status", ckdb.UInt8).SetComment("状态 0:正常, 1:异常 ,2:不存在，3:服务端异常, 4:客户端异常"),
	ckdb.NewColumn("acl_gids", ckdb.ArrayUInt16),
	ckdb.NewColumn("gprocess_id_0", ckdb.UInt32),
	ckdb.NewColumn("gprocess_id_1", ckdb.UInt32),
	ckdb.NewColumn("nat_real_ip4_0", ckdb.IPv4),
	ckdb.NewColumn("nat_real_ip4_1", ckdb.IPv4),
	ckdb.NewColumn("nat_real_port_0", ckdb.UInt16),
	ckdb.NewColumn("nat_real_port_1", ckdb.UInt16),
	ckdb.NewColumn("direction_score", ckdb.UInt8).SetIndex(ckdb.IndexMinmax),
}

func (f *FlowInfo) WriteBlock(block *ckdb.Block) {
	block.WriteDateTime(uint32(f.EndTime / US_TO_S_DEVISOR))
	block.Write(
		f.CloseType,
		f.SignalSource,
		f.FlowID,
		f.TapType,
		f.NatSource,
		f.TapPortType,
		f.TapPort,
		f.TapSide,
		f.VtapID,
		f.L2End0,
		f.L2End1,
		f.L3End0,
		f.L3End1,
		f.StartTime,
		f.EndTime,

		f.Duration,
		f.IsNewFlow,
		f.Status,
		f.AclGids,
		f.GPID0,
		f.GPID1)

	block.WriteIPv4(f.NatRealIP0)
	block.WriteIPv4(f.NatRealIP1)
	block.Write(f.NatRealPort0, f.NatRealPort1, f.DirectionScore)
}

type Metrics struct {
	PacketTx      uint64 `json:"packet_tx,omitempty"`
	PacketRx      uint64 `json:"packet_rx,omitempty"`
	ByteTx        uint64 `json:"byte_tx,omitempty"`
	ByteRx        uint64 `json:"byte_rx,omitempty"`
	L3ByteTx      uint64 `json:"l3_byte_tx,omitempty"`
	L3ByteRx      uint64 `json:"l3_byte_rx,omitempty"`
	L4ByteTx      uint64 `json:"l4_byte_tx,omitempty"`
	L4ByteRx      uint64 `json:"l4_byte_rx,omitempty"`
	TotalPacketTx uint64 `json:"total_packet_tx,omitempty"`
	TotalPacketRx uint64 `json:"total_packet_rx,omitempty"`
	TotalByteTx   uint64 `json:"total_byte_tx,omitempty"`
	TotalByteRx   uint64 `json:"total_byte_rx,omitempty"`
	L7Request     uint32 `json:"l7_request,omitempty"`
	L7Response    uint32 `json:"l7_response,omitempty"`
	L7ParseFailed uint32 `json:"l7_parse_failed,omitempty"`

	RTT       uint32 `json:"rtt,omitempty"`         // us
	RTTClient uint32 `json:"rtt_client,omitempty"`  // us
	RTTServer uint32 `json:"rtt_server,omitempty"`  // us
	TLSRTT    uint32 `json:"tls_rtt_sum,omitempty"` // us

	SRTSum uint32 `json:"srt_sum,omitempty"`
	ARTSum uint32 `json:"art_sum,omitempty"`
	RRTSum uint64 `json:"rrt_sum,omitempty"`
	CITSum uint32 `json:"cit_sum,omitempty"`

	SRTCount uint32 `json:"srt_count,omitempty"`
	ARTCount uint32 `json:"art_count,omitempty"`
	RRTCount uint32 `json:"rrt_count,omitempty"`
	CITCount uint32 `json:"cit_count,omitempty"`

	SRTMax uint32 `json:"srt_max,omitempty"` // us
	ARTMax uint32 `json:"art_max,omitempty"` // us
	RRTMax uint32 `json:"rrt_max,omitempty"` // us
	CITMax uint32 `json:"cit_max,omitempty"` // us

	RetransTx       uint32 `json:"retrans_tx,omitempty"`
	RetransRx       uint32 `json:"retrans_rx,omitempty"`
	ZeroWinTx       uint32 `json:"zero_win_tx,omitempty"`
	ZeroWinRx       uint32 `json:"zero_win_rx,omitempty"`
	SynCount        uint32 `json:"syn_count,omitempty"`
	SynackCount     uint32 `json:"synack_count,omitempty"`
	RetransSyn      uint32 `json:"retrans_syn,omitempty"`
	RetransSynack   uint32 `json:"retrans_synack,omitempty"`
	L7ClientError   uint32 `json:"l7_client_error,omitempty"`
	L7ServerError   uint32 `json:"l7_server_error,omitempty"`
	L7ServerTimeout uint32 `json:"l7_server_timeout,omitempty"`
	L7Error         uint32 `json:"l7_error,omitempty"`
}

var MetricsColumns = []*ckdb.Column{
	// 指标量
	ckdb.NewColumn("packet_tx", ckdb.UInt64),
	ckdb.NewColumn("packet_rx", ckdb.UInt64),
	ckdb.NewColumn("byte_tx", ckdb.UInt64),
	ckdb.NewColumn("byte_rx", ckdb.UInt64),
	ckdb.NewColumn("l3_byte_tx", ckdb.UInt64),
	ckdb.NewColumn("l3_byte_rx", ckdb.UInt64),
	ckdb.NewColumn("l4_byte_tx", ckdb.UInt64),
	ckdb.NewColumn("l4_byte_rx", ckdb.UInt64),
	ckdb.NewColumn("total_packet_tx", ckdb.UInt64),
	ckdb.NewColumn("total_packet_rx", ckdb.UInt64),
	ckdb.NewColumn("total_byte_tx", ckdb.UInt64),
	ckdb.NewColumn("total_byte_rx", ckdb.UInt64),
	ckdb.NewColumn("l7_request", ckdb.UInt32),
	ckdb.NewColumn("l7_response", ckdb.UInt32),
	ckdb.NewColumn("l7_parse_failed", ckdb.UInt32),

	ckdb.NewColumn("rtt", ckdb.Float64).SetComment("单位: 微秒"),
	ckdb.NewColumn("rtt_client", ckdb.Float64).SetComment("单位: 微秒"),
	ckdb.NewColumn("rtt_server", ckdb.Float64).SetComment("单位: 微秒"),
	ckdb.NewColumn("tls_rtt", ckdb.Float64).SetComment("单位: 微秒"),

	ckdb.NewColumn("srt_sum", ckdb.Float64),
	ckdb.NewColumn("art_sum", ckdb.Float64),
	ckdb.NewColumn("rrt_sum", ckdb.Float64),
	ckdb.NewColumn("cit_sum", ckdb.Float64),

	ckdb.NewColumn("srt_count", ckdb.UInt64),
	ckdb.NewColumn("art_count", ckdb.UInt64),
	ckdb.NewColumn("rrt_count", ckdb.UInt64),
	ckdb.NewColumn("cit_count", ckdb.UInt64),

	ckdb.NewColumn("srt_max", ckdb.UInt32).SetComment("单位: 微秒"),
	ckdb.NewColumn("art_max", ckdb.UInt32).SetComment("单位: 微秒"),
	ckdb.NewColumn("rrt_max", ckdb.UInt32).SetComment("单位: 微秒"),
	ckdb.NewColumn("cit_max", ckdb.UInt32).SetComment("单位: 微秒"),

	ckdb.NewColumn("retrans_tx", ckdb.UInt32),
	ckdb.NewColumn("retrans_rx", ckdb.UInt32),
	ckdb.NewColumn("zero_win_tx", ckdb.UInt32),
	ckdb.NewColumn("zero_win_rx", ckdb.UInt32),
	ckdb.NewColumn("syn_count", ckdb.UInt32),
	ckdb.NewColumn("synack_count", ckdb.UInt32),
	ckdb.NewColumn("retrans_syn", ckdb.UInt32),
	ckdb.NewColumn("retrans_synack", ckdb.UInt32),
	ckdb.NewColumn("l7_client_error", ckdb.UInt32),
	ckdb.NewColumn("l7_server_error", ckdb.UInt32),
	ckdb.NewColumn("l7_server_timeout", ckdb.UInt32),
	ckdb.NewColumn("l7_error", ckdb.UInt32),
}

func (m *Metrics) WriteBlock(block *ckdb.Block) {
	block.Write(
		m.PacketTx,
		m.PacketRx,
		m.ByteTx,
		m.ByteRx,
		m.L3ByteTx,
		m.L3ByteRx,
		m.L4ByteTx,
		m.L4ByteRx,
		m.TotalPacketTx,
		m.TotalPacketRx,
		m.TotalByteTx,
		m.TotalByteRx,
		m.L7Request,
		m.L7Response,
		m.L7ParseFailed,

		float64(m.RTT),
		float64(m.RTTClient),
		float64(m.RTTServer),
		float64(m.TLSRTT),

		float64(m.SRTSum),
		float64(m.ARTSum),
		float64(m.RRTSum),
		float64(m.CITSum),

		uint64(m.SRTCount),
		uint64(m.ARTCount),
		uint64(m.RRTCount),
		uint64(m.CITCount),

		m.SRTMax,
		m.ARTMax,
		m.RRTMax,
		m.CITMax,

		m.RetransTx,
		m.RetransRx,
		m.ZeroWinTx,
		m.ZeroWinRx,
		m.SynCount,
		m.SynackCount,
		m.RetransSyn,
		m.RetransSynack,
		m.L7ClientError,
		m.L7ServerError,
		m.L7ServerTimeout,
		m.L7Error)
}

func parseUint32EpcID(v uint32) int32 {
	switch int16(v) {
	case datatype.EPC_FROM_DEEPFLOW:
		fallthrough
	case datatype.EPC_FROM_INTERNET:
		return int32(int16(v))
	}
	return int32(math.MaxUint16 & v)
}

func (d *DataLinkLayer) Fill(f *pb.Flow) {
	d.MAC0 = f.FlowKey.MacSrc
	d.MAC1 = f.FlowKey.MacDst
	d.EthType = uint16(f.EthType)
	d.VLAN = uint16(f.Vlan)
}

func cloneIP(src net.IP) net.IP {
	l := len(src)
	if l == 0 {
		return nil
	}
	dst := make([]byte, l)
	copy(dst, src)
	return dst
}

func (n *NetworkLayer) Fill(f *pb.Flow, isIPV6 bool) {
	// 广域网IP为0.0.0.0或::
	if isIPV6 {
		n.IsIPv4 = false
		n.IP60 = cloneIP(f.FlowKey.Ip6Src)
		n.IP61 = cloneIP(f.FlowKey.Ip6Dst)
	} else {
		n.IsIPv4 = true
		n.IP40 = f.FlowKey.IpSrc
		n.IP41 = f.FlowKey.IpDst
	}

	n.Protocol = uint8(f.FlowKey.Proto)
	if f.Tunnel.TunnelType != uint32(datatype.TUNNEL_TYPE_NONE) {
		n.TunnelTier = uint8(f.Tunnel.Tier)
		n.TunnelTxID = f.Tunnel.TxId
		n.TunnelRxID = f.Tunnel.RxId
		n.TunnelType = uint16(f.Tunnel.TunnelType)
		n.TunnelTxIP40 = f.Tunnel.TxIp0
		n.TunnelTxIP41 = f.Tunnel.TxIp1
		n.TunnelRxIP40 = f.Tunnel.RxIp0
		n.TunnelRxIP41 = f.Tunnel.RxIp1
		n.TunnelIsIPv4 = true
		n.TunnelTxMac0 = f.Tunnel.TxMac0
		n.TunnelTxMac1 = f.Tunnel.TxMac1
		n.TunnelRxMac0 = f.Tunnel.RxMac0
		n.TunnelRxMac1 = f.Tunnel.RxMac1
	}
}

func (t *TransportLayer) Fill(f *pb.Flow) {
	t.ClientPort = uint16(f.FlowKey.PortSrc)
	t.ServerPort = uint16(f.FlowKey.PortDst)
	t.TCPFlagsBit0 = uint16(f.MetricsPeerSrc.TcpFlags)
	t.TCPFlagsBit1 = uint16(f.MetricsPeerDst.TcpFlags)
	t.SynSeq = f.SynSeq
	t.SynAckSeq = f.SynackSeq
	t.LastKeepaliveSeq = f.LastKeepaliveSeq
	t.LastKeepaliveAck = f.LastKeepaliveAck
}

func (a *ApplicationLayer) Fill(f *pb.Flow) {
	if f.HasPerfStats == 1 {
		a.L7Protocol = uint8(f.PerfStats.L7Protocol)
	}
}

func (i *Internet) Fill(f *pb.Flow) {
	i.Province0 = geo.QueryProvince(f.FlowKey.IpSrc)
	i.Province1 = geo.QueryProvince(f.FlowKey.IpDst)
}

func isLocalIP(isIPv6 bool, ip4 uint32, ip6 net.IP) bool {
	ip := ip6
	if !isIPv6 {
		ip = utils.IpFromUint32(ip4)
	}
	return !ip.IsGlobalUnicast()
}

func (k *KnowledgeGraph) fill(
	platformData *grpc.PlatformInfoTable,
	isIPv6, isVipInterface0, isVipInterface1 bool,
	l3EpcID0, l3EpcID1 int32,
	ip40, ip41 uint32,
	ip60, ip61 net.IP,
	mac0, mac1 uint64,
	gpID0, gpID1 uint32,
	vtapId, podId0, podId1 uint32,
	port uint16,
	tapSide uint32,
	protocol layers.IPProtocol) {

	var info0, info1 *grpc.Info

	// 对于VIP的流量，需要使用MAC来匹配
	lookupByMac0, lookupByMac1 := isVipInterface0, isVipInterface1
	// 对于本地的流量，也需要使用MAC来匹配
	if tapSide == uint32(zerodoc.Local) {
		// for local non-unicast IPs, MAC matching is preferred.
		if isLocalIP(isIPv6, ip40, ip60) {
			lookupByMac0 = true
		}
		if isLocalIP(isIPv6, ip41, ip61) {
			lookupByMac1 = true
		}
	} else if tapSide == uint32(zerodoc.ClientProcess) || tapSide == uint32(zerodoc.ServerProcess) {
		// For ebpf traffic, if MAC is valid, MAC lookup is preferred
		if mac0 != 0 {
			lookupByMac0 = true
		}
		if mac1 != 0 {
			lookupByMac1 = true
		}
	}
	l3EpcMac0, l3EpcMac1 := mac0|uint64(l3EpcID0)<<48, mac1|uint64(l3EpcID1)<<48 // 使用l3EpcID和mac查找，防止跨AZ mac冲突

	if gpID0 != 0 && podId0 == 0 {
		vtapID, podId := platformData.QueryGprocessInfo(gpID0)
		if podId != 0 && vtapID == vtapId {
			podId0 = podId
			k.TagSource0 |= uint8(zerodoc.GpId)
		}
	}
	if gpID1 != 0 && podId1 == 0 {
		vtapID, podId := platformData.QueryGprocessInfo(gpID1)
		if podId != 0 && vtapID == vtapId {
			podId1 = podId
			k.TagSource1 |= uint8(zerodoc.GpId)
		}
	}

	// use podId to match first
	if podId0 != 0 {
		k.TagSource0 |= uint8(zerodoc.PodId)
		info0 = platformData.QueryPodIdInfo(podId0)
	}
	if podId1 != 0 {
		k.TagSource1 |= uint8(zerodoc.PodId)
		info1 = platformData.QueryPodIdInfo(podId1)
	}

	if info0 == nil {
		if lookupByMac0 {
			k.TagSource0 |= uint8(zerodoc.Mac)
			info0 = platformData.QueryMacInfo(l3EpcMac0)
		}
		if info0 == nil {
			k.TagSource0 |= uint8(zerodoc.EpcIP)
			info0 = common.RegetInfoFromIP(isIPv6, ip60, ip40, l3EpcID0, platformData)
		}
	}

	if info1 == nil {
		if lookupByMac1 {
			k.TagSource1 |= uint8(zerodoc.Mac)
			info1 = platformData.QueryMacInfo(l3EpcMac1)
		}
		if info1 == nil {
			k.TagSource1 |= uint8(zerodoc.EpcIP)
			info1 = common.RegetInfoFromIP(isIPv6, ip61, ip41, l3EpcID1, platformData)
		}
	}

	var l2Info0, l2Info1 *grpc.Info
	if l3EpcID0 > 0 && l3EpcID1 > 0 {
		l2Info0, l2Info1 = platformData.QueryMacInfosPair(l3EpcMac0, l3EpcMac1)
	} else if l3EpcID0 > 0 {
		l2Info0 = platformData.QueryMacInfo(l3EpcMac0)
	} else if l3EpcID1 > 0 {
		l2Info1 = platformData.QueryMacInfo(l3EpcMac1)
	}

	if info0 != nil {
		k.RegionID0 = uint16(info0.RegionID)
		k.AZID0 = uint16(info0.AZID)
		k.HostID0 = uint16(info0.HostID)
		k.L3DeviceType0 = uint8(info0.DeviceType)
		k.L3DeviceID0 = info0.DeviceID
		k.PodNodeID0 = info0.PodNodeID
		k.PodNSID0 = uint16(info0.PodNSID)
		k.PodGroupID0 = info0.PodGroupID
		k.PodGroupType0 = info0.PodGroupType
		k.PodID0 = info0.PodID
		k.PodClusterID0 = uint16(info0.PodClusterID)
		k.SubnetID0 = uint16(info0.SubnetID)
	}
	if info1 != nil {
		k.RegionID1 = uint16(info1.RegionID)
		k.AZID1 = uint16(info1.AZID)
		k.HostID1 = uint16(info1.HostID)
		k.L3DeviceType1 = uint8(info1.DeviceType)
		k.L3DeviceID1 = info1.DeviceID
		k.PodNodeID1 = info1.PodNodeID
		k.PodNSID1 = uint16(info1.PodNSID)
		k.PodGroupID1 = info1.PodGroupID
		k.PodGroupType1 = info1.PodGroupType
		k.PodID1 = info1.PodID
		k.PodClusterID1 = uint16(info1.PodClusterID)
		k.SubnetID1 = uint16(info1.SubnetID)
	}
	k.L3EpcID0, k.L3EpcID1 = l3EpcID0, l3EpcID1
	if l2Info0 != nil {
		k.EpcID0 = l2Info0.L2EpcID
	}
	if l2Info1 != nil {
		k.EpcID1 = l2Info1.L2EpcID
	}

	// 0端如果是clusterIP或后端podIP需要匹配service_id
	if common.IsPodServiceIP(zerodoc.DeviceType(k.L3DeviceType0), k.PodID0, 0) {
		k.ServiceID0 = platformData.QueryService(k.PodID0, k.PodNodeID0, uint32(k.PodClusterID0), k.PodGroupID0, l3EpcID0, isIPv6, ip40, ip60, protocol, 0)
	}
	if common.IsPodServiceIP(zerodoc.DeviceType(k.L3DeviceType1), k.PodID1, k.PodNodeID1) {
		k.ServiceID1 = platformData.QueryService(k.PodID1, k.PodNodeID1, uint32(k.PodClusterID1), k.PodGroupID1, l3EpcID1, isIPv6, ip41, ip61, protocol, port)
	}

	k.AutoInstanceID0, k.AutoInstanceType0 = common.GetAutoInstance(k.PodID0, gpID0, k.PodNodeID0, k.L3DeviceID0, k.L3DeviceType0, k.L3EpcID0)
	k.AutoServiceID0, k.AutoServiceType0 = common.GetAutoService(k.ServiceID0, k.PodGroupID0, gpID0, k.PodNodeID0, k.L3DeviceID0, k.L3DeviceType0, k.PodGroupType0, k.L3EpcID0)

	k.AutoInstanceID1, k.AutoInstanceType1 = common.GetAutoInstance(k.PodID1, gpID1, k.PodNodeID1, k.L3DeviceID1, k.L3DeviceType1, k.L3EpcID1)
	k.AutoServiceID1, k.AutoServiceType1 = common.GetAutoService(k.ServiceID1, k.PodGroupID1, gpID1, k.PodNodeID1, k.L3DeviceID1, k.L3DeviceType1, k.PodGroupType1, k.L3EpcID1)
}

func (k *KnowledgeGraph) FillL4(f *pb.Flow, isIPv6 bool, platformData *grpc.PlatformInfoTable) {
	k.fill(platformData,
		isIPv6, f.MetricsPeerSrc.IsVipInterface == 1, f.MetricsPeerDst.IsVipInterface == 1,
		// The range of EPC ID is [-2,65533], if EPC ID < -2 needs to be transformed into the range.
		zerodoc.MarshalInt32WithSpecialID(f.MetricsPeerSrc.L3EpcId), zerodoc.MarshalInt32WithSpecialID(f.MetricsPeerDst.L3EpcId),
		f.FlowKey.IpSrc, f.FlowKey.IpDst,
		f.FlowKey.Ip6Src, f.FlowKey.Ip6Dst,
		f.FlowKey.MacSrc, f.FlowKey.MacDst,
		f.MetricsPeerSrc.Gpid, f.MetricsPeerDst.Gpid,
		f.FlowKey.VtapId, 0, 0,
		uint16(f.FlowKey.PortDst),
		f.TapSide,
		layers.IPProtocol(f.FlowKey.Proto))
}

func getStatus(t datatype.CloseType, p layers.IPProtocol) datatype.LogMessageStatus {
	if t == datatype.CloseTypeTCPFin || t == datatype.CloseTypeForcedReport || t == datatype.CloseTypeTCPFinClientRst ||
		(p != layers.IPProtocolTCP && t == datatype.CloseTypeTimeout) {
		return datatype.STATUS_OK
	} else if t.IsClientError() {
		return datatype.STATUS_CLIENT_ERROR
	} else if p == layers.IPProtocolTCP && t.IsServerError() {
		return datatype.STATUS_SERVER_ERROR
	} else {
		return datatype.STATUS_NOT_EXIST
	}
}

func (i *FlowInfo) Fill(f *pb.Flow) {
	i.CloseType = uint16(f.CloseType)
	i.SignalSource = uint16(f.SignalSource)
	i.FlowID = f.FlowId
	i.TapType = uint16(f.FlowKey.TapType)
	var natSource datatype.NATSource
	i.TapPort, i.TapPortType, natSource, _ = datatype.TapPort(f.FlowKey.TapPort).SplitToPortTypeTunnel()
	i.NatSource = uint8(natSource)
	i.TapSide = zerodoc.TAPSideEnum(f.TapSide).String()
	i.VtapID = uint16(f.FlowKey.VtapId)

	i.L2End0 = f.MetricsPeerSrc.IsL2End == 1
	i.L2End1 = f.MetricsPeerDst.IsL2End == 1
	i.L3End0 = f.MetricsPeerSrc.IsL3End == 1
	i.L3End1 = f.MetricsPeerDst.IsL3End == 1

	i.StartTime = int64(f.StartTime) / int64(time.Microsecond)
	i.EndTime = int64(f.EndTime) / int64(time.Microsecond)
	i.Duration = f.Duration / uint64(time.Microsecond)
	i.IsNewFlow = uint8(f.IsNewFlow)
	i.Status = uint8(getStatus(datatype.CloseType(i.CloseType), layers.IPProtocol(f.FlowKey.Proto)))
	i.AclGids = []uint16{}
	for _, v := range f.AclGids {
		i.AclGids = append(i.AclGids, uint16(v))
	}
	i.GPID0 = f.MetricsPeerSrc.Gpid
	i.GPID1 = f.MetricsPeerDst.Gpid
	i.NatRealIP0 = f.MetricsPeerSrc.RealIp
	i.NatRealIP1 = f.MetricsPeerDst.RealIp
	i.NatRealPort0 = uint16(f.MetricsPeerSrc.RealPort)
	i.NatRealPort1 = uint16(f.MetricsPeerDst.RealPort)
	i.DirectionScore = uint8(f.DirectionScore)
}

func (m *Metrics) Fill(f *pb.Flow) {
	m.PacketTx = f.MetricsPeerSrc.PacketCount
	m.PacketRx = f.MetricsPeerDst.PacketCount
	m.ByteTx = f.MetricsPeerSrc.ByteCount
	m.ByteRx = f.MetricsPeerDst.ByteCount
	m.L3ByteTx = f.MetricsPeerSrc.L3ByteCount
	m.L3ByteRx = f.MetricsPeerDst.L3ByteCount
	m.L4ByteTx = f.MetricsPeerSrc.L4ByteCount
	m.L4ByteRx = f.MetricsPeerDst.L4ByteCount

	m.TotalPacketTx = f.MetricsPeerSrc.TotalPacketCount
	m.TotalPacketRx = f.MetricsPeerDst.TotalPacketCount
	m.TotalByteTx = f.MetricsPeerSrc.TotalByteCount
	m.TotalByteRx = f.MetricsPeerDst.TotalByteCount

	if f.HasPerfStats == 1 {
		p := f.PerfStats
		m.L7Request = p.L7.RequestCount
		m.L7Response = p.L7.ResponseCount
		m.L7ClientError = p.L7.ErrClientCount
		m.L7ServerError = p.L7.ErrServerCount
		m.L7ServerTimeout = p.L7.ErrTimeout
		m.L7Error = m.L7ClientError + m.L7ServerError
		m.L7ParseFailed = p.L7FailedCount

		m.RTT = p.Tcp.Rtt
		m.RTTClient = p.Tcp.RttClientMax
		m.RTTServer = p.Tcp.RttServerMax
		m.TLSRTT = p.L7.TlsRtt

		m.SRTSum = p.Tcp.SrtSum
		m.SRTCount = p.Tcp.SrtCount

		m.ARTSum = p.Tcp.ArtSum
		m.ARTCount = p.Tcp.ArtCount

		m.RRTSum = p.L7.RrtSum
		m.RRTCount = p.L7.RrtCount

		m.CITSum = p.Tcp.CitSum
		m.CITCount = p.Tcp.CitCount

		m.SRTMax = p.Tcp.SrtMax
		m.ARTMax = p.Tcp.ArtMax
		m.RRTMax = p.L7.RrtMax
		m.CITMax = p.Tcp.CitMax

		if p.Tcp.CountsPeerTx != nil {
			m.RetransTx = p.Tcp.CountsPeerTx.RetransCount
			m.ZeroWinTx = p.Tcp.CountsPeerTx.ZeroWinCount
		}
		if p.Tcp.CountsPeerRx != nil {
			m.RetransRx = p.Tcp.CountsPeerRx.RetransCount
			m.ZeroWinRx = p.Tcp.CountsPeerRx.ZeroWinCount
		}
		m.SynCount = p.Tcp.SynCount
		m.SynackCount = p.Tcp.SynackCount
		if m.SynCount > 0 {
			m.RetransSyn = m.SynCount - 1
		}
		if m.SynackCount > 0 {
			m.RetransSynack = m.SynackCount - 1
		}
	}
}

func (f *L4FlowLog) Release() {
	ReleaseL4FlowLog(f)
}

func L4FlowLogColumns() []*ckdb.Column {
	columns := []*ckdb.Column{}
	columns = append(columns, ckdb.NewColumn("_id", ckdb.UInt64).SetCodec(ckdb.CodecDoubleDelta))
	columns = append(columns, DataLinkLayerColumns...)
	columns = append(columns, KnowledgeGraphColumns...)
	columns = append(columns, NetworkLayerColumns...)
	columns = append(columns, TransportLayerColumns...)
	columns = append(columns, ApplicationLayerColumns...)
	columns = append(columns, InternetColumns...)
	columns = append(columns, FlowInfoColumns...)
	columns = append(columns, MetricsColumns...)
	return columns
}

func (f *L4FlowLog) WriteBlock(block *ckdb.Block) {
	block.Write(f._id)
	f.DataLinkLayer.WriteBlock(block)
	f.KnowledgeGraph.WriteBlock(block)
	f.NetworkLayer.WriteBlock(block)
	f.TransportLayer.WriteBlock(block)
	f.ApplicationLayer.WriteBlock(block)
	f.Internet.WriteBlock(block)
	f.FlowInfo.WriteBlock(block)
	f.Metrics.WriteBlock(block)
}

func (f *L4FlowLog) EndTime() time.Duration {
	return time.Duration(f.FlowInfo.EndTime) * time.Microsecond
}

func (f *L4FlowLog) String() string {
	return fmt.Sprintf("flow: %+v\n", *f)
}

func (f *L4FlowLog) HitPcapPolicy() bool {
	// AclGids currently only records the policy ID of PCAP, but does not record the policy ID of NPB
	return len(f.AclGids) > 0
}

var poolL4FlowLog = pool.NewLockFreePool(func() interface{} {
	l := new(L4FlowLog)
	return l
})

func AcquireL4FlowLog() *L4FlowLog {
	l := poolL4FlowLog.Get().(*L4FlowLog)
	l.ReferenceCount.Reset()
	return l
}

func ReleaseL4FlowLog(l *L4FlowLog) {
	if l == nil {
		return
	}
	if l.SubReferenceCount() {
		return
	}
	*l = L4FlowLog{}
	poolL4FlowLog.Put(l)
}

var L4FlowCounter uint32

func genID(time uint32, counter *uint32, analyzerID uint32) uint64 {
	count := atomic.AddUint32(counter, 1)
	// 高32位时间，23-32位 表示 analyzerId, 低22位是counter
	return uint64(time)<<32 | uint64(analyzerID&0x3ff)<<22 | (uint64(count) & 0x3fffff)
}

func TaggedFlowToL4FlowLog(f *pb.TaggedFlow, platformData *grpc.PlatformInfoTable) *L4FlowLog {
	isIPV6 := f.Flow.EthType == uint32(layers.EthernetTypeIPv6)

	s := AcquireL4FlowLog()
	s._id = genID(uint32(f.Flow.EndTime/uint64(time.Second)), &L4FlowCounter, platformData.QueryAnalyzerID())
	s.DataLinkLayer.Fill(f.Flow)
	s.NetworkLayer.Fill(f.Flow, isIPV6)
	s.TransportLayer.Fill(f.Flow)
	s.ApplicationLayer.Fill(f.Flow)
	s.Internet.Fill(f.Flow)
	s.KnowledgeGraph.FillL4(f.Flow, isIPV6, platformData)
	s.FlowInfo.Fill(f.Flow)
	s.Metrics.Fill(f.Flow)

	return s
}
