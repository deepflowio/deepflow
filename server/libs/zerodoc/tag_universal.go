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

package zerodoc

import (
	"net"

	"github.com/deepflowio/deepflow/server/libs/ckdb"
)

type UniversalTag struct {
	// 注意：字节对齐！
	// Note: byte alignment!

	IP6            net.IP // FIXME: merge IP6 and IP
	IP             uint32
	L3EpcID        int32 // (8B)
	L3DeviceID     uint32
	RegionID       uint16
	SubnetID       uint16
	HostID         uint16
	AZID           uint16
	PodClusterID   uint16
	PodNSID        uint16
	PodID          uint32
	PodNodeID      uint32
	PodGroupID     uint32
	ServiceID      uint32
	AutoInstanceID uint32
	AutoServiceID  uint32
	GPID           uint32

	IsIPv6           uint8
	L3DeviceType     DeviceType
	AutoInstanceType uint8
	AutoServiceType  uint8

	VTAPID uint16
	//SignalSource uint16
}

// Note: The order of append() must be consistent with the order of Write() in WriteBlock.
// Currently all fields are sorted lexicographically by name.
func GenUniversalTagColumns(columns []*ckdb.Column) []*ckdb.Column {
	columns = append(columns, ckdb.NewColumnWithGroupBy("az_id", ckdb.UInt16).SetComment("可用区ID"))
	columns = append(columns, ckdb.NewColumnWithGroupBy("gprocess_id", ckdb.UInt32).SetComment("全局进程ID"))
	columns = append(columns, ckdb.NewColumnWithGroupBy("host_id", ckdb.UInt16).SetComment("宿主机ID"))
	columns = append(columns, ckdb.NewColumnWithGroupBy("ip4", ckdb.IPv4).SetComment("IPv4地址"))
	columns = append(columns, ckdb.NewColumnWithGroupBy("ip6", ckdb.IPv6).SetComment("IPV6地址"))
	columns = append(columns, ckdb.NewColumnWithGroupBy("is_ipv4", ckdb.UInt8).SetIndex(ckdb.IndexMinmax).SetComment("是否IPV4地址. 0: 否, ip6字段有效, 1: 是, ip4字段有效"))
	columns = append(columns, ckdb.NewColumnWithGroupBy("l3_device_id", ckdb.UInt32).SetComment("ip对应的资源ID"))
	columns = append(columns, ckdb.NewColumnWithGroupBy("l3_device_type", ckdb.UInt8).SetComment("ip对应的资源类型"))
	columns = append(columns, ckdb.NewColumnWithGroupBy("l3_epc_id", ckdb.Int32).SetComment("ip对应的EPC ID"))
	columns = append(columns, ckdb.NewColumnWithGroupBy("pod_cluster_id", ckdb.UInt16).SetComment("ip对应的容器集群ID"))
	columns = append(columns, ckdb.NewColumnWithGroupBy("pod_group_id", ckdb.UInt32).SetComment("ip对应的容器工作负载ID"))
	columns = append(columns, ckdb.NewColumnWithGroupBy("pod_id", ckdb.UInt32).SetComment("ip对应的容器POD ID"))
	columns = append(columns, ckdb.NewColumnWithGroupBy("pod_node_id", ckdb.UInt32).SetComment("ip对应的容器节点ID"))
	columns = append(columns, ckdb.NewColumnWithGroupBy("pod_ns_id", ckdb.UInt16).SetComment("ip对应的容器命名空间ID"))
	columns = append(columns, ckdb.NewColumnWithGroupBy("region_id", ckdb.UInt16).SetComment("ip对应的云平台区域ID"))
	columns = append(columns, ckdb.NewColumnWithGroupBy("auto_instance_id", ckdb.UInt32).SetComment("ip对应的容器pod优先的资源ID, 取值优先级为pod_id -> pod_node_id -> l3_device_id"))
	columns = append(columns, ckdb.NewColumnWithGroupBy("auto_instance_type", ckdb.UInt8).SetComment("资源类型, 0:IP地址(无法对应资源), 0-100:deviceType(其中10:pod, 14:podNode), 101-200:DeepFlow抽象出的资源(其中101:podGroup, 102:service), 201-255:其他"))
	columns = append(columns, ckdb.NewColumnWithGroupBy("auto_service_id", ckdb.UInt32).SetComment("ip对应的服务优先的资源ID, 取值优先级为service_id  -> pod_node_id -> l3_device_id"))
	columns = append(columns, ckdb.NewColumnWithGroupBy("auto_service_type", ckdb.UInt8).SetComment("资源类型, 0:IP地址(无法对应资源), 0-100:deviceType(其中10:pod, 14:podNode), 101-200:DeepFlow抽象出的资源(其中101:podGroup, 102:service), 201-255:其他"))
	//columns = append(columns, ckdb.NewColumnWithGroupBy("signal_source", ckdb.UInt16).SetComment("信号源"))
	columns = append(columns, ckdb.NewColumnWithGroupBy("service_id", ckdb.UInt32).SetComment("ip对应的服务ID"))
	columns = append(columns, ckdb.NewColumnWithGroupBy("subnet_id", ckdb.UInt16).SetComment("ip对应的子网ID(0: 未找到)"))
	columns = append(columns, ckdb.NewColumnWithGroupBy("agent_id", ckdb.UInt16).SetComment("采集器的ID"))

	return columns
}

// Note: The order of Write() must be consistent with the order of append() in GenUniversalTagColumns.
// Currently all fields are sorted lexicographically by name.
func (t *UniversalTag) WriteBlock(block *ckdb.Block) {
	block.Write(
		t.AZID,
		t.GPID,
		t.HostID,
	)
	block.WriteIPv4(t.IP)
	block.WriteIPv6(t.IP6)
	block.Write(
		1-t.IsIPv6,
		t.L3DeviceID,
		uint8(t.L3DeviceType),
		t.L3EpcID,
		t.PodClusterID,
		t.PodGroupID,
		t.PodID,
		t.PodNodeID,
		t.PodNSID,
		t.RegionID,
		t.AutoInstanceID,
		t.AutoInstanceType,
		t.AutoServiceID,
		t.AutoServiceType,
		//t.SignalSource,
		t.ServiceID,
		t.SubnetID,
		t.VTAPID,
	)
}
