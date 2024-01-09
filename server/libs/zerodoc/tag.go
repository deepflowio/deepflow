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

package zerodoc

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"

	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/datatype/prompb"
	"github.com/deepflowio/deepflow/server/libs/pool"
	"github.com/deepflowio/deepflow/server/libs/utils"
	"github.com/deepflowio/deepflow/server/libs/zerodoc/pb"
	"github.com/google/gopacket/layers"
)

type Code uint64

const (
	IP Code = 0x1 << iota
	L3EpcID
	L3Device
	SubnetID
	RegionID
	PodNodeID
	HostID
	AZID
	PodGroupID
	PodNSID
	PodID
	MAC
	PodClusterID
	ServiceID
	Resource // 1<< 14
	GPID     // 1<< 15

	// Make sure the max offset <= 19
)

const (
	IPPath Code = 0x100000 << iota // 1 << 20
	L3EpcIDPath
	L3DevicePath
	SubnetIDPath
	RegionIDPath
	PodNodeIDPath
	HostIDPath
	AZIDPath
	PodGroupIDPath
	PodNSIDPath
	PodIDPath
	MACPath
	PodClusterIDPath
	ServiceIDPath
	ResourcePath // 1<< 34
	GPIDPath     // 1<< 35

	// Make sure the max offset <= 39
)

const (
	Direction Code = 0x10000000000 << iota // 1 << 40
	ACLGID
	Protocol
	ServerPort
	_
	TAPType
	_
	VTAPID
	TAPSide
	TAPPort
	IsKeyService
	L7Protocol
	SignalSource
)

const (
	TagType  Code = 1 << 62
	TagValue Code = 1 << 63
)

func (c Code) HasEdgeTagField() bool {
	return c&0xfffff00000 != 0
}

type DeviceType uint8

const (
	_ DeviceType = iota
	VMDevice
	_
	ThirdPartyDevice // 3
	_
	VGatewayDevice // 5
	HostDevice
	NetworkDevice
	FloatingIPDevice
	DHCPDevice
)

type SideType uint8

const (
	NodeSide SideType = (iota + 1) << 3
	HypervisorSide
	GatewayHypervisorSide
	GatewaySide
	ProcessSide
	AppSide
)

type DirectionEnum uint8

const (
	_CLIENT_SERVER_MASK = 0x7
	_SIDE_TYPE_MASK     = 0xf8
)

const (
	ClientToServer = 1 << iota
	ServerToClient
	LocalToLocal

	// 以下类型为转换tapside而增加，在写入db时均记为c2s或s2c
	ClientNodeToServer              = ClientToServer | DirectionEnum(NodeSide)              // 客户端容器节点，路由、SNAT、隧道
	ServerNodeToClient              = ServerToClient | DirectionEnum(NodeSide)              // 服务端容器节点，路由、SNAT、隧道
	ClientHypervisorToServer        = ClientToServer | DirectionEnum(HypervisorSide)        // 客户端宿主机，隧道
	ServerHypervisorToClient        = ServerToClient | DirectionEnum(HypervisorSide)        // 服务端宿主机，隧道
	ClientGatewayHypervisorToServer = ClientToServer | DirectionEnum(GatewayHypervisorSide) // 客户端网关宿主机
	ServerGatewayHypervisorToClient = ServerToClient | DirectionEnum(GatewayHypervisorSide) // 服务端网关宿主机
	ClientGatewayToServer           = ClientToServer | DirectionEnum(GatewaySide)           // 客户端网关（特指VIP机制的SLB，例如微软云MUX等）, Mac地址对应的接口为vip设备
	ServerGatewayToClient           = ServerToClient | DirectionEnum(GatewaySide)           // 服务端网关（特指VIP机制的SLB，例如微软云MUX等）, Mac地址对应的接口为vip设备
	ClientProcessToServer           = ClientToServer | DirectionEnum(ProcessSide)           // 客户端进程
	ServerProcessToClient           = ServerToClient | DirectionEnum(ProcessSide)           // 服务端进程
	ClientAppToServer               = ClientToServer | DirectionEnum(AppSide)               // 客户端应用
	ServerAppToClient               = ServerToClient | DirectionEnum(AppSide)               // 服务端应用
)

func (d DirectionEnum) IsClientToServer() bool {
	return d&_CLIENT_SERVER_MASK == ClientToServer
}

func (d DirectionEnum) IsServerToClient() bool {
	return d&_CLIENT_SERVER_MASK == ServerToClient
}

func (d DirectionEnum) IsGateway() bool {
	return SideType(d&_SIDE_TYPE_MASK)&(GatewaySide|GatewayHypervisorSide) != 0
}

type TAPSideEnum uint8

const (
	Client TAPSideEnum = 1 << iota
	Server
	Local
	ClientNode              = Client | TAPSideEnum(NodeSide)
	ServerNode              = Server | TAPSideEnum(NodeSide)
	ClientHypervisor        = Client | TAPSideEnum(HypervisorSide)
	ServerHypervisor        = Server | TAPSideEnum(HypervisorSide)
	ClientGatewayHypervisor = Client | TAPSideEnum(GatewayHypervisorSide)
	ServerGatewayHypervisor = Server | TAPSideEnum(GatewayHypervisorSide)
	ClientGateway           = Client | TAPSideEnum(GatewaySide)
	ServerGateway           = Server | TAPSideEnum(GatewaySide)
	ClientProcess           = Client | TAPSideEnum(ProcessSide)
	ServerProcess           = Server | TAPSideEnum(ProcessSide)
	ClientApp               = Client | TAPSideEnum(AppSide)
	ServerApp               = Server | TAPSideEnum(AppSide)
	App                     = TAPSideEnum(AppSide)
	Rest                    = 0
)

var TAPSideEnumsString = []string{
	Rest:                    "rest",
	Client:                  "c",
	Server:                  "s",
	Local:                   "local",
	ClientNode:              "c-nd",
	ServerNode:              "s-nd",
	ClientHypervisor:        "c-hv",
	ServerHypervisor:        "s-hv",
	ClientGatewayHypervisor: "c-gw-hv",
	ServerGatewayHypervisor: "s-gw-hv",
	ClientGateway:           "c-gw",
	ServerGateway:           "s-gw",
	ClientProcess:           "c-p",
	ServerProcess:           "s-p",
	ClientApp:               "c-app",
	ServerApp:               "s-app",
	App:                     "app",
}

func (s TAPSideEnum) String() string {
	return TAPSideEnumsString[s]
}

func (d DirectionEnum) ToTAPSide() TAPSideEnum {
	return TAPSideEnum(d)
}

// TAP: Traffic Access Point
//
// Indicates the flow data collection location.  Currently supports 255
// acquisition locations. The traffic in cloud is uniformly represented by
// a special value `3`, and the other values represent the traffic
// collected from optical splitting and mirroring at different locations
// in the IDC.
//
// Note: For historical reasons, we use the confusing term VTAP to refer
// to deepflow-agent, and vtap_id to represent the id of a deepflow-agent.
type TAPTypeEnum uint8

const (
	IDC_MIN TAPTypeEnum = 1 // 1~2, 4~255: IDC
	CLOUD   TAPTypeEnum = 3
)

const (
	_ = 1 + iota // TAG_TYPE_PROVINCE = 1 + iota，已删除
	_            // TAG_TYPE_TCP_FLAG，已删除
	_            // TAG_TYPE_CAST_TYPE，已删除
	TAG_TYPE_TUNNEL_IP_ID
	_ // TAG_TYPE_TTL，已删除
	_ // TAG_TYPE_PACKET_SIZE，已删除
)

type TagSource uint8

const (
	GpId  TagSource = 1 << iota // if the GpId exists but the podId does not exist, first obtain the podId through the GprocessId table delivered by the Controller
	PodId                       // use vtapId + podId to match first
	Mac                         // if vtapId + podId cannot be matched, finally use Mac/EpcIP to match resources
	EpcIP
	Peer           // Multicast, filled with peer information
	None TagSource = 0
)

type Field struct {
	// 注意字节对齐！

	// 用于区分不同的trident及其不同的pipeline，用于如下场景：
	//   - trident和roze之间的数据传输
	//   - roze写入influxdb，作用类似_id，序列化为_tid
	GlobalThreadID uint8

	IP6              net.IP // FIXME: 合并IP6和IP
	MAC              uint64
	IP               uint32
	L3EpcID          int32 // (8B)
	L3DeviceID       uint32
	L3DeviceType     DeviceType
	RegionID         uint16
	SubnetID         uint16
	HostID           uint16
	PodNodeID        uint32
	AZID             uint16
	PodGroupID       uint32
	PodNSID          uint16
	PodID            uint32
	PodClusterID     uint16
	ServiceID        uint32
	AutoInstanceID   uint32
	AutoInstanceType uint8
	AutoServiceID    uint32
	AutoServiceType  uint8
	GPID             uint32

	MAC1              uint64
	IP61              net.IP // FIXME: 合并IP61和IP1
	IP1               uint32
	L3EpcID1          int32 // (8B)
	L3DeviceID1       uint32
	L3DeviceType1     DeviceType // (+1B=8B)
	RegionID1         uint16
	SubnetID1         uint16 // (8B)
	HostID1           uint16
	PodNodeID1        uint32
	AZID1             uint16
	PodGroupID1       uint32
	PodNSID1          uint16
	PodID1            uint32
	PodClusterID1     uint16
	ServiceID1        uint32
	AutoInstanceID1   uint32
	AutoInstanceType1 uint8
	AutoServiceID1    uint32
	AutoServiceType1  uint8
	GPID1             uint32

	ACLGID       uint16
	Direction    DirectionEnum
	Protocol     layers.IPProtocol
	ServerPort   uint16
	VTAPID       uint16
	TAPPort      datatype.TapPort
	TAPSide      TAPSideEnum
	TAPType      TAPTypeEnum
	IsIPv6       uint8 // (8B) 与IP/IP6是共生字段
	IsKeyService uint8
	L7Protocol   datatype.L7Protocol
	AppService   string
	AppInstance  string
	Endpoint     string
	SignalSource uint16

	TagSource, TagSource1 uint8

	TagType  uint8
	TagValue uint16
}

func newMetricsMinuteTable(id MetricsTableID, engine ckdb.EngineType, version, cluster, storagePolicy string, ttl int, coldStorage *ckdb.ColdStorage) *ckdb.Table {
	timeKey := "time"

	var orderKeys []string
	code := metricsTableCodes[id]
	if code&L3EpcID != 0 {
		orderKeys = []string{timeKey, "l3_epc_id", "ip4", "ip6"}
	} else if code&L3EpcIDPath != 0 {
		orderKeys = []string{timeKey, "l3_epc_id_1", "ip4_1", "ip6_1", "l3_epc_id_0", "ip4_0", "ip6_0"}
	} else if code&ACLGID != 0 {
		orderKeys = []string{timeKey, "acl_gid"}
	}
	if code&ServerPort != 0 {
		orderKeys = append(orderKeys, "server_port")
	}

	var meterColumns []*ckdb.Column
	switch id {
	case VTAP_FLOW_PORT_1M, VTAP_FLOW_EDGE_PORT_1M:
		meterColumns = FlowMeterColumns()
	case VTAP_ACL_1M:
		meterColumns = UsageMeterColumns()
	case VTAP_APP_PORT_1M, VTAP_APP_EDGE_PORT_1M:
		meterColumns = AppMeterColumns()
	}

	return &ckdb.Table{
		Version:         version,
		ID:              uint8(id),
		Database:        ckdb.METRICS_DB,
		LocalName:       id.TableName() + ckdb.LOCAL_SUBFFIX,
		GlobalName:      id.TableName(),
		Columns:         append(GenTagColumns(metricsTableCodes[id]), meterColumns...),
		TimeKey:         timeKey,
		TTL:             ttl,
		PartitionFunc:   ckdb.TimeFuncTwelveHour,
		Engine:          engine,
		Cluster:         cluster,
		StoragePolicy:   storagePolicy,
		ColdStorage:     *coldStorage,
		OrderKeys:       orderKeys,
		PrimaryKeyCount: len(orderKeys),
	}
}

// 由分钟表生成秒表
func newMetricsSecondTable(minuteTable *ckdb.Table, ttl int, coldStorages *ckdb.ColdStorage) *ckdb.Table {
	t := *minuteTable
	t.ID = minuteTable.ID + uint8(VTAP_FLOW_PORT_1S)
	t.LocalName = MetricsTableID(t.ID).TableName() + ckdb.LOCAL_SUBFFIX
	t.GlobalName = MetricsTableID(t.ID).TableName()
	t.TTL = ttl
	t.ColdStorage = *coldStorages
	t.PartitionFunc = ckdb.TimeFuncFourHour
	t.Engine = ckdb.MergeTree // 秒级数据不用支持使用replica

	return &t
}

func GetMetricsTables(engine ckdb.EngineType, version, cluster, storagePolicy string, flowMinuteTtl, flowSecondTtl, appMinuteTtl, appSecondTtl int, coldStorages map[string]*ckdb.ColdStorage) []*ckdb.Table {
	var metricsTables []*ckdb.Table

	minuteTables := []*ckdb.Table{}
	for i := VTAP_FLOW_PORT_1M; i <= VTAP_FLOW_EDGE_PORT_1M; i++ {
		minuteTables = append(minuteTables, newMetricsMinuteTable(i, engine, version, cluster, storagePolicy, flowMinuteTtl, ckdb.GetColdStorage(coldStorages, ckdb.METRICS_DB, i.TableName())))
	}
	for i := VTAP_APP_PORT_1M; i <= VTAP_APP_EDGE_PORT_1M; i++ {
		minuteTables = append(minuteTables, newMetricsMinuteTable(i, engine, version, cluster, storagePolicy, appMinuteTtl, ckdb.GetColdStorage(coldStorages, ckdb.METRICS_DB, i.TableName())))
	}
	minuteTables = append(minuteTables, newMetricsMinuteTable(VTAP_ACL_1M, engine, version, cluster, storagePolicy, 7*24, ckdb.GetColdStorage(coldStorages, ckdb.METRICS_DB, VTAP_ACL_1M.TableName()))) // vtap_acl ttl is always 7 day

	secondTables := []*ckdb.Table{}
	for i := VTAP_FLOW_PORT_1S; i <= VTAP_FLOW_EDGE_PORT_1S; i++ {
		secondTables = append(secondTables, newMetricsSecondTable(minuteTables[i-VTAP_FLOW_PORT_1S], flowSecondTtl, ckdb.GetColdStorage(coldStorages, ckdb.METRICS_DB, i.TableName())))
	}
	for i := VTAP_APP_PORT_1S; i <= VTAP_APP_EDGE_PORT_1S; i++ {
		secondTables = append(secondTables, newMetricsSecondTable(minuteTables[i-VTAP_FLOW_PORT_1S], appSecondTtl, ckdb.GetColdStorage(coldStorages, ckdb.METRICS_DB, i.TableName())))
	}
	metricsTables = append(minuteTables, secondTables...)
	return metricsTables
}

type MetricsTableID uint8

const (
	VTAP_FLOW_PORT_1M MetricsTableID = iota
	VTAP_FLOW_EDGE_PORT_1M

	VTAP_APP_PORT_1M
	VTAP_APP_EDGE_PORT_1M

	VTAP_ACL_1M

	VTAP_FLOW_PORT_1S
	VTAP_FLOW_EDGE_PORT_1S

	VTAP_APP_PORT_1S
	VTAP_APP_EDGE_PORT_1S

	VTAP_TABLE_ID_MAX
)

func (i MetricsTableID) TableName() string {
	return metricsTableNames[i]
}

func (i MetricsTableID) TableCode() Code {
	return metricsTableCodes[i]
}

var metricsTableNames = []string{
	VTAP_FLOW_PORT_1M:      "vtap_flow_port.1m",
	VTAP_FLOW_EDGE_PORT_1M: "vtap_flow_edge_port.1m",

	VTAP_APP_PORT_1M:      "vtap_app_port.1m",
	VTAP_APP_EDGE_PORT_1M: "vtap_app_edge_port.1m",

	VTAP_ACL_1M: "vtap_acl.1m",

	VTAP_FLOW_PORT_1S:      "vtap_flow_port.1s",
	VTAP_FLOW_EDGE_PORT_1S: "vtap_flow_edge_port.1s",

	VTAP_APP_PORT_1S:      "vtap_app_port.1s",
	VTAP_APP_EDGE_PORT_1S: "vtap_app_edge_port.1s",
}

func MetricsTableNameToID(name string) MetricsTableID {
	for i, n := range metricsTableNames {
		if n == name {
			return MetricsTableID(i)
		}
	}
	return VTAP_TABLE_ID_MAX
}

const (
	BaseCode     = AZID | HostID | IP | L3Device | L3EpcID | PodClusterID | PodGroupID | PodID | PodNodeID | PodNSID | RegionID | SubnetID | TAPType | VTAPID | ServiceID | Resource | GPID | SignalSource
	BasePathCode = AZIDPath | HostIDPath | IPPath | L3DevicePath | L3EpcIDPath | PodClusterIDPath | PodGroupIDPath | PodIDPath | PodNodeIDPath | PodNSIDPath | RegionIDPath | SubnetIDPath | TAPSide | TAPType | VTAPID | ServiceIDPath | ResourcePath | GPIDPath | SignalSource
	BasePortCode = Protocol | ServerPort | IsKeyService

	VTAP_FLOW_PORT      = BaseCode | BasePortCode | Direction
	VTAP_FLOW_EDGE_PORT = BasePathCode | BasePortCode | TAPPort
	VTAP_APP_PORT       = BaseCode | BasePortCode | Direction | L7Protocol
	VTAP_APP_EDGE_PORT  = BasePathCode | BasePortCode | TAPPort | L7Protocol

	VTAP_ACL = ACLGID | TagType | TagValue | VTAPID
)

var metricsTableCodes = []Code{
	VTAP_FLOW_PORT_1M:      VTAP_FLOW_PORT,
	VTAP_FLOW_EDGE_PORT_1M: VTAP_FLOW_EDGE_PORT,

	VTAP_APP_PORT_1M:      VTAP_APP_PORT,
	VTAP_APP_EDGE_PORT_1M: VTAP_APP_EDGE_PORT,

	VTAP_ACL_1M: VTAP_ACL,

	VTAP_FLOW_PORT_1S:      VTAP_FLOW_PORT,
	VTAP_FLOW_EDGE_PORT_1S: VTAP_FLOW_EDGE_PORT,

	VTAP_APP_PORT_1S:      VTAP_APP_PORT,
	VTAP_APP_EDGE_PORT_1S: VTAP_APP_EDGE_PORT,
}

type Tag struct {
	*Field
	Code
	id string
}

func (t *Tag) ToKVString() string {
	buffer := make([]byte, MAX_STRING_LENGTH)
	size := t.MarshalTo(buffer)
	return string(buffer[:size])
}

const (
	ID_OTHER    = -1
	ID_INTERNET = -2
)

func marshalUint16WithSpecialID(v int16) string {
	switch v {
	case ID_OTHER:
		fallthrough
	case ID_INTERNET:
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatUint(uint64(v)&math.MaxUint16, 10)
}

func unmarshalUint16WithSpecialID(s string) (int16, error) {
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return -1, err
	}
	return int16(i), nil
}

func MarshalInt32WithSpecialID(v int32) int32 {
	if v > 0 || v == ID_OTHER || v == ID_INTERNET {
		return v
	}
	return int32(uint64(v) & math.MaxUint16)
}

func unmarshalInt32WithSpecialID(v int32) int16 {
	return int16(v)
}

func marshalUint16s(vs []uint16) string {
	var buf strings.Builder
	for i, v := range vs {
		buf.WriteString(strconv.FormatUint(uint64(v), 10))
		if i < len(vs)-1 {
			buf.WriteString("|")
		}
	}
	return buf.String()
}

func unmarshalUint16s(s string) ([]uint16, error) {
	uint16s := []uint16{}
	vs := strings.Split(s, "|")
	for _, v := range vs {
		i, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return uint16s, err
		}
		uint16s = append(uint16s, uint16(i))
	}
	return uint16s, nil
}

// 注意: 必须要按tag字段的字典顺序进行处理
func (t *Tag) MarshalTo(b []byte) int {
	offset := 0

	// 在InfluxDB的line protocol中，tag紧跟在measurement name之后，总会以逗号开头
	if t.GlobalThreadID != 0 { // FIXME: zero写入的数据此字段总为0，目前无需该字段
		offset += copy(b[offset:], ",_tid=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.GlobalThreadID), 10))
	}

	if t.Code&ACLGID != 0 {
		offset += copy(b[offset:], ",acl_gid=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.ACLGID), 10))
	}
	if t.Code&AZID != 0 {
		offset += copy(b[offset:], ",az_id=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.AZID), 10))
	}
	if t.Code&AZIDPath != 0 {
		offset += copy(b[offset:], ",az_id_0=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.AZID), 10))
		offset += copy(b[offset:], ",az_id_1=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.AZID1), 10))
	}

	if t.Code&Direction != 0 {
		if t.Direction.IsClientToServer() {
			offset += copy(b[offset:], ",direction=c2s")
		} else if t.Direction.IsServerToClient() {
			offset += copy(b[offset:], ",direction=s2c")
		}
	}
	if t.Code&GPID != 0 {
		offset += copy(b[offset:], ",gprocess_id=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.GPID), 10))
	}
	if t.Code&GPIDPath != 0 {
		offset += copy(b[offset:], ",gprocess_id_0=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.GPID), 10))
		offset += copy(b[offset:], ",gprocess_id_1=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.GPID1), 10))
	}
	if t.Code&HostID != 0 {
		offset += copy(b[offset:], ",host_id=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.HostID), 10))
	}
	if t.Code&HostIDPath != 0 {
		offset += copy(b[offset:], ",host_id_0=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.HostID), 10))
		offset += copy(b[offset:], ",host_id_1=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.HostID1), 10))
	}
	if t.Code&IP != 0 {
		if t.IsIPv6 != 0 {
			offset += copy(b[offset:], ",ip=")
			offset += copy(b[offset:], t.IP6.String())
			offset += copy(b[offset:], ",ip_version=6")
		} else {
			offset += copy(b[offset:], ",ip=")
			offset += copy(b[offset:], utils.IpFromUint32(t.IP).String())
			offset += copy(b[offset:], ",ip_version=4")
		}
	}
	if t.Code&IPPath != 0 {
		if t.IsIPv6 != 0 {
			offset += copy(b[offset:], ",ip_0=")
			offset += copy(b[offset:], t.IP6.String())
			offset += copy(b[offset:], ",ip_1=")
			offset += copy(b[offset:], t.IP61.String())
			offset += copy(b[offset:], ",is_version=6")
		} else {
			offset += copy(b[offset:], ",ip_0=")
			offset += copy(b[offset:], utils.IpFromUint32(t.IP).String())
			offset += copy(b[offset:], ",ip_1=")
			offset += copy(b[offset:], utils.IpFromUint32(t.IP1).String())
			offset += copy(b[offset:], ",ip_version=4")
		}
	}

	if t.Code&IsKeyService != 0 {
		if t.IsKeyService == 1 {
			offset += copy(b[offset:], ",is_key_service=1")
		} else {
			offset += copy(b[offset:], ",is_key_service=0")
		}
	}

	if t.Code&L3Device != 0 {
		offset += copy(b[offset:], ",l3_device_id=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.L3DeviceID), 10))
		offset += copy(b[offset:], ",l3_device_type=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.L3DeviceType), 10))
	}
	if t.Code&L3DevicePath != 0 {
		offset += copy(b[offset:], ",l3_device_id_0=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.L3DeviceID), 10))
		offset += copy(b[offset:], ",l3_device_id_1=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.L3DeviceID1), 10))
		offset += copy(b[offset:], ",l3_device_type_0=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.L3DeviceType), 10))
		offset += copy(b[offset:], ",l3_device_type_1=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.L3DeviceType1), 10))
	}
	if t.Code&L3EpcID != 0 {
		offset += copy(b[offset:], ",l3_epc_id=")
		offset += copy(b[offset:], strconv.FormatInt(int64(t.L3EpcID), 10))
	}
	if t.Code&L3EpcIDPath != 0 {
		offset += copy(b[offset:], ",l3_epc_id_0=")
		offset += copy(b[offset:], strconv.FormatInt(int64(t.L3EpcID), 10))
		offset += copy(b[offset:], ",l3_epc_id_1=")
		offset += copy(b[offset:], strconv.FormatInt(int64(t.L3EpcID1), 10))
	}
	if t.Code&L7Protocol != 0 {
		offset += copy(b[offset:], ",l7_protocol=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.L7Protocol), 10))
		offset += copy(b[offset:], ",app_service="+t.AppService)
		offset += copy(b[offset:], ",app_instance="+t.AppInstance)
		offset += copy(b[offset:], ",endpoint="+t.Endpoint)
	}
	if t.Code&MAC != 0 {
		// 不存入tsdb中
		//offset += copy(b[offset:], ",mac=")
		//offset += copy(b[offset:], utils.Uint64ToMac(t.MAC).String())
	}
	if t.Code&MACPath != 0 {
		// 不存入tsdb中
		//offset += copy(b[offset:], ",mac_0=")
		//offset += copy(b[offset:], utils.Uint64ToMac(t.MAC).String())
		//offset += copy(b[offset:], ",mac_1=")
		//offset += copy(b[offset:], utils.Uint64ToMac(t.MAC1).String())
	}

	if t.Code&PodClusterID != 0 {
		offset += copy(b[offset:], ",pod_cluster_id=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.PodClusterID), 10))
	}

	if t.Code&PodClusterIDPath != 0 {
		offset += copy(b[offset:], ",pod_cluster_id_0=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.PodClusterID), 10))
		offset += copy(b[offset:], ",pod_cluster_id_1=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.PodClusterID1), 10))
	}

	if t.Code&PodGroupID != 0 {
		offset += copy(b[offset:], ",pod_group_id=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.PodGroupID), 10))
	}

	if t.Code&PodGroupIDPath != 0 {
		offset += copy(b[offset:], ",pod_group_id_0=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.PodGroupID), 10))
		offset += copy(b[offset:], ",pod_group_id_1=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.PodGroupID1), 10))
	}

	if t.Code&PodID != 0 {
		offset += copy(b[offset:], ",pod_id=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.PodID), 10))
	}

	if t.Code&PodIDPath != 0 {
		offset += copy(b[offset:], ",pod_id_0=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.PodID), 10))
		offset += copy(b[offset:], ",pod_id_1=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.PodID1), 10))
	}

	if t.Code&PodNodeID != 0 {
		offset += copy(b[offset:], ",pod_node_id=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.PodNodeID), 10))
	}

	if t.Code&PodNodeIDPath != 0 {
		offset += copy(b[offset:], ",pod_node_id_0=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.PodNodeID), 10))
		offset += copy(b[offset:], ",pod_node_id_1=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.PodNodeID1), 10))
	}

	if t.Code&PodNSID != 0 {
		offset += copy(b[offset:], ",pod_ns_id=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.PodNSID), 10))
	}

	if t.Code&PodNSIDPath != 0 {
		offset += copy(b[offset:], ",pod_ns_id_0=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.PodNSID), 10))
		offset += copy(b[offset:], ",pod_ns_id_1=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.PodNSID1), 10))
	}

	if t.Code&Protocol != 0 {
		offset += copy(b[offset:], ",protocol=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.Protocol), 10))
	}

	if t.Code&RegionID != 0 {
		offset += copy(b[offset:], ",region_id=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.RegionID), 10))
	}
	if t.Code&RegionIDPath != 0 {
		offset += copy(b[offset:], ",region_id_0=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.RegionID), 10))
		offset += copy(b[offset:], ",region_id_1=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.RegionID1), 10))
	}

	if t.Code&Resource != 0 {
		offset += copy(b[offset:], ",auto_instance_id=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.AutoInstanceID), 10))
		offset += copy(b[offset:], ",auto_instance_type=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.AutoInstanceType), 10))
		offset += copy(b[offset:], ",auto_service_id=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.AutoServiceID), 10))
		offset += copy(b[offset:], ",auto_service_type=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.AutoServiceType), 10))
	}
	if t.Code&ResourcePath != 0 {
		offset += copy(b[offset:], ",auto_instance_id_0=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.AutoInstanceID), 10))
		offset += copy(b[offset:], ",auto_instance_type_0=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.AutoInstanceType), 10))
		offset += copy(b[offset:], ",auto_service_id_0=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.AutoServiceID), 10))
		offset += copy(b[offset:], ",auto_service_type_0=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.AutoServiceType), 10))

		offset += copy(b[offset:], ",auto_instance_id_1=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.AutoInstanceID1), 10))
		offset += copy(b[offset:], ",auto_instance_type_1=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.AutoInstanceType1), 10))
		offset += copy(b[offset:], ",auto_service_id_1=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.AutoServiceID1), 10))
		offset += copy(b[offset:], ",auto_service_type_1=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.AutoServiceType1), 10))
	}

	if t.Code&SignalSource != 0 {
		offset += copy(b[offset:], ",signal_source=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.SignalSource), 10))
	}

	if t.Code&ServerPort != 0 {
		offset += copy(b[offset:], ",server_port=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.ServerPort), 10))
	}

	if t.Code&ServiceID != 0 {
		offset += copy(b[offset:], ",service_id=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.ServiceID), 10))
	}

	if t.Code&ServiceIDPath != 0 {
		offset += copy(b[offset:], ",service_id_0=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.ServiceID), 10))
		offset += copy(b[offset:], ",service_id_1=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.ServiceID1), 10))
	}

	if t.Code&SubnetID != 0 {
		offset += copy(b[offset:], ",subnet_id=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.SubnetID), 10))
	}
	if t.Code&SubnetIDPath != 0 {
		offset += copy(b[offset:], ",subnet_id_0=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.SubnetID), 10))
		offset += copy(b[offset:], ",subnet_id_1=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.SubnetID1), 10))
	}
	if t.Code&TagType != 0 && t.Code&TagValue != 0 {
		offset += copy(b[offset:], ",tag_type=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.TagType), 10))
		switch t.TagType {
		case TAG_TYPE_TUNNEL_IP_ID:
			offset += copy(b[offset:], ",tag_value=")
			offset += copy(b[offset:], strconv.FormatUint(uint64(t.TagValue), 10))
		}
	}
	if t.Code&TAPPort != 0 {
		offset += copy(b[offset:], ",tap_port=")
		offset += putTAPPort(b[offset:], uint64(t.TAPPort))
	}
	if t.Code&TAPSide != 0 {
		switch t.TAPSide {
		case Rest:
			offset += copy(b[offset:], ",tap_side=rest")
		case Client:
			offset += copy(b[offset:], ",tap_side=c")
		case Server:
			offset += copy(b[offset:], ",tap_side=s")
		case ClientNode:
			offset += copy(b[offset:], ",tap_side=c-nd")
		case ServerNode:
			offset += copy(b[offset:], ",tap_side=s-nd")
		case ClientHypervisor:
			offset += copy(b[offset:], ",tap_side=c-hv")
		case ServerHypervisor:
			offset += copy(b[offset:], ",tap_side=s-hv")
		case ClientGatewayHypervisor:
			offset += copy(b[offset:], ",tap_side=c-gw-hv")
		case ServerGatewayHypervisor:
			offset += copy(b[offset:], ",tap_side=s-gw-hv")
		case ClientGateway:
			offset += copy(b[offset:], ",tap_side=c-gw")
		case ServerGateway:
			offset += copy(b[offset:], ",tap_side=s-gw")
		}
	}
	if t.Code&TAPType != 0 {
		offset += copy(b[offset:], ",tap_type=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.TAPType), 10))
	}
	if t.Code&VTAPID != 0 {
		offset += copy(b[offset:], ",vtap_id=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.VTAPID), 10))
	}

	return offset
}

func (t *Tag) TableID(isSecond bool) (uint8, error) {
	for i, code := range metricsTableCodes {
		// 有时会有MAC,MACPath字段，需要先排除再比较
		if t.Code&^MAC&^MACPath == code {
			if isSecond {
				return uint8(i) + uint8(VTAP_FLOW_PORT_1S), nil
			}
			return uint8(i), nil
		}
	}
	return 0, fmt.Errorf("not match table, tag code is 0x%x is second %v", t.Code, isSecond)
}

// 顺序需要和WriteBlock中一致, 目前time排第一位，其他按字段名字典排序
func GenTagColumns(code Code) []*ckdb.Column {
	columns := []*ckdb.Column{}
	columns = append(columns, ckdb.NewColumnWithGroupBy("time", ckdb.DateTime))
	columns = append(columns, ckdb.NewColumn("_tid", ckdb.UInt8).SetComment("用于区分trident不同的pipeline").SetIndex(ckdb.IndexNone))
	if code&ACLGID != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("acl_gid", ckdb.UInt16).SetComment("ACL组ID"))
	}
	if code&AZID != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("az_id", ckdb.UInt16).SetComment("可用区ID"))
	}
	if code&AZIDPath != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("az_id_0", ckdb.UInt16).SetComment("ip4/6_0对应的可用区ID"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("az_id_1", ckdb.UInt16).SetComment("ip4/6_1对应的可用区ID"))
	}

	if code&Direction != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("role", ckdb.UInt8).SetComment("统计量对应的流方向. 0: ip为客户端, 1: ip为服务端"))
	}

	if code&GPID != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("gprocess_id", ckdb.UInt32).SetComment("全局进程ID"))
	}
	if code&GPIDPath != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("gprocess_id_0", ckdb.UInt32).SetComment("ip0对应的全局进程ID"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("gprocess_id_1", ckdb.UInt32).SetComment("ip1对应的全局进程ID"))
	}
	if code&HostID != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("host_id", ckdb.UInt16).SetComment("宿主机ID"))
	}
	if code&HostIDPath != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("host_id_0", ckdb.UInt16).SetComment("ip4/6_0对应的宿主机ID"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("host_id_1", ckdb.UInt16).SetComment("ip4/6_1对应的宿主机ID"))
	}
	if code&IP != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("ip4", ckdb.IPv4).SetComment("IPv4地址"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("ip6", ckdb.IPv6).SetComment("IPV6地址"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("is_ipv4", ckdb.UInt8).SetIndex(ckdb.IndexMinmax).SetComment("是否IPV4地址. 0: 否, ip6字段有效, 1: 是, ip4字段有效"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("tag_source", ckdb.UInt8).SetComment("tag来源"))
	}
	if code&IPPath != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("ip4_0", ckdb.IPv4))
		columns = append(columns, ckdb.NewColumnWithGroupBy("ip4_1", ckdb.IPv4))
		columns = append(columns, ckdb.NewColumnWithGroupBy("ip6_0", ckdb.IPv6))
		columns = append(columns, ckdb.NewColumnWithGroupBy("ip6_1", ckdb.IPv6))
		columns = append(columns, ckdb.NewColumnWithGroupBy("is_ipv4", ckdb.UInt8).SetIndex(ckdb.IndexMinmax))
		columns = append(columns, ckdb.NewColumnWithGroupBy("tag_source_0", ckdb.UInt8).SetComment("ip_0对应的tag来源"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("tag_source_1", ckdb.UInt8).SetComment("ip_1对应的tag来源"))
	}

	if code&IsKeyService != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("is_key_service", ckdb.UInt8).SetComment("是否属于关键服务0: 否, 1: 是").SetIndex(ckdb.IndexMinmax))
	}

	if code&L3Device != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("l3_device_id", ckdb.UInt32).SetComment("ip对应的资源ID"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("l3_device_type", ckdb.UInt8).SetComment("ip对应的资源类型"))
	}

	if code&L3DevicePath != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("l3_device_id_0", ckdb.UInt32).SetComment("ip4/6_0对应的资源ID"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("l3_device_id_1", ckdb.UInt32).SetComment("ip4/6_1对应的资源ID"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("l3_device_type_0", ckdb.UInt8).SetComment("ip4/6_0对应的资源类型"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("l3_device_type_1", ckdb.UInt8).SetComment("ip4/6_1对应的资源类型"))
	}

	if code&L3EpcID != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("l3_epc_id", ckdb.Int32).SetComment("ip对应的EPC ID"))
	}
	if code&L3EpcIDPath != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("l3_epc_id_0", ckdb.Int32).SetComment("ip4/6_0对应的EPC ID"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("l3_epc_id_1", ckdb.Int32).SetComment("ip4/6_1对应的EPC ID"))
	}
	if code&L7Protocol != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("l7_protocol", ckdb.UInt8).SetComment("应用协议0: unknown, 1: http, 2: dns, 3: mysql, 4: redis, 5: dubbo, 6: kafka"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("app_service", ckdb.LowCardinalityString))
		columns = append(columns, ckdb.NewColumnWithGroupBy("app_instance", ckdb.String))
		columns = append(columns, ckdb.NewColumnWithGroupBy("endpoint", ckdb.String))
	}

	if code&MAC != 0 {
		// 不存
		// columns = append(columns, ckdb.NewColumnWithGroupBy("mac", UInt64))
	}
	if code&MACPath != 0 {
		// 不存
		// columns = append(columns, ckdb.NewColumnWithGroupBy("mac_0", UInt64))
		// columns = append(columns, ckdb.NewColumnWithGroupBy("mac_1", UInt64))
	}

	if code&PodClusterID != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("pod_cluster_id", ckdb.UInt16).SetComment("ip对应的容器集群ID"))
	}

	if code&PodClusterIDPath != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("pod_cluster_id_0", ckdb.UInt16).SetComment("ip4/6_0对应的容器集群ID"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("pod_cluster_id_1", ckdb.UInt16).SetComment("ip4/6_1对应的容器集群ID"))
	}

	if code&PodGroupID != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("pod_group_id", ckdb.UInt32).SetComment("ip对应的容器工作负载ID"))
	}

	if code&PodGroupIDPath != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("pod_group_id_0", ckdb.UInt32).SetComment("ip4/6_0对应的容器工作负载ID"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("pod_group_id_1", ckdb.UInt32).SetComment("ip4/6_1对应的容器工作负载ID"))
	}

	if code&PodID != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("pod_id", ckdb.UInt32).SetComment("ip对应的容器POD ID"))
	}

	if code&PodIDPath != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("pod_id_0", ckdb.UInt32).SetComment("ip4/6_0对应的容器POD ID"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("pod_id_1", ckdb.UInt32).SetComment("ip4/6_1对应的容器POD ID"))
	}

	if code&PodNodeID != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("pod_node_id", ckdb.UInt32).SetComment("ip对应的容器节点ID"))
	}

	if code&PodNodeIDPath != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("pod_node_id_0", ckdb.UInt32).SetComment("ip4/6_0对应的容器节点ID"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("pod_node_id_1", ckdb.UInt32).SetComment("ip4/6_1对应的容器节点ID"))
	}

	if code&PodNSID != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("pod_ns_id", ckdb.UInt16).SetComment("ip对应的容器命名空间ID"))
	}

	if code&PodNSIDPath != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("pod_ns_id_0", ckdb.UInt16).SetComment("ip4/6_0对应的容器命名空间ID"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("pod_ns_id_1", ckdb.UInt16).SetComment("ip4/6_1对应的容器命名空间ID"))
	}

	if code&Protocol != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("protocol", ckdb.UInt8).SetComment("0: 非IP包, 1-255: ip协议号(其中 1:icmp 6:tcp 17:udp)"))
	}

	if code&RegionID != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("region_id", ckdb.UInt16).SetComment("ip对应的云平台区域ID"))
	}
	if code&RegionIDPath != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("region_id_0", ckdb.UInt16).SetComment("ip4/6_0对应的云平台区域ID"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("region_id_1", ckdb.UInt16).SetComment("ip4/6_1对应的云平台区域ID"))
	}

	if code&Resource != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("auto_instance_id", ckdb.UInt32).SetComment("ip对应的容器pod优先的资源ID, 取值优先级为pod_id -> pod_node_id -> l3_device_id"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("auto_instance_type", ckdb.UInt8).SetComment("资源类型, 0:IP地址(无法对应资源), 0-100:deviceType(其中10:pod, 14:podNode), 101-200:DeepFlow抽象出的资源(其中101:podGroup, 102:service), 201-255:其他"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("auto_service_id", ckdb.UInt32).SetComment("ip对应的服务优先的资源ID, 取值优先级为service_id  -> pod_node_id -> l3_device_id"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("auto_service_type", ckdb.UInt8).SetComment("资源类型, 0:IP地址(无法对应资源), 0-100:deviceType(其中10:pod, 14:podNode), 101-200:DeepFlow抽象出的资源(其中101:podGroup, 102:service), 201-255:其他"))
	}
	if code&ResourcePath != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("auto_instance_id_0", ckdb.UInt32).SetComment("ip0对应的容器pod优先的资源ID, 取值优先级为pod_id -> pod_node_id -> l3_device_id"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("auto_instance_type_0", ckdb.UInt8).SetComment("资源类型, 0:IP地址(无法对应资源), 0-100:deviceType(其中10:pod, 14:podNode), 101-200:DeepFlow抽象出的资源(其中101:podGroup, 102:service), 201-255:其他"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("auto_service_id_0", ckdb.UInt32).SetComment("ip0对应的服务优先的资源ID, 取值优先级为service_id  -> pod_node_id -> l3_device_id"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("auto_service_type_0", ckdb.UInt8).SetComment("资源类型, 0:IP地址(无法对应资源), 0-100:deviceType(其中10:pod, 14:podNode), 101-200:DeepFlow抽象出的资源(其中101:podGroup, 102:service), 201-255:其他"))

		columns = append(columns, ckdb.NewColumnWithGroupBy("auto_instance_id_1", ckdb.UInt32).SetComment("ip1对应的容器pod优先的资源ID, 取值优先级为pod_id -> pod_node_id -> l3_device_id"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("auto_instance_type_1", ckdb.UInt8).SetComment("资源类型, 0:IP地址(无法对应资源), 0-100:deviceType(其中10:pod, 14:podNode), 101-200:DeepFlow抽象出的资源(其中101:podGroup, 102:service), 201-255:其他"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("auto_service_id_1", ckdb.UInt32).SetComment("ip1对应的服务优先的资源ID, 取值优先级为service_id  -> pod_node_id -> l3_device_id"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("auto_service_type_1", ckdb.UInt8).SetComment("资源类型, 0:IP地址(无法对应资源), 0-100:deviceType(其中10:pod, 14:podNode), 101-200:DeepFlow抽象出的资源(其中101:podGroup, 102:service), 201-255:其他"))
	}

	if code&SignalSource != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("signal_source", ckdb.UInt16).SetComment("信号源"))
	}
	if code&ServiceID != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("service_id", ckdb.UInt32).SetComment("ip对应的服务ID"))
	}
	if code&ServiceIDPath != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("service_id_0", ckdb.UInt32).SetComment("ip4/6_0对应的服务ID"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("service_id_1", ckdb.UInt32).SetComment("ip4/6_1对应的服务ID"))
	}

	if code&ServerPort != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("server_port", ckdb.UInt16).SetIndex(ckdb.IndexSet).SetComment("服务端端口"))
	}

	if code&SubnetID != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("subnet_id", ckdb.UInt16).SetComment("ip对应的子网ID(0: 未找到)"))
	}
	if code&SubnetIDPath != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("subnet_id_0", ckdb.UInt16).SetComment("ip4/6_0对应的子网ID(0: 未找到)"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("subnet_id_1", ckdb.UInt16).SetComment("ip4/6_1对应的子网ID(0: 未找到)"))
	}
	if code&TagType != 0 && code&TagValue != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("tag_type", ckdb.UInt8).SetComment("1: 省份(仅针对geo库), 2: TCP Flag(仅针对packet库), 3: 播送类型(仅针对packet库), 4: 隧道分发点ID(仅针对flow库), 5: TTL, 6: 包长范围"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("tag_value", ckdb.LowCardinalityString).SetComment("tag_type对应的具体值. tag_type=1: 省份, tag_type=2: TCP包头的Flag字段, tag_type=3: 播送类性(broadcast: 广播, multicast: 组播, unicast: 未知单播), tag_type=4: 隧道分发点ID, tag_type=5: TTL的值, tag_type=6: 包长范围值"))
	}
	if code&TAPPort != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("tap_port_type", ckdb.UInt8).SetIndex(ckdb.IndexNone).SetComment("采集位置标识类型 0: MAC，1: IPv4, 2: IPv6, 3: ID, 4: NetFlow, 5: SFlow"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("tunnel_type", ckdb.UInt8).SetIndex(ckdb.IndexNone).SetComment("隧道封装类型 0：--，1：VXLAN，2：IPIP，3：GRE"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("tap_port", ckdb.UInt32).SetIndex(ckdb.IndexNone).SetComment("采集位置标识 若tap_type为3: 虚拟网络流量源, 表示虚拟接口MAC地址低4字节 00000000~FFFFFFFF"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("nat_source", ckdb.UInt8).SetComment("0: NONE, 1: VIP, 2: TOA"))
	}
	if code&TAPSide != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("tap_side", ckdb.LowCardinalityString).SetComment("流量采集位置(c: 客户端(0侧)采集, s: 服务端(1侧)采集)"))
	}
	if code&TAPType != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("tap_type", ckdb.UInt8).SetComment("流量采集点(1-2,4-255: 接入网络流量, 3: 虚拟网络流量)"))
	}
	if code&VTAPID != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("vtap_id", ckdb.UInt16).SetComment("采集器的ID"))
	}

	return columns
}

// 顺序需要和GenTagColumns的一致
func (t *Tag) WriteBlock(block *ckdb.Block, time uint32) {
	code := t.Code

	block.WriteDateTime(time)
	block.Write(t.GlobalThreadID)

	if code&ACLGID != 0 {
		block.Write(t.ACLGID)
	}
	if code&AZID != 0 {
		block.Write(t.AZID)
	}

	if code&AZIDPath != 0 {
		block.Write(t.AZID, t.AZID1)
	}

	if code&Direction != 0 {
		if t.Direction.IsClientToServer() {
			// 0: client, 1: server
			block.Write(uint8(0))
		} else {
			block.Write(uint8(1))
		}
	}

	if code&GPID != 0 {
		block.Write(t.GPID)
	}
	if code&GPIDPath != 0 {
		block.Write(t.GPID, t.GPID1)
	}
	if code&HostID != 0 {
		block.Write(t.HostID)
	}
	if code&HostIDPath != 0 {
		block.Write(t.HostID, t.HostID1)
	}
	if code&IP != 0 {
		block.WriteIPv4(t.IP)
		block.WriteIPv6(t.IP6)
		block.Write(1 - t.IsIPv6)
		block.Write(t.TagSource)
	}
	if code&IPPath != 0 {
		block.WriteIPv4(t.IP)
		block.WriteIPv4(t.IP1)
		block.WriteIPv6(t.IP6)
		block.WriteIPv6(t.IP61)
		block.Write(1 - t.IsIPv6)
		block.Write(t.TagSource)
		block.Write(t.TagSource1)
	}

	if code&IsKeyService != 0 {
		block.Write(t.IsKeyService)
	}

	if code&L3Device != 0 {
		block.Write(t.L3DeviceID, uint8(t.L3DeviceType))
	}
	if code&L3DevicePath != 0 {
		block.Write(t.L3DeviceID, t.L3DeviceID1, uint8(t.L3DeviceType), uint8(t.L3DeviceType1))
	}

	if code&L3EpcID != 0 {
		block.Write(t.L3EpcID)
	}
	if code&L3EpcIDPath != 0 {
		block.Write(t.L3EpcID, t.L3EpcID1)
	}

	if code&L7Protocol != 0 {
		block.Write(uint8(t.L7Protocol))
		block.Write(t.AppService)
		block.Write(t.AppInstance)
		block.Write(t.Endpoint)
	}

	if code&MAC != 0 {
		// 不存
		// block.Write(t.MAC)
	}
	if code&MACPath != 0 {
		// 不存
		// block.Writes(t.MAC, t.MAC1)
	}

	if code&PodClusterID != 0 {
		block.Write(t.PodClusterID)
	}

	if code&PodClusterIDPath != 0 {
		block.Write(t.PodClusterID, t.PodClusterID1)
	}

	if code&PodGroupID != 0 {
		block.Write(t.PodGroupID)
	}

	if code&PodGroupIDPath != 0 {
		block.Write(t.PodGroupID, t.PodGroupID1)
	}

	if code&PodID != 0 {
		block.Write(t.PodID)
	}

	if code&PodIDPath != 0 {
		block.Write(t.PodID, t.PodID1)
	}

	if code&PodNodeID != 0 {
		block.Write(t.PodNodeID)
	}

	if code&PodNodeIDPath != 0 {
		block.Write(t.PodNodeID, t.PodNodeID1)
	}

	if code&PodNSID != 0 {
		block.Write(t.PodNSID)
	}
	if code&PodNSIDPath != 0 {
		block.Write(t.PodNSID, t.PodNSID1)
	}
	if code&Protocol != 0 {
		block.Write(uint8(t.Protocol))
	}

	if code&RegionID != 0 {
		block.Write(t.RegionID)
	}
	if code&RegionIDPath != 0 {
		block.Write(t.RegionID, t.RegionID1)
	}

	if code&Resource != 0 || code&ResourcePath != 0 {
		block.Write(
			t.AutoInstanceID,
			t.AutoInstanceType,
			t.AutoServiceID,
			t.AutoServiceType,
		)
	}

	if code&ResourcePath != 0 {
		block.Write(
			t.AutoInstanceID1,
			t.AutoInstanceType1,
			t.AutoServiceID1,
			t.AutoServiceType1,
		)
	}

	if code&SignalSource != 0 {
		block.Write(t.SignalSource)
	}

	if code&ServiceID != 0 {
		block.Write(t.ServiceID)
	}
	if code&ServiceIDPath != 0 {
		block.Write(t.ServiceID, t.ServiceID1)
	}

	if code&ServerPort != 0 {
		block.Write(t.ServerPort)
	}

	if code&SubnetID != 0 {
		block.Write(t.SubnetID)
	}
	if code&SubnetIDPath != 0 {
		block.Write(t.SubnetID, t.SubnetID1)
	}
	if code&TagType != 0 && code&TagValue != 0 {
		block.Write(t.TagType)
		switch t.TagType {
		case TAG_TYPE_TUNNEL_IP_ID:
			block.Write(strconv.FormatUint(uint64(t.TagValue), 10))
		}
	}
	if code&TAPPort != 0 {
		tapPort, tapPortType, natSource, tunnelType := t.TAPPort.SplitToPortTypeTunnel()
		block.Write(tapPortType, uint8(tunnelType), tapPort, uint8(natSource))
	}
	if code&TAPSide != 0 {
		block.Write(t.TAPSide.String())
	}
	if code&TAPType != 0 {
		block.Write(uint8(t.TAPType))
	}
	if code&VTAPID != 0 {
		block.Write(t.VTAPID)
	}
}

const TAP_PORT_STR_LEN = 8

func putTAPPort(bs []byte, tapPort uint64) int {
	copy(bs, "00000000")
	s := strconv.FormatUint(tapPort, 16)
	if TAP_PORT_STR_LEN >= len(s) {
		copy(bs[TAP_PORT_STR_LEN-len(s):], s)
	} else {
		copy(bs, s[len(s)-TAP_PORT_STR_LEN:])
	}
	return TAP_PORT_STR_LEN
}

func (t *Tag) String() string {
	var buf strings.Builder
	buf.WriteString("fields:")
	buf.WriteString(t.ToKVString())
	if t.Code&MAC != 0 {
		buf.WriteString(",mac=")
		buf.WriteString(utils.Uint64ToMac(t.MAC).String())
	}
	if t.Code&MACPath != 0 {
		buf.WriteString(",mac_0=")
		buf.WriteString(utils.Uint64ToMac(t.MAC).String())
		buf.WriteString(",mac_1=")
		buf.WriteString(utils.Uint64ToMac(t.MAC1).String())
	}

	buf.WriteString(" code:")
	buf.WriteString(fmt.Sprintf("x%016x", t.Code))
	return buf.String()
}

func (t *Tag) ReadFromPB(p *pb.MiniTag) {
	t.Code = Code(p.Code)
	t.IsIPv6 = uint8(p.Field.IsIpv6)
	if t.IsIPv6 != 0 {
		if t.IP6 == nil {
			t.IP6 = make([]byte, 16)
		}
		copy(t.IP6, p.Field.Ip[:net.IPv6len])
		if t.Code&IPPath != 0 {
			if t.IP61 == nil {
				t.IP61 = make([]byte, 16)
			}
			copy(t.IP61, p.Field.Ip1[:net.IPv6len])
		}
	} else {
		t.IP = binary.BigEndian.Uint32(p.Field.Ip[:net.IPv4len])
		if t.Code&IPPath != 0 {
			t.IP1 = binary.BigEndian.Uint32(p.Field.Ip1[:net.IPv4len])
		}
	}
	t.MAC = p.Field.Mac
	t.MAC1 = p.Field.Mac1
	// The range of EPC ID is [-2,65533], if EPC ID < -2 needs to be transformed into the range.
	t.L3EpcID = MarshalInt32WithSpecialID(p.Field.L3EpcId)
	t.L3EpcID1 = MarshalInt32WithSpecialID(p.Field.L3EpcId1)
	t.Direction = DirectionEnum(p.Field.Direction)
	t.TAPSide = TAPSideEnum(p.Field.TapSide)
	t.Protocol = layers.IPProtocol(p.Field.Protocol)
	t.ACLGID = uint16(p.Field.AclGid)
	t.ServerPort = uint16(p.Field.ServerPort)
	t.VTAPID = uint16(p.Field.VtapId)
	t.TAPPort = datatype.TapPort(p.Field.TapPort)
	t.TAPType = TAPTypeEnum(p.Field.TapType)
	t.L7Protocol = datatype.L7Protocol(p.Field.L7Protocol)
	t.AppService = p.Field.AppService
	t.AppInstance = p.Field.AppInstance
	t.Endpoint = p.Field.Endpoint
	// In order to be compatible with the old version of Agent data, GPID needs to be set
	if t.Code&IPPath != 0 {
		t.Code |= GPIDPath
		t.Code |= SignalSource
	} else if t.Code != VTAP_ACL {
		t.Code |= GPID
		t.Code |= SignalSource
	}
	t.GPID = p.Field.Gpid
	t.GPID1 = p.Field.Gpid1

	if p.Field.PodId != 0 {
		if t.Code&IPPath != 0 && t.Direction.IsServerToClient() {
			t.PodID1 = p.Field.PodId
		} else {
			t.PodID = p.Field.PodId
		}
	}
	t.SignalSource = uint16(p.Field.SignalSource)
	t.TagType = uint8(p.Field.TagType)
	t.TagValue = uint16(p.Field.TagValue)
}

func (t *Tag) SetID(id string) {
	t.id = id
}

func (t *Tag) GetCode() uint64 {
	return uint64(t.Code)
}

func (t *Tag) SetCode(code uint64) {
	t.Code = Code(code)
}

func (t *Tag) SetTID(tid uint8) {
	t.GlobalThreadID = tid
}

func (t *Tag) GetTAPType() uint8 {
	return uint8(t.TAPType)
}

const (
	SUFFIX_ACL = 1 + iota
	SUFFIX_EDGE
	SUFFIX_ACL_EDGE
	SUFFIX_PORT
	SUFFIX_ACL_PORT
	SUFFIX_EDGE_PORT
	SUFFIX_ACL_EDGE_PORT
)

var DatabaseSuffix = [...]string{
	0:                    "",               // 000
	SUFFIX_ACL:           "_acl",           // 001
	SUFFIX_EDGE:          "_edge",          // 010
	SUFFIX_ACL_EDGE:      "_acl_edge",      // 011
	SUFFIX_PORT:          "_port",          // 100
	SUFFIX_ACL_PORT:      "_acl_port",      // 101
	SUFFIX_EDGE_PORT:     "_edge_port",     // 110
	SUFFIX_ACL_EDGE_PORT: "_acl_edge_port", // 111
}

func (t *Tag) DatabaseSuffixID() int {
	code := 0
	if t.Code&ACLGID != 0 {
		code |= SUFFIX_ACL // 0x1
	}
	if t.Code.HasEdgeTagField() {
		code |= SUFFIX_EDGE // 0x2
	}
	if t.Code&ServerPort != 0 {
		code |= SUFFIX_PORT // 0x4
	}
	return code
}

func (t *Tag) DatabaseSuffix() string {
	return DatabaseSuffix[t.DatabaseSuffixID()]
}

var fieldPool = pool.NewLockFreePool(func() interface{} {
	return &Field{}
})

func AcquireField() *Field {
	return fieldPool.Get().(*Field)
}

func ReleaseField(field *Field) {
	if field == nil {
		return
	}
	*field = Field{}
	fieldPool.Put(field)
}

func CloneField(field *Field) *Field {
	newField := AcquireField()
	*newField = *field
	if field.IP6 != nil {
		newField.IP6 = make(net.IP, len(field.IP6))
		copy(newField.IP6, field.IP6)
	}
	if field.IP61 != nil {
		newField.IP61 = make(net.IP, len(field.IP61))
		copy(newField.IP61, field.IP61)
	}
	return newField
}

var tagPool = pool.NewLockFreePool(func() interface{} {
	return &Tag{}
})

func AcquireTag() *Tag {
	return tagPool.Get().(*Tag)
}

// ReleaseTag 需要释放Tag拥有的Field
func ReleaseTag(tag *Tag) {
	if tag == nil {
		return
	}
	if tag.Field != nil {
		ReleaseField(tag.Field)
	}
	*tag = Tag{}
	tagPool.Put(tag)
}

// CloneTag 需要复制Tag拥有的Field
func CloneTag(tag *Tag) *Tag {
	newTag := AcquireTag()
	newTag.Field = CloneField(tag.Field)
	newTag.Code = tag.Code
	newTag.id = tag.id
	return newTag
}

func (t *Tag) Clone() Tagger {
	return CloneTag(t)
}

func (t *Tag) Release() {
	ReleaseTag(t)
}

func (f *Field) NewTag(c Code) *Tag {
	tag := AcquireTag()
	tag.Field = CloneField(f)
	tag.Code = c
	tag.id = ""
	return tag
}

func parseUint(s string, base int, bitSize int) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	return strconv.ParseUint(s, base, bitSize)
}

// EncodeTagToPromLabels 将 Tag 编码成 prom Label
func EncodeTagToPromLabels(tag *Tag) []prompb.Label {
	if tag == nil {
		return nil
	}
	buffer := make([]byte, MAX_STRING_LENGTH)
	size := tag.MarshalTo(buffer)
	return encodePromLabels(buffer[:size])
}
