package zerodoc

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"

	"github.com/google/gopacket/layers"
	"gitlab.yunshan.net/yunshan/droplet-libs/app"
	"gitlab.yunshan.net/yunshan/droplet-libs/ckdb"
	"gitlab.yunshan.net/yunshan/droplet-libs/codec"
	"gitlab.yunshan.net/yunshan/droplet-libs/pool"
	"gitlab.yunshan.net/yunshan/droplet-libs/utils"
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
	BusinessIDs
	GroupIDs
	ServiceID // 1<<15 后续不能再添加了
)

const (
	IPPath Code = 0x10000 << iota // 1 << 16
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
	BusinessIDsPath
	GroupIDsPath
	ServiceIDPath // 1<<31
)

const (
	Direction Code = 0x100000000 << iota // 1 << 32
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
)

const (
	TagType  Code = 1 << 62
	TagValue Code = 1 << 63
)

func (c Code) HasEdgeTagField() bool {
	return c&0xffff0000 != 0
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
	NodeSide SideType = (iota + 1) << 2
	HypervisorSide
	GatewayHypervisorSide
	GatewaySide
)

type DirectionEnum uint8

const (
	_CLIENT_SERVER_MASK = 0x3
	_SIDE_TYPE_MASK     = 0xfc
)

const (
	_ DirectionEnum = iota
	ClientToServer
	ServerToClient

	// 以下类型为转换tapside而增加，在写入db时均记为c2s或s2c
	ClientNodeToServer              = ClientToServer | DirectionEnum(NodeSide)              // 客户端容器节点，路由、SNAT、隧道
	ServerNodeToClient              = ServerToClient | DirectionEnum(NodeSide)              // 服务端容器节点，路由、SNAT、隧道
	ClientHypervisorToServer        = ClientToServer | DirectionEnum(HypervisorSide)        // 客户端宿主机，隧道
	ServerHypervisorToClient        = ServerToClient | DirectionEnum(HypervisorSide)        // 服务端宿主机，隧道
	ClientGatewayHypervisorToServer = ClientToServer | DirectionEnum(GatewayHypervisorSide) // 客户端网关宿主机
	ServerGatewayHypervisorToClient = ServerToClient | DirectionEnum(GatewayHypervisorSide) // 服务端网关宿主机
	ClientGatewayToServer           = ClientToServer | DirectionEnum(GatewaySide)           // 客户端网关（特指VIP机制的SLB，例如微软云MUX等）, Mac地址对应的接口为vip设备
	ServerGatewayToClient           = ServerToClient | DirectionEnum(GatewaySide)           // 服务端网关（特指VIP机制的SLB，例如微软云MUX等）, Mac地址对应的接口为vip设备
)

func (d DirectionEnum) IsClientToServer() bool {
	return d&_CLIENT_SERVER_MASK == ClientToServer
}

func (d DirectionEnum) IsServerToClient() bool {
	return d&_CLIENT_SERVER_MASK == ServerToClient
}

func (d DirectionEnum) IsGateway() bool {
	return SideType(d&_SIDE_TYPE_MASK) == GatewaySide
}

type TAPSideEnum uint8

const (
	Rest TAPSideEnum = iota
	Client
	Server
	ClientNode              = Client | TAPSideEnum(NodeSide)
	ServerNode              = Server | TAPSideEnum(NodeSide)
	ClientHypervisor        = Client | TAPSideEnum(HypervisorSide)
	ServerHypervisor        = Server | TAPSideEnum(HypervisorSide)
	ClientGatewayHypervisor = Client | TAPSideEnum(GatewayHypervisorSide)
	ServerGatewayHypervisor = Server | TAPSideEnum(GatewayHypervisorSide)
	ClientGateway           = Client | TAPSideEnum(GatewaySide)
	ServerGateway           = Server | TAPSideEnum(GatewaySide)
)

var TAPSideEnumsString = []string{
	Rest:                    "rest",
	Client:                  "c",
	Server:                  "s",
	ClientNode:              "c-nd",
	ServerNode:              "s-nd",
	ClientHypervisor:        "c-hv",
	ServerHypervisor:        "s-hv",
	ClientGatewayHypervisor: "c-gw-hv",
	ServerGatewayHypervisor: "s-gw-hv",
	ClientGateway:           "c-gw",
	ServerGateway:           "s-gw",
}

func (s TAPSideEnum) String() string {
	return TAPSideEnumsString[s]
}

func (d DirectionEnum) ToTAPSide() TAPSideEnum {
	return TAPSideEnum(d)
}

type TAPTypeEnum uint8

const (
	ISP0 TAPTypeEnum = iota
	ISP1
	ISP2
	ToR
	// 4~255 ISP
)

const (
	_ = 1 + iota // TAG_TYPE_PROVINCE = 1 + iota，已删除
	_            // TAG_TYPE_TCP_FLAG，已删除
	_            // TAG_TYPE_CAST_TYPE，已删除
	TAG_TYPE_TUNNEL_IP_ID
	_ // TAG_TYPE_TTL，已删除
	_ // TAG_TYPE_PACKET_SIZE，已删除
)

type Field struct {
	// 注意字节对齐！

	// 用于区分不同的trident及其不同的pipeline，用于如下场景：
	//   - trident和roze之间的数据传输
	//   - roze写入influxdb，作用类似_id，序列化为_tid
	GlobalThreadID uint8

	IP6          net.IP // FIXME: 合并IP6和IP
	MAC          uint64
	IP           uint32
	L3EpcID      int16 // (8B)
	L3DeviceID   uint32
	L3DeviceType DeviceType
	RegionID     uint16
	SubnetID     uint16
	HostID       uint16
	PodNodeID    uint32
	AZID         uint16
	PodGroupID   uint32
	PodNSID      uint16
	PodID        uint32
	PodClusterID uint16
	BusinessIDs  []uint16
	GroupIDs     []uint16
	ServiceID    uint32

	MAC1          uint64
	IP61          net.IP // FIXME: 合并IP61和IP1
	IP1           uint32
	L3EpcID1      int16 // (8B)
	L3DeviceID1   uint32
	L3DeviceType1 DeviceType // (+1B=8B)
	RegionID1     uint16
	SubnetID1     uint16 // (8B)
	HostID1       uint16
	PodNodeID1    uint32
	AZID1         uint16
	PodGroupID1   uint32
	PodNSID1      uint16
	PodID1        uint32
	PodClusterID1 uint16
	BusinessIDs1  []uint16
	GroupIDs1     []uint16
	ServiceID1    uint32

	ACLGID       uint16
	Direction    DirectionEnum
	Protocol     layers.IPProtocol
	ServerPort   uint16
	VTAPID       uint16
	TAPPort      uint32
	TAPSide      TAPSideEnum
	TAPType      TAPTypeEnum
	IsIPv6       uint8 // (8B) 与IP/IP6是共生字段
	IsKeyService uint8

	TagType  uint8
	TagValue uint16
}

func newMetricsMinuteTable(id MetricsDBID, engine ckdb.EngineType, version string) *ckdb.Table {
	timeKey := "time"
	cluster := ckdb.DF_CLUSTER
	if engine == ckdb.ReplicatedMergeTree {
		cluster = ckdb.DF_REPLICATED_CLUSTER
	}

	var orderKeys []string
	code := metricsDBCodes[id]
	if code&L3EpcID != 0 {
		orderKeys = []string{"l3_epc_id", "ip4", "ip6"}
	} else if code&L3EpcIDPath != 0 {
		orderKeys = []string{"l3_epc_id_1", "ip4_1", "ip6_1", "l3_epc_id_0", "ip4_0", "ip6_0"}
	} else if code&ACLGID != 0 {
		orderKeys = []string{"acl_gid"}
	}
	if code&ServerPort != 0 {
		orderKeys = append(orderKeys, "server_port")
	}
	orderKeys = append(orderKeys, timeKey)

	var meterColumns []*ckdb.Column
	switch id {
	case VTAP_FLOW, VTAP_FLOW_PORT, VTAP_FLOW_EDGE, VTAP_FLOW_EDGE_PORT:
		meterColumns = FlowMeterColumns()
	case VTAP_ACL:
		meterColumns = UsageMeterColumns()
	}

	return &ckdb.Table{
		Version:         version,
		ID:              uint8(id),
		Database:        id.DBName(),
		LocalName:       ckdb.LOCAL_1M,
		GlobalName:      ckdb.GLOBAL_1M,
		Columns:         append(genTagColumns(metricsDBCodes[id]), meterColumns...),
		TimeKey:         timeKey,
		TTL:             7, // 分钟数据默认保留7天
		PartitionFunc:   ckdb.TimeFuncDay,
		Engine:          engine,
		Cluster:         cluster,
		OrderKeys:       orderKeys,
		PrimaryKeyCount: len(orderKeys),
	}
}

// 由分钟表生成秒表
func newMetricsSecondTable(minuteTable *ckdb.Table) *ckdb.Table {
	t := *minuteTable
	t.ID = minuteTable.ID + uint8(VTAP_FLOW_1S)
	t.LocalName = ckdb.LOCAL_1S
	t.GlobalName = ckdb.GLOBAL_1S
	t.TTL = 1 // 秒数据默认保存1天
	t.PartitionFunc = ckdb.TimeFuncFourHour
	t.Engine = ckdb.MergeTree // 秒级数据不用支持使用replica
	t.Cluster = ckdb.DF_CLUSTER

	return &t
}

var metricsTables []*ckdb.Table

func GetMetricsTables(engine ckdb.EngineType, version string) []*ckdb.Table {
	if metricsTables != nil {
		return metricsTables
	}

	minuteTables := []*ckdb.Table{}
	for i := VTAP_FLOW; i < VTAP_FLOW_1S; i++ {
		minuteTables = append(minuteTables, newMetricsMinuteTable(i, engine, version))
	}
	secondTables := []*ckdb.Table{}
	for i := VTAP_FLOW_1S; i < VTAP_DB_ID_MAX; i++ {
		secondTables = append(secondTables, newMetricsSecondTable(minuteTables[i-VTAP_FLOW_1S]))
	}
	metricsTables = append(minuteTables, secondTables...)
	return metricsTables
}

type MetricsDBID uint8

const (
	VTAP_FLOW MetricsDBID = iota
	VTAP_FLOW_PORT
	VTAP_FLOW_EDGE
	VTAP_FLOW_EDGE_PORT

	VTAP_ACL

	VTAP_FLOW_1S
	VTAP_FLOW_PORT_1S
	VTAP_FLOW_EDGE_1S
	VTAP_FLOW_EDGE_PORT_1S

	VTAP_DB_ID_MAX
)

func (i MetricsDBID) DBName() string {
	if i >= VTAP_FLOW_1S {
		return metricsDBNames[i-VTAP_FLOW_1S]
	}
	return metricsDBNames[i]
}

func (i MetricsDBID) DBCode() Code {
	if i >= VTAP_FLOW_1S {
		return metricsDBCodes[i-VTAP_FLOW_1S]
	}
	return metricsDBCodes[i]
}

var metricsDBNames = []string{
	VTAP_FLOW:           "vtap_flow",
	VTAP_FLOW_PORT:      "vtap_flow_port",
	VTAP_FLOW_EDGE:      "vtap_flow_edge",
	VTAP_FLOW_EDGE_PORT: "vtap_flow_edge_port",

	VTAP_ACL: "vtap_acl",
}

func MetricsDBNameToID(name string) MetricsDBID {
	for i, n := range metricsDBNames {
		if n == name {
			return MetricsDBID(i)
		}
	}
	return VTAP_DB_ID_MAX
}

const (
	BaseCode     = AZID | HostID | IP | L3Device | L3EpcID | PodClusterID | PodGroupID | PodID | PodNodeID | PodNSID | RegionID | SubnetID | TAPType | VTAPID | BusinessIDs | GroupIDs | ServiceID
	BasePathCode = AZIDPath | HostIDPath | IPPath | L3DevicePath | L3EpcIDPath | PodClusterIDPath | PodGroupIDPath | PodIDPath | PodNodeIDPath | PodNSIDPath | RegionIDPath | SubnetIDPath | TAPSide | TAPType | VTAPID | BusinessIDsPath | GroupIDsPath | ServiceIDPath
	BasePortCode = Protocol | ServerPort | IsKeyService
)

var metricsDBCodes = []Code{
	VTAP_FLOW:           BaseCode | Direction | Protocol,
	VTAP_FLOW_PORT:      BaseCode | BasePortCode | Direction,
	VTAP_FLOW_EDGE:      BasePathCode | Protocol | TAPPort,
	VTAP_FLOW_EDGE_PORT: BasePathCode | BasePortCode | TAPPort,
	VTAP_ACL:            ACLGID | TagType | TagValue | VTAPID,
}

type Tag struct {
	*Field
	Code
	id string
}

func (t *Tag) ToKVString() string {
	buffer := make([]byte, app.MAX_DOC_STRING_LENGTH)
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

func marshalInt32WithSpecialID(v int16) int32 {
	switch v {
	case ID_OTHER:
		fallthrough
	case ID_INTERNET:
		return int32(v)
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
	if t.Code&BusinessIDs != 0 {
		offset += copy(b[offset:], ",business_ids=")
		offset += copy(b[offset:], marshalUint16s(t.BusinessIDs))
	}
	if t.Code&BusinessIDsPath != 0 {
		offset += copy(b[offset:], ",business_ids_0=")
		offset += copy(b[offset:], marshalUint16s(t.BusinessIDs))
		offset += copy(b[offset:], ",business_ids_1=")
		offset += copy(b[offset:], marshalUint16s(t.BusinessIDs1))
	}

	if t.Code&Direction != 0 {
		if t.Direction.IsClientToServer() {
			offset += copy(b[offset:], ",direction=c2s")
		} else if t.Direction.IsServerToClient() {
			offset += copy(b[offset:], ",direction=s2c")
		}
	}
	if t.Code&GroupIDs != 0 {
		offset += copy(b[offset:], ",group_ids=")
		offset += copy(b[offset:], marshalUint16s(t.GroupIDs))
	}
	if t.Code&GroupIDsPath != 0 {
		offset += copy(b[offset:], ",group_ids_0=")
		offset += copy(b[offset:], marshalUint16s(t.GroupIDs))
		offset += copy(b[offset:], ",group_ids_1=")
		offset += copy(b[offset:], marshalUint16s(t.GroupIDs1))
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
		offset += copy(b[offset:], marshalUint16WithSpecialID(t.L3EpcID))
	}
	if t.Code&L3EpcIDPath != 0 {
		offset += copy(b[offset:], ",l3_epc_id_0=")
		offset += copy(b[offset:], marshalUint16WithSpecialID(t.L3EpcID))
		offset += copy(b[offset:], ",l3_epc_id_1=")
		offset += copy(b[offset:], marshalUint16WithSpecialID(t.L3EpcID1))
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
		offset += putTAPPort(b[offset:], t.TAPPort)
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
	for i, code := range metricsDBCodes {
		// 有时会有MAC,MACPath字段，需要先排除再比较
		if t.Code&^MAC&^MACPath == code {
			if isSecond {
				return uint8(i) + uint8(VTAP_FLOW_1S), nil
			}
			return uint8(i), nil
		}
	}
	return 0, fmt.Errorf("not match table, tag code is 0x%x is second %v", t.Code, isSecond)
}

// 顺序需要和WriteBlock中一致, 目前time排第一位，其他按字段名字典排序
func genTagColumns(code Code) []*ckdb.Column {
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

	if code&BusinessIDs != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("business_ids", ckdb.ArrayUInt16).SetComment("ip对应的业务ID列表"))
	}
	if code&BusinessIDsPath != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("business_ids_0", ckdb.ArrayUInt16).SetComment("ip4/6_0对应的的业务ID列表"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("business_ids_1", ckdb.ArrayUInt16).SetComment("ip4/6_1对应的的业务ID列表"))
	}

	if code&Direction != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("direction", ckdb.LowCardinalityString).SetComment("统计量对应的流方向. c2s: ip为客户端, s2c: ip为服务端"))
	}

	if code&GroupIDs != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("group_ids", ckdb.ArrayUInt16).SetComment("ip对应的资源组ID列表"))
	}
	if code&GroupIDsPath != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("group_ids_0", ckdb.ArrayUInt16).SetComment("ip4/6_0对应的资源组ID列表"))
		columns = append(columns, ckdb.NewColumnWithGroupBy("group_ids_1", ckdb.ArrayUInt16).SetComment("ip4/6_1对应的资源组ID列表"))
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
	}
	if code&IPPath != 0 {
		columns = append(columns, ckdb.NewColumnWithGroupBy("ip4_0", ckdb.IPv4))
		columns = append(columns, ckdb.NewColumnWithGroupBy("ip4_1", ckdb.IPv4))
		columns = append(columns, ckdb.NewColumnWithGroupBy("ip6_0", ckdb.IPv6))
		columns = append(columns, ckdb.NewColumnWithGroupBy("ip6_1", ckdb.IPv6))
		columns = append(columns, ckdb.NewColumnWithGroupBy("is_ipv4", ckdb.UInt8).SetIndex(ckdb.IndexMinmax))
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
		columns = append(columns, ckdb.NewColumnWithGroupBy("tap_port", ckdb.UInt32).SetIndex(ckdb.IndexNone).SetComment("采集网口标识 若tap_type为3: 虚拟网络流量源, 表示虚拟接口MAC地址低4字节 00000000~FFFFFFFF"))
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

// 顺序需要和genTagColumns的一致
func (t *Tag) WriteBlock(block *ckdb.Block, time uint32) error {
	code := t.Code

	if err := block.WriteUInt32(time); err != nil {
		return err
	}

	if err := block.WriteUInt8(t.GlobalThreadID); err != nil {
		return err
	}

	if code&ACLGID != 0 {
		if err := block.WriteUInt16(t.ACLGID); err != nil {
			return err
		}
	}
	if code&AZID != 0 {
		if err := block.WriteUInt16(t.AZID); err != nil {
			return err
		}
	}

	if code&AZIDPath != 0 {
		if err := block.WriteUInt16(t.AZID); err != nil {
			return err
		}
		if err := block.WriteUInt16(t.AZID1); err != nil {
			return err
		}
	}

	if code&BusinessIDs != 0 {
		if err := block.WriteArray(t.BusinessIDs); err != nil {
			return err
		}
	}
	if code&BusinessIDsPath != 0 {
		if err := block.WriteArray(t.BusinessIDs); err != nil {
			return err
		}
		if err := block.WriteArray(t.BusinessIDs1); err != nil {
			return err
		}
	}

	if code&Direction != 0 {
		if t.Direction.IsClientToServer() {
			if err := block.WriteString("c2s"); err != nil {
				return err
			}
		} else {
			if err := block.WriteString("s2c"); err != nil {
				return err
			}
		}
	}

	if code&GroupIDs != 0 {
		if err := block.WriteArray(t.GroupIDs); err != nil {
			return err
		}
	}
	if code&GroupIDsPath != 0 {
		if err := block.WriteArray(t.GroupIDs); err != nil {
			return err
		}
		if err := block.WriteArray(t.GroupIDs1); err != nil {
			return err
		}
	}

	if code&HostID != 0 {
		if err := block.WriteUInt16(t.HostID); err != nil {
			return err
		}
	}
	if code&HostIDPath != 0 {
		if err := block.WriteUInt16(t.HostID); err != nil {
			return err
		}
		if err := block.WriteUInt16(t.HostID1); err != nil {
			return err
		}
	}
	if code&IP != 0 {
		if err := block.WriteUInt32(t.IP); err != nil {
			return err
		}
		if len(t.IP6) == 0 {
			t.IP6 = net.IPv6zero
		}
		if err := block.WriteIP(t.IP6); err != nil {
			return err
		}
		if err := block.WriteUInt8(1 - t.IsIPv6); err != nil {
			return err
		}
	}
	if code&IPPath != 0 {
		if err := block.WriteUInt32(t.IP); err != nil {
			return err
		}
		if err := block.WriteUInt32(t.IP1); err != nil {
			return err
		}
		if len(t.IP6) == 0 {
			t.IP6 = net.IPv6zero
		}
		if err := block.WriteIP(t.IP6); err != nil {
			return err
		}
		if len(t.IP61) == 0 {
			t.IP61 = net.IPv6zero
		}
		if err := block.WriteIP(t.IP61); err != nil {
			return err
		}
		if err := block.WriteUInt8(1 - t.IsIPv6); err != nil {
			return err
		}
	}

	if code&IsKeyService != 0 {
		if err := block.WriteUInt8(t.IsKeyService); err != nil {
			return err
		}
	}

	if code&L3Device != 0 {
		if err := block.WriteUInt32(t.L3DeviceID); err != nil {
			return err
		}
		if err := block.WriteUInt8(uint8(t.L3DeviceType)); err != nil {
			return err
		}
	}
	if code&L3DevicePath != 0 {
		if err := block.WriteUInt32(t.L3DeviceID); err != nil {
			return err
		}
		if err := block.WriteUInt32(t.L3DeviceID1); err != nil {
			return err
		}
		if err := block.WriteUInt8(uint8(t.L3DeviceType)); err != nil {
			return err
		}
		if err := block.WriteUInt8(uint8(t.L3DeviceType1)); err != nil {
			return err
		}
	}

	if code&L3EpcID != 0 {
		if err := block.WriteInt32(marshalInt32WithSpecialID(t.L3EpcID)); err != nil {
			return err
		}
	}
	if code&L3EpcIDPath != 0 {
		if err := block.WriteInt32(marshalInt32WithSpecialID(t.L3EpcID)); err != nil {
			return err
		}

		if err := block.WriteInt32(marshalInt32WithSpecialID(t.L3EpcID1)); err != nil {
			return err
		}
	}

	if code&MAC != 0 {
		// 不存
		// if err := block.WriteUInt64(t.MAC); err != nil {
		//     return err
		// }
		//
	}
	if code&MACPath != 0 {
		// 不存
		// if err := block.WriteUInt64(t.MAC); err != nil {
		//     return err
		// }
		//
		// if err := block.WriteUInt64(t.MAC1); err != nil {
		//     return err
		// }
		//
	}

	if code&PodClusterID != 0 {
		if err := block.WriteUInt16(t.PodClusterID); err != nil {
			return err
		}
	}

	if code&PodClusterIDPath != 0 {
		if err := block.WriteUInt16(t.PodClusterID); err != nil {
			return err
		}

		if err := block.WriteUInt16(t.PodClusterID1); err != nil {
			return err
		}
	}

	if code&PodGroupID != 0 {
		if err := block.WriteUInt32(t.PodGroupID); err != nil {
			return err
		}
	}

	if code&PodGroupIDPath != 0 {
		if err := block.WriteUInt32(t.PodGroupID); err != nil {
			return err
		}

		if err := block.WriteUInt32(t.PodGroupID1); err != nil {
			return err
		}
	}

	if code&PodID != 0 {
		if err := block.WriteUInt32(t.PodID); err != nil {
			return err
		}
	}

	if code&PodIDPath != 0 {
		if err := block.WriteUInt32(t.PodID); err != nil {
			return err
		}

		if err := block.WriteUInt32(t.PodID1); err != nil {
			return err
		}
	}

	if code&PodNodeID != 0 {
		if err := block.WriteUInt32(t.PodNodeID); err != nil {
			return err
		}
	}

	if code&PodNodeIDPath != 0 {
		if err := block.WriteUInt32(t.PodNodeID); err != nil {
			return err
		}

		if err := block.WriteUInt32(t.PodNodeID1); err != nil {
			return err
		}
	}

	if code&PodNSID != 0 {
		if err := block.WriteUInt16(t.PodNSID); err != nil {
			return err
		}
	}
	if code&PodNSIDPath != 0 {
		if err := block.WriteUInt16(t.PodNSID); err != nil {
			return err
		}

		if err := block.WriteUInt16(t.PodNSID1); err != nil {
			return err
		}
	}
	if code&Protocol != 0 {
		if err := block.WriteUInt8(uint8(t.Protocol)); err != nil {
			return err
		}
	}

	if code&RegionID != 0 {
		if err := block.WriteUInt16(t.RegionID); err != nil {
			return err
		}
	}
	if code&RegionIDPath != 0 {
		if err := block.WriteUInt16(t.RegionID); err != nil {
			return err
		}

		if err := block.WriteUInt16(t.RegionID1); err != nil {
			return err
		}
	}
	if code&ServiceID != 0 {
		if err := block.WriteUInt32(t.ServiceID); err != nil {
			return err
		}
	}
	if code&ServiceIDPath != 0 {
		if err := block.WriteUInt32(t.ServiceID); err != nil {
			return err
		}

		if err := block.WriteUInt32(t.ServiceID1); err != nil {
			return err
		}
	}

	if code&ServerPort != 0 {
		if err := block.WriteUInt16(t.ServerPort); err != nil {
			return err
		}
	}

	if code&SubnetID != 0 {
		if err := block.WriteUInt16(t.SubnetID); err != nil {
			return err
		}
	}
	if code&SubnetIDPath != 0 {
		if err := block.WriteUInt16(t.SubnetID); err != nil {
			return err
		}
		if err := block.WriteUInt16(t.SubnetID1); err != nil {
			return err
		}
	}
	if code&TagType != 0 && code&TagValue != 0 {
		if err := block.WriteUInt8(t.TagType); err != nil {
			return err
		}

		switch t.TagType {
		case TAG_TYPE_TUNNEL_IP_ID:
			if err := block.WriteString(strconv.FormatUint(uint64(t.TagValue), 10)); err != nil {
				return err
			}
		}
	}
	if code&TAPPort != 0 {
		if err := block.WriteUInt32(t.TAPPort); err != nil {
			return err
		}
	}
	if code&TAPSide != 0 {
		if err := block.WriteString(t.TAPSide.String()); err != nil {
			return err
		}
	}
	if code&TAPType != 0 {
		if err := block.WriteUInt8(uint8(t.TAPType)); err != nil {
			return err
		}
	}
	if code&VTAPID != 0 {
		if err := block.WriteUInt16(t.VTAPID); err != nil {
			return err
		}
	}

	return nil
}

const TAP_PORT_STR_LEN = 8

func putTAPPort(bs []byte, tapPort uint32) int {
	copy(bs, "00000000")
	s := strconv.FormatUint(uint64(tapPort), 16)
	copy(bs[TAP_PORT_STR_LEN-len(s):], s)
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

func (t *Tag) Decode(decoder *codec.SimpleDecoder) {
	offset := decoder.Offset()

	t.Code = Code(decoder.ReadU64())
	t.GlobalThreadID = decoder.ReadU8()

	if t.Code&MAC != 0 {
		t.MAC = decoder.ReadU64()
	}
	if t.Code&IP != 0 {
		t.IsIPv6 = decoder.ReadU8()
		if t.IsIPv6 != 0 {
			if t.IP6 == nil {
				t.IP6 = make([]byte, 16)
			}
			decoder.ReadIPv6(t.IP6)
		} else {
			t.IP = decoder.ReadU32()
		}
	}

	if t.Code&BusinessIDs != 0 {
		t.BusinessIDs = decoder.ReadU16Slice()
	}
	if t.Code&GroupIDs != 0 {
		t.GroupIDs = decoder.ReadU16Slice()
	}
	if t.Code&L3EpcID != 0 {
		t.L3EpcID = int16(decoder.ReadU16())
	}
	if t.Code&L3Device != 0 {
		t.L3DeviceID = decoder.ReadU32()
		t.L3DeviceType = DeviceType(decoder.ReadU8())
	}
	if t.Code&HostID != 0 {
		t.HostID = decoder.ReadU16()
	}
	if t.Code&RegionID != 0 {
		t.RegionID = decoder.ReadU16()
	}
	if t.Code&PodNodeID != 0 {
		t.PodNodeID = decoder.ReadU32()
	}
	if t.Code&PodNSID != 0 {
		t.PodNSID = decoder.ReadU16()
	}
	if t.Code&PodID != 0 {
		t.PodID = decoder.ReadU32()
	}
	if t.Code&AZID != 0 {
		t.AZID = decoder.ReadU16()
	}
	if t.Code&PodGroupID != 0 {
		t.PodGroupID = decoder.ReadU32()
	}
	if t.Code&PodClusterID != 0 {
		t.PodClusterID = decoder.ReadU16()
	}

	if t.Code&MACPath != 0 {
		t.MAC = decoder.ReadU64()
		t.MAC1 = decoder.ReadU64()
	}
	if t.Code&IPPath != 0 {
		t.IsIPv6 = decoder.ReadU8()
		if t.IsIPv6 != 0 {
			if t.IP6 == nil {
				t.IP6 = make([]byte, 16)
			}
			if t.IP61 == nil {
				t.IP61 = make([]byte, 16)
			}
			decoder.ReadIPv6(t.IP6)
			decoder.ReadIPv6(t.IP61)
		} else {
			t.IP = decoder.ReadU32()
			t.IP1 = decoder.ReadU32()
		}
	}
	if t.Code&BusinessIDsPath != 0 {
		t.BusinessIDs = decoder.ReadU16Slice()
		t.BusinessIDs1 = decoder.ReadU16Slice()
	}
	if t.Code&GroupIDsPath != 0 {
		t.GroupIDs = decoder.ReadU16Slice()
		t.GroupIDs1 = decoder.ReadU16Slice()
	}
	if t.Code&L3EpcIDPath != 0 {
		t.L3EpcID = int16(decoder.ReadU16())
		t.L3EpcID1 = int16(decoder.ReadU16())
	}
	if t.Code&L3DevicePath != 0 {
		t.L3DeviceID = decoder.ReadU32()
		t.L3DeviceType = DeviceType(decoder.ReadU8())
		t.L3DeviceID1 = decoder.ReadU32()
		t.L3DeviceType1 = DeviceType(decoder.ReadU8())
	}
	if t.Code&HostIDPath != 0 {
		t.HostID = decoder.ReadU16()
		t.HostID1 = decoder.ReadU16()
	}
	if t.Code&SubnetIDPath != 0 {
		t.SubnetID = decoder.ReadU16()
		t.SubnetID1 = decoder.ReadU16()
	}
	if t.Code&RegionIDPath != 0 {
		t.RegionID = decoder.ReadU16()
		t.RegionID1 = decoder.ReadU16()
	}
	if t.Code&PodNodeIDPath != 0 {
		t.PodNodeID = decoder.ReadU32()
		t.PodNodeID1 = decoder.ReadU32()
	}
	if t.Code&PodNSIDPath != 0 {
		t.PodNSID = decoder.ReadU16()
		t.PodNSID1 = decoder.ReadU16()
	}
	if t.Code&PodIDPath != 0 {
		t.PodID = decoder.ReadU32()
		t.PodID1 = decoder.ReadU32()
	}
	if t.Code&AZIDPath != 0 {
		t.AZID = decoder.ReadU16()
		t.AZID1 = decoder.ReadU16()
	}
	if t.Code&PodGroupIDPath != 0 {
		t.PodGroupID = decoder.ReadU32()
		t.PodGroupID1 = decoder.ReadU32()
	}
	if t.Code&PodClusterIDPath != 0 {
		t.PodClusterID = decoder.ReadU16()
		t.PodClusterID1 = decoder.ReadU16()
	}

	if t.Code&Direction != 0 {
		t.Direction = DirectionEnum(decoder.ReadU8())
	}
	if t.Code&ACLGID != 0 {
		t.ACLGID = decoder.ReadU16()
	}
	if t.Code&Protocol != 0 {
		t.Protocol = layers.IPProtocol(decoder.ReadU8())
	}
	if t.Code&ServerPort != 0 {
		t.ServerPort = decoder.ReadU16()
	}
	if t.Code&VTAPID != 0 {
		t.VTAPID = decoder.ReadU16()
	}
	if t.Code&TAPPort != 0 {
		t.TAPPort = decoder.ReadU32()
	}
	if t.Code&TAPSide != 0 {
		t.TAPSide = TAPSideEnum(decoder.ReadU8())
	}
	if t.Code&TAPType != 0 {
		t.TAPType = TAPTypeEnum(decoder.ReadU8())
	}
	if t.Code&SubnetID != 0 {
		t.SubnetID = decoder.ReadU16()
	}

	if t.Code&TagType != 0 {
		t.TagType = decoder.ReadU8()
	}
	if t.Code&TagValue != 0 {
		t.TagValue = decoder.ReadU16()
	}
	if t.Code&IsKeyService != 0 {
		t.IsKeyService = decoder.ReadU8()
	}

	if !decoder.Failed() {
		t.id = string(decoder.Bytes()[offset:decoder.Offset()]) // Encode内容就是它的id
	}
}

func (t *Tag) Encode(encoder *codec.SimpleEncoder) {
	if t.id != "" {
		encoder.WriteRawString(t.id) // ID就是序列化bytes，避免重复计算
		return
	}
	t.EncodeByCodeTID(t.Code, t.GlobalThreadID, encoder)
}

func (t *Tag) EncodeByCodeTID(code Code, tid uint8, encoder *codec.SimpleEncoder) {
	encoder.WriteU64(uint64(code))
	encoder.WriteU8(tid)

	if code&MAC != 0 {
		encoder.WriteU64(t.MAC)
	}
	if code&IP != 0 {
		encoder.WriteU8(t.IsIPv6)
		if t.IsIPv6 != 0 {
			if t.IP6 == nil {
				t.IP6 = make([]byte, 16)
			}
			encoder.WriteIPv6(t.IP6)
		} else {
			encoder.WriteU32(t.IP)
		}
	}
	if code&BusinessIDs != 0 {
		encoder.WriteU16Slice(t.BusinessIDs)
	}
	if code&GroupIDs != 0 {
		encoder.WriteU16Slice(t.GroupIDs)
	}
	if code&L3EpcID != 0 {
		encoder.WriteU16(uint16(t.L3EpcID))
	}
	if code&L3Device != 0 {
		encoder.WriteU32(t.L3DeviceID)
		encoder.WriteU8(uint8(t.L3DeviceType))
	}
	if code&HostID != 0 {
		encoder.WriteU16(t.HostID)
	}
	if code&RegionID != 0 {
		encoder.WriteU16(t.RegionID)
	}
	if code&PodNodeID != 0 {
		encoder.WriteU32(t.PodNodeID)
	}
	if code&PodNSID != 0 {
		encoder.WriteU16(t.PodNSID)
	}
	if code&PodID != 0 {
		encoder.WriteU32(t.PodID)
	}
	if code&AZID != 0 {
		encoder.WriteU16(t.AZID)
	}
	if code&PodGroupID != 0 {
		encoder.WriteU16(uint16(t.PodGroupID))
	}
	if code&PodClusterID != 0 {
		encoder.WriteU16(t.PodClusterID)
	}

	if code&MACPath != 0 {
		encoder.WriteU64(t.MAC)
		encoder.WriteU64(t.MAC1)
	}
	if code&IPPath != 0 {
		encoder.WriteU8(t.IsIPv6)
		if t.IsIPv6 != 0 {
			// 当influxdb打包数据发送给reciter时, 存在code中有IPPath,
			// 而实际查询结果只要IP6或IP61或都没有, 这时如果对IP6, IP61 进行encode会导致panic
			if t.IP6 == nil {
				t.IP6 = make([]byte, 16)
			}
			if t.IP61 == nil {
				t.IP61 = make([]byte, 16)
			}
			encoder.WriteIPv6(t.IP6)
			encoder.WriteIPv6(t.IP61)
		} else {
			encoder.WriteU32(t.IP)
			encoder.WriteU32(t.IP1)
		}
	}
	if code&BusinessIDsPath != 0 {
		encoder.WriteU16Slice(t.BusinessIDs)
		encoder.WriteU16Slice(t.BusinessIDs1)
	}
	if code&GroupIDsPath != 0 {
		encoder.WriteU16Slice(t.GroupIDs)
		encoder.WriteU16Slice(t.GroupIDs1)
	}
	if code&L3EpcIDPath != 0 {
		encoder.WriteU16(uint16(t.L3EpcID))
		encoder.WriteU16(uint16(t.L3EpcID1))
	}
	if code&L3DevicePath != 0 {
		encoder.WriteU32(t.L3DeviceID)
		encoder.WriteU8(uint8(t.L3DeviceType))
		encoder.WriteU32(t.L3DeviceID1)
		encoder.WriteU8(uint8(t.L3DeviceType1))
	}
	if code&HostIDPath != 0 {
		encoder.WriteU16(t.HostID)
		encoder.WriteU16(t.HostID1)
	}
	if code&SubnetIDPath != 0 {
		encoder.WriteU16(t.SubnetID)
		encoder.WriteU16(t.SubnetID1)
	}
	if code&RegionIDPath != 0 {
		encoder.WriteU16(t.RegionID)
		encoder.WriteU16(t.RegionID1)
	}
	if code&PodNodeIDPath != 0 {
		encoder.WriteU32(t.PodNodeID)
		encoder.WriteU32(t.PodNodeID1)
	}
	if code&PodNSIDPath != 0 {
		encoder.WriteU16(t.PodNSID)
		encoder.WriteU16(t.PodNSID1)
	}
	if code&PodIDPath != 0 {
		encoder.WriteU32(t.PodID)
		encoder.WriteU32(t.PodID1)
	}
	if code&AZIDPath != 0 {
		encoder.WriteU16(t.AZID)
		encoder.WriteU16(t.AZID1)
	}
	if code&PodGroupIDPath != 0 {
		encoder.WriteU16(uint16(t.PodGroupID))
		encoder.WriteU16(uint16(t.PodGroupID1))
	}
	if code&PodClusterIDPath != 0 {
		encoder.WriteU16(t.PodClusterID)
		encoder.WriteU16(t.PodClusterID1)
	}

	if code&Direction != 0 {
		encoder.WriteU8(uint8(t.Direction))
	}
	if code&ACLGID != 0 {
		encoder.WriteU16(t.ACLGID)
	}
	if code&Protocol != 0 {
		encoder.WriteU8(uint8(t.Protocol))
	}
	if code&ServerPort != 0 {
		encoder.WriteU16(t.ServerPort)
	}
	if code&VTAPID != 0 {
		encoder.WriteU16(t.VTAPID)
	}
	if code&TAPPort != 0 {
		encoder.WriteU32(t.TAPPort)
	}
	if code&TAPSide != 0 {
		encoder.WriteU8(uint8(t.TAPSide))
	}
	if code&TAPType != 0 {
		encoder.WriteU8(uint8(t.TAPType))
	}
	if code&SubnetID != 0 {
		encoder.WriteU16(t.SubnetID)
	}

	if code&TagType != 0 {
		encoder.WriteU8(t.TagType)
	}
	if code&TagValue != 0 {
		encoder.WriteU16(t.TagValue)
	}
	if code&IsKeyService != 0 {
		encoder.WriteU8(t.IsKeyService)
	}
}

func (t *Tag) GetID(encoder *codec.SimpleEncoder) string {
	if t.id == "" {
		encoder.Reset()
		t.Encode(encoder)
		t.id = encoder.String()
	}
	return t.id
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

func (t *Tag) Clone() app.Tag {
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
