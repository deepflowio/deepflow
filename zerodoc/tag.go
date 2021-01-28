package zerodoc

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"

	"github.com/google/gopacket/layers"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/geo"
	"gitlab.x.lan/yunshan/droplet-libs/pool"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
)

type Code uint64

const (
	IP Code = 0x1 << iota
	GroupID
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
)

const (
	IPPath Code = 0x10000 << iota // 1 << 16
	GroupIDPath
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

const (
	// 用于DirectionEnum，标记是否需要颠倒IP等字段
	// 大部分场景Server端需要颠倒，GateWay场景特殊因为实际流量采集点和对应的主机类型相反，所以Client端需要颠倒
	_EDGE_TAG_FIELD_NEED_REVERSE uint8 = 1 << 7
)

type DirectionEnum uint8

const (
	_ DirectionEnum = iota
	_ClientToServer
	_ServerToClient

	ClientToServer = _ClientToServer
	ServerToClient = _ServerToClient | DirectionEnum(_EDGE_TAG_FIELD_NEED_REVERSE)
	// 以下类型为转换tapside而增加，在写入db时均记为c2s或s2c
	ClientNodeToServer              = _ClientToServer | DirectionEnum(NodeSide)                                                            // 客户端容器节点，路由、SNAT、隧道
	ServerNodeToClient              = _ServerToClient | DirectionEnum(NodeSide) | DirectionEnum(_EDGE_TAG_FIELD_NEED_REVERSE)              // 服务端容器节点，路由、SNAT、隧道
	ClientHypervisorToServer        = _ClientToServer | DirectionEnum(HypervisorSide)                                                      // 客户端宿主机，隧道
	ServerHypervisorToClient        = _ServerToClient | DirectionEnum(HypervisorSide) | DirectionEnum(_EDGE_TAG_FIELD_NEED_REVERSE)        // 服务端宿主机，隧道
	ClientGatewayHypervisorToServer = _ClientToServer | DirectionEnum(GatewayHypervisorSide) | DirectionEnum(_EDGE_TAG_FIELD_NEED_REVERSE) // 客户端网关宿主机
	ServerGatewayHypervisorToClient = _ServerToClient | DirectionEnum(GatewayHypervisorSide)                                               // 服务端网关宿主机
	ClientGatewayToServer           = _ClientToServer | DirectionEnum(GatewaySide) | DirectionEnum(_EDGE_TAG_FIELD_NEED_REVERSE)           // 客户端网关（特指VIP机制的SLB，例如微软云MUX等）, Mac地址对应的接口为vip设备
	ServerGatewayToClient           = _ServerToClient | DirectionEnum(GatewaySide)                                                         // 服务端网关（特指VIP机制的SLB，例如微软云MUX等）, Mac地址对应的接口为vip设备
)

func (d DirectionEnum) IsClientToServer() bool {
	return d&0x3 == _ClientToServer
}

func (d DirectionEnum) IsServerToClient() bool {
	return d&0x3 == _ServerToClient
}

func (d DirectionEnum) EdgeTagFieldNeedReverse() bool {
	return uint8(d)&_EDGE_TAG_FIELD_NEED_REVERSE == _EDGE_TAG_FIELD_NEED_REVERSE
}

type TAPSideEnum uint8

const (
	Client TAPSideEnum = iota
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

func (d DirectionEnum) ToTAPSide() TAPSideEnum {
	d &= DirectionEnum(^_EDGE_TAG_FIELD_NEED_REVERSE)
	if uint8(d) == 0 {
		panic("invalid direction")
	}
	return TAPSideEnum(d - 1)
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
	TAG_TYPE_PROVINCE = 1 + iota
	TAG_TYPE_TCP_FLAG
	TAG_TYPE_CAST_TYPE
	TAG_TYPE_TUNNEL_IP_ID
	TAG_TYPE_TTL
	TAG_TYPE_PACKET_SIZE
)

type CastTypeEnum uint8

// 作为TagValue值使用字符串;统计数据UNKNOWN无效，Index取值范围是1~3
const (
	UNKNOWN CastTypeEnum = iota
	BROADCAST
	MULTICAST
	UNICAST
	MAX_CAST_TYPE //  4
)

type TCPFlag uint8

// TagValue使用具体的Flags值
const (
	TCP_FLAG_FIN TCPFlag = 1 << iota
	TCP_FLAG_SYN
	TCP_FLAG_RST
	TCP_FLAG_PSH
	TCP_FLAG_ACK

	TCP_FLAG_FIN_ACK = TCP_FLAG_FIN | TCP_FLAG_ACK
	TCP_FLAG_SYN_ACK = TCP_FLAG_SYN | TCP_FLAG_ACK
	TCP_FLAG_RST_ACK = TCP_FLAG_RST | TCP_FLAG_ACK
	TCP_FLAG_PSH_ACK = TCP_FLAG_PSH | TCP_FLAG_ACK

	TCP_FLAG_OTHERS TCPFlag = 255 // 特殊标记，不能用于判断TCP Flag比特是否置位
)

// TCP Flags统计时映射的Index取值范围是4~10
const (
	TCP_FLAG_SYN_INDEX = iota + uint8(MAX_CAST_TYPE)
	TCP_FLAG_SYN_ACK_INDEX
	TCP_FLAG_ACK_INDEX
	TCP_FLAG_PSH_ACK_INDEX
	TCP_FLAG_FIN_ACK_INDEX
	TCP_FLAG_RST_ACK_INDEX
	TCP_FLAG_OTHERS_INDEX

	MAX_TCP_FLAGS_INDEX
)

var TCPIndexToFlags = [MAX_TCP_FLAGS_INDEX]TCPFlag{
	TCP_FLAG_SYN_INDEX:     TCP_FLAG_SYN,
	TCP_FLAG_SYN_ACK_INDEX: TCP_FLAG_SYN_ACK,
	TCP_FLAG_ACK_INDEX:     TCP_FLAG_ACK,
	TCP_FLAG_PSH_ACK_INDEX: TCP_FLAG_PSH_ACK,
	TCP_FLAG_FIN_ACK_INDEX: TCP_FLAG_FIN_ACK,
	TCP_FLAG_RST_ACK_INDEX: TCP_FLAG_RST_ACK,
	TCP_FLAG_OTHERS_INDEX:  TCP_FLAG_OTHERS,
}

// 作为TagValue值和统计数据的Index，取值范围是11~21
const (
	TTL_1 = iota + MAX_TCP_FLAGS_INDEX
	TTL_2
	TTL_3
	TTL_4
	TTL_30
	TTL_32
	TTL_60
	TTL_64
	TTL_128
	TTL_255
	TTL_OTHER
	MAX_TTL
)

// 作为TagValue值和统计数据的Index，取值范围是22~30
const (
	PACKET_SIZE_0_64 = iota + MAX_TTL
	PACKET_SIZE_65_128
	PACKET_SIZE_129_256
	PACKET_SIZE_257_512
	PACKET_SIZE_513_1024
	PACKET_SIZE_1025_1500
	PACKET_SIZE_1501_9000
	PACKET_SIZE_9001_30000
	PACKET_SIZE_30001_65535
	MAX_PACKET_SIZE
)

const (
	N_METERS = MAX_PACKET_SIZE
)

var TTL_PACKET_SIZE [MAX_PACKET_SIZE]string = [MAX_PACKET_SIZE]string{
	TTL_1:                   "1",
	TTL_2:                   "2",
	TTL_3:                   "3",
	TTL_4:                   "4",
	TTL_30:                  "30",
	TTL_32:                  "32",
	TTL_60:                  "60",
	TTL_64:                  "64",
	TTL_128:                 "128",
	TTL_255:                 "255",
	TTL_OTHER:               "others",
	PACKET_SIZE_0_64:        "0-64",
	PACKET_SIZE_65_128:      "65-128",
	PACKET_SIZE_129_256:     "129-256",
	PACKET_SIZE_257_512:     "257-512",
	PACKET_SIZE_513_1024:    "513-1024",
	PACKET_SIZE_1025_1500:   "1025-1500",
	PACKET_SIZE_1501_9000:   "1501-9000",
	PACKET_SIZE_9001_30000:  "9001-30000",
	PACKET_SIZE_30001_65535: "30001-65535",
}

type Field struct {
	// 注意字节对齐！

	// 用于区分不同的trident及其不同的pipeline，用于如下场景：
	//   - trident和roze之间的数据传输
	//   - roze写入influxdb，作用类似_id，序列化为_tid
	GlobalThreadID uint8

	IP6          net.IP // FIXME: 合并IP6和IP
	MAC          uint64
	IP           uint32
	GroupID      int16
	L3EpcID      int16 // (8B)
	L3DeviceID   uint16
	L3DeviceType DeviceType
	RegionID     uint16
	SubnetID     uint16
	HostID       uint16
	PodNodeID    uint16
	AZID         uint16
	PodGroupID   int16
	PodNSID      uint16
	PodID        uint16
	PodClusterID uint16

	MAC1          uint64
	IP61          net.IP // FIXME: 合并IP61和IP1
	IP1           uint32
	GroupID1      int16
	L3EpcID1      int16 // (8B)
	L3DeviceID1   uint16
	L3DeviceType1 DeviceType // (+1B=8B)
	RegionID1     uint16
	SubnetID1     uint16 // (8B)
	HostID1       uint16
	PodNodeID1    uint16
	AZID1         uint16
	PodGroupID1   int16
	PodNSID1      uint16
	PodID1        uint16
	PodClusterID1 uint16

	ACLGID     uint16
	Direction  DirectionEnum
	Protocol   layers.IPProtocol
	ServerPort uint16
	VTAPID     uint16
	TAPPort    uint32
	TAPSide    TAPSideEnum
	TAPType    TAPTypeEnum
	IsIPv6     uint8 // (8B) 与IP/IP6是共生字段

	TagType  uint8
	TagValue uint16
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
	if t.Code&GroupID != 0 {
		offset += copy(b[offset:], ",group_id=")
		offset += copy(b[offset:], marshalUint16WithSpecialID(t.GroupID))
	}
	if t.Code&GroupIDPath != 0 {
		offset += copy(b[offset:], ",group_id_0=")
		offset += copy(b[offset:], marshalUint16WithSpecialID(t.GroupID))
		offset += copy(b[offset:], ",group_id_1=")
		offset += copy(b[offset:], marshalUint16WithSpecialID(t.GroupID1))
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
			offset += copy(b[offset:], ",ip_version=6")
		} else {
			offset += copy(b[offset:], ",ip_0=")
			offset += copy(b[offset:], utils.IpFromUint32(t.IP).String())
			offset += copy(b[offset:], ",ip_1=")
			offset += copy(b[offset:], utils.IpFromUint32(t.IP1).String())
			offset += copy(b[offset:], ",ip_version=4")
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
		offset += copy(b[offset:], marshalUint16WithSpecialID(t.PodGroupID))
	}

	if t.Code&PodGroupIDPath != 0 {
		offset += copy(b[offset:], ",pod_group_id_0=")
		offset += copy(b[offset:], marshalUint16WithSpecialID(t.PodGroupID))
		offset += copy(b[offset:], ",pod_group_id_1=")
		offset += copy(b[offset:], marshalUint16WithSpecialID(t.PodGroupID1))
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
		case TAG_TYPE_PROVINCE:
			offset += copy(b[offset:], ",tag_value=")
			offset += copy(b[offset:], geo.DecodeRegion(uint8(t.TagValue)))
		// offset += copy(b[offset:], ",isp=")
		// offset += copy(b[offset:], geo.DecodeISP(t.ISP))
		// offset += copy(b[offset:], ",country=")
		// offset += copy(b[offset:], geo.DecodeCountry(t.Country))
		case TAG_TYPE_TCP_FLAG:
			offset += copy(b[offset:], ",tag_value=")
			offset += copy(b[offset:], strconv.FormatUint(uint64(t.TagValue), 10))
		case TAG_TYPE_CAST_TYPE:
			switch CastTypeEnum(t.TagValue) {
			case BROADCAST:
				offset += copy(b[offset:], ",tag_value=broadcast")
			case MULTICAST:
				offset += copy(b[offset:], ",tag_value=multicast")
			case UNICAST:
				offset += copy(b[offset:], ",tag_value=unicast")
			default:
				offset += copy(b[offset:], ",tag_value=unknown")
			}
		case TAG_TYPE_TUNNEL_IP_ID:
			offset += copy(b[offset:], ",tag_value=")
			offset += copy(b[offset:], strconv.FormatUint(uint64(t.TagValue), 10))
		case TAG_TYPE_TTL:
			fallthrough
		case TAG_TYPE_PACKET_SIZE:
			offset += copy(b[offset:], ",tag_value=")
			if t.TagValue < uint16(MAX_PACKET_SIZE) && t.TagValue >= uint16(TTL_1) {
				offset += copy(b[offset:], TTL_PACKET_SIZE[t.TagValue])
			} else {
				offset += copy(b[offset:], strconv.FormatUint(uint64(t.TagValue), 10))
			}
		}
	}
	if t.Code&TAPPort != 0 {
		offset += copy(b[offset:], ",tap_port=")
		offset += putTAPPort(b[offset:], t.TAPPort)
	}
	if t.Code&TAPSide != 0 {
		switch t.TAPSide {
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
	if t.Code&GroupID != 0 {
		t.GroupID = int16(decoder.ReadU16())
	}
	if t.Code&L3EpcID != 0 {
		t.L3EpcID = int16(decoder.ReadU16())
	}
	if t.Code&L3Device != 0 {
		t.L3DeviceID = decoder.ReadU16()
		t.L3DeviceType = DeviceType(decoder.ReadU8())
	}
	if t.Code&HostID != 0 {
		t.HostID = decoder.ReadU16()
	}
	if t.Code&RegionID != 0 {
		t.RegionID = decoder.ReadU16()
	}
	if t.Code&PodNodeID != 0 {
		t.PodNodeID = decoder.ReadU16()
	}
	if t.Code&PodNSID != 0 {
		t.PodNSID = decoder.ReadU16()
	}
	if t.Code&PodID != 0 {
		t.PodID = decoder.ReadU16()
	}
	if t.Code&AZID != 0 {
		t.AZID = decoder.ReadU16()
	}
	if t.Code&PodGroupID != 0 {
		t.PodGroupID = int16(decoder.ReadU16())
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
	if t.Code&GroupIDPath != 0 {
		t.GroupID = int16(decoder.ReadU16())
		t.GroupID1 = int16(decoder.ReadU16())
	}
	if t.Code&L3EpcIDPath != 0 {
		t.L3EpcID = int16(decoder.ReadU16())
		t.L3EpcID1 = int16(decoder.ReadU16())
	}
	if t.Code&L3DevicePath != 0 {
		t.L3DeviceID = decoder.ReadU16()
		t.L3DeviceType = DeviceType(decoder.ReadU8())
		t.L3DeviceID1 = decoder.ReadU16()
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
		t.PodNodeID = decoder.ReadU16()
		t.PodNodeID1 = decoder.ReadU16()
	}
	if t.Code&PodNSIDPath != 0 {
		t.PodNSID = decoder.ReadU16()
		t.PodNSID1 = decoder.ReadU16()
	}
	if t.Code&PodIDPath != 0 {
		t.PodID = decoder.ReadU16()
		t.PodID1 = decoder.ReadU16()
	}
	if t.Code&AZIDPath != 0 {
		t.AZID = decoder.ReadU16()
		t.AZID1 = decoder.ReadU16()
	}
	if t.Code&PodGroupIDPath != 0 {
		t.PodGroupID = int16(decoder.ReadU16())
		t.PodGroupID1 = int16(decoder.ReadU16())
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
	if code&GroupID != 0 {
		encoder.WriteU16(uint16(t.GroupID))
	}
	if code&L3EpcID != 0 {
		encoder.WriteU16(uint16(t.L3EpcID))
	}
	if code&L3Device != 0 {
		encoder.WriteU16(t.L3DeviceID)
		encoder.WriteU8(uint8(t.L3DeviceType))
	}
	if code&HostID != 0 {
		encoder.WriteU16(t.HostID)
	}
	if code&RegionID != 0 {
		encoder.WriteU16(t.RegionID)
	}
	if code&PodNodeID != 0 {
		encoder.WriteU16(t.PodNodeID)
	}
	if code&PodNSID != 0 {
		encoder.WriteU16(t.PodNSID)
	}
	if code&PodID != 0 {
		encoder.WriteU16(t.PodID)
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
	if code&GroupIDPath != 0 {
		encoder.WriteU16(uint16(t.GroupID))
		encoder.WriteU16(uint16(t.GroupID1))
	}
	if code&L3EpcIDPath != 0 {
		encoder.WriteU16(uint16(t.L3EpcID))
		encoder.WriteU16(uint16(t.L3EpcID1))
	}
	if code&L3DevicePath != 0 {
		encoder.WriteU16(t.L3DeviceID)
		encoder.WriteU8(uint8(t.L3DeviceType))
		encoder.WriteU16(t.L3DeviceID1)
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
		encoder.WriteU16(t.PodNodeID)
		encoder.WriteU16(t.PodNodeID1)
	}
	if code&PodNSIDPath != 0 {
		encoder.WriteU16(t.PodNSID)
		encoder.WriteU16(t.PodNSID1)
	}
	if code&PodIDPath != 0 {
		encoder.WriteU16(t.PodID)
		encoder.WriteU16(t.PodID1)
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
