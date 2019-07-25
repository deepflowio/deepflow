package zerodoc

import (
	"fmt"
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
	_       // 1 << 1, MAC
	GroupID
	L2EpcID
	L3EpcID
	L2Device // 1 << 5
	L3Device
	Host
	RegionID
)

const (
	IPPath Code = 0x10000 << iota // 1 << 16
	_                             // 1 << 17, MACPath
	GroupIDPath
	L2EpcIDPath
	L3EpcIDPath
	L2DevicePath // 1 << 21
	L3DevicePath
	HostPath
	SubnetIDPath
	RegionIDPath
)

const (
	Direction Code = 0x100000000 << iota // 1 << 32
	ACLGID
	VLANID
	Protocol
	ServerPort
	CastType
	VTAP
	TAPType
	SubnetID
	TCPFlags
	ACLDirection
	Scope
)

const (
	Country Code = 1 << 63
	Region  Code = 1 << 62
	ISPCode Code = 1 << 61

	CodeIndexBits uint32 = 6 // 修改此值需更新zero
	MaxCodeIndex  uint32 = (1 << CodeIndexBits) - 1
	CodeIndices   Code   = Code(MaxCodeIndex) << 48 // 1<<48 ~ 1<<53: code index
)

func IndexToCode(i uint32) Code {
	if i > MaxCodeIndex {
		panic(fmt.Sprintf("目前支持的最大CodeIndex为%d", MaxCodeIndex))
	}
	return Code(i) << 48
}

func CodeToIndex(c Code) uint32 {
	return uint32(c>>48) & MaxCodeIndex
}

func (c Code) HasEdgeTagField() bool {
	return c&0xffff0000 != 0
}

func (c Code) HasL2TagField() bool {
	// FIXME: GroupID、GroupIDPath待定
	return c&(L2EpcID|L2Device|L2EpcIDPath|L2DevicePath|VLANID|SubnetID) != 0
}

func (c Code) RemoveIndex() Code {
	return c &^ CodeIndices
}

// 从不同EndPoint获取的网包字段组成Field，是否可能重复。
// 注意，不能判断从同样的EndPoint获取的网包字段组成Field可能重复。
func (c Code) PossibleDuplicate() bool {
	return c&(CodeIndices|GroupID|L2EpcID|L3EpcID|Host|RegionID|GroupIDPath|L2EpcIDPath|L3EpcIDPath|HostPath|ACLGID|VLANID|Protocol|TCPFlags|VTAP|TAPType|SubnetID|SubnetIDPath|RegionIDPath|ACLDirection|Country|Region|ISPCode|Scope) == c
}

// 是否全部取自网包的对称字段（非源、目的字段）
func (c Code) IsSymmetric() bool {
	return c&(CodeIndices|ACLGID|VLANID|Protocol|TCPFlags|VTAP|TAPType|ACLDirection|Scope) == c
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

type DirectionEnum uint8

const (
	_ DirectionEnum = iota
	ClientToServer
	ServerToClient
)

type TAPTypeEnum uint8

const (
	ISP0 TAPTypeEnum = iota
	ISP1
	ISP2
	ToR
	// 4~30 ISP
)

type ACLDirectionEnum uint8

const (
	ACL_FORWARD ACLDirectionEnum = 1 << iota
	ACL_BACKWARD
)

type TCPFlag uint8

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

type CastTypeEnum uint8

const (
	UNKNOWN CastTypeEnum = iota
	BROADCAST
	MULTICAST
	UNICAST
)

type ScopeEnum uint8

const (
	SCOPE_ALL ScopeEnum = iota
	SCOPE_IN_EPC
	SCOPE_OUT_EPC
	SCOPE_IN_SUBNET
	SCOPE_OUT_SUBNET

	SCOPE_INVALID
)

type Field struct {
	// 注意字节对齐！

	// 用于区分不同的trident及其不同的pipeline，用于如下场景：
	//   - trident和roze之间的数据传输
	//   - roze写入influxdb，作用类似_id，序列化为_tid
	GlobalThreadID uint64

	IP6          net.IP // FIXME: 合并IP6和IP
	IP           uint32
	GroupID      int16
	L2EpcID      int16 // (8B)
	L3EpcID      int16
	L2DeviceID   uint16
	L3DeviceID   uint16
	L2DeviceType DeviceType
	L3DeviceType DeviceType // (8B)
	Host         uint32

	IP1           uint32 // (8B)
	IP61          net.IP // FIXME: 合并IP61和IP1
	GroupID1      int16
	L2EpcID1      int16
	L3EpcID1      int16
	L2DeviceID1   uint16 // (8B)
	Host1         uint32
	L3DeviceID1   uint16
	L2DeviceType1 DeviceType
	L3DeviceType1 DeviceType // (8B)

	RegionID  uint16
	RegionID1 uint16

	ACLGID       uint16
	VLANID       uint16 // (8B)
	Direction    DirectionEnum
	Protocol     layers.IPProtocol
	ServerPort   uint16
	SubnetID     uint16
	SubnetID1    uint16 // (8B)
	VTAP         uint32
	TAPType      TAPTypeEnum
	ACLDirection ACLDirectionEnum
	CastType     CastTypeEnum
	IsIPv6       uint8 // (8B) 与IP/IP6是共生字段
	TCPFlags     TCPFlag

	Scope ScopeEnum

	Country uint8
	Region  uint8
	ISP     uint8 // (+3B = 8B)
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

func marshalUint16WithMinusOne(v int16) string {
	if v == -1 {
		return "-1"
	}
	return strconv.FormatUint(uint64(v)&uint64(^uint16(0)), 10)
}

func unmarshalUint16WithMinusOne(s string) (int16, error) {
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return -1, err
	}
	return int16(i), nil
}

func (t *Tag) MarshalTo(b []byte) int {
	offset := 0

	// 在InfluxDB的line protocol中，tag紧跟在measurement name之后，总会以逗号开头

	if t.GlobalThreadID != 0 { // FIXME: zero写入的数据此字段总为0，目前无需该字段
		offset += copy(b[offset:], ",_tid=")
		offset += copy(b[offset:], strconv.FormatUint(t.GlobalThreadID, 10))
	}

	// 1<<0 ~ 1<<6
	if t.Code&IP != 0 {
		if t.IsIPv6 != 0 {
			offset += copy(b[offset:], ",ip_version=6,ip=")
			offset += copy(b[offset:], t.IP6.String())
			offset += copy(b[offset:], ",ip_bin=") // 用于支持前缀匹配
			offset += copy(b[offset:], utils.IPv6ToBinary(t.IP6))
		} else {
			offset += copy(b[offset:], ",ip_version=4,ip=")
			offset += copy(b[offset:], utils.IpFromUint32(t.IP).String())
			offset += copy(b[offset:], ",ip_bin=") // 用于支持前缀匹配
			offset += copy(b[offset:], utils.IPv4ToBinary(t.IP))
		}
	}
	if t.Code&GroupID != 0 {
		offset += copy(b[offset:], ",group_id=")
		offset += copy(b[offset:], marshalUint16WithMinusOne(t.GroupID))
	}
	if t.Code&L2EpcID != 0 {
		offset += copy(b[offset:], ",l2_epc_id=")
		offset += copy(b[offset:], marshalUint16WithMinusOne(t.L2EpcID))
	}
	if t.Code&L3EpcID != 0 {
		offset += copy(b[offset:], ",l3_epc_id=")
		offset += copy(b[offset:], marshalUint16WithMinusOne(t.L3EpcID))
	}
	if t.Code&L2Device != 0 {
		offset += copy(b[offset:], ",l2_device_id=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.L2DeviceID), 10))
		offset += copy(b[offset:], ",l2_device_type=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.L2DeviceType), 10))
	}
	if t.Code&L3Device != 0 {
		offset += copy(b[offset:], ",l3_device_id=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.L3DeviceID), 10))
		offset += copy(b[offset:], ",l3_device_type=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.L3DeviceType), 10))
	}
	if t.Code&Host != 0 {
		offset += copy(b[offset:], ",host=")
		offset += copy(b[offset:], utils.IpFromUint32(t.Host).String())
	}
	if t.Code&RegionID != 0 {
		offset += copy(b[offset:], ",region=") // 由于历史原因，此字段和省份同名
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.RegionID), 10))
	}

	// 1<<16 ~ 1<<22
	if t.Code&IPPath != 0 {
		if t.IsIPv6 != 0 {
			offset += copy(b[offset:], ",ip_version=6,ip_0=")
			offset += copy(b[offset:], t.IP6.String())
			offset += copy(b[offset:], ",ip_1=")
			offset += copy(b[offset:], t.IP61.String())
			offset += copy(b[offset:], ",ip_bin_0=") // 用于支持前缀匹配
			offset += copy(b[offset:], utils.IPv6ToBinary(t.IP6))
			offset += copy(b[offset:], ",ip_bin_1=") // 用于支持前缀匹配
			offset += copy(b[offset:], utils.IPv6ToBinary(t.IP61))
		} else {
			offset += copy(b[offset:], ",ip_version=4,ip_0=")
			offset += copy(b[offset:], utils.IpFromUint32(t.IP).String())
			offset += copy(b[offset:], ",ip_1=")
			offset += copy(b[offset:], utils.IpFromUint32(t.IP1).String())
			offset += copy(b[offset:], ",ip_bin_0=") // 用于支持前缀匹配
			offset += copy(b[offset:], utils.IPv4ToBinary(t.IP))
			offset += copy(b[offset:], ",ip_bin_1=") // 用于支持前缀匹配
			offset += copy(b[offset:], utils.IPv4ToBinary(t.IP1))
		}
	}
	if t.Code&GroupIDPath != 0 {
		offset += copy(b[offset:], ",group_id_0=")
		offset += copy(b[offset:], marshalUint16WithMinusOne(t.GroupID))
		offset += copy(b[offset:], ",group_id_1=")
		offset += copy(b[offset:], marshalUint16WithMinusOne(t.GroupID1))
	}
	if t.Code&L2EpcIDPath != 0 {
		offset += copy(b[offset:], ",l2_epc_id_0=")
		offset += copy(b[offset:], marshalUint16WithMinusOne(t.L2EpcID))
		offset += copy(b[offset:], ",l2_epc_id_1=")
		offset += copy(b[offset:], marshalUint16WithMinusOne(t.L2EpcID1))
	}
	if t.Code&L3EpcIDPath != 0 {
		offset += copy(b[offset:], ",l3_epc_id_0=")
		offset += copy(b[offset:], marshalUint16WithMinusOne(t.L3EpcID))
		offset += copy(b[offset:], ",l3_epc_id_1=")
		offset += copy(b[offset:], marshalUint16WithMinusOne(t.L3EpcID1))
	}
	if t.Code&L2DevicePath != 0 {
		offset += copy(b[offset:], ",l2_device_id_0=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.L2DeviceID), 10))
		offset += copy(b[offset:], ",l2_device_id_1=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.L2DeviceID1), 10))
		offset += copy(b[offset:], ",l2_device_type_0=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.L2DeviceType), 10))
		offset += copy(b[offset:], ",l2_device_type_1=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.L2DeviceType1), 10))
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
	if t.Code&HostPath != 0 {
		offset += copy(b[offset:], ",host_0=")
		offset += copy(b[offset:], utils.IpFromUint32(t.Host).String())
		offset += copy(b[offset:], ",host_1=")
		offset += copy(b[offset:], utils.IpFromUint32(t.Host1).String())
	}
	if t.Code&SubnetIDPath != 0 {
		offset += copy(b[offset:], ",subnet_id_0=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.SubnetID), 10))
		offset += copy(b[offset:], ",subnet_id_1=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.SubnetID1), 10))
	}
	if t.Code&RegionIDPath != 0 {
		offset += copy(b[offset:], ",region_0=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.RegionID), 10))
		offset += copy(b[offset:], ",region_1=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.RegionID1), 10))
	}

	// 1<<32 ~ 1<<48
	if t.Code&Direction != 0 {
		switch t.Direction {
		case ClientToServer:
			offset += copy(b[offset:], ",direction=c2s")
		case ServerToClient:
			offset += copy(b[offset:], ",direction=s2c")
		}
	}
	if t.Code&ACLGID != 0 {
		offset += copy(b[offset:], ",acl_gid=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.ACLGID), 10))
	}
	if t.Code&VLANID != 0 {
		offset += copy(b[offset:], ",vlan_id=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.VLANID), 10))
	}
	if t.Code&Protocol != 0 {
		offset += copy(b[offset:], ",protocol=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.Protocol), 10))
	}
	if t.Code&ServerPort != 0 {
		offset += copy(b[offset:], ",server_port=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.ServerPort), 10))
	}
	if t.Code&VTAP != 0 {
		offset += copy(b[offset:], ",vtap=")
		offset += copy(b[offset:], utils.IpFromUint32(t.VTAP).String())
	}
	if t.Code&TAPType != 0 {
		offset += copy(b[offset:], ",tap_type=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.TAPType), 10))
	}
	if t.Code&SubnetID != 0 {
		offset += copy(b[offset:], ",subnet_id=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.SubnetID), 10))
	}
	if t.Code&ACLDirection != 0 {
		switch t.ACLDirection {
		case ACL_FORWARD:
			offset += copy(b[offset:], ",acl_direction=fwd")
		case ACL_BACKWARD:
			offset += copy(b[offset:], ",acl_direction=bwd")
		}
	}
	if t.Code&CastType != 0 {
		switch t.CastType {
		case BROADCAST:
			offset += copy(b[offset:], ",cast_type=broadcast")
		case MULTICAST:
			offset += copy(b[offset:], ",cast_type=multicast")
		case UNICAST:
			offset += copy(b[offset:], ",cast_type=unicast")
		default:
			offset += copy(b[offset:], ",cast_type=unknown")
		}
	}
	if t.Code&TCPFlags != 0 {
		offset += copy(b[offset:], ",tcp_flags=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.TCPFlags), 10))
	}
	if t.Code&Scope != 0 {
		offset += copy(b[offset:], ",scope=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.Scope), 10))
	}

	if t.Code&Country != 0 {
		offset += copy(b[offset:], ",country=")
		offset += copy(b[offset:], geo.DecodeCountry(t.Country))
	}
	if t.Code&Region != 0 {
		offset += copy(b[offset:], ",region=")
		offset += copy(b[offset:], geo.DecodeRegion(t.Region))
	}
	if t.Code&ISPCode != 0 {
		offset += copy(b[offset:], ",isp=")
		offset += copy(b[offset:], geo.DecodeISP(t.ISP))
	}

	return offset
}

func (t *Tag) String() string {
	var buf strings.Builder
	buf.WriteString("fields:")
	buf.WriteString(t.ToKVString())
	buf.WriteString(" code:")
	buf.WriteString(fmt.Sprintf("x%016x", t.Code))
	return buf.String()
}

func (t *Tag) Decode(decoder *codec.SimpleDecoder) {
	offset := decoder.Offset()

	t.Code = Code(decoder.ReadU64())
	t.GlobalThreadID = decoder.ReadU64()

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
	if t.Code&L2EpcID != 0 {
		t.L2EpcID = int16(decoder.ReadU16())
	}
	if t.Code&L3EpcID != 0 {
		t.L3EpcID = int16(decoder.ReadU16())
	}
	if t.Code&L2Device != 0 {
		t.L2DeviceID = decoder.ReadU16()
		t.L2DeviceType = DeviceType(decoder.ReadU8())
	}
	if t.Code&L3Device != 0 {
		t.L3DeviceID = decoder.ReadU16()
		t.L3DeviceType = DeviceType(decoder.ReadU8())
	}
	if t.Code&Host != 0 {
		t.Host = decoder.ReadU32()
	}
	if t.Code&RegionID != 0 {
		t.RegionID = decoder.ReadU16()
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
	if t.Code&L2EpcIDPath != 0 {
		t.L2EpcID = int16(decoder.ReadU16())
		t.L2EpcID1 = int16(decoder.ReadU16())
	}
	if t.Code&L3EpcIDPath != 0 {
		t.L3EpcID = int16(decoder.ReadU16())
		t.L3EpcID1 = int16(decoder.ReadU16())
	}
	if t.Code&L2DevicePath != 0 {
		t.L2DeviceID = decoder.ReadU16()
		t.L2DeviceType = DeviceType(decoder.ReadU8())
		t.L2DeviceID1 = decoder.ReadU16()
		t.L2DeviceType1 = DeviceType(decoder.ReadU8())
	}
	if t.Code&L3DevicePath != 0 {
		t.L3DeviceID = decoder.ReadU16()
		t.L3DeviceType = DeviceType(decoder.ReadU8())
		t.L3DeviceID1 = decoder.ReadU16()
		t.L3DeviceType1 = DeviceType(decoder.ReadU8())
	}
	if t.Code&HostPath != 0 {
		t.Host = decoder.ReadU32()
		t.Host1 = decoder.ReadU32()
	}
	if t.Code&SubnetIDPath != 0 {
		t.SubnetID = decoder.ReadU16()
		t.SubnetID1 = decoder.ReadU16()
	}
	if t.Code&RegionIDPath != 0 {
		t.RegionID = decoder.ReadU16()
		t.RegionID1 = decoder.ReadU16()
	}

	if t.Code&Direction != 0 {
		t.Direction = DirectionEnum(decoder.ReadU8())
	}
	if t.Code&ACLGID != 0 {
		t.ACLGID = decoder.ReadU16()
	}
	if t.Code&VLANID != 0 {
		t.VLANID = decoder.ReadU16()
	}
	if t.Code&Protocol != 0 {
		t.Protocol = layers.IPProtocol(decoder.ReadU8())
	}
	if t.Code&ServerPort != 0 {
		t.ServerPort = decoder.ReadU16()
	}
	if t.Code&VTAP != 0 {
		t.VTAP = decoder.ReadU32()
	}
	if t.Code&TAPType != 0 {
		t.TAPType = TAPTypeEnum(decoder.ReadU8())
	}
	if t.Code&SubnetID != 0 {
		t.SubnetID = decoder.ReadU16()
	}
	if t.Code&ACLDirection != 0 {
		t.ACLDirection = ACLDirectionEnum(decoder.ReadU8())
	}
	if t.Code&CastType != 0 {
		t.CastType = CastTypeEnum(decoder.ReadU8())
	}
	if t.Code&TCPFlags != 0 {
		t.TCPFlags = TCPFlag(decoder.ReadU8())
	}
	if t.Code&Scope != 0 {
		t.Scope = ScopeEnum(decoder.ReadU8())
	}

	if t.Code&Country != 0 {
		t.Country = decoder.ReadU8()
	}
	if t.Code&Region != 0 {
		t.Region = decoder.ReadU8()
	}
	if t.Code&ISPCode != 0 {
		t.ISP = decoder.ReadU8()
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

	encoder.WriteU64(uint64(t.Code))
	encoder.WriteU64(uint64(t.GlobalThreadID))

	if t.Code&IP != 0 {
		encoder.WriteU8(t.IsIPv6)
		if t.IsIPv6 != 0 {
			encoder.WriteIPv6(t.IP6)
		} else {
			encoder.WriteU32(t.IP)
		}
	}
	if t.Code&GroupID != 0 {
		encoder.WriteU16(uint16(t.GroupID))
	}
	if t.Code&L2EpcID != 0 {
		encoder.WriteU16(uint16(t.L2EpcID))
	}
	if t.Code&L3EpcID != 0 {
		encoder.WriteU16(uint16(t.L3EpcID))
	}
	if t.Code&L2Device != 0 {
		encoder.WriteU16(t.L2DeviceID)
		encoder.WriteU8(uint8(t.L2DeviceType))
	}
	if t.Code&L3Device != 0 {
		encoder.WriteU16(t.L3DeviceID)
		encoder.WriteU8(uint8(t.L3DeviceType))
	}
	if t.Code&Host != 0 {
		encoder.WriteU32(t.Host)
	}
	if t.Code&RegionID != 0 {
		encoder.WriteU16(t.RegionID)
	}

	if t.Code&IPPath != 0 {
		encoder.WriteU8(t.IsIPv6)
		if t.IsIPv6 != 0 {
			encoder.WriteIPv6(t.IP6)
			encoder.WriteIPv6(t.IP61)
		} else {
			encoder.WriteU32(t.IP)
			encoder.WriteU32(t.IP1)
		}
	}
	if t.Code&GroupIDPath != 0 {
		encoder.WriteU16(uint16(t.GroupID))
		encoder.WriteU16(uint16(t.GroupID1))
	}
	if t.Code&L2EpcIDPath != 0 {
		encoder.WriteU16(uint16(t.L2EpcID))
		encoder.WriteU16(uint16(t.L2EpcID1))
	}
	if t.Code&L3EpcIDPath != 0 {
		encoder.WriteU16(uint16(t.L3EpcID))
		encoder.WriteU16(uint16(t.L3EpcID1))
	}
	if t.Code&L2DevicePath != 0 {
		encoder.WriteU16(t.L2DeviceID)
		encoder.WriteU8(uint8(t.L2DeviceType))
		encoder.WriteU16(t.L2DeviceID1)
		encoder.WriteU8(uint8(t.L2DeviceType1))
	}
	if t.Code&L3DevicePath != 0 {
		encoder.WriteU16(t.L3DeviceID)
		encoder.WriteU8(uint8(t.L3DeviceType))
		encoder.WriteU16(t.L3DeviceID1)
		encoder.WriteU8(uint8(t.L3DeviceType1))
	}
	if t.Code&HostPath != 0 {
		encoder.WriteU32(t.Host)
		encoder.WriteU32(t.Host1)
	}
	if t.Code&SubnetIDPath != 0 {
		encoder.WriteU16(t.SubnetID)
		encoder.WriteU16(t.SubnetID1)
	}
	if t.Code&RegionIDPath != 0 {
		encoder.WriteU16(t.RegionID)
		encoder.WriteU16(t.RegionID1)
	}

	if t.Code&Direction != 0 {
		encoder.WriteU8(uint8(t.Direction))
	}
	if t.Code&ACLGID != 0 {
		encoder.WriteU16(t.ACLGID)
	}
	if t.Code&VLANID != 0 {
		encoder.WriteU16(t.VLANID)
	}
	if t.Code&Protocol != 0 {
		encoder.WriteU8(uint8(t.Protocol))
	}
	if t.Code&ServerPort != 0 {
		encoder.WriteU16(t.ServerPort)
	}
	if t.Code&VTAP != 0 {
		encoder.WriteU32(t.VTAP)
	}
	if t.Code&TAPType != 0 {
		encoder.WriteU8(uint8(t.TAPType))
	}
	if t.Code&SubnetID != 0 {
		encoder.WriteU16(t.SubnetID)
	}
	if t.Code&ACLDirection != 0 {
		encoder.WriteU8(uint8(t.ACLDirection))
	}
	if t.Code&CastType != 0 {
		encoder.WriteU8(uint8(t.CastType))
	}
	if t.Code&TCPFlags != 0 {
		encoder.WriteU8(uint8(t.TCPFlags))
	}
	if t.Code&Scope != 0 {
		encoder.WriteU8(uint8(t.Scope))
	}

	if t.Code&Country != 0 {
		encoder.WriteU8(t.Country)
	}
	if t.Code&Region != 0 {
		encoder.WriteU8(t.Region)
	}
	if t.Code&ISPCode != 0 {
		encoder.WriteU8(t.ISP)
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

// FIXME: 不支持IPv6，预计droplet/app在v5.5.5中支持
func isFastCode(code Code) bool {
	// 认为所有只包含这四个Code子集的Tag能使用FashID
	return (code & ^(CodeIndices | ACLGID | IP | L3EpcID | TAPType)) == 0
}

// GetFastID 返回uint64的ID，0代表该tag的code不在fast ID的范围内
// 注意：ID中会忽略TAPType
// FIXME: 不支持IPv6，预计droplet/app在v5.5.5中支持
func (t *Tag) GetFastID() uint64 {
	if !isFastCode(t.Code) || t.Code == 0 {
		return 0
	}

	var id uint64
	// 16b ACLGID + 32b IP + 16b L3EpcID
	//
	// 当code不存在的时候，有以下条件使得不同code的tag不会产生相同的fast ID：
	//   1. L3EpcID 0是不存在的
	//   2. IP 255.255.255.255不用
	//   3. ACLGID 0不存在
	if t.Code&L3EpcID != 0 {
		id |= uint64(uint16(t.L3EpcID))
	}
	if t.Code&IP != 0 {
		id |= uint64(t.IP) << 16
	} else {
		id |= uint64(0xFFFFFFFF) << 16
	}
	if t.Code&ACLGID != 0 {
		id |= uint64(t.ACLGID) << 48
	}
	return id
}

func (t *Tag) GetCode() uint64 {
	return uint64(t.Code)
}

func (t *Tag) GetTAPType() uint8 {
	return uint8(t.TAPType)
}

func (t *Tag) HasVariedField() bool {
	return t.Code&(ServerPort|Region|Country|ISPCode) != 0 || t.HasEdgeTagField()
}

var databaseSuffix = [...]string{
	"",              // 000
	"acl",           // 001
	"edge",          // 010
	"acl_edge",      // 011
	"port",          // 100
	"acl_port",      // 101
	"edge_port",     // 110
	"acl_edge_port", // 111
}

func (t *Tag) DatabaseSuffix() string {
	code := 0
	if t.Code&ACLGID != 0 {
		code |= 0x1
	}
	if t.Code.HasEdgeTagField() {
		code |= 0x2
	}
	if t.Code&ServerPort != 0 {
		code |= 0x4
	}
	return databaseSuffix[code]
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

func (f *Field) FillTag(c Code, tag *Tag) {
	if tag.Field == nil {
		tag.Field = CloneField(f)
	} else {
		*tag.Field = *f
	}
	tag.Code = c
	tag.id = ""
}

func (t *Tag) Fill(code Code, tags map[string]string) error {
	t.Code = code
	for tagk, tagv := range tags {
		if err := t.fillValue(tagk, tagv); err != nil {
			return err
		}
	}
	return nil
}

func (t *Tag) fillValue(name, value string) (err error) {
	field := t.Field
	var i uint64
	switch name {
	case "ip_bin", "ip_bin_0", "ip_bin_1", "_id", "_tid":
		return nil
	case "ip_version":
		i, _ = strconv.ParseUint(value, 10, 8) // 老版本可能未写入ip_version字段，忽略err
		if i == 6 {
			field.IsIPv6 = 1
		} else {
			field.IsIPv6 = 0
		}
	case "ip", "ip_0":
		field.IP6 = net.ParseIP(value)
		if field.IP6.To4() != nil {
			field.IP = utils.IpToUint32(field.IP6.To4())
			field.IP6 = nil
		} else {
			field.IP = 0
		}
	case "group_id", "group_id_0":
		field.GroupID, err = unmarshalUint16WithMinusOne(value)
	case "l2_epc_id", "l2_epc_id_0":
		field.L2EpcID, err = unmarshalUint16WithMinusOne(value)
	case "l3_epc_id", "l3_epc_id_0":
		field.L3EpcID, err = unmarshalUint16WithMinusOne(value)
	case "l2_device_id", "l2_device_id_0":
		i, err = strconv.ParseUint(value, 10, 16)
		field.L2DeviceID = uint16(i)
	case "l2_device_type", "l2_device_type_0":
		i, err = strconv.ParseUint(value, 10, 8)
		field.L2DeviceType = DeviceType(i)
	case "l3_device_id", "l3_device_id_0":
		i, err = strconv.ParseUint(value, 10, 16)
		field.L3DeviceID = uint16(i)
	case "l3_device_type", "l3_device_type_0":
		i, err = strconv.ParseUint(value, 10, 8)
		field.L3DeviceType = DeviceType(i)
	case "host", "host_0":
		field.Host = utils.IpToUint32(net.ParseIP(value).To4())
	case "region_0":
		i, err = strconv.ParseUint(value, 10, 16)
		field.RegionID = uint16(i)
	case "host_1":
		field.Host1 = utils.IpToUint32(net.ParseIP(value).To4())
	case "ip_1":
		field.IP61 = net.ParseIP(value)
		if field.IP61.To4() != nil {
			field.IP1 = utils.IpToUint32(field.IP61.To4())
			field.IP61 = nil
		} else {
			field.IP1 = 0
		}
	case "group_id_1":
		field.GroupID1, err = unmarshalUint16WithMinusOne(value)
	case "l2_epc_id_1":
		field.L2EpcID1, err = unmarshalUint16WithMinusOne(value)
	case "l3_epc_id_1":
		field.L3EpcID1, err = unmarshalUint16WithMinusOne(value)
	case "l2_device_id_1":
		i, err = strconv.ParseUint(value, 10, 16)
		field.L2DeviceID1 = uint16(i)
	case "l2_device_type_1":
		i, err = strconv.ParseUint(value, 10, 8)
		field.L2DeviceType1 = DeviceType(i)
	case "l3_device_id_1":
		i, err = strconv.ParseUint(value, 10, 16)
		field.L3DeviceID1 = uint16(i)
	case "l3_device_type_1":
		i, err = strconv.ParseUint(value, 10, 8)
		field.L3DeviceType1 = DeviceType(i)
	case "subnet_id", "subnet_id_0":
		i, err = strconv.ParseUint(value, 10, 16)
		field.SubnetID = uint16(i)
	case "subnet_id_1":
		i, err = strconv.ParseUint(value, 10, 16)
		field.SubnetID1 = uint16(i)
	case "region_1":
		i, err = strconv.ParseUint(value, 10, 16)
		field.RegionID1 = uint16(i)
	case "direction":
		switch value {
		case "c2s":
			field.Direction = ClientToServer
		case "s2c":
			field.Direction = ServerToClient
		default:
			field.Direction = 0
		}
	case "acl_gid":
		i, err = strconv.ParseUint(value, 10, 16)
		field.ACLGID = uint16(i)
	case "vlan_id":
		i, err = strconv.ParseUint(value, 10, 16)
		field.VLANID = uint16(i)
	case "protocol":
		i, err = strconv.ParseUint(value, 10, 8)
		field.Protocol = layers.IPProtocol(i)
	case "server_port":
		i, err = strconv.ParseUint(value, 10, 16)
		field.ServerPort = uint16(i)
	case "vtap":
		field.VTAP = utils.IpToUint32(net.ParseIP(value).To4())
	case "tap_type":
		i, err = strconv.ParseUint(value, 10, 8)
		field.TAPType = TAPTypeEnum(i)
	case "acl_direction":
		switch value {
		case "fwd":
			field.ACLDirection = ACL_FORWARD
		case "bwd":
			field.ACLDirection = ACL_BACKWARD
		default:
			field.ACLDirection = 0
		}
	case "cast_type":
		switch value {
		case "broadcast":
			field.CastType = BROADCAST
		case "multicast":
			field.CastType = MULTICAST
		case "unicast":
			field.CastType = UNICAST
		default:
			field.CastType = 0
		}
	case "tcp_flags":
		i, err = strconv.ParseUint(value, 10, 16)
		field.TCPFlags = TCPFlag(i)
	case "scope":
		i, err = strconv.ParseUint(value, 10, 8)
		field.Scope = ScopeEnum(i)
	case "country":
		field.Country = geo.EncodeCountry(value)
	case "region":
		// 由于历史原因，这个字段表示两个含义：
		// 数字：表示云平台所处区域的ID
		// 非数字：表示中国的省份（仅在df_geo库中有此含义）
		i, err = strconv.ParseUint(value, 10, 16)
		if err == nil {
			field.RegionID = uint16(i)
			field.Region = 0
		} else {
			err = nil
			field.RegionID = 0
			field.Region = geo.EncodeRegion(value)
		}
	case "isp":
		field.ISP = geo.EncodeISP(value)
	default:
		err = fmt.Errorf("unsupoort tag name %s ", name)
	}
	if err != nil {
		return fmt.Errorf("fill tag:%s value:%s failed: %s", name, value, err)
	}
	return nil
}

var TAG_NAMES map[string]uint8 = map[string]uint8{
	"_id":              0,
	"_tid":             0,
	"ip_version":       0,
	"ip":               0,
	"ip_bin":           0,
	"ip_0":             0,
	"ip_bin_0":         0,
	"group_id":         0,
	"group_id_0":       0,
	"l2_epc_id":        0,
	"l2_epc_id_0":      0,
	"l3_epc_id":        0,
	"l3_epc_id_0":      0,
	"l2_device_id":     0,
	"l2_device_id_0":   0,
	"l2_device_type":   0,
	"l2_device_type_0": 0,
	"l3_device_id":     0,
	"l3_device_id_0":   0,
	"l3_device_type":   0,
	"l3_device_type_0": 0,
	"host":             0,
	"host_0":           0,
	"region_0":         0,
	"ip_1":             0,
	"ip_bin_1":         0,
	"group_id_1":       0,
	"l2_epc_id_1":      0,
	"l3_epc_id_1":      0,
	"l2_device_id_1":   0,
	"l2_device_type_1": 0,
	"l3_device_id_1":   0,
	"l3_device_type_1": 0,
	"host_1":           0,
	"subnet_id_0":      0,
	"subnet_id_1":      0,
	"region_1":         0,
	"direction":        0,
	"acl_gid":          0,
	"vlan_id":          0,
	"protocol":         0,
	"server_port":      0,
	"vtap":             0,
	"tap_type":         0,
	"subnet_id":        0,
	"acl_direction":    0,
	"cast_type":        0,
	"tcp_flags":        0,
	"scope":            0,
	"country":          0,
	"region":           0,
	"isp":              0,
}

func IsTag(names []string) []bool {
	b := make([]bool, len(names))
	for i, name := range names {
		if _, ok := TAG_NAMES[name]; ok {
			b[i] = true
		}
	}
	return b
}

func (t *Tag) FillValues(isTag []bool, names []string, values []interface{}) error {
	for i, name := range names {
		if isTag[i] {
			v, _ := values[i].(string)
			if err := t.fillValue(name, v); err != nil {
				return err
			}
		}
	}
	return nil
}
