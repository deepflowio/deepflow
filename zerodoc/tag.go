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
	_       // 1 << 1, MAC
	GroupID
	_
	L3EpcID
	_
	L3Device
	Host
	RegionID
	HostID
)

const (
	IPPath Code = 0x10000 << iota // 1 << 16
	_                             // 1 << 17, MACPath
	GroupIDPath
	_
	L3EpcIDPath
	_
	L3DevicePath
	HostPath
	SubnetIDPath
	RegionIDPath
	PodNodeIDPath
	HostIDPath
)

const (
	Direction Code = 0x100000000 << iota // 1 << 32
	ACLGID
	VLANID
	Protocol
	ServerPort
	CastType
	_
	TAPType
	SubnetID
	TCPFlags
	ACLDirection
	_
	VTAPID
	PodNodeID
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

func (c Code) RemoveIndex() Code {
	return c &^ CodeIndices
}

// 从不同EndPoint获取的网包字段组成Field，是否可能重复。
// 注意，不能判断从同样的EndPoint获取的网包字段组成Field可能重复。
func (c Code) PossibleDuplicate() bool {
	return c&(CodeIndices|GroupID|L3EpcID|Host|HostID|RegionID|PodNodeID|GroupIDPath|L3EpcIDPath|HostPath|HostIDPath|ACLGID|VLANID|Protocol|TCPFlags|VTAPID|TAPType|SubnetID|SubnetIDPath|RegionIDPath|PodNodeIDPath|ACLDirection|Country|Region|ISPCode) == c
}

// 是否全部取自网包的对称字段（非源、目的字段）
func (c Code) IsSymmetric() bool {
	return c&(CodeIndices|ACLGID|VLANID|Protocol|TCPFlags|VTAPID|TAPType|ACLDirection) == c
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

type Field struct {
	// 注意字节对齐！

	// 用于区分不同的trident及其不同的pipeline，用于如下场景：
	//   - trident和roze之间的数据传输
	//   - roze写入influxdb，作用类似_id，序列化为_tid
	GlobalThreadID uint8

	IP6          net.IP // FIXME: 合并IP6和IP
	IP           uint32
	GroupID      int16
	L3EpcID      int16 // (8B)
	L3DeviceID   uint16
	L3DeviceType DeviceType
	Host         uint32 // (+1B=8B)
	HostID       uint16
	PodNodeID    uint16

	IP61          net.IP // FIXME: 合并IP61和IP1
	IP1           uint32
	GroupID1      int16
	L3EpcID1      int16 // (8B)
	Host1         uint32
	HostID1       uint16
	L3DeviceID1   uint16
	L3DeviceType1 DeviceType // (+1B=8B)
	PodNodeID1    uint16

	RegionID  uint16
	RegionID1 uint16

	ACLGID       uint16
	VLANID       uint16 // (8B)
	Direction    DirectionEnum
	Protocol     layers.IPProtocol
	ServerPort   uint16
	SubnetID     uint16
	SubnetID1    uint16 // (8B)
	VTAPID       uint16
	TAPType      TAPTypeEnum
	ACLDirection ACLDirectionEnum
	CastType     CastTypeEnum
	IsIPv6       uint8 // (8B) 与IP/IP6是共生字段
	TCPFlags     TCPFlag
	Side         uint8 // 目前没有对应的code标识，encode，decode均不处理

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

	if t.Code&ACLDirection != 0 {
		switch t.ACLDirection {
		case ACL_FORWARD:
			offset += copy(b[offset:], ",acl_direction=fwd")
		case ACL_BACKWARD:
			offset += copy(b[offset:], ",acl_direction=bwd")
		}
	}
	if t.Code&ACLGID != 0 {
		offset += copy(b[offset:], ",acl_gid=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.ACLGID), 10))
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
	if t.Code&Country != 0 {
		offset += copy(b[offset:], ",country=")
		offset += copy(b[offset:], geo.DecodeCountry(t.Country))
	}

	if t.Code&Direction != 0 {
		switch t.Direction {
		case ClientToServer:
			offset += copy(b[offset:], ",direction=c2s")
		case ServerToClient:
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
	if t.Code&Host != 0 {
		offset += copy(b[offset:], ",host=")
		offset += copy(b[offset:], utils.IpFromUint32(t.Host).String())
	}
	if t.Code&HostPath != 0 {
		offset += copy(b[offset:], ",host_0=")
		offset += copy(b[offset:], utils.IpFromUint32(t.Host).String())
		offset += copy(b[offset:], ",host_1=")
		offset += copy(b[offset:], utils.IpFromUint32(t.Host1).String())
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
			offset += copy(b[offset:], ",ip_bin=") // 用于支持前缀匹配
			offset += copy(b[offset:], utils.IPv6ToBinary(t.IP6))
			offset += copy(b[offset:], ",ip_version=6")
		} else {

			offset += copy(b[offset:], ",ip=")
			offset += copy(b[offset:], utils.IpFromUint32(t.IP).String())
			offset += copy(b[offset:], ",ip_bin=") // 用于支持前缀匹配
			offset += copy(b[offset:], utils.IPv4ToBinary(t.IP))
			offset += copy(b[offset:], ",ip_version=4")
		}
	}
	if t.Code&IPPath != 0 {
		if t.IsIPv6 != 0 {
			offset += copy(b[offset:], ",ip_0=")
			offset += copy(b[offset:], t.IP6.String())
			offset += copy(b[offset:], ",ip_1=")
			offset += copy(b[offset:], t.IP61.String())
			offset += copy(b[offset:], ",ip_bin_0=") // 用于支持前缀匹配
			offset += copy(b[offset:], utils.IPv6ToBinary(t.IP6))
			offset += copy(b[offset:], ",ip_bin_1=") // 用于支持前缀匹配
			offset += copy(b[offset:], utils.IPv6ToBinary(t.IP61))
			offset += copy(b[offset:], ",ip_version=6")
		} else {
			offset += copy(b[offset:], ",ip_0=")
			offset += copy(b[offset:], utils.IpFromUint32(t.IP).String())
			offset += copy(b[offset:], ",ip_1=")
			offset += copy(b[offset:], utils.IpFromUint32(t.IP1).String())
			offset += copy(b[offset:], ",ip_bin_0=") // 用于支持前缀匹配
			offset += copy(b[offset:], utils.IPv4ToBinary(t.IP))
			offset += copy(b[offset:], ",ip_bin_1=") // 用于支持前缀匹配
			offset += copy(b[offset:], utils.IPv4ToBinary(t.IP1))
			offset += copy(b[offset:], ",ip_version=4")
		}
	}

	if t.Code&ISPCode != 0 {
		offset += copy(b[offset:], ",isp=")
		offset += copy(b[offset:], geo.DecodeISP(t.ISP))
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

	if t.Code&Protocol != 0 {
		offset += copy(b[offset:], ",protocol=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.Protocol), 10))
	}

	if t.Code&RegionID != 0 {
		offset += copy(b[offset:], ",region=") // 由于历史原因，此字段和省份同名
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.RegionID), 10))
	}
	if t.Code&Region != 0 {
		offset += copy(b[offset:], ",region=")
		offset += copy(b[offset:], geo.DecodeRegion(t.Region))
	}
	if t.Code&RegionIDPath != 0 {
		offset += copy(b[offset:], ",region_0=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.RegionID), 10))
		offset += copy(b[offset:], ",region_1=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.RegionID1), 10))
	}

	if t.Code&ServerPort != 0 {
		offset += copy(b[offset:], ",server_port=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.ServerPort), 10))
	}

	// 增加side字段，为5.5.8 到后续版本升级做准备
	offset += copy(b[offset:], ",side=")
	offset += copy(b[offset:], strconv.FormatUint(uint64(t.Side), 10))

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
	if t.Code&TAPType != 0 {
		offset += copy(b[offset:], ",tap_type=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.TAPType), 10))
	}
	if t.Code&TCPFlags != 0 {
		offset += copy(b[offset:], ",tcp_flags=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.TCPFlags), 10))
	}
	if t.Code&VLANID != 0 {
		offset += copy(b[offset:], ",vlan_id=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.VLANID), 10))
	}
	if t.Code&VTAPID != 0 {
		offset += copy(b[offset:], ",vtap_id=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.VTAPID), 10))
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
	t.GlobalThreadID = decoder.ReadU8()

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

	if t.Code&Host != 0 {
		t.Host = decoder.ReadU32()
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
	if t.Code&HostPath != 0 {
		t.Host = decoder.ReadU32()
		t.Host1 = decoder.ReadU32()
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
	if t.Code&VTAPID != 0 {
		t.VTAPID = decoder.ReadU16()
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
	t.EncodeByCodeTID(t.Code, t.GlobalThreadID, encoder)
}

func (t *Tag) EncodeByCodeTID(code Code, tid uint8, encoder *codec.SimpleEncoder) {
	encoder.WriteU64(uint64(code))
	encoder.WriteU8(tid)

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
	if code&Host != 0 {
		encoder.WriteU32(t.Host)
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
	if code&HostPath != 0 {
		encoder.WriteU32(t.Host)
		encoder.WriteU32(t.Host1)
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

	if code&Direction != 0 {
		encoder.WriteU8(uint8(t.Direction))
	}
	if code&ACLGID != 0 {
		encoder.WriteU16(t.ACLGID)
	}
	if code&VLANID != 0 {
		encoder.WriteU16(t.VLANID)
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
	if code&TAPType != 0 {
		encoder.WriteU8(uint8(t.TAPType))
	}
	if code&SubnetID != 0 {
		encoder.WriteU16(t.SubnetID)
	}
	if code&ACLDirection != 0 {
		encoder.WriteU8(uint8(t.ACLDirection))
	}
	if code&CastType != 0 {
		encoder.WriteU8(uint8(t.CastType))
	}
	if code&TCPFlags != 0 {
		encoder.WriteU8(uint8(t.TCPFlags))
	}

	if code&Country != 0 {
		encoder.WriteU8(t.Country)
	}
	if code&Region != 0 {
		encoder.WriteU8(t.Region)
	}
	if code&ISPCode != 0 {
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

func (f *Field) FillTag(c Code, tag *Tag) {
	if tag.Field == nil {
		tag.Field = CloneField(f)
	} else {
		*tag.Field = *f
	}
	tag.Code = c
	tag.id = ""
}

func (t *Tag) IsMatchPublishPolicy(p *PublishPolicy) bool {
	if p.Code == 0 {
		p.IsMatched = true
		return true
	}

	if p.Code&FilterTapType != 0 && t.TAPType != p.TAPType {
		return false
	}
	if p.Code&FilterAclGid != 0 && t.ACLGID != p.ACLGID {
		return false
	}
	if p.Code&FilterL3EpcID != 0 && t.L3EpcID != p.L3EpcID {
		return false
	}
	if p.Code&FilterL3DeviceID != 0 && t.L3DeviceID != p.L3DeviceID {
		return false
	}
	if p.Code&FilterL3DeviceType != 0 && t.L3DeviceType != p.L3DeviceType {
		return false
	}
	if p.Code&FilterL3EpcID0 != 0 && t.L3EpcID != p.L3EpcID0 {
		return false
	}
	if p.Code&FilterL3EpcID1 != 0 && t.L3EpcID1 != p.L3EpcID1 {
		return false
	}
	if p.Code&FilterACLDirection != 0 && t.ACLDirection != p.ACLDirection {
		return false
	}
	if p.Code&FilterDirection != 0 && t.Direction != p.Direction {
		return false
	}

	p.IsMatched = true
	return true
}

func (t *Tag) FillPublishPolicy(p *PublishPolicy) {
	t.Code = Code(p.TagCode)
	t.TAPType = p.TAPType
	t.ACLGID = p.ACLGID
	t.L3DeviceID = p.L3DeviceID
	t.L3DeviceType = p.L3DeviceType

	if t.Code&L3EpcID != 0 {
		t.L3EpcID = p.L3EpcID
	} else {
		t.L3EpcID = p.L3EpcID0
	}
	t.L3EpcID1 = p.L3EpcID1
	t.ACLDirection = p.ACLDirection
	t.Direction = p.Direction
}

func parseUint(s string, base int, bitSize int) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	return strconv.ParseUint(s, base, bitSize)
}

func (t *Tag) fillValue(id uint8, value string) (err error) {
	field := t.Field
	var i uint64
	switch id {
	case _TAG_IP_BIN, _TAG_IP_BIN_0, _TAG_IP_BIN_1, _TAG__ID, _TAG__TID:
		return nil
	case _TAG_IP_VERSION:
		i, err = parseUint(value, 10, 8)
		t.Code |= IP
		if i == 6 {
			field.IsIPv6 = 1
		} else {
			field.IsIPv6 = 0
		}
	case _TAG_IP, _TAG_IP_0:
		if id == _TAG_IP {
			t.Code |= IP
		} else {
			t.Code |= IPPath
		}
		field.IP6 = net.ParseIP(value)
		if field.IP6.To4() != nil {
			field.IP = utils.IpToUint32(field.IP6.To4())
			field.IP6 = nil
		} else {
			field.IP = 0
		}
	case _TAG_GROUP_ID, _TAG_GROUP_ID_0:
		if id == _TAG_GROUP_ID {
			t.Code |= GroupID
		} else {
			t.Code |= GroupIDPath
		}
		field.GroupID, err = unmarshalUint16WithSpecialID(value)
	case _TAG_L3_EPC_ID, _TAG_L3_EPC_ID_0:
		if id == _TAG_L3_EPC_ID {
			t.Code |= L3EpcID
		} else {
			t.Code |= L3EpcIDPath
		}
		field.L3EpcID, err = unmarshalUint16WithSpecialID(value)
	case _TAG_L3_DEVICE_ID, _TAG_L3_DEVICE_ID_0:
		if id == _TAG_L3_DEVICE_ID {
			t.Code |= L3Device
		} else {
			t.Code |= L3DevicePath
		}
		i, err = parseUint(value, 10, 16)
		field.L3DeviceID = uint16(i)
	case _TAG_L3_DEVICE_TYPE, _TAG_L3_DEVICE_TYPE_0:
		if id == _TAG_L3_DEVICE_TYPE {
			t.Code |= L3Device
		} else {
			t.Code |= L3DevicePath
		}
		i, err = parseUint(value, 10, 8)
		field.L3DeviceType = DeviceType(i)
	case _TAG_HOST, _TAG_HOST_0:
		if id == _TAG_HOST {
			t.Code |= Host
		} else {
			t.Code |= HostPath
		}
		field.Host = utils.IpToUint32(net.ParseIP(value).To4())
	case _TAG_HOST_ID, _TAG_HOST_ID_0:
		if id == _TAG_HOST_ID {
			t.Code |= HostID
		} else {
			t.Code |= HostIDPath
		}
		i, err = parseUint(value, 10, 16)
		field.HostID = uint16(i)
	case _TAG_HOST_1:
		t.Code |= HostPath
		field.Host1 = utils.IpToUint32(net.ParseIP(value).To4())
	case _TAG_HOST_ID_1:
		t.Code |= HostIDPath
		i, err = parseUint(value, 10, 16)
		field.HostID1 = uint16(i)
	case _TAG_IP_1:
		t.Code |= IPPath
		field.IP61 = net.ParseIP(value)
		if field.IP61.To4() != nil {
			field.IP1 = utils.IpToUint32(field.IP61.To4())
			field.IP61 = nil
		} else {
			field.IP1 = 0
		}
	case _TAG_GROUP_ID_1:
		t.Code |= GroupIDPath
		field.GroupID1, err = unmarshalUint16WithSpecialID(value)
	case _TAG_L3_EPC_ID_1:
		t.Code |= L3EpcIDPath
		field.L3EpcID1, err = unmarshalUint16WithSpecialID(value)
	case _TAG_L3_DEVICE_ID_1:
		t.Code |= L3DevicePath
		i, err = parseUint(value, 10, 16)
		field.L3DeviceID1 = uint16(i)
	case _TAG_L3_DEVICE_TYPE_1:
		t.Code |= L3DevicePath
		i, err = parseUint(value, 10, 8)
		field.L3DeviceType1 = DeviceType(i)
	case _TAG_SUBNET_ID, _TAG_SUBNET_ID_0:
		if id == _TAG_SUBNET_ID {
			t.Code |= SubnetID
		} else {
			t.Code |= SubnetIDPath
		}
		i, err = parseUint(value, 10, 16)
		field.SubnetID = uint16(i)
	case _TAG_SUBNET_ID_1:
		t.Code |= SubnetIDPath
		i, err = parseUint(value, 10, 16)
		field.SubnetID1 = uint16(i)
	case _TAG_REGION_0:
		t.Code |= RegionIDPath
		i, err = parseUint(value, 10, 16)
		field.RegionID = uint16(i)
	case _TAG_REGION_1:
		t.Code |= RegionIDPath
		i, err = parseUint(value, 10, 16)
		field.RegionID1 = uint16(i)
	case _TAG_DIRECTION:
		t.Code |= Direction
		switch value {
		case "c2s":
			field.Direction = ClientToServer
		case "s2c":
			field.Direction = ServerToClient
		default:
			field.Direction = 0
		}
	case _TAG_ACL_GID:
		t.Code |= ACLGID
		i, err = parseUint(value, 10, 16)
		field.ACLGID = uint16(i)
	case _TAG_VLAN_ID:
		t.Code |= VLANID
		i, err = parseUint(value, 10, 16)
		field.VLANID = uint16(i)
	case _TAG_PROTOCOL:
		t.Code |= Protocol
		i, err = parseUint(value, 10, 8)
		field.Protocol = layers.IPProtocol(i)
	case _TAG_SERVER_PORT:
		t.Code |= ServerPort
		i, err = parseUint(value, 10, 16)
		field.ServerPort = uint16(i)
	case _TAG_VTAP_ID:
		t.Code |= VTAPID
		i, err = parseUint(value, 10, 16)
		field.VTAPID = uint16(i)
	case _TAG_TAP_TYPE:
		t.Code |= TAPType
		// 在vtap中新增了tap_type字段，读取老版本数据时，若没有该字段返回空，则设置tap_type为3
		if value == "" {
			i = 3
		} else {
			i, err = parseUint(value, 10, 8)
		}
		field.TAPType = TAPTypeEnum(i)
	case _TAG_ACL_DIRECTION:
		t.Code |= ACLDirection
		switch value {
		case "fwd":
			field.ACLDirection = ACL_FORWARD
		case "bwd":
			field.ACLDirection = ACL_BACKWARD
		default:
			field.ACLDirection = 0
		}
	case _TAG_CAST_TYPE:
		t.Code |= CastType
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
	case _TAG_TCP_FLAGS:
		t.Code |= TCPFlags
		i, err = parseUint(value, 10, 8)
		field.TCPFlags = TCPFlag(i)
	case _TAG_POD_NODE_ID, _TAG_POD_NODE_ID_0:
		if id == _TAG_POD_NODE_ID {
			t.Code |= PodNodeID
		} else {
			t.Code |= PodNodeIDPath
		}
		i, err = parseUint(value, 10, 16)
		field.PodNodeID = uint16(i)
	case _TAG_POD_NODE_ID_1:
		t.Code |= PodNodeIDPath
		i, err = parseUint(value, 10, 16)
		field.PodNodeID1 = uint16(i)
	case _TAG_COUNTRY:
		t.Code |= Country
		field.Country = geo.EncodeCountry(value)
	case _TAG_REGION:
		// 由于历史原因，这个字段表示两个含义：
		// 数字：表示云平台所处区域的ID
		// 非数字：表示中国的省份（仅在df_geo库中有此含义）
		i, err = parseUint(value, 10, 16)
		if err == nil {
			t.Code |= RegionID
			field.RegionID = uint16(i)
			field.Region = 0
		} else {
			t.Code |= Region
			err = nil
			field.RegionID = 0
			field.Region = geo.EncodeRegion(value)
		}
	case _TAG_ISP:
		t.Code |= ISPCode
		field.ISP = geo.EncodeISP(value)
	case _TAG_SIDE:
		i, _ = parseUint(value, 10, 16)
		field.Side = uint8(i)
	default:
		err = fmt.Errorf("unsupoort tag id %d ", id)
	}
	if err != nil {
		return fmt.Errorf("fill tag id:%d value:%s failed: %s", id, value, err)
	}
	return nil
}

func (t *Tag) FillValues(ids []uint8, values []interface{}) error {
	for i, id := range ids {
		if id > _TAG_INVALID_ && id < _TAG_MAX_ID_ {
			v, _ := values[i].(string)
			if err := t.fillValue(id, v); err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *Tag) Fill(tags map[string]string) error {
	for tagk, tagv := range tags {
		if id, ok := COLUMN_IDS[tagk]; ok {
			if err := t.fillValue(id, tagv); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("unsupport tag name %s\n", tagk)
		}
	}
	return nil
}
