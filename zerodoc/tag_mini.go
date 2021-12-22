package zerodoc

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/google/gopacket/layers"
	"gitlab.yunshan.net/yunshan/droplet-libs/codec"
	"gitlab.yunshan.net/yunshan/droplet-libs/datatype"
	"gitlab.yunshan.net/yunshan/droplet-libs/pool"
)

const (
	MINI_FIELD_FULL_CODES = IP | IPPath | L3EpcID | L3EpcIDPath | VTAPID | Protocol | ServerPort |
		MAC | MACPath | Direction | TAPType | ACLGID | L7Protocol | TagType | TagValue
)

type MiniField struct {
	// 注意字节对齐！

	rawIP  [net.IPv6len]byte // (16B)
	rawIP1 [net.IPv6len]byte // (16B)

	// 用于区分不同的trident及其不同的pipeline，用于如下场景：
	//   - trident和roze之间的数据传输
	//   - roze写入influxdb，作用类似_id，序列化为_tid
	GlobalThreadID uint8
	IsIPv6         uint8 // 与IP/IP6是共生字段
	L3EpcID        int16
	L3EpcID1       int16

	MAC, MAC1  uint64
	Direction  DirectionEnum
	Protocol   layers.IPProtocol // (8B)
	ACLGID     uint16
	ServerPort uint16
	VTAPID     uint16
	TAPPort    uint32
	TAPType    TAPTypeEnum
	L7Protocol datatype.L7Protocol

	TagType  uint8 // (8B)
	TagValue uint16
}

func (f *MiniField) IP() net.IP {
	if f.IsIPv6 != 0 {
		return net.IP(f.rawIP[:net.IPv6len])
	}
	return net.IP(f.rawIP[:net.IPv4len])
}

func (f *MiniField) SetIP(ip net.IP) {
	copy(f.rawIP[:], ip)
}

func (f *MiniField) IP1() net.IP {
	if f.IsIPv6 != 0 {
		return net.IP(f.rawIP1[:net.IPv6len])
	}
	return net.IP(f.rawIP1[:net.IPv4len])
}

func (f *MiniField) SetIP1(ip net.IP) {
	copy(f.rawIP1[:], ip)
}

type MiniTag struct {
	*MiniField
	Code
	id string
}

// 只用于调试
func (t *MiniTag) ToKVString() string {
	buffer := make([]byte, MAX_STRING_LENGTH)
	size := t.MarshalTo(buffer)
	return string(buffer[:size])
}

// 注意: 必须要按tag字段的字典顺序进行处理
func (t *MiniTag) MarshalTo(b []byte) int {
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

	if t.Code&Direction != 0 {
		if t.Direction.IsClientToServer() {
			offset += copy(b[offset:], ",direction=c2s")
		} else if t.Direction.IsServerToClient() {
			offset += copy(b[offset:], ",direction=s2c")
		}
	}
	if t.Code&IP != 0 {
		offset += copy(b[offset:], ",ip=")
		offset += copy(b[offset:], t.IP().String())
		if t.IsIPv6 != 0 {
			offset += copy(b[offset:], ",ip_version=6")
		} else {
			offset += copy(b[offset:], ",ip_version=4")
		}
	}
	if t.Code&IPPath != 0 {
		offset += copy(b[offset:], ",ip_0=")
		offset += copy(b[offset:], t.IP().String())
		offset += copy(b[offset:], ",ip_1=")
		offset += copy(b[offset:], t.IP1().String())
		if t.IsIPv6 != 0 {
			offset += copy(b[offset:], ",ip_version=6")
		} else {
			offset += copy(b[offset:], ",ip_version=4")
		}
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

	if t.Code&Protocol != 0 {
		offset += copy(b[offset:], ",protocol=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.Protocol), 10))
	}

	if t.Code&ServerPort != 0 {
		offset += copy(b[offset:], ",server_port=")
		offset += copy(b[offset:], strconv.FormatUint(uint64(t.ServerPort), 10))
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

func (t *MiniTag) String() string {
	var buf strings.Builder
	buf.WriteString("fields:")
	buf.WriteString(t.ToKVString())
	buf.WriteString(" code:")
	buf.WriteString(fmt.Sprintf("x%016x", t.Code))
	return buf.String()
}

func (t *MiniTag) Decode(_ *codec.SimpleDecoder) {
	panic("not supported")
}

func (t *MiniTag) Encode(encoder *codec.SimpleEncoder) {
	if t.id != "" {
		encoder.WriteRawString(t.id) // ID就是序列化bytes，避免重复计算
		return
	}
	t.EncodeByCodeTID(t.Code, t.GlobalThreadID, encoder)
}

func (t *MiniTag) EncodeByCodeTID(code Code, tid uint8, encoder *codec.SimpleEncoder) {
	srcIP, dstIP := t.IP(), t.IP1()
	srcMAC, dstMAC := t.MAC, t.MAC1
	srcEpc, dstEpc := t.L3EpcID, t.L3EpcID1
	var tapSide TAPSideEnum
	if code&Direction != 0 && code.HasEdgeTagField() {
		code |= TAPSide
		code &= ^Direction
		tapSide = t.Direction.ToTAPSide()
	}
	encoder.WriteU64(uint64(code))
	encoder.WriteU8(tid)

	if code&MAC != 0 {
		encoder.WriteU64(srcMAC)
	}
	if code&IP != 0 {
		encoder.WriteU8(t.IsIPv6)
		if t.IsIPv6 != 0 {
			encoder.WriteIPv6(srcIP)
		} else {
			encoder.WriteU32(binary.BigEndian.Uint32(srcIP))
		}
	}
	if code&L3EpcID != 0 {
		encoder.WriteU16(uint16(srcEpc))
	}
	if code&L7Protocol != 0 {
		encoder.WriteU8(uint8(t.L7Protocol))
	}

	if code&MACPath != 0 {
		encoder.WriteU64(srcMAC)
		encoder.WriteU64(dstMAC)
	}
	if code&IPPath != 0 {
		encoder.WriteU8(t.IsIPv6)
		if t.IsIPv6 != 0 {
			encoder.WriteIPv6(srcIP)
			encoder.WriteIPv6(dstIP)
		} else {
			encoder.WriteU32(binary.BigEndian.Uint32(srcIP))
			encoder.WriteU32(binary.BigEndian.Uint32(dstIP))
		}
	}
	if code&L3EpcIDPath != 0 {
		encoder.WriteU16(uint16(srcEpc))
		encoder.WriteU16(uint16(dstEpc))
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
		encoder.WriteU8(uint8(tapSide))
	}
	if code&TAPType != 0 {
		encoder.WriteU8(uint8(t.TAPType))
	}

	if code&TagType != 0 {
		encoder.WriteU8(t.TagType)
	}
	if code&TagValue != 0 {
		encoder.WriteU16(t.TagValue)
	}
}

func (t *MiniTag) GetID(encoder *codec.SimpleEncoder) string {
	if t.id == "" {
		encoder.Reset()
		t.Encode(encoder)
		t.id = encoder.String()
	}
	return t.id
}

func (t *MiniTag) SetID(id string) {
	t.id = id
}

func (t *MiniTag) GetCode() uint64 {
	return uint64(t.Code)
}

func (t *MiniTag) SetCode(code uint64) {
	t.Code = Code(code) & MINI_FIELD_FULL_CODES
}

func (t *MiniTag) SetTID(tid uint8) {
	t.GlobalThreadID = tid
}

func (t *MiniTag) GetTAPType() uint8 {
	return uint8(t.TAPType)
}

var miniFieldPool = pool.NewLockFreePool(func() interface{} {
	return &MiniField{}
})

func AcquireMiniField() *MiniField {
	return miniFieldPool.Get().(*MiniField)
}

func ReleaseMiniField(miniField *MiniField) {
	if miniField == nil {
		return
	}
	*miniField = MiniField{}
	miniFieldPool.Put(miniField)
}

func CloneMiniField(miniField *MiniField) *MiniField {
	newMiniField := AcquireMiniField()
	*newMiniField = *miniField
	return newMiniField
}

var miniTagPool = pool.NewLockFreePool(func() interface{} {
	return &MiniTag{}
})

func AcquireMiniTag() *MiniTag {
	return miniTagPool.Get().(*MiniTag)
}

// ReleaseMiniTag 需要释放Tag拥有的Field
func ReleaseMiniTag(miniTag *MiniTag) {
	if miniTag == nil {
		return
	}
	if miniTag.MiniField != nil {
		ReleaseMiniField(miniTag.MiniField)
	}
	*miniTag = MiniTag{}
	miniTagPool.Put(miniTag)
}

// CloneMiniTag 需要复制Tag拥有的Field
func CloneMiniTag(miniTag *MiniTag) *MiniTag {
	newMiniTag := AcquireMiniTag()
	newMiniTag.MiniField = CloneMiniField(miniTag.MiniField)
	newMiniTag.Code = miniTag.Code
	newMiniTag.id = miniTag.id
	return newMiniTag
}

func (t *MiniTag) Clone() Tagger {
	return CloneMiniTag(t)
}

func (t *MiniTag) Release() {
	ReleaseMiniTag(t)
}
