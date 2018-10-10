package zerodoc

import (
	"strconv"
	"strings"
	"sync"

	"fmt"

	"github.com/google/gopacket/layers"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
)

type Code uint64

const (
	IP Code = 0x1 << iota
	MAC
	GroupID
	L2EpcID
	L3EpcID
	L2Device // 1 << 5
	L3Device
	Host
)

const (
	IPPath Code = 0x10000 << iota // 1 << 16
	MACPath
	GroupIDPath
	L2EpcIDPath
	L3EpcIDPath
	L2DevicePath // 1 << 21
	L3DevicePath
	HostPath
)

const (
	Direction Code = 0x100000000 << iota // 1 << 32
	ACLGID
	VLANID
	Protocol
	ServerPort
	_ // 37
	VTAP
	TAPType
	SubnetID
	ACLID
	ACLDirection
)

func (c Code) HasEdgeTagField() bool {
	return c&0xffff0000 != 0
}

func (c Code) HasL2TagField() bool {
	// FIXME: GroupID、GroupIDPath待定
	return c&(MAC|L2EpcID|L2Device|Host|MACPath|L2EpcIDPath|L2DevicePath|HostPath|VLANID|VTAP|SubnetID) != 0
}

const (
	// df_geo的自定义code
	Country Code = 1 << 63
	Region  Code = 1 << 62
	ISPCode Code = 1 << 61
)

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
	OvS TAPTypeEnum = iota
	ISP
	Spine
	ToR
)

type ACLDirectionEnum uint8

const (
	ACL_FORWARD ACLDirectionEnum = 1 << iota
	ACL_BACKWARD
)

type Field struct {
	IP           uint32
	MAC          uint64
	GroupID      uint32
	L2EpcID      int32
	L3EpcID      int32
	L2DeviceID   uint32
	L2DeviceType DeviceType
	L3DeviceID   uint32
	L3DeviceType DeviceType
	Host         uint32

	IP0           uint32
	IP1           uint32
	MAC0          uint64
	MAC1          uint64
	GroupID0      uint32
	GroupID1      uint32
	L2EpcID0      int32
	L2EpcID1      int32
	L3EpcID0      int32
	L3EpcID1      int32
	L2DeviceID0   uint32
	L2DeviceType0 DeviceType
	L2DeviceID1   uint32
	L2DeviceType1 DeviceType
	L3DeviceID0   uint32
	L3DeviceType0 DeviceType
	L3DeviceID1   uint32
	L3DeviceType1 DeviceType
	Host0         uint32
	Host1         uint32

	Direction    DirectionEnum
	ACLGID       uint32
	VLANID       uint16
	Protocol     layers.IPProtocol
	ServerPort   uint16
	VTAP         uint32
	TAPType      TAPTypeEnum
	SubnetID     uint32
	ACLID        uint32
	ACLDirection ACLDirectionEnum

	CustomFields []*StringField
}

const CustomFieldNumber = 16

type StringField struct {
	Key   string
	Value string
}

type Tag struct {
	*Field
	Code
	id string
}

func codeToPos(code Code) int {
	pos := 0
	for code != 0 {
		pos++
		code >>= 1
	}
	return pos - 1
}

func (f *Field) AddCustomField(code Code, key, value string) {
	if code < 1<<48 {
		panic("code必须大于1<<48")
	}
	if f.CustomFields == nil {
		f.CustomFields = make([]*StringField, CustomFieldNumber)
	}
	f.CustomFields[codeToPos(code)-(64-CustomFieldNumber)] = &StringField{key, value}
}

func formatU32(u uint32) string {
	return strconv.FormatUint(uint64(u), 10)
}

func formatI32(i int32) string {
	return strconv.FormatInt(int64(i), 10)
}

func (t *Tag) ToKVString() string {
	var buf strings.Builder
	// 在InfluxDB的line protocol中，tag紧跟在measurement name之后，总会以逗号开头

	// 1<<0 ~ 1<<6
	if t.Code&IP != 0 {
		buf.WriteString(",ip=")
		buf.WriteString(utils.IpFromUint32(t.IP).String())
	}
	if t.Code&MAC != 0 {
		buf.WriteString(",mac=")
		buf.WriteString(utils.Uint64ToMac(t.MAC).String())
	}
	if t.Code&GroupID != 0 {
		buf.WriteString(",group_id=")
		buf.WriteString(formatU32(t.GroupID))
	}
	if t.Code&L2EpcID != 0 {
		buf.WriteString(",l2_epc_id=")
		buf.WriteString(formatI32(t.L2EpcID))
	}
	if t.Code&L3EpcID != 0 {
		buf.WriteString(",l3_epc_id=")
		buf.WriteString(formatI32(t.L3EpcID))
	}
	if t.Code&L2Device != 0 {
		buf.WriteString(",l2_device_id=")
		buf.WriteString(formatU32(t.L2DeviceID))
		buf.WriteString(",l2_device_type=")
		buf.WriteString(strconv.FormatUint(uint64(t.L2DeviceType), 10))
	}
	if t.Code&L3Device != 0 {
		buf.WriteString(",l3_device_id=")
		buf.WriteString(formatU32(t.L3DeviceID))
		buf.WriteString(",l3_device_type=")
		buf.WriteString(strconv.FormatUint(uint64(t.L3DeviceType), 10))
	}
	if t.Code&Host != 0 {
		buf.WriteString(",host=")
		buf.WriteString(utils.IpFromUint32(t.Host).String())
	}

	// 1<<16 ~ 1<<22
	if t.Code&IPPath != 0 {
		buf.WriteString(",ip_0=")
		buf.WriteString(utils.IpFromUint32(t.IP0).String())
		buf.WriteString(",ip_1=")
		buf.WriteString(utils.IpFromUint32(t.IP1).String())
	}
	if t.Code&MACPath != 0 {
		buf.WriteString(",mac_0=")
		buf.WriteString(utils.Uint64ToMac(t.MAC0).String())
		buf.WriteString(",mac_1=")
		buf.WriteString(utils.Uint64ToMac(t.MAC1).String())
	}
	if t.Code&GroupIDPath != 0 {
		buf.WriteString(",group_id_0=")
		buf.WriteString(formatU32(t.GroupID0))
		buf.WriteString(",group_id_1=")
		buf.WriteString(formatU32(t.GroupID1))
	}
	if t.Code&L2EpcIDPath != 0 {
		buf.WriteString(",l2_epc_id_0=")
		buf.WriteString(formatI32(t.L2EpcID0))
		buf.WriteString(",l2_epc_id_1=")
		buf.WriteString(formatI32(t.L2EpcID1))
	}
	if t.Code&L3EpcIDPath != 0 {
		buf.WriteString(",l3_epc_id_0=")
		buf.WriteString(formatI32(t.L3EpcID0))
		buf.WriteString(",l3_epc_id_1=")
		buf.WriteString(formatI32(t.L3EpcID1))
	}
	if t.Code&L2DevicePath != 0 {
		buf.WriteString(",l2_device_id_0=")
		buf.WriteString(formatU32(t.L2DeviceID0))
		buf.WriteString(",l2_device_id_1=")
		buf.WriteString(formatU32(t.L2DeviceID1))
		buf.WriteString(",l2_device_type_0=")
		buf.WriteString(strconv.FormatUint(uint64(t.L2DeviceType0), 10))
		buf.WriteString(",l2_device_type_1=")
		buf.WriteString(strconv.FormatUint(uint64(t.L2DeviceType1), 10))
	}
	if t.Code&L3DevicePath != 0 {
		buf.WriteString(",l3_device_id_0=")
		buf.WriteString(formatU32(t.L3DeviceID0))
		buf.WriteString(",l3_device_id_1=")
		buf.WriteString(formatU32(t.L3DeviceID1))
		buf.WriteString(",l3_device_type_0=")
		buf.WriteString(strconv.FormatUint(uint64(t.L3DeviceType0), 10))
		buf.WriteString(",l3_device_type_1=")
		buf.WriteString(strconv.FormatUint(uint64(t.L3DeviceType1), 10))
	}
	if t.Code&HostPath != 0 {
		buf.WriteString(",host_0=")
		buf.WriteString(utils.IpFromUint32(t.Host0).String())
		buf.WriteString(",host_1=")
		buf.WriteString(utils.IpFromUint32(t.Host1).String())
	}

	// 1<<32 ~ 1<<48
	if t.Code&Direction != 0 {
		switch t.Direction {
		case ClientToServer:
			buf.WriteString(",direction=c2s")
		case ServerToClient:
			buf.WriteString(",direction=s2c")
		}
	}
	if t.Code&ACLGID != 0 {
		buf.WriteString(",acl_gid=")
		buf.WriteString(formatU32(t.ACLGID))
	}
	if t.Code&VLANID != 0 {
		buf.WriteString(",vlan_id=")
		buf.WriteString(strconv.FormatUint(uint64(t.VLANID), 10))
	}
	if t.Code&Protocol != 0 {
		buf.WriteString(",protocol=")
		buf.WriteString(strconv.FormatUint(uint64(t.Protocol), 10))
	}
	if t.Code&ServerPort != 0 {
		buf.WriteString(",server_port=")
		buf.WriteString(strconv.FormatUint(uint64(t.ServerPort), 10))
	}
	if t.Code&VTAP != 0 {
		buf.WriteString(",vtap=")
		buf.WriteString(utils.IpFromUint32(t.VTAP).String())
	}
	if t.Code&TAPType != 0 {
		buf.WriteString(",tap_type=")
		buf.WriteString(strconv.FormatUint(uint64(t.TAPType), 10))
	}
	if t.Code&SubnetID != 0 {
		buf.WriteString(",subnet_id=")
		buf.WriteString(formatU32(t.SubnetID))
	}
	if t.Code&ACLID != 0 {
		buf.WriteString(",acl_id=")
		buf.WriteString(formatU32(t.ACLID))
	}
	if t.Code&ACLDirection != 0 {
		switch t.ACLDirection {
		case ACL_FORWARD:
			buf.WriteString(",acl_direction=fwd")
		case ACL_BACKWARD:
			buf.WriteString(",acl_direction=bwd")
		}
	}

	// 1<<63 ~ 1<<49
	if t.CustomFields != nil {
		for i := 0; i < CustomFieldNumber; i++ {
			code := 1 << uint(i+64-CustomFieldNumber)
			if t.Code&Code(code) != 0 && t.CustomFields[i] != nil {
				buf.WriteRune(',')
				buf.WriteString(t.CustomFields[i].Key)
				buf.WriteRune('=')
				buf.WriteString(t.CustomFields[i].Value)
			}
		}
	}

	return buf.String()
}

func (t *Tag) String() string {
	var buf strings.Builder
	buf.WriteString("fields:")
	buf.WriteString(t.ToKVString())
	buf.WriteString(" code:")
	buf.WriteString(fmt.Sprint(t.Code))
	buf.WriteString(" id:")
	buf.WriteString(t.id)
	return buf.String()
}

func (t *Tag) GetID(buf *utils.IntBuffer) string {
	if t.id == "" {
		buf.Reset()

		buf.WriteU64(uint64(t.Code))

		if t.Code&IP != 0 {
			buf.WriteU32(t.IP)
		}
		if t.Code&MAC != 0 {
			buf.WriteU48(t.MAC) // XXX: 32bit
		}
		if t.Code&GroupID != 0 {
			buf.WriteU24(t.GroupID) // XXX: 16bit
		}
		if t.Code&L2EpcID != 0 {
			buf.WriteU32(uint32(t.L2EpcID)) // XXX: 16bit
		}
		if t.Code&L3EpcID != 0 {
			buf.WriteU32(uint32(t.L3EpcID)) // XXX: 16bit
		}
		if t.Code&L2Device != 0 {
			buf.WriteU32(t.L2DeviceID) // XXX: 16bit
			buf.WriteU8(uint8(t.L2DeviceType))
		}
		if t.Code&L3Device != 0 {
			buf.WriteU32(t.L3DeviceID) // XXX: 16bit
			buf.WriteU8(uint8(t.L3DeviceType))
		}
		if t.Code&Host != 0 {
			buf.WriteU32(t.Host)
		}

		if t.Code&IPPath != 0 {
			buf.WriteU32(t.IP0)
			buf.WriteU32(t.IP1)
		}
		if t.Code&MACPath != 0 {
			buf.WriteU48(t.MAC0)
			buf.WriteU48(t.MAC1)
		}
		if t.Code&GroupIDPath != 0 {
			buf.WriteU24(t.GroupID0) // XXX: 16bit
			buf.WriteU24(t.GroupID1) // XXX: 16bit
		}
		if t.Code&L2EpcIDPath != 0 {
			buf.WriteU32(uint32(t.L2EpcID0)) // XXX: 16bit
			buf.WriteU32(uint32(t.L2EpcID1)) // XXX: 16bit
		}
		if t.Code&L3EpcIDPath != 0 {
			buf.WriteU32(uint32(t.L3EpcID0)) // XXX: 16bit
			buf.WriteU32(uint32(t.L3EpcID1)) // XXX: 16bit
		}
		if t.Code&L2DevicePath != 0 {
			buf.WriteU32(t.L2DeviceID0) // XXX: 16bit
			buf.WriteU8(uint8(t.L2DeviceType0))
			buf.WriteU32(t.L2DeviceID1) // XXX: 16bit
			buf.WriteU8(uint8(t.L2DeviceType1))
		}
		if t.Code&L3DevicePath != 0 {
			buf.WriteU32(t.L3DeviceID0) // XXX: 16bit
			buf.WriteU8(uint8(t.L3DeviceType0))
			buf.WriteU32(t.L3DeviceID1) // XXX: 16bit
			buf.WriteU8(uint8(t.L3DeviceType1))
		}
		if t.Code&HostPath != 0 {
			buf.WriteU32(t.Host0)
			buf.WriteU32(t.Host1)
		}

		if t.Code&Direction != 0 {
			buf.WriteU8(uint8(t.Direction))
		}
		if t.Code&ACLGID != 0 {
			buf.WriteU24(t.ACLGID) // XXX: 14bit
		}
		if t.Code&VLANID != 0 {
			buf.WriteU16(uint16(t.VLANID))
		}
		if t.Code&Protocol != 0 {
			buf.WriteU8(uint8(t.Protocol))
		}
		if t.Code&ServerPort != 0 {
			buf.WriteU16(uint16(t.ServerPort))
		}
		if t.Code&VTAP != 0 {
			buf.WriteU32(t.VTAP)
		}
		if t.Code&TAPType != 0 {
			buf.WriteU8(uint8(t.TAPType))
		}
		if t.Code&SubnetID != 0 {
			buf.WriteU32(t.SubnetID)
		}
		if t.Code&ACLID != 0 {
			buf.WriteU24(t.ACLID) // XXX: 14bit
		}
		if t.Code&ACLDirection != 0 {
			buf.WriteU8(uint8(t.ACLDirection))
		}
		if t.CustomFields != nil {
			for i := 0; i < CustomFieldNumber; i++ {
				code := 1 << uint(i+64-CustomFieldNumber)
				if t.Code&Code(code) != 0 && t.CustomFields[i] != nil {
					buf.WriteU8(uint8(32)) // space
					buf.WriteString(t.CustomFields[i].Value)
				}
			}
		}

		t.id = buf.String()
	}
	return t.id
}

var FAST_CODES = []Code{
	TAPType,
	IP | TAPType,
	L3EpcID | TAPType,
	L3EpcID | IP | TAPType,
	ACLGID | TAPType,
	ACLGID | IP | TAPType,
	ACLGID | IP | L3EpcID,
}

// GetFastID 返回uint64的ID，0代表该tag的code不在fast ID的范围内
func (t *Tag) GetFastID() uint64 {
	var id uint64
	// 14b ACLGID + 32b IP + 16b L3EpcID + 2b TAPType
	//
	// 当code不存在的时候，有以下条件使得不同code的tag不会产生相同的fast ID：
	//   1. TAPType 0已经弃用，不会冲突
	//   2. L3EpcID 0是不存在的
	//   3. IP 255.255.255.255不用
	//   4. ACLGID 0不存在
	if t.Code&TAPType != 0 {
		id |= uint64(t.TAPType & 0x3)
	}
	if t.Code&L3EpcID != 0 {
		id |= uint64(t.L3EpcID&0xFFFF) << 2
	}
	if t.Code&IP != 0 {
		id |= uint64(t.IP) << 18
	} else {
		id |= uint64(0xFFFFFFFF) << 18
	}
	if t.Code&ACLGID != 0 {
		id |= uint64(t.ACLGID&0x3FFF) << 50
	}
	return id
}

func (t *Tag) GetCode() uint64 {
	return uint64(t.Code)
}

func (t *Tag) HasVariedField() bool {
	return t.Code&ServerPort != 0
}

var poolField sync.Pool = sync.Pool{
	New: func() interface{} {
		return &Field{}
	},
}

func AcquireField() *Field {
	return poolField.Get().(*Field)
}

func ReleaseField(field *Field) {
	if field == nil {
		return
	}
	*field = Field{}
	poolField.Put(field)
}

func CloneField(field *Field) *Field {
	newField := AcquireField()
	*newField = *field
	return newField
}

var poolTag sync.Pool = sync.Pool{
	New: func() interface{} {
		return &Tag{}
	},
}

func AcquireTag() *Tag {
	return poolTag.Get().(*Tag)
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
	poolTag.Put(tag)
}

// CloneTag 需要复制Tag拥有的Field
func CloneTag(tag *Tag) *Tag {
	newTag := AcquireTag()
	newTag.Field = CloneField(tag.Field)
	newTag.Code = tag.Code
	newTag.id = tag.id
	return newTag
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
