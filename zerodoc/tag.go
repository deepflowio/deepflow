package zerodoc

import (
	"strconv"
	"strings"

	"fmt"

	"github.com/google/gopacket/layers"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
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
)

const (
	IPPath Code = 0x10000 << iota // 1 << 16
	MACPath
	GroupIDPath
	L2EpcIDPath
	L3EpcIDPath
	L2DevicePath // 1 << 21
	L3DevicePath
)

const (
	Direction Code = 0x100000000 << iota // 1 << 32
	Policy
	VLANID
	Protocol
	ServerPort
	Host // 37
	VTAP
	TAPType
	SubnetID
	ACLID
)

const (
	// df_geo的自定义code
	Country Code = 1 << 63
	Region  Code = 1 << 62
	ISPCode Code = 1 << 61
)

type DeviceType int

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

type DirectionEnum int

const (
	AnyDirection DirectionEnum = iota
	ClientToServer
	ServerToClient
)

type TAPTypeEnum int

const (
	OvS TAPTypeEnum = iota
	ISP
	Spine
	ToR
)

type Field struct {
	IP           uint32
	MAC          uint64
	GroupID      int
	L2EpcID      int
	L3EpcID      int
	L2DeviceID   int
	L2DeviceType DeviceType
	L3DeviceID   int
	L3DeviceType DeviceType

	IP0           uint32
	IP1           uint32
	MAC0          uint64
	MAC1          uint64
	GroupID0      int
	GroupID1      int
	L2EpcID0      int
	L2EpcID1      int
	L3EpcID0      int
	L3EpcID1      int
	L2DeviceID0   int
	L2DeviceType0 DeviceType
	L2DeviceID1   int
	L2DeviceType1 DeviceType
	L3DeviceID0   int
	L3DeviceType0 DeviceType
	L3DeviceID1   int
	L3DeviceType1 DeviceType

	Direction  DirectionEnum
	PolicyType datatype.PolicyType
	PolicyID   int
	VLANID     int
	Protocol   layers.IPProtocol
	ServerPort int
	Host       uint32
	VTAP       uint32
	TAPType    TAPTypeEnum
	SubnetID   int
	ACLID      int

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
		buf.WriteString(strconv.Itoa(t.GroupID))
	}
	if t.Code&L2EpcID != 0 {
		buf.WriteString(",l2_epc_id=")
		buf.WriteString(strconv.Itoa(t.L2EpcID))
	}
	if t.Code&L3EpcID != 0 {
		buf.WriteString(",l3_epc_id=")
		buf.WriteString(strconv.Itoa(t.L3EpcID))
	}
	if t.Code&L2Device != 0 {
		buf.WriteString(",l2_device_id=")
		buf.WriteString(strconv.Itoa(t.L2DeviceID))
		buf.WriteString(",l2_device_type=")
		buf.WriteString(strconv.Itoa(int(t.L2DeviceType)))
	}
	if t.Code&L3Device != 0 {
		buf.WriteString(",l3_device_id=")
		buf.WriteString(strconv.Itoa(t.L3DeviceID))
		buf.WriteString(",l3_device_type=")
		buf.WriteString(strconv.Itoa(int(t.L3DeviceType)))
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
		buf.WriteString(strconv.Itoa(t.GroupID0))
		buf.WriteString(",group_id_1=")
		buf.WriteString(strconv.Itoa(t.GroupID1))
	}
	if t.Code&L2EpcIDPath != 0 {
		buf.WriteString(",l2_epc_id_0=")
		buf.WriteString(strconv.Itoa(t.L2EpcID0))
		buf.WriteString(",l2_epc_id_1=")
		buf.WriteString(strconv.Itoa(t.L2EpcID1))
	}
	if t.Code&L3EpcIDPath != 0 {
		buf.WriteString(",l3_epc_id_0=")
		buf.WriteString(strconv.Itoa(t.L3EpcID0))
		buf.WriteString(",l3_epc_id_1=")
		buf.WriteString(strconv.Itoa(t.L3EpcID1))
	}
	if t.Code&L2DevicePath != 0 {
		buf.WriteString(",l2_device_id_0=")
		buf.WriteString(strconv.Itoa(t.L2DeviceID0))
		buf.WriteString(",l2_device_id_1=")
		buf.WriteString(strconv.Itoa(t.L2DeviceID1))
		buf.WriteString(",l2_device_type_0=")
		buf.WriteString(strconv.Itoa(int(t.L2DeviceType0)))
		buf.WriteString(",l2_device_type_1=")
		buf.WriteString(strconv.Itoa(int(t.L2DeviceType1)))
	}
	if t.Code&L3DevicePath != 0 {
		buf.WriteString(",l3_device_id_0=")
		buf.WriteString(strconv.Itoa(t.L3DeviceID0))
		buf.WriteString(",l3_device_id_1=")
		buf.WriteString(strconv.Itoa(t.L3DeviceID1))
		buf.WriteString(",l3_device_type_0=")
		buf.WriteString(strconv.Itoa(int(t.L3DeviceType0)))
		buf.WriteString(",l3_device_type_1=")
		buf.WriteString(strconv.Itoa(int(t.L3DeviceType1)))
	}

	// 1<<32 ~ 1<<48
	if t.Code&Direction != 0 {
		buf.WriteString(",direction=")
		switch t.Direction {
		case ClientToServer:
			buf.WriteString("c2s")
		case ServerToClient:
			buf.WriteString("s2c")
		default:
			buf.WriteString("any")
		}
	}
	if t.Code&Policy != 0 {
		buf.WriteString(",policy_type=")
		buf.WriteString(strconv.Itoa(int(t.PolicyType)))
		buf.WriteString(",policy_id=")
		buf.WriteString(strconv.Itoa(t.PolicyID))
	}
	if t.Code&VLANID != 0 {
		buf.WriteString(",vlan_id=")
		buf.WriteString(strconv.Itoa(t.VLANID))
	}
	if t.Code&Protocol != 0 {
		buf.WriteString(",protocol=")
		buf.WriteString(strconv.Itoa(int(t.Protocol)))
	}
	if t.Code&ServerPort != 0 {
		buf.WriteString(",server_port=")
		buf.WriteString(strconv.Itoa(t.ServerPort))
	}
	if t.Code&Host != 0 {
		buf.WriteString(",host=")
		buf.WriteString(utils.IpFromUint32(t.Host).String())
	}
	if t.Code&VTAP != 0 {
		buf.WriteString(",vtap=")
		buf.WriteString(utils.IpFromUint32(t.VTAP).String())
	}
	if t.Code&TAPType != 0 {
		buf.WriteString(",tap_type=")
		buf.WriteString(strconv.Itoa(int(t.TAPType)))
	}
	if t.Code&SubnetID != 0 {
		buf.WriteString(",subnet_id=")
		buf.WriteString(strconv.Itoa(t.SubnetID))
	}
	if t.Code&ACLID != 0 {
		buf.WriteString(",acl_id=")
		buf.WriteString(strconv.Itoa(t.ACLID))
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

func (f *Field) NewTag(c Code) *Tag {
	return &Tag{Field: f, Code: c}
}

func (f *Field) FillTag(c Code, tag *Tag) {
	tag.Field = f
	tag.Code = c
	tag.id = ""
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
			buf.WriteU48(t.MAC)
		}
		if t.Code&GroupID != 0 {
			buf.WriteU24(uint32(t.GroupID)) // 24bit
		}
		if t.Code&L2EpcID != 0 {
			buf.WriteU32(uint32(t.L2EpcID))
		}
		if t.Code&L3EpcID != 0 {
			buf.WriteU32(uint32(t.L3EpcID))
		}
		if t.Code&L2Device != 0 {
			buf.WriteU32(uint32(t.L2DeviceID))
			buf.WriteU8(uint8(t.L2DeviceType))
		}
		if t.Code&L3Device != 0 {
			buf.WriteU32(uint32(t.L3DeviceID))
			buf.WriteU8(uint8(t.L3DeviceType))
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
			buf.WriteU24(uint32(t.GroupID0)) // 24bit
			buf.WriteU24(uint32(t.GroupID1)) // 24bit
		}
		if t.Code&L2EpcIDPath != 0 {
			buf.WriteU32(uint32(t.L2EpcID0))
			buf.WriteU32(uint32(t.L2EpcID1))
		}
		if t.Code&L3EpcIDPath != 0 {
			buf.WriteU32(uint32(t.L3EpcID0))
			buf.WriteU32(uint32(t.L3EpcID1))
		}
		if t.Code&L2DevicePath != 0 {
			buf.WriteU32(uint32(t.L2DeviceID0))
			buf.WriteU8(uint8(t.L2DeviceType0))
			buf.WriteU32(uint32(t.L2DeviceID1))
			buf.WriteU8(uint8(t.L2DeviceType1))
		}
		if t.Code&L3DevicePath != 0 {
			buf.WriteU32(uint32(t.L3DeviceID0))
			buf.WriteU8(uint8(t.L3DeviceType0))
			buf.WriteU32(uint32(t.L3DeviceID1))
			buf.WriteU8(uint8(t.L3DeviceType1))
		}

		if t.Code&Direction != 0 {
			buf.WriteU8(uint8(t.Direction))
		}
		if t.Code&Policy != 0 {
			buf.WriteU8(uint8(t.PolicyType))
			buf.WriteU24(uint32(t.PolicyID)) // 24bit
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
		if t.Code&Host != 0 {
			buf.WriteU32(t.Host)
		}
		if t.Code&VTAP != 0 {
			buf.WriteU32(t.VTAP)
		}
		if t.Code&TAPType != 0 {
			buf.WriteU8(uint8(t.TAPType))
		}
		if t.Code&SubnetID != 0 {
			buf.WriteU32(uint32(t.SubnetID))
		}
		if t.Code&ACLID != 0 {
			buf.WriteU24(uint32(t.ACLID)) // 24bit
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

func (t *Tag) HasVariedField() bool {
	return t.Code&ServerPort != 0
}
