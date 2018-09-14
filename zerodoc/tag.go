package zerodoc

import (
	"bytes"
	"strconv"

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

func (t *Tag) ToMap() map[string]string {
	ret := make(map[string]string)

	// 1<<0 ~ 1<<6
	if t.Code&IP != 0 {
		ret["ip"] = utils.IpFromUint32(t.IP).String()
	}
	if t.Code&MAC != 0 {
		ret["mac"] = utils.Uint64ToMac(t.MAC).String()
	}
	if t.Code&GroupID != 0 {
		ret["group_id"] = strconv.Itoa(t.GroupID)
	}
	if t.Code&L2EpcID != 0 {
		ret["l2_epc_id"] = strconv.Itoa(t.L2EpcID)
	}
	if t.Code&L3EpcID != 0 {
		ret["l3_epc_id"] = strconv.Itoa(t.L3EpcID)
	}
	if t.Code&L2Device != 0 {
		ret["l2_device_id"] = strconv.Itoa(t.L2DeviceID)
		ret["l2_device_type"] = strconv.Itoa(int(t.L2DeviceType))
	}
	if t.Code&L3Device != 0 {
		ret["l3_device_id"] = strconv.Itoa(t.L3DeviceID)
		ret["l3_device_type"] = strconv.Itoa(int(t.L3DeviceType))
	}

	// 1<<16 ~ 1<<22
	if t.Code&IPPath != 0 {
		ret["ip_0"] = utils.IpFromUint32(t.IP0).String()
		ret["ip_1"] = utils.IpFromUint32(t.IP1).String()
	}
	if t.Code&MACPath != 0 {
		ret["mac_0"] = utils.Uint64ToMac(t.MAC0).String()
		ret["mac_1"] = utils.Uint64ToMac(t.MAC1).String()
	}
	if t.Code&GroupIDPath != 0 {
		ret["group_id_0"] = strconv.Itoa(t.GroupID0)
		ret["group_id_1"] = strconv.Itoa(t.GroupID1)
	}
	if t.Code&L2EpcIDPath != 0 {
		ret["l2_epc_id_0"] = strconv.Itoa(t.L2EpcID0)
		ret["l2_epc_id_1"] = strconv.Itoa(t.L2EpcID1)
	}
	if t.Code&L3EpcIDPath != 0 {
		ret["l3_epc_id_0"] = strconv.Itoa(t.L3EpcID0)
		ret["l3_epc_id_1"] = strconv.Itoa(t.L3EpcID1)
	}
	if t.Code&L2DevicePath != 0 {
		ret["l2_device_id_0"] = strconv.Itoa(t.L2DeviceID0)
		ret["l2_device_id_1"] = strconv.Itoa(t.L2DeviceID1)
		ret["l2_device_type_0"] = strconv.Itoa(int(t.L2DeviceType0))
		ret["l2_device_type_1"] = strconv.Itoa(int(t.L2DeviceType1))
	}
	if t.Code&L3DevicePath != 0 {
		ret["l3_device_id_0"] = strconv.Itoa(t.L3DeviceID0)
		ret["l3_device_id_1"] = strconv.Itoa(t.L3DeviceID1)
		ret["l3_device_type_0"] = strconv.Itoa(int(t.L3DeviceType0))
		ret["l3_device_type_1"] = strconv.Itoa(int(t.L3DeviceType1))
	}

	// 1<<32 ~ 1<<39
	if t.Code&Direction != 0 {
		ret["direction"] = strconv.Itoa(int(t.Direction))
	}
	if t.Code&Policy != 0 {
		ret["policy_type"] = strconv.Itoa(int(t.PolicyType))
		ret["policy_id"] = strconv.Itoa(t.PolicyID)
	}
	if t.Code&VLANID != 0 {
		ret["vlan_id"] = strconv.Itoa(t.VLANID)
	}
	if t.Code&Protocol != 0 {
		ret["protocol"] = strconv.Itoa(int(t.Protocol))
	}
	if t.Code&ServerPort != 0 {
		ret["server_port"] = strconv.Itoa(t.ServerPort)
	}
	if t.Code&Host != 0 {
		ret["host"] = utils.IpFromUint32(t.Host).String()
	}
	if t.Code&VTAP != 0 {
		ret["vtap"] = utils.IpFromUint32(t.VTAP).String()
	}
	if t.Code&TAPType != 0 {
		ret["tap_type"] = strconv.Itoa(int(t.TAPType))
	}
	if t.Code&SubnetID != 0 {
		ret["subnet_id"] = strconv.Itoa(t.SubnetID)
	}
	if t.Code&ACLID != 0 {
		ret["acl_id"] = strconv.Itoa(t.ACLID)
	}

	if t.CustomFields != nil {
		for i := 0; i < CustomFieldNumber; i++ {
			code := 1 << uint(i+64-CustomFieldNumber)
			if t.Code&Code(code) != 0 && t.CustomFields[i] != nil {
				ret[t.CustomFields[i].Key] = t.CustomFields[i].Value
			}
		}
	}

	return ret
}

func (f *Field) NewTag(c Code) *Tag {
	return &Tag{Field: f, Code: c}
}

func (t *Tag) String() string {
	var buffer bytes.Buffer
	tagMap := t.ToMap()
	buffer.WriteString("fields:")
	for key, value := range tagMap {
		buffer.WriteString(" ")
		buffer.WriteString(key)
		buffer.WriteString(":")
		buffer.WriteString(value)
	}
	buffer.WriteString(" code:")
	buffer.WriteString(fmt.Sprint(t.Code))
	buffer.WriteString(" id:")
	buffer.WriteString(t.id)
	return buffer.String()
}

func (t *Tag) GetID() string {
	if t.id == "" {
		var buf bytes.Buffer
		if t.Code&IP != 0 {
			buf.WriteString(strconv.FormatInt(int64(t.IP), 16))
			buf.WriteRune(' ')
		}
		if t.Code&MAC != 0 {
			buf.WriteString(strconv.FormatInt(int64(t.MAC), 16))
			buf.WriteRune(' ')
		}
		if t.Code&GroupID != 0 {
			buf.WriteString(strconv.Itoa(t.GroupID))
			buf.WriteRune(' ')
		}
		if t.Code&L2EpcID != 0 {
			buf.WriteString(strconv.Itoa(t.L2EpcID))
			buf.WriteRune(' ')
		}
		if t.Code&L3EpcID != 0 {
			buf.WriteString(strconv.Itoa(t.L3EpcID))
			buf.WriteRune(' ')
		}
		if t.Code&L2Device != 0 {
			buf.WriteString(strconv.Itoa(t.L2DeviceID))
			buf.WriteRune(' ')
			buf.WriteString(strconv.Itoa(int(t.L2DeviceType)))
			buf.WriteRune(' ')
		}
		if t.Code&L3Device != 0 {
			buf.WriteString(strconv.Itoa(t.L3DeviceID))
			buf.WriteRune(' ')
			buf.WriteString(strconv.Itoa(int(t.L3DeviceType)))
			buf.WriteRune(' ')
		}

		if t.Code&IPPath != 0 {
			buf.WriteString(strconv.FormatInt(int64(t.IP0), 16))
			buf.WriteRune(' ')
			buf.WriteString(strconv.FormatInt(int64(t.IP1), 16))
			buf.WriteRune(' ')
		}
		if t.Code&MACPath != 0 {
			buf.WriteString(strconv.FormatInt(int64(t.MAC0), 16))
			buf.WriteRune(' ')
			buf.WriteString(strconv.FormatInt(int64(t.MAC1), 16))
			buf.WriteRune(' ')
		}
		if t.Code&GroupIDPath != 0 {
			buf.WriteString(strconv.Itoa(t.GroupID0))
			buf.WriteRune(' ')
			buf.WriteString(strconv.Itoa(t.GroupID1))
			buf.WriteRune(' ')
		}
		if t.Code&L2EpcIDPath != 0 {
			buf.WriteString(strconv.Itoa(t.L2EpcID0))
			buf.WriteRune(' ')
			buf.WriteString(strconv.Itoa(t.L2EpcID1))
			buf.WriteRune(' ')
		}
		if t.Code&L3EpcIDPath != 0 {
			buf.WriteString(strconv.Itoa(t.L3EpcID0))
			buf.WriteRune(' ')
			buf.WriteString(strconv.Itoa(t.L3EpcID1))
			buf.WriteRune(' ')
		}
		if t.Code&L2DevicePath != 0 {
			buf.WriteString(strconv.Itoa(t.L2DeviceID0))
			buf.WriteRune(' ')
			buf.WriteString(strconv.Itoa(int(t.L2DeviceType0)))
			buf.WriteRune(' ')
			buf.WriteString(strconv.Itoa(t.L2DeviceID1))
			buf.WriteRune(' ')
			buf.WriteString(strconv.Itoa(int(t.L2DeviceType1)))
			buf.WriteRune(' ')
		}
		if t.Code&L3DevicePath != 0 {
			buf.WriteString(strconv.Itoa(t.L3DeviceID0))
			buf.WriteRune(' ')
			buf.WriteString(strconv.Itoa(int(t.L3DeviceType0)))
			buf.WriteRune(' ')
			buf.WriteString(strconv.Itoa(t.L3DeviceID1))
			buf.WriteRune(' ')
			buf.WriteString(strconv.Itoa(int(t.L3DeviceType1)))
			buf.WriteRune(' ')
		}

		if t.Code&Direction != 0 {
			buf.WriteString(strconv.Itoa(int(t.Direction)))
			buf.WriteRune(' ')
		}
		if t.Code&Policy != 0 {
			buf.WriteString(strconv.Itoa(int(t.PolicyType)))
			buf.WriteRune(' ')
			buf.WriteString(strconv.Itoa(t.PolicyID))
			buf.WriteRune(' ')
		}
		if t.Code&VLANID != 0 {
			buf.WriteString(strconv.Itoa(t.VLANID))
			buf.WriteRune(' ')
		}
		if t.Code&Protocol != 0 {
			buf.WriteString(strconv.Itoa(int(t.Protocol)))
			buf.WriteRune(' ')
		}
		if t.Code&ServerPort != 0 {
			buf.WriteString(strconv.Itoa(t.ServerPort))
			buf.WriteRune(' ')
		}
		if t.Code&Host != 0 {
			buf.WriteString(strconv.FormatInt(int64(t.Host), 16))
			buf.WriteRune(' ')
		}
		if t.Code&VTAP != 0 {
			buf.WriteString(strconv.FormatInt(int64(t.VTAP), 16))
			buf.WriteRune(' ')
		}
		if t.Code&TAPType != 0 {
			buf.WriteString(strconv.Itoa(int(t.TAPType)))
			buf.WriteRune(' ')
		}
		if t.Code&SubnetID != 0 {
			buf.WriteString(strconv.Itoa(t.SubnetID))
			buf.WriteRune(' ')
		}
		if t.Code&ACLID != 0 {
			buf.WriteString(strconv.Itoa(t.ACLID))
			buf.WriteRune(' ')
		}
		if t.CustomFields != nil {
			for i := 0; i < CustomFieldNumber; i++ {
				code := 1 << uint(i+64-CustomFieldNumber)
				if t.Code&Code(code) != 0 && t.CustomFields[i] != nil {
					buf.WriteString(t.CustomFields[i].Value)
					buf.WriteRune(' ')
				}
			}
		}
		buf.WriteString(strconv.Itoa(int(t.Code)))

		t.id = buf.String()
	}
	return t.id
}

func (t *Tag) HasVariedField() bool {
	return t.Code&ServerPort != 0
}

func (t *Tag) Equal(other *Tag) bool {
	return t.GetID() == other.GetID()
}
