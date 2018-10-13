package datatype

import (
	"fmt"
	"reflect"
	"sync"
	"time"

	. "github.com/google/gopacket/layers"
)

var (
	INVALID_ENDPOINT_DATA = AcquireEndpointData()
)

type TapType uint8

const (
	TAP_ANY TapType = iota
	TAP_ISP
	TAP_SPINE
	TAP_TOR
	TAP_MAX

	TAP_MIN TapType = TAP_ANY + 1
)

const (
	IP_GROUP_ID_FLAG = 1e9
)

type EndpointInfo struct {
	L2EpcId      int32 // -1表示其它项目
	L2DeviceType uint32
	L2DeviceId   uint32
	L2End        bool

	L3EpcId      int32 // -1表示其它项目
	L3DeviceType uint32
	L3DeviceId   uint32
	L3End        bool

	HostIp   uint32
	SubnetId uint32
	GroupIds []uint32
}

type LookupKey struct {
	Timestamp                time.Duration
	SrcMac, DstMac           uint64
	SrcIp, DstIp             uint32
	SrcPort, DstPort         uint16
	EthType                  EthernetType
	Vlan                     uint16
	Proto                    uint8
	Ttl                      uint8
	L2End0, L2End1           bool
	Tap                      TapType
	Invalid                  bool
	FastIndex                int
	SrcGroupIds, DstGroupIds []uint32
}

type EndpointData struct {
	SrcInfo *EndpointInfo
	DstInfo *EndpointInfo
}

func NewEndpointInfo() *EndpointInfo {
	return &EndpointInfo{GroupIds: make([]uint32, 0)}
}

func NewEndpointData() *EndpointData {
	return &EndpointData{}
}

func (i *EndpointInfo) SetL2Data(data *PlatformData) {
	i.L2EpcId = data.EpcId
	i.L2DeviceType = data.DeviceType
	i.L2DeviceId = data.DeviceId
	i.HostIp = data.HostIp
	i.GroupIds = append(i.GroupIds, data.GroupIds...)
}

func (i *EndpointInfo) SetL3Data(data *PlatformData, ip uint32) {
	i.L3EpcId = -1
	if data.EpcId != 0 {
		i.L3EpcId = data.EpcId
	}
	i.L3DeviceType = data.DeviceType
	i.L3DeviceId = data.DeviceId

	for _, ipInfo := range data.Ips {
		if ipInfo.Ip == (ip & (NETMASK << (MAX_MASK_LEN - ipInfo.Netmask))) {
			i.SubnetId = ipInfo.SubnetId
			break
		}
	}
}

func (i *EndpointInfo) SetL3EndByTtl(ttl uint8) {
	if ttl == 64 || ttl == 128 || ttl == 255 {
		i.L3End = true
	}
}

func (i *EndpointInfo) SetL3EndByIp(data *PlatformData, ip uint32) {
	for _, ipInfo := range data.Ips {
		if ipInfo.Ip == (ip & (NETMASK << (MAX_MASK_LEN - ipInfo.Netmask))) {
			i.L3End = true
			break
		}
	}
}

func (i *EndpointInfo) SetL3EndByMac(data *PlatformData, mac uint64) {
	if data.Mac == mac {
		i.L3End = true
	}
}

func GroupIdToString(id uint32) string {
	if id >= IP_GROUP_ID_FLAG {
		return fmt.Sprintf("IP-%d", id-IP_GROUP_ID_FLAG)
	} else {
		return fmt.Sprintf("DEV-%d", id)
	}
}

func (i *EndpointInfo) GetGroupIdsString() string {
	str := ""
	for id, group := range i.GroupIds {
		if id != 0 {
			str += " "
		}
		str += GroupIdToString(group)
	}
	return str
}

func (i *EndpointInfo) String() string {
	infoString := "{"
	infoType := reflect.TypeOf(*i)
	infoValue := reflect.ValueOf(*i)
	for n := 0; n < infoType.NumField(); n++ {
		if infoType.Field(n).Name == "GroupIds" {
			infoString += fmt.Sprintf("%v: [%s]", infoType.Field(n).Name, i.GetGroupIdsString())
		} else {
			infoString += fmt.Sprintf("%v: %v ", infoType.Field(n).Name, infoValue.Field(n))
		}
	}
	infoString += "}"
	return infoString
}

func (d *EndpointData) String() string {
	return fmt.Sprintf("{Src: %v Dst: %v}", d.SrcInfo, d.DstInfo)
}

func (d *EndpointData) SetL2End(key *LookupKey) {
	d.SrcInfo.L2End = key.L2End0
	d.DstInfo.L2End = key.L2End1
}

func (t *TapType) CheckTapType(tapType TapType) bool {
	if tapType < TAP_MAX {
		return true
	}
	return false
}

func FormatGroupId(id uint32) uint32 {
	if id >= IP_GROUP_ID_FLAG {
		return id - IP_GROUP_ID_FLAG
	} else {
		return id
	}
}

var endpointInfoPool = sync.Pool{
	New: func() interface{} {
		return NewEndpointInfo()
	},
}

func AcquireEndpointInfo() *EndpointInfo {
	return endpointInfoPool.Get().(*EndpointInfo)
}

func ReleaseEndpointInfo(i *EndpointInfo) {
	if i.GroupIds != nil {
		i.GroupIds = i.GroupIds[:0]
	}
	*i = EndpointInfo{GroupIds: i.GroupIds}
	endpointInfoPool.Put(i)
}

func CloneEndpointInfo(i *EndpointInfo) *EndpointInfo {
	dup := AcquireEndpointInfo()
	*dup = *i
	dup.GroupIds = make([]uint32, len(i.GroupIds))
	copy(dup.GroupIds, i.GroupIds)
	return dup
}

var endpointDataPool = sync.Pool{
	New: func() interface{} {
		return NewEndpointData()
	},
}

func AcquireEndpointData(infos ...*EndpointInfo) *EndpointData {
	d := endpointDataPool.Get().(*EndpointData)
	len := len(infos)
	if len == 0 {
		d.SrcInfo = AcquireEndpointInfo()
		d.DstInfo = AcquireEndpointInfo()
	} else if len == 1 {
		d.SrcInfo = infos[0]
		d.DstInfo = AcquireEndpointInfo()
	} else if len == 2 {
		d.SrcInfo = infos[0]
		d.DstInfo = infos[1]
	}
	return d
}

func ReleaseEndpointData(d *EndpointData) {
	if d.SrcInfo != nil {
		ReleaseEndpointInfo(d.SrcInfo)
	}
	if d.DstInfo != nil {
		ReleaseEndpointInfo(d.DstInfo)
	}
	*d = EndpointData{}
	endpointDataPool.Put(d)
}

func CloneEndpointData(d *EndpointData) *EndpointData {
	dup := AcquireEndpointData(nil, nil)
	if d.SrcInfo != nil {
		dup.SrcInfo = CloneEndpointInfo(d.SrcInfo)
	}
	if d.DstInfo != nil {
		dup.DstInfo = CloneEndpointInfo(d.DstInfo)
	}
	return dup
}
