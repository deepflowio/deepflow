package datatype

import (
	"fmt"
	"reflect"
	"time"

	. "github.com/google/gopacket/layers"

	"gitlab.x.lan/yunshan/droplet-libs/pool"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

var (
	INVALID_ENDPOINT_INFO                   = new(EndpointInfo)
	INVALID_ENDPOINT_INFO_L3EPCID           = &EndpointInfo{L3EpcId: -1}
	INVALID_ENDPOINT_INFO_L2END             = &EndpointInfo{L2End: true}
	INVALID_ENDPOINT_INFO_L3END             = &EndpointInfo{L3End: true}
	INVALID_ENDPOINT_INFO_L2AND3END         = &EndpointInfo{L2End: true, L3End: true}
	INVALID_ENDPOINT_INFO_L2END_L3EPCID     = &EndpointInfo{L2End: true, L3EpcId: -1}
	INVALID_ENDPOINT_INFO_L3END_L3EPCID     = &EndpointInfo{L3End: true, L3EpcId: -1}
	INVALID_ENDPOINT_INFO_L2AND3END_L3EPCID = &EndpointInfo{L2End: true, L3End: true, L3EpcId: -1}
	INVALID_ENDPOINT_DATA                   = &EndpointData{SrcInfo: INVALID_ENDPOINT_INFO, DstInfo: INVALID_ENDPOINT_INFO}
	INVALID_ENDPOINT_DATA_L3EPCID           = &EndpointData{SrcInfo: INVALID_ENDPOINT_INFO_L3EPCID, DstInfo: INVALID_ENDPOINT_INFO_L3EPCID}
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

func (k *LookupKey) String() string {
	return fmt.Sprintf("%d %s:%v > %s:%v %v vlan: %v %v:%d > %v:%d proto: %v ttl %v tap: %v",
		k.Timestamp, Uint64ToMac(k.SrcMac), k.L2End0, Uint64ToMac(k.DstMac), k.L2End1, k.EthType, k.Vlan,
		IpFromUint32(k.SrcIp), k.SrcPort, IpFromUint32(k.DstIp), k.DstPort, k.Proto, k.Ttl, k.Tap)
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
		if ipInfo.Ip == (ip & (MAX_NETMASK << (MAX_MASK_LEN - ipInfo.Netmask))) {
			i.SubnetId = ipInfo.SubnetId
			break
		}
	}
}

func IsOriginalTtl(ttl uint8) bool {
	if ttl == 64 || ttl == 128 || ttl == 255 {
		return true
	}
	return false
}

func (i *EndpointInfo) SetL3EndByTtl(ttl uint8) {
	if IsOriginalTtl(ttl) {
		i.L3End = true
	}
}

func (i *EndpointInfo) SetL3EndByIp(data *PlatformData, ip uint32) {
	for _, ipInfo := range data.Ips {
		if ipInfo.Ip == (ip & (MAX_NETMASK << (MAX_MASK_LEN - ipInfo.Netmask))) {
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
	if key.Tap == TAP_TOR {
		d.SrcInfo.L2End = key.L2End0
		d.DstInfo.L2End = key.L2End1
	}
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

var endpointInfoPool = pool.NewLockFreePool(func() interface{} {
	return new(EndpointInfo)
})

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

var endpointDataPool = pool.NewLockFreePool(func() interface{} {
	return new(EndpointData)
})

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
		d.SrcInfo = nil
	}
	if d.DstInfo != nil {
		ReleaseEndpointInfo(d.DstInfo)
		d.DstInfo = nil
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

// 浅拷贝 共用同一个资源组信息
func ShallowCopyEndpointInfo(i *EndpointInfo) *EndpointInfo {
	dup := new(EndpointInfo)
	*dup = *i
	return dup
}

func ShallowCopyEndpointData(d *EndpointData) *EndpointData {
	dup := new(EndpointData)
	if d.SrcInfo != nil {
		dup.SrcInfo = ShallowCopyEndpointInfo(d.SrcInfo)
	}
	if d.DstInfo != nil {
		dup.DstInfo = ShallowCopyEndpointInfo(d.DstInfo)
	}
	return dup
}
