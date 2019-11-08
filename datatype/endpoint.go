package datatype

import (
	"fmt"
	"math"
	"net"
	"reflect"

	"gitlab.x.lan/yunshan/droplet-libs/pool"
)

const (
	EPC_FROM_DEEPFLOW = -1
	EPC_FROM_INTERNET = -2 // 当流量在所有平台数据建立的map中都无法查询到对应的epcId时，epc为-2, 在函数ModifyInternetEpcId中修改
	GROUP_INTERNET    = -2 // Trisolaris下发使用固定值，策略匹配不做特殊处理
)

var (
	INVALID_ENDPOINT_INFO                   = new(EndpointInfo)
	INVALID_ENDPOINT_INFO_L3EPCID           = &EndpointInfo{L3EpcId: EPC_FROM_DEEPFLOW}
	INVALID_ENDPOINT_INFO_L2END             = &EndpointInfo{L2End: true}
	INVALID_ENDPOINT_INFO_L3END             = &EndpointInfo{L3End: true}
	INVALID_ENDPOINT_INFO_L2AND3END         = &EndpointInfo{L2End: true, L3End: true}
	INVALID_ENDPOINT_INFO_L2END_L3EPCID     = &EndpointInfo{L2End: true, L3EpcId: EPC_FROM_DEEPFLOW}
	INVALID_ENDPOINT_INFO_L3END_L3EPCID     = &EndpointInfo{L3End: true, L3EpcId: EPC_FROM_DEEPFLOW}
	INVALID_ENDPOINT_INFO_L2AND3END_L3EPCID = &EndpointInfo{L2End: true, L3End: true, L3EpcId: EPC_FROM_DEEPFLOW}
	INVALID_ENDPOINT_DATA                   = &EndpointData{SrcInfo: INVALID_ENDPOINT_INFO, DstInfo: INVALID_ENDPOINT_INFO}
	INVALID_ENDPOINT_DATA_L3EPCID           = &EndpointData{SrcInfo: INVALID_ENDPOINT_INFO_L3EPCID, DstInfo: INVALID_ENDPOINT_INFO_L3EPCID}
)

type FeatureFlags uint32

const (
	NPM FeatureFlags = 1 << iota
	NPB
)

const (
	IP_GROUP_ID_FLAG = 1e9
)

type EndpointInfo struct {
	L2EpcId      int32 // 负数表示特殊值
	L2DeviceType uint32
	L2DeviceId   uint32

	L3EpcId      int32 // 负数表示特殊值
	L3DeviceType uint32
	L3DeviceId   uint32

	GroupIds []uint32
	HostIp   uint32
	SubnetId uint32

	L2End bool
	L3End bool
}

type L3L2End int

const (
	L3_L2_END_FALSE_FALSE L3L2End = iota
	L3_L2_END_FALSE_TRUE
	L3_L2_END_TRUE_FALSE
	L3_L2_END_TRUE_TRUE
	L3_L2_END_MAX
)

type EndpointStore struct {
	Endpoints *EndpointData

	SrcInfos [L3_L2_END_MAX]EndpointInfo
	DstInfos [L3_L2_END_MAX]EndpointInfo
	Datas    [L3_L2_END_MAX][L3_L2_END_MAX]EndpointData
}

type EndpointData struct {
	SrcInfo *EndpointInfo
	DstInfo *EndpointInfo
}

func NewL3L2End(l2End, l3End bool) L3L2End {
	ends := L3_L2_END_FALSE_FALSE
	if l2End {
		ends += L3_L2_END_FALSE_TRUE
	}
	if l3End {
		ends += L3_L2_END_TRUE_FALSE
	}
	return ends
}

func (i *EndpointInfo) SetL3L2End(ends L3L2End) {
	i.L2End, i.L3End = false, false
	if (ends & L3_L2_END_FALSE_TRUE) > 0 {
		i.L2End = true
	}
	if ends >= L3_L2_END_TRUE_FALSE {
		i.L3End = true
	}
}

func (i *EndpointInfo) GetL3L2End() L3L2End {
	return NewL3L2End(i.L2End, i.L3End)
}

func (i *EndpointInfo) SetL2Data(data *PlatformData) {
	i.L2EpcId = data.EpcId
	i.L2DeviceType = data.DeviceType
	i.L2DeviceId = data.DeviceId
	i.GroupIds = append(i.GroupIds, data.GroupIds...)
}

func (i *EndpointInfo) SetL3Data(data *PlatformData, ip net.IP) {
	i.L3EpcId = EPC_FROM_DEEPFLOW
	if data.EpcId != 0 {
		i.L3EpcId = data.EpcId
	}
	i.L3DeviceType = data.DeviceType
	i.L3DeviceId = data.DeviceId
	i.HostIp = data.HostIp

	for _, ipInfo := range data.Ips {
		var mask net.IPMask
		if len(ipInfo.RawIp) == 4 {
			mask = net.CIDRMask(int(ipInfo.Netmask), 32)
		} else {
			mask = net.CIDRMask(int(ipInfo.Netmask), 128)
		}
		if ipInfo.RawIp.Equal(ip.Mask(mask)) {
			i.SubnetId = ipInfo.SubnetId
			break
		}
	}
}

func (i *EndpointInfo) SetL3DataByMac(data *PlatformData) {
	// 默认MAC对应的SubentId唯一, 取第一个IpNet的SubnetId
	if len(data.Ips) != 0 {
		i.SubnetId = data.Ips[0].SubnetId
	}
	i.L3EpcId = data.EpcId
	i.L3DeviceType = data.DeviceType
	i.L3DeviceId = data.DeviceId
}

func (i *EndpointInfo) GetL3Epc() uint16 {
	if i.L3EpcId == 0 {
		return uint16(EPC_FROM_INTERNET & 0xffff)
	} else {
		return uint16(i.L3EpcId & 0xffff)
	}
}

func (i *EndpointInfo) GetEpc() uint16 {
	id := uint16(0)
	if i.L2EpcId > 0 {
		id = uint16(i.L2EpcId)
	} else if i.L2EpcId == EPC_FROM_DEEPFLOW {
		// 和L3的EpcId == EPC_FROM_DEEPFLOW进行区分
		id = math.MaxUint16 - 1
	} else if i.L2EpcId == 0 {
		if i.L3EpcId > 0 {
			id = uint16(i.L3EpcId)
		} else if i.L3EpcId == EPC_FROM_DEEPFLOW {
			id = math.MaxUint16
		}
	}
	return id
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
			infoString += fmt.Sprintf("%v: [%s] ", infoType.Field(n).Name, i.GetGroupIdsString())
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

func (s *EndpointStore) InitPointer(d *EndpointData) {
	s.Endpoints = d
	for i := L3_L2_END_FALSE_FALSE; i < L3_L2_END_MAX; i++ {
		s.SrcInfos[i] = *d.SrcInfo
		s.SrcInfos[i].SetL3L2End(i)
		s.DstInfos[i] = *d.DstInfo
		s.DstInfos[i].SetL3L2End(i)
	}
	for i := L3_L2_END_FALSE_FALSE; i < L3_L2_END_MAX; i++ {
		for j := L3_L2_END_FALSE_FALSE; j < L3_L2_END_MAX; j++ {
			s.Datas[i][j].SrcInfo = &s.SrcInfos[i]
			s.Datas[i][j].DstInfo = &s.DstInfos[j]
		}
	}
}

func (s *EndpointStore) UpdatePointer(l2End0, l2End1, l3End0, l3End1 bool) *EndpointData {
	return &s.Datas[NewL3L2End(l2End0, l3End0)][NewL3L2End(l2End1, l3End1)]
}

// ReverseData will return a reversed replica of the current EndpointData
func (d *EndpointData) ReverseData() *EndpointData {
	newEndpointData := CloneEndpointData(d)
	newEndpointData.SrcInfo, newEndpointData.DstInfo = newEndpointData.DstInfo, newEndpointData.SrcInfo
	return newEndpointData
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
