/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package datatype

import (
	"fmt"
	"net"
	"reflect"

	"github.com/deepflowio/deepflow/server/libs/pool"
)

const (
	EPC_FROM_DEEPFLOW = -1
	EPC_FROM_INTERNET = -2 // 当流量在所有平台数据建立的map中都无法查询到对应的epcId时，epc为-2, 在函数ModifyInternetEpcId中修改
	EPC_UNKNOWN       = 0
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
	RealIP         net.IP // IsVIP为true时，该字段有值
	L2EpcId        int32  // 负数表示特殊值
	L3EpcId        int32  // 负数表示特殊值
	L2End          bool
	L3End          bool
	IsDevice       bool
	IsVIPInterface bool
	IsVIP          bool
	IsLocalMac     bool // 对应平台数据中的IsLocal字段
	IsLocalIp      bool // 对应平台数据中的IsLocal字段
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
	// L3和L2都是TRUE的时候, 更新L3EpcId
	if ends == L3_L2_END_TRUE_TRUE {
		if i.L2EpcId != 0 && i.L3EpcId == EPC_FROM_INTERNET {
			i.L3EpcId = i.L2EpcId
		}
	}
	// L2End不是true, 一定不是VIP设备采集的流量
	if !i.L2End {
		i.IsVIPInterface = false
	}
}

func (i *EndpointInfo) GetL3L2End() L3L2End {
	return NewL3L2End(i.L2End, i.L3End)
}

func (i *EndpointInfo) SetL2Data(data *PlatformData) {
	if data.EpcId > 0 {
		i.L2EpcId = data.EpcId
	}
	i.IsDevice = true
	i.IsLocalMac = data.IsLocal
}

func (i *EndpointInfo) SetL3Data(data *PlatformData) {
	i.L3EpcId = data.EpcId
	i.IsDevice = true
	i.IsLocalIp = data.IsLocal
}

func (i *EndpointInfo) GetL3Epc() uint16 {
	if i.L3EpcId == 0 {
		return uint16(EPC_FROM_INTERNET & 0xffff)
	} else {
		return uint16(i.L3EpcId & 0xffff)
	}
}

func GroupIdToString(id uint32) string {
	if id >= IP_GROUP_ID_FLAG {
		return fmt.Sprintf("IP-%d", id-IP_GROUP_ID_FLAG)
	} else {
		return fmt.Sprintf("DEV-%d", id)
	}
}

func (i *EndpointInfo) String() string {
	infoString := "{"
	infoType := reflect.TypeOf(*i)
	infoValue := reflect.ValueOf(*i)
	for n := 0; n < infoType.NumField(); n++ {
		infoString += fmt.Sprintf("%v: %v ", infoType.Field(n).Name, infoValue.Field(n))
	}
	infoString += "}"
	return infoString
}

func (d *EndpointData) String() string {
	return fmt.Sprintf("{Src: %v Dst: %v}", d.SrcInfo, d.DstInfo)
}

func (d *EndpointData) Valid() bool {
	return d.SrcInfo != nil
}

func (d *EndpointData) SetL2End(key *LookupKey) {
	if key.TapType == TAP_CLOUD {
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
	*i = EndpointInfo{}
	endpointInfoPool.Put(i)
}

func CloneEndpointInfo(i *EndpointInfo) *EndpointInfo {
	dup := AcquireEndpointInfo()
	*dup = *i
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
