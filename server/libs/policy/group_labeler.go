/*
 * Copyright (c) 2022 Yunshan Networks
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

package policy

import (
	"math"
	"net"

	. "github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

const (
	NAMED     = 0
	ANONYMOUS = 1
)

type IpGroupData struct {
	Id    uint32
	EpcId int32
	Type  uint8
	Ips   []string
	VmIds []uint32
}

type Ip6GroupItem struct {
	id    uint32
	ipNet *net.IPNet
}

type MaskLenGroupData struct {
	maskLenGroups [MASK_LEN_NUM]map[uint64]*GroupIdData
}

type MaskLenGroupDataMini struct {
	maskLenGroups [MASK_LEN_NUM]map[uint32]*GroupIdData
}

type MaskLenData struct {
	maskLenMap   map[uint16]bool
	maskLenSlice []uint16
}

// IpResourceGroup is the labeler for resource groups
type IpResourceGroup struct {
	maskLenGroupData     *MaskLenGroupData     // 保存大于16掩码的资源组信息
	maskLenGroupDataMini *MaskLenGroupDataMini // 保存小于等于16掩码的资源组信息
	anonymousGroupIds    map[uint32]bool       // 匿名资源组相关数据
	anonymousIp4GroupIds map[uint32]bool       // 匿名资源组相关数据由IPv4数据生成
	anonymousIp6GroupIds map[uint32]bool       // 匿名资源组相关数据由IPv6数据生成
	maskLenData          *MaskLenData          // IP资源组涉及到大于16掩码
	maskLenDataMini      *MaskLenData          // IP资源组涉及到小于等于16掩码

	ip6EpcMap *[math.MaxUint16 + 1][]*Ip6GroupItem

	internetGroupIds []uint32 // internet资源组ID单独存放, 因为是0.0.0.0/0网段匹配所有IP地址
}

type GroupIdData struct {
	GroupIdMap   map[uint16]bool
	GroupIdSlice []uint16
}

func NewMaskLenData() *MaskLenData {
	return &MaskLenData{
		maskLenMap:   map[uint16]bool{},
		maskLenSlice: []uint16{},
	}
}

func (d *MaskLenData) Add(maskLen uint16) {
	if ok := d.maskLenMap[maskLen]; !ok {
		d.maskLenMap[maskLen] = true
		d.maskLenSlice = append(d.maskLenSlice, maskLen)
	}
}

func NewMaskLenGroupData() *MaskLenGroupData {
	var maskLenGroupData MaskLenGroupData
	for i := STANDARD_MASK_LEN + 1; i < MASK_LEN_NUM; i++ {
		maskLenGroupData.maskLenGroups[i] = make(map[uint64]*GroupIdData)
	}
	return &maskLenGroupData
}

func NewMaskLenGroupDataMini() *MaskLenGroupDataMini {
	var maskLenGroupDataMini MaskLenGroupDataMini
	for i := 0; i < STANDARD_MASK_LEN+1; i++ {
		maskLenGroupDataMini.maskLenGroups[i] = make(map[uint32]*GroupIdData)
	}
	return &maskLenGroupDataMini
}

func NewIpResourceGroup() *IpResourceGroup {
	return &IpResourceGroup{NewMaskLenGroupData(), NewMaskLenGroupDataMini(), map[uint32]bool{},
		map[uint32]bool{}, map[uint32]bool{}, NewMaskLenData(), NewMaskLenData(), nil, nil}
}

func addGroupIdToMap(epcMaskedIpGroupMap map[uint64]*GroupIdData, epcIpKey uint64, id uint16) {
	if group, ok := epcMaskedIpGroupMap[epcIpKey]; ok {
		if ok := group.GroupIdMap[id]; ok {
			return
		} else {
			group.GroupIdMap[id] = true
			group.GroupIdSlice = append(group.GroupIdSlice, id)
		}
	} else {
		epcMaskedIpGroupMap[epcIpKey] = &GroupIdData{
			GroupIdMap:   map[uint16]bool{id: true},
			GroupIdSlice: []uint16{id},
		}
	}
}

func addGroupIdToMiniMap(epcMaskedIpGroupMap map[uint32]*GroupIdData, epcIpKey uint32, id uint16) {
	if group, ok := epcMaskedIpGroupMap[epcIpKey]; ok {
		if ok := group.GroupIdMap[id]; ok {
			return
		} else {
			group.GroupIdMap[id] = true
			group.GroupIdSlice = append(group.GroupIdSlice, id)
		}
	} else {
		epcMaskedIpGroupMap[epcIpKey] = &GroupIdData{
			GroupIdMap:   map[uint16]bool{id: true},
			GroupIdSlice: []uint16{id},
		}
	}
}

func (g *IpResourceGroup) GenerateIp6NetmaskMap(ipgroupData []*IpGroupData) {
	var ip6EpcMap [math.MaxUint16 + 1][]*Ip6GroupItem
	anonymousGroupIds := map[uint32]bool{}
	for _, group := range ipgroupData {
		// 建立AnonymousGroupId表
		g.AddAnonymousGroupId(anonymousGroupIds, group)
		for _, raw := range group.Ips {
			_, ipNet, err := net.ParseCIDR(raw)
			if err != nil || len(ipNet.IP) == 4 {
				continue
			}
			epc := group.EpcId & 0xffff
			item := &Ip6GroupItem{id: group.Id, ipNet: ipNet}
			ip6EpcMap[epc] = append(ip6EpcMap[epc], item)
		}
	}
	g.ip6EpcMap = &ip6EpcMap
	g.anonymousIp6GroupIds = anonymousGroupIds
}

func (g *IpResourceGroup) GenerateIpNetmaskMap(ipgroupData []*IpGroupData) {
	maskLenGroupData := NewMaskLenGroupData()
	maskLenGroupDataMini := NewMaskLenGroupDataMini()
	anonymousGroupIds := map[uint32]bool{}
	maskLenData := NewMaskLenData()
	maskLenDataMini := NewMaskLenData()
	internetGroupIds := make([]uint32, 0, 10)

	for _, group := range ipgroupData {
		g.AddAnonymousGroupId(anonymousGroupIds, group)
		epcId := group.EpcId
		if group.EpcId == EPC_FROM_DEEPFLOW {
			epcId = 0
		}
		id := group.Id
		for _, raw := range group.Ips {
			ip, maskLen, err := utils.IpNetmaskFromStringCIDR(raw)
			if err != nil || len(ip) == 16 {
				continue
			}
			ip4 := utils.IpToUint32(ip)
			// internet资源组只有这一种即 "{epc: EPC_FROM_INTERNET, ips:"0.0.0.0/0"}", 所以不建立查询map
			if ip4 == 0 && maskLen == 0 && epcId == EPC_FROM_INTERNET {
				internetGroupIds = append(internetGroupIds, IP_GROUP_ID_FLAG+id)
				continue
			}

			mask := utils.MaskLenToNetmask(maskLen)
			if maskLen > STANDARD_MASK_LEN {
				epcIpKey := (uint64(epcId) << 32) | uint64(ip4&mask)
				addGroupIdToMap(maskLenGroupData.maskLenGroups[maskLen], epcIpKey, uint16(id))
				maskLenData.Add(uint16(maskLen))
			} else {
				epcIpKey := uint32(epcId)<<16 | uint32(ip4&mask)>>16
				addGroupIdToMiniMap(maskLenGroupDataMini.maskLenGroups[maskLen], epcIpKey, uint16(id))
				maskLenDataMini.Add(uint16(maskLen))
			}
		}
	}
	g.maskLenGroupData = maskLenGroupData
	g.maskLenGroupDataMini = maskLenGroupDataMini
	g.anonymousIp4GroupIds = anonymousGroupIds
	g.maskLenData = maskLenData
	g.maskLenDataMini = maskLenDataMini
	g.internetGroupIds = internetGroupIds
}

func getIpGroupIdFromMap(key uint64, groupIdSlice []uint16, groupIdMap map[uint16]bool, epcMaskedIpGroupMap map[uint64]*GroupIdData) []uint16 {
	if group, ok := epcMaskedIpGroupMap[key]; ok {
		for _, value := range group.GroupIdSlice {
			if ok := groupIdMap[value]; !ok {
				groupIdSlice = append(groupIdSlice, value)
				groupIdMap[value] = true
			}
		}
	}
	return groupIdSlice
}

func getIpGroupIdFromMiniMap(key uint32, groupIdSlice []uint16, groupIdMap map[uint16]bool, epcMaskedIpGroupMap map[uint32]*GroupIdData) []uint16 {
	if group, ok := epcMaskedIpGroupMap[key]; ok {
		for _, value := range group.GroupIdSlice {
			if ok := groupIdMap[value]; !ok {
				groupIdSlice = append(groupIdSlice, value)
				groupIdMap[value] = true
			}
		}
	}

	return groupIdSlice
}

func (g *IpResourceGroup) GetGroupIdsByIpv6(ip net.IP, endpointInfo *EndpointInfo) []uint16 {
	// 未初始化直接返回
	if g.ip6EpcMap == nil {
		return nil
	}
	groupIdSlice := make([]uint16, 0, 4)
	var groupIdMap [math.MaxUint16 + 1]bool
	if endpointInfo.L3EpcId > 0 {
		for _, item := range g.ip6EpcMap[endpointInfo.L3EpcId] {
			if item.ipNet.Contains(ip) && groupIdMap[item.id] == false {
				groupIdSlice = append(groupIdSlice, uint16(item.id))
				// 避免添加重复的资源组ID
				groupIdMap[item.id] = true
			}
		}
	}
	// 查找epc为0的
	for _, item := range g.ip6EpcMap[0] {
		if item.ipNet.Contains(ip) && groupIdMap[item.id] == false {
			groupIdSlice = append(groupIdSlice, uint16(item.id))
			// 避免添加重复的资源组ID
			groupIdMap[item.id] = true
		}
	}
	return groupIdSlice
}

func (g *IpResourceGroup) GetGroupIds(ip uint32, endpointInfo *EndpointInfo) []uint16 {
	var groupIdSlice []uint16
	groupIdMap := map[uint16]bool{}
	epcId := uint16(0)
	if endpointInfo.L3EpcId > 0 {
		epcId = uint16(endpointInfo.L3EpcId)
	}
	for _, maskLen := range g.maskLenData.maskLenSlice {
		epcMaskedIpGroupMap := g.maskLenGroupData.maskLenGroups[maskLen]
		key := uint64(epcId)<<32 | uint64(ip&utils.MaskLenToNetmask(uint32(maskLen)))
		groupIdSlice = getIpGroupIdFromMap(key, groupIdSlice, groupIdMap, epcMaskedIpGroupMap)
		// 查找项目全采集的资源组
		if epcId != 0 {
			key = uint64(ip & (math.MaxUint32 << uint32(MAX_MASK_LEN-maskLen)))
			groupIdSlice = getIpGroupIdFromMap(key, groupIdSlice, groupIdMap, epcMaskedIpGroupMap)
		}
	}
	for _, maskLen := range g.maskLenDataMini.maskLenSlice {
		epcMaskedIpGroupMap := g.maskLenGroupDataMini.maskLenGroups[maskLen]
		key := uint32(epcId)<<16 | uint32(ip&utils.MaskLenToNetmask(uint32(maskLen)))>>16
		groupIdSlice = getIpGroupIdFromMiniMap(key, groupIdSlice, groupIdMap, epcMaskedIpGroupMap)
		// 查找项目全采集的资源组
		if epcId != 0 {
			key = uint32(ip&(math.MaxUint32<<uint32(MAX_MASK_LEN-maskLen))) >> 16
			groupIdSlice = getIpGroupIdFromMiniMap(key, groupIdSlice, groupIdMap, epcMaskedIpGroupMap)
		}
	}

	return groupIdSlice
}

func (g *IpResourceGroup) GenerateAnonymousGroupIdMap() {
	// 合并IPv4和IPv6的anonymousGroupIds
	anonymousGroupIds := g.anonymousIp4GroupIds
	for key, value := range g.anonymousIp6GroupIds {
		anonymousGroupIds[key] = value
	}
	g.anonymousGroupIds = anonymousGroupIds
}

func (g *IpResourceGroup) Update(groups []*IpGroupData) {
	g.GenerateIpNetmaskMap(groups)
	g.GenerateIp6NetmaskMap(groups)
	g.GenerateAnonymousGroupIdMap()
}

func (g *IpResourceGroup) AddAnonymousGroupId(anonymous map[uint32]bool, group *IpGroupData) {
	if group.Type == ANONYMOUS {
		anonymous[group.Id] = true
	}
}

func (g *IpResourceGroup) RemoveAnonymousGroupIds(groupIds []uint32, relationIds []uint16) ([]uint32, []uint16) {
	groups := make([]uint32, 0, len(groupIds))
	relations := make([]uint16, 0, len(relationIds))
	for index := range groupIds {
		if _, ok := g.anonymousGroupIds[FormatGroupId(groupIds[index])]; !ok {
			groups = append(groups, groupIds[index])
			relations = append(relations, relationIds[index])
		}
	}

	return groups, relations
}
