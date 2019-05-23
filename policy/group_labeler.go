package policy

import (
	"math"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
)

const (
	VM_GROUP     = 0
	IP_GROUP     = 1
	ANONYMOUS_VM = 2
	ANONYMOUS_IP = 3
)

type IpGroupData struct {
	Id    uint32
	EpcId int32
	Type  uint8
	Ips   []string
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
	maskLenData          *MaskLenData          // IP资源组涉及到大于16掩码
	maskLenDataMini      *MaskLenData          // IP资源组涉及到小于等于16掩码

	internetGroupIds []uint32 // internet资源组ID单独存放, 因为是0.0.0.0/0网段匹配所有IP地址
}

type GroupIdData struct {
	GroupIdMap   map[uint32]bool
	GroupIdSlice []uint32
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
	return &IpResourceGroup{NewMaskLenGroupData(), NewMaskLenGroupDataMini(), map[uint32]bool{}, NewMaskLenData(), NewMaskLenData(), nil}
}

func addGroupIdToMap(epcMaskedIpGroupMap map[uint64]*GroupIdData, epcIpKey uint64, id uint32) {
	if group, ok := epcMaskedIpGroupMap[epcIpKey]; ok {
		if ok := group.GroupIdMap[id]; ok {
			return
		} else {
			group.GroupIdMap[id] = true
			group.GroupIdSlice = append(group.GroupIdSlice, id)
		}
	} else {
		epcMaskedIpGroupMap[epcIpKey] = &GroupIdData{
			GroupIdMap:   map[uint32]bool{id: true},
			GroupIdSlice: []uint32{id},
		}
	}
}

func addGroupIdToMiniMap(epcMaskedIpGroupMap map[uint32]*GroupIdData, epcIpKey uint32, id uint32) {
	if group, ok := epcMaskedIpGroupMap[epcIpKey]; ok {
		if ok := group.GroupIdMap[id]; ok {
			return
		} else {
			group.GroupIdMap[id] = true
			group.GroupIdSlice = append(group.GroupIdSlice, id)
		}
	} else {
		epcMaskedIpGroupMap[epcIpKey] = &GroupIdData{
			GroupIdMap:   map[uint32]bool{id: true},
			GroupIdSlice: []uint32{id},
		}
	}
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
		id := group.Id
		for _, raw := range group.Ips {
			ip, maskLen, err := utils.IpNetmaskFromStringCIDR(raw)
			if err != nil {
				continue
			}
			// internet资源组只有这一种即 "{epc: EPC_FROM_INTERNET, ips:"0.0.0.0/0"}", 所以不建立查询map
			if ip == 0 && maskLen == 0 && epcId == EPC_FROM_INTERNET {
				internetGroupIds = append(internetGroupIds, IP_GROUP_ID_FLAG+id)
				continue
			}

			mask := utils.MaskLenToNetmask(maskLen)
			if maskLen > STANDARD_MASK_LEN {
				epcIpKey := (uint64(epcId) << 32) | uint64(ip&mask)
				addGroupIdToMap(maskLenGroupData.maskLenGroups[maskLen], epcIpKey, id)
				maskLenData.Add(uint16(maskLen))
			} else {
				epcIpKey := uint32(epcId)<<16 | uint32(ip&mask)>>16
				addGroupIdToMiniMap(maskLenGroupDataMini.maskLenGroups[maskLen], epcIpKey, id)
				maskLenDataMini.Add(uint16(maskLen))
			}
		}
	}
	g.maskLenGroupData = maskLenGroupData
	g.maskLenGroupDataMini = maskLenGroupDataMini
	g.anonymousGroupIds = anonymousGroupIds
	g.maskLenData = maskLenData
	g.maskLenDataMini = maskLenDataMini
	g.internetGroupIds = internetGroupIds
}

func getIpGroupIdFromMap(key uint64, groupIdSlice []uint32, groupIdMap map[uint32]bool, epcMaskedIpGroupMap map[uint64]*GroupIdData) []uint32 {
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

func getIpGroupIdFromMiniMap(key uint32, groupIdSlice []uint32, groupIdMap map[uint32]bool, epcMaskedIpGroupMap map[uint32]*GroupIdData) []uint32 {
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

func (g *IpResourceGroup) GetGroupIds(ip uint32, endpointInfo *EndpointInfo) []uint32 {
	var groupIdSlice []uint32
	groupIdMap := map[uint32]bool{}
	epcId := uint16(0)
	if endpointInfo.L3EpcId != -1 {
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

func (g *IpResourceGroup) Update(groups []*IpGroupData) {
	g.GenerateIpNetmaskMap(groups)
}

func inDevGroupIds(groupIds []uint32, len int, groupId uint32) bool {
	for i := 0; i < len; i++ {
		if groupId == groupIds[i] {
			return true
		}
	}

	return false
}

// Populate fills tags in flow message
func (g *IpResourceGroup) Populate(ip uint32, endpointInfo *EndpointInfo) {
	devGroupIdLen := len(endpointInfo.GroupIds)
	for _, v := range g.GetGroupIds(ip, endpointInfo) {
		if !inDevGroupIds(endpointInfo.GroupIds, devGroupIdLen, v) {
			endpointInfo.GroupIds = append(endpointInfo.GroupIds, uint32(v)+IP_GROUP_ID_FLAG)
		}
	}
	// 当流量未匹配到任何资源组，其为internet网络IP
	// ip为0时，L2EpcId会赋值给L3EpcId, 是非internet流量
	if len(endpointInfo.GroupIds) == 0 && endpointInfo.L3EpcId == 0 && ip != 0 {
		endpointInfo.GroupIds = append(endpointInfo.GroupIds, g.internetGroupIds...)
	}
}

func (g *IpResourceGroup) AddAnonymousGroupId(anonymous map[uint32]bool, group *IpGroupData) {
	if group.Type == ANONYMOUS_IP || group.Type == ANONYMOUS_VM {
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
