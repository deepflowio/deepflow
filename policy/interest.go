package policy

import (
	"math"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

type InterestTable struct {
	groupIdMaps         map[uint32]int
	groupIdFromPlatform []uint32
	groupIdFromIpGroup  []uint32

	InterestProtoMaps *[TAP_MAX][math.MaxUint8 + 1]bool
	InterestPortMaps  *[TAP_MAX][math.MaxUint16 + 1]PortRange

	fromInterestGroupMaps *[TAP_MAX][math.MaxUint16 + 1]uint16
}

func (t *InterestTable) Init() {
	t.InterestProtoMaps = &[TAP_MAX][math.MaxUint8 + 1]bool{}
	t.InterestPortMaps = &[TAP_MAX][math.MaxUint16 + 1]PortRange{}
	t.fromInterestGroupMaps = &[TAP_MAX][math.MaxUint16 + 1]uint16{}
}

func (t *InterestTable) generateGroupIdMap() {
	groupIdMaps := make(map[uint32]int, len(t.groupIdFromPlatform)+len(t.groupIdFromIpGroup))

	for _, id := range t.groupIdFromPlatform {
		groupIdMaps[id] = RESOURCE_GROUP_TYPE_DEV
	}

	// 资源组ID一致的情况，设备资源组优先
	for _, id := range t.groupIdFromIpGroup {
		if groupIdMaps[id] != RESOURCE_GROUP_TYPE_DEV {
			groupIdMaps[id] = RESOURCE_GROUP_TYPE_IP
		}
	}
	t.groupIdMaps = groupIdMaps
}

func (t *InterestTable) GenerateGroupIdMapByIpGroupData(datas []*IpGroupData) {
	t.groupIdFromIpGroup = make([]uint32, len(datas))
	for _, data := range datas {
		t.groupIdFromIpGroup = append(t.groupIdFromIpGroup, data.Id)
	}
	t.generateGroupIdMap()
}

func (t *InterestTable) GenerateGroupIdMapByPlatformData(datas []*PlatformData) {
	t.groupIdFromPlatform = make([]uint32, 1024)
	for _, data := range datas {
		t.groupIdFromPlatform = append(t.groupIdFromPlatform, data.GroupIds...)
	}
	t.generateGroupIdMap()
}

func (t *InterestTable) generateInterestKeys(endpointData *EndpointData, packet *LookupKey, any bool) {
	hasAnyGroup := false
	packet.SrcGroupIds = make([]uint16, 0, len(endpointData.SrcInfo.GroupIds))
	packet.SrcAllGroupIds = make([]uint16, 0, len(endpointData.SrcInfo.GroupIds))
	packet.DstGroupIds = make([]uint16, 0, len(endpointData.DstInfo.GroupIds))
	packet.DstAllGroupIds = make([]uint16, 0, len(endpointData.DstInfo.GroupIds))
	// 添加groupid 0匹配全采集的策略
	for _, id := range endpointData.SrcInfo.GroupIds {
		id = FormatGroupId(id)
		if relations := t.fromInterestGroupMaps[packet.Tap][id]; relations > 0 {
			packet.SrcGroupIds = t.appendNoRepeat(packet.SrcGroupIds, relations)
			packet.SrcAllGroupIds = append(packet.SrcAllGroupIds, relations)
			if id == ANY_GROUP {
				hasAnyGroup = true
			}
		} else {
			packet.SrcAllGroupIds = append(packet.SrcAllGroupIds, 0)
		}
	}
	if !hasAnyGroup && any {
		// 添加groupid 0匹配全采集的策略
		packet.SrcGroupIds = t.appendNoRepeat(packet.SrcGroupIds, ANY_GROUP)
	}

	hasAnyGroup = false
	for _, id := range endpointData.DstInfo.GroupIds {
		id = FormatGroupId(id)
		if relations := t.fromInterestGroupMaps[packet.Tap][id]; relations > 0 {
			packet.DstGroupIds = t.appendNoRepeat(packet.DstGroupIds, relations)
			packet.DstAllGroupIds = append(packet.DstAllGroupIds, relations)
			if id == ANY_GROUP {
				hasAnyGroup = true
			}
		} else {
			packet.DstAllGroupIds = append(packet.DstAllGroupIds, 0)
		}
	}
	if !hasAnyGroup && any {
		// 添加groupid 0匹配全采集的策略
		packet.DstGroupIds = t.appendNoRepeat(packet.DstGroupIds, ANY_GROUP)
	}

	t.getFastInterestKeys(packet)
}

func (t *InterestTable) generateInterestPortMap(acls []*Acl) {
	interestPortMaps := &[TAP_MAX][math.MaxUint16 + 1]PortRange{}
	ports := make([]PortRange, 0, 1000)

	for tapType := TAP_MIN - 1; tapType < TAP_MAX; tapType++ {
		ports = ports[:0]
		for _, acl := range acls {
			if acl.Type == tapType || acl.Type == TAP_ANY || tapType == TAP_ANY {
				ports = append(ports, acl.SrcPortRange...)
				ports = append(ports, acl.DstPortRange...)
			}
		}

		ports = GetPortRanges(ports)

		for _, port := range ports {
			for i := int(port.Min()); i <= int(port.Max()); i++ {
				interestPortMaps[tapType][i] = port
			}
		}
	}

	for _, acl := range acls {
		for _, port := range acl.SrcPortRange {
			for i := int(port.Min()); i <= int(port.Max()); {
				portRangs := interestPortMaps[acl.Type][i]
				acl.SrcPorts = append(acl.SrcPorts, portRangs.Min())
				i = int(portRangs.Max()) + 1
			}
		}

		for _, port := range acl.DstPortRange {
			for i := int(port.Min()); i <= int(port.Max()); {
				portRangs := interestPortMaps[acl.Type][i]
				acl.DstPorts = append(acl.DstPorts, portRangs.Min())
				i = int(portRangs.Max()) + 1
			}
		}
	}
	t.InterestPortMaps = interestPortMaps
}

func (t *InterestTable) splitGroups(raw []uint16, keys []uint32) ([]uint16, []uint16) {
	both := make([]uint16, 0, len(raw))
	last := make([]uint16, 0, len(raw))
	for _, id := range raw {
		repeat := false
		for _, key := range keys {
			if uint16(key&0xffff) == id {
				repeat = true
				break
			}
		}
		if !repeat {
			last = append(last, id)
		} else {
			both = append(both, id)
		}
	}

	return both, last
}

func (t *InterestTable) appendNoRepeat(raws []uint16, key uint16) []uint16 {
	for _, raw := range raws {
		if raw == key {
			return raws
		}
	}
	return append(raws, key)
}

// 使用策略中的资源组，根据资源组Map结构获取资源组对应的组ID，存入Src/DstGroupRelations字段
// 后面的策略Map生成使用Src/DstGroupRelations字段
func (t *InterestTable) getGroupRelation(acls []*Acl, from *[TAP_MAX][math.MaxUint16 + 1]uint16) {
	for _, acl := range acls {
		relationIds := make([]uint16, 0, len(acl.SrcGroups))
		for _, group := range acl.SrcGroups {
			relationIds = t.appendNoRepeat(relationIds, from[acl.Type][group])
		}
		acl.SrcGroupRelations = relationIds

		relationIds = make([]uint16, 0, len(acl.DstGroups))
		for _, group := range acl.DstGroups {
			relationIds = t.appendNoRepeat(relationIds, from[acl.Type][group])
		}
		acl.DstGroupRelations = relationIds
	}
}

func (t *InterestTable) generateGroupRelationByGroups(groups []uint32, tapType TapType, id *uint16, to *[TAP_MAX][math.MaxUint16 + 1][]uint16, from *[TAP_MAX][math.MaxUint16 + 1]uint16) {
	insert := make([]uint16, 0, len(groups))
	for _, group := range groups {
		if group == 0 {
			continue
		}
		relateId := from[tapType][uint16(group&0xffff)]
		if relateId == 0 {
			insert = append(insert, uint16(group&0xffff))
			continue
		}
		both, raw := t.splitGroups(to[tapType][relateId], groups)
		if len(raw) != 0 {
			to[tapType][*id] = both
			to[tapType][relateId] = raw
			for _, gid := range both {
				from[tapType][gid] = *id
			}
			from[tapType][uint16(group&0xffff)] = *id
			*id++
		}
	}
	if len(insert) > 0 {
		for _, group := range insert {
			from[tapType][group] = *id
		}
		to[tapType][*id] = insert
		*id++
	}
}

// 将策略中的资源组ID进行再分组，存储在资源组Map结构
// 例如所有策略中原资源组都是[1, 2], 目的资源组为[3, 4]
// 原算法：
//     key个数 = 2 * 2 = 4
// 资源组再分组后， [1, 2]为组m，[3, 4]为组n:
//     key个数 = m * n = 1
func (t *InterestTable) generateGroupRelation(acls []*Acl, to *[TAP_MAX][math.MaxUint16 + 1][]uint16, from *[TAP_MAX][math.MaxUint16 + 1]uint16) {
	for tapType := TAP_MIN; tapType < TAP_MAX; tapType++ {
		id := uint16(1)
		for _, acl := range acls {
			if acl.Type != tapType && acl.Type != TAP_ANY {
				continue
			}
			for _, groups := range [][]uint32{acl.SrcGroups, acl.DstGroups} {
				if acl.Type != TAP_ANY {
					t.generateGroupRelationByGroups(groups, acl.Type, &id, to, from)
				} else {
					for tapType := TAP_MIN; tapType < TAP_MAX; tapType++ {
						t.generateGroupRelationByGroups(groups, tapType, &id, to, from)
					}
				}
			}
		}
	}
}

func (t *InterestTable) generateInterestGroupMap(acls []*Acl) {
	to := &[TAP_MAX][math.MaxUint16 + 1][]uint16{}
	from := &[TAP_MAX][math.MaxUint16 + 1]uint16{}
	t.generateGroupRelation(acls, to, from)
	t.getGroupRelation(acls, from)
	t.fromInterestGroupMaps = from
}

func (t *InterestTable) generateInterestProtoMaps(acls []*Acl) {
	interestProtoMaps := &[TAP_MAX][math.MaxUint8 + 1]bool{}

	for _, acl := range acls {
		if !acl.Type.CheckTapType(acl.Type) {
			continue
		}
		if acl.Type != TAP_ANY {
			interestProtoMaps[acl.Type][acl.Proto] = true
		} else {
			for tapType := TAP_MIN; tapType < TAP_MAX; tapType++ {
				interestProtoMaps[tapType][acl.Proto] = true
			}
		}
	}
	t.InterestProtoMaps = interestProtoMaps
}

func (t *InterestTable) GenerateInterestMaps(acls []*Acl) {
	t.generateInterestPortMap(acls)
	t.generateInterestGroupMap(acls)
	t.generateInterestProtoMaps(acls)
}

func (t *InterestTable) getFastInterestKeys(packet *LookupKey) {
	ports := t.InterestPortMaps[packet.Tap][packet.SrcPort]
	packet.SrcPort = ports.Min()
	ports = t.InterestPortMaps[packet.Tap][packet.DstPort]
	packet.DstPort = ports.Min()
	if !t.InterestProtoMaps[packet.Tap][packet.Proto] {
		packet.Proto = ANY_PROTO
	}
}
