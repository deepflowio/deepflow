package datatype

import (
	"fmt"
	"math"

	"gitlab.x.lan/yunshan/droplet-libs/bit"
	"gitlab.x.lan/yunshan/droplet-libs/pool"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

var (
	INVALID_POLICY_DATA = new(PolicyData)
)

type ActionFlag uint16

type NpbAction uint64 // tunnel-ip | tunnel-id | Dep/Ip | TapSide | payload-slice

const (
	TAPSIDE_SRC  = 0x1
	TAPSIDE_DST  = 0x2
	TAPSIDE_MASK = TAPSIDE_SRC | TAPSIDE_DST
	TAPSIDE_ALL  = TAPSIDE_SRC | TAPSIDE_DST
)

const (
	RESOURCE_GROUP_TYPE_DEV  = 0x1
	RESOURCE_GROUP_TYPE_IP   = 0x2
	RESOURCE_GROUP_TYPE_MASK = RESOURCE_GROUP_TYPE_DEV | RESOURCE_GROUP_TYPE_IP
)

const (
	GROUP_TYPE_OFFSET    = 62
	GROUP_MAPBITS_OFFSET = 56
	GROUP_TYPE_MASK      = 0x1
	GROUP_TYPE_SRC       = 0x0
	GROUP_TYPE_DST       = 0x1
	GROUP_MAPOFFSET_MASK = 0x3F
	GROUP_MAPBITS_MASK   = math.MaxUint64 >> 8
)

func (a NpbAction) TapSideCompare(flag int) bool {
	return (a.TapSide() & flag) == flag
}

func (a NpbAction) TapSide() int {
	return int((a >> 16) & TAPSIDE_MASK)
}

func (a *NpbAction) SetTapSide(flag int) {
	*a &= ^NpbAction(TAPSIDE_MASK << 16)
	*a |= NpbAction((flag & TAPSIDE_MASK) << 16)
}

func (a *NpbAction) AddTapSide(flag int) {
	*a |= NpbAction((flag & TAPSIDE_MASK) << 16)
}

func (a *NpbAction) ReverseTapSide() NpbAction {
	if a.TapSide() == TAPSIDE_ALL {
		return *a
	}

	return *a ^ NpbAction(uint64(TAPSIDE_MASK)<<16)
}

func (a NpbAction) ResourceGroupTypeCompare(flag int) bool {
	return (a.ResourceGroupType() & flag) == flag
}

func (a *NpbAction) AddResourceGroupType(groupType int) {
	*a |= ((NpbAction(groupType & RESOURCE_GROUP_TYPE_MASK)) << 18)
}

func (a NpbAction) ResourceGroupType() int {
	return int((a >> 18) & RESOURCE_GROUP_TYPE_MASK)
}

func (a NpbAction) TunnelIp() IPv4Int {
	return IPv4Int(a >> 32)
}

func (a NpbAction) TunnelId() uint32 {
	return uint32((a >> 20) & 0xff)
}

func (a *NpbAction) SetTunnelId(id uint32) {
	*a &= ^NpbAction(0xff << 20)
	*a |= NpbAction((id & 0xff) << 20)
}

func (a NpbAction) TunnelInfo() uint64 {
	return uint64(a >> 20)
}

func (a NpbAction) PayloadSlice() uint16 {
	return uint16(a)
}

func (a *NpbAction) SetPayloadSlice(payload uint16) {
	*a &= ^NpbAction(0xffff)
	*a |= NpbAction(payload)
}

func (a NpbAction) String() string {
	return fmt.Sprintf("{%d@%s slice %d side: %d group: %d}", a.TunnelId(), IpFromUint32(a.TunnelIp()), a.PayloadSlice(), a.TapSide(), a.ResourceGroupType())
}

func ToNpbAction(ip uint32, id uint8, group, tapSide uint8, slice uint16) NpbAction {
	return NpbAction(uint64(ip)<<32 | uint64(id)<<20 | (uint64(group)&RESOURCE_GROUP_TYPE_MASK)<<18 | (uint64(tapSide)&TAPSIDE_MASK)<<16 | uint64(slice))
}

const (
	ACTION_PACKET_COUNTING ActionFlag = 1 << iota
	ACTION_FLOW_COUNTING
	ACTION_FLOW_STORING
	ACTION_TCP_FLOW_PERF_COUNTING
	ACTION_PACKET_CAPTURING
	ACTION_FLOW_MISC_COUNTING
	ACTION_PACKET_BROKERING
	ACTION_PACKET_COUNT_BROKERING
	ACTION_FLOW_COUNT_BROKERING
	ACTION_TCP_FLOW_PERF_COUNT_BROKERING
	ACTION_GEO_POSITIONING
)

func (f ActionFlag) String() string {
	s := "|"
	if f&ACTION_PACKET_COUNTING != 0 {
		s += "PC|"
	}
	if f&ACTION_FLOW_COUNTING != 0 {
		s += "FC|"
	}
	if f&ACTION_FLOW_STORING != 0 {
		s += "FS|"
	}
	if f&ACTION_TCP_FLOW_PERF_COUNTING != 0 {
		s += "TFPC|"
	}
	if f&ACTION_PACKET_CAPTURING != 0 {
		s += "PC2|"
	}
	if f&ACTION_FLOW_MISC_COUNTING != 0 {
		s += "FMC|"
	}
	if f&ACTION_PACKET_BROKERING != 0 {
		s += "PB|"
	}
	if f&ACTION_PACKET_COUNT_BROKERING != 0 {
		s += "PCB|"
	}
	if f&ACTION_FLOW_COUNT_BROKERING != 0 {
		s += "FCB|"
	}
	if f&ACTION_TCP_FLOW_PERF_COUNT_BROKERING != 0 {
		s += "TFPCB|"
	}
	if f&ACTION_GEO_POSITIONING != 0 {
		s += "GP|"
	}
	return s
}

type ACLID uint16

type PolicyData struct {
	ACLID         ACLID      // 匹配的第一个ACL
	ActionFlags   ActionFlag // bitwise OR
	AclActions    []AclAction
	NpbActions    []NpbAction
	AclGidBitmaps []AclGidBitmap
}

type DirectionType uint8

const (
	NO_DIRECTION DirectionType = 0
)

const (
	FORWARD DirectionType = 1 << iota
	BACKWARD
)

type TagTemplate uint16

const (
	TEMPLATE_NODE TagTemplate = 1 << iota
	TEMPLATE_NODE_PORT
	TEMPLATE_EDGE
	TEMPLATE_EDGE_PORT
	TEMPLATE_PORT
	TEMPLATE_ACL_NODE
	TEMPLATE_ACL_NODE_PORT
	TEMPLATE_ACL_EDGE
	TEMPLATE_ACL_EDGE_PORT
	TEMPLATE_ACL_PORT
	TEMPLATE_ACL_EDGE_PORT_ALL
)

func (t TagTemplate) String() string {
	s := "|"
	if t&TEMPLATE_NODE != 0 {
		s += "N|"
	}
	if t&TEMPLATE_NODE_PORT != 0 {
		s += "NP|"
	}
	if t&TEMPLATE_EDGE != 0 {
		s += "E|"
	}
	if t&TEMPLATE_EDGE_PORT != 0 {
		s += "EP|"
	}
	if t&TEMPLATE_PORT != 0 {
		s += "P|"
	}
	if t&TEMPLATE_ACL_NODE != 0 {
		s += "AN|"
	}
	if t&TEMPLATE_ACL_NODE_PORT != 0 {
		s += "ANP|"
	}
	if t&TEMPLATE_ACL_EDGE != 0 {
		s += "AE|"
	}
	if t&TEMPLATE_ACL_EDGE_PORT != 0 {
		s += "AEP|"
	}
	if t&TEMPLATE_ACL_PORT != 0 {
		s += "AP|"
	}
	if t&TEMPLATE_ACL_EDGE_PORT_ALL != 0 {
		s += "AEP+|"
	}
	return s
}

//  MSB        63          62              56         0
//  +-------------------------------------------------+
//  | RESERVED | SRC/DST   |   MapOffset   |  MapBits |
//  +-------------------------------------------------+
// SRC/DST: 源或目的资源组
// MapOffset: AclGidBitmap在资源组的起始偏移量
// MapBits: AclGidBitmap在资源组相对起始值的偏移量,每个bit是对应一个资源组
type AclGidBitmap uint64

func (b *AclGidBitmap) SetSrcFlag() {
	*b &= ^AclGidBitmap(GROUP_TYPE_MASK << GROUP_TYPE_OFFSET)
}

func (b *AclGidBitmap) SetDstFlag() {
	*b |= AclGidBitmap(GROUP_TYPE_MASK << GROUP_TYPE_OFFSET)
}

func (b *AclGidBitmap) SetMapOffset(offset uint32) {
	realOffset := offset / GROUP_MAPBITS_OFFSET
	*b &= ^(AclGidBitmap(GROUP_MAPOFFSET_MASK) << GROUP_MAPBITS_OFFSET)
	*b |= AclGidBitmap(realOffset&GROUP_MAPOFFSET_MASK) << GROUP_MAPBITS_OFFSET
}

func (b *AclGidBitmap) SetMapBits(offset uint32) {
	realOffset := offset % GROUP_MAPBITS_OFFSET
	*b |= (AclGidBitmap(1) << realOffset) & GROUP_MAPBITS_MASK
}

func (b *AclGidBitmap) ReverseGroupType() {
	if b.GetGroupType() == GROUP_TYPE_SRC {
		b.SetDstFlag()
	} else {
		b.SetSrcFlag()
	}
}

func (b AclGidBitmap) GetGroupType() uint8 {
	return uint8((b >> GROUP_TYPE_OFFSET) & GROUP_TYPE_MASK)
}

func (b AclGidBitmap) GetMapOffset() uint32 {
	return uint32((b>>GROUP_MAPBITS_OFFSET)&GROUP_MAPOFFSET_MASK) * GROUP_MAPBITS_OFFSET
}

func (b AclGidBitmap) GetMapBits() uint64 {
	return uint64(uint64(b) & GROUP_MAPBITS_MASK)
}

func (b AclGidBitmap) String() string {
	return fmt.Sprintf("{Type: %d, MapOffset: %d, MapBitOffset: 0x%x, RAW: 0x%x}",
		b.GetGroupType(), b.GetMapOffset(), b.GetMapBits(), uint64(b))
}

// keys (16b ACLGID + 16b ActionFlags + ), values (14b AclGidMapOffset + 4b MapCount + 2b Directions + 12b TagTemplates)
type AclAction uint64

func (a AclAction) SetACLGID(aclGID ACLID) AclAction {
	a &= ^AclAction(0xFFFF << 48)
	a |= AclAction(aclGID&0xFFFF) << 48
	return a
}

func (a AclAction) SetActionFlags(actionFlags ActionFlag) AclAction {
	a &= ^AclAction(0xFFFF << 32)
	a |= AclAction(actionFlags&0xFFFF) << 32
	return a
}

func (a AclAction) AddActionFlags(actionFlags ActionFlag) AclAction {
	a |= AclAction(actionFlags&0xFFFF) << 32
	return a
}

func (a AclAction) SetDirections(directions DirectionType) AclAction {
	a &= ^AclAction(0x3 << 12)
	a |= AclAction(directions&0x3) << 12
	return a
}

func (a AclAction) AddDirections(directions DirectionType) AclAction {
	a |= AclAction(directions&0x3) << 12
	return a
}

func (a AclAction) SetAclGidBitmapOffset(offset uint16) AclAction {
	a &= ^AclAction(0x3FFF << 18)
	a |= AclAction(offset&0x3FFF) << 18
	return a
}

func (a AclAction) SetAclGidBitmapCount(count uint8) AclAction {
	a &= ^AclAction(0xF << 14)
	a |= AclAction(count&0xF) << 14
	return a
}

func (a AclAction) ReverseDirection() AclAction {
	switch a.GetDirections() {
	case FORWARD:
		return a.SetDirections(BACKWARD)
	case BACKWARD:
		return a.SetDirections(FORWARD)
	}
	return a
}

func (a AclAction) SetTagTemplates(tagTemplates TagTemplate) AclAction {
	a &= ^AclAction(0xFFF)
	a |= AclAction(tagTemplates & 0xFFF)
	return a
}

func (a AclAction) AddTagTemplates(tagTemplates TagTemplate) AclAction {
	a |= AclAction(tagTemplates & 0xFFF)
	return a
}

func (a AclAction) GetACLGID() ACLID {
	return ACLID((a >> 48) & 0xFFFF)
}

func (a AclAction) GetActionFlags() ActionFlag {
	return ActionFlag((a >> 32) & 0xFFFF)
}

func (a AclAction) GetDirections() DirectionType {
	return DirectionType((a >> 12) & 0x3)
}

func (a AclAction) GetTagTemplates() TagTemplate {
	return TagTemplate(a & 0xFFF)
}

func (a AclAction) GetAclGidBitmapOffset() uint16 {
	return uint16(a>>18) & 0x3FF
}

func (a AclAction) GetAclGidBitmapCount() uint8 {
	return uint8(a>>14) & 0xF
}

func (a AclAction) String() string {
	return fmt.Sprintf("{GID: %d ActionFlags: %s Directions: %d TagTemplates: %s GidMapOffset: %d, GidMapCount: %d}",
		a.GetACLGID(), a.GetActionFlags().String(), a.GetDirections(), a.GetTagTemplates().String(), a.GetAclGidBitmapOffset(),
		a.GetAclGidBitmapCount())
}

// 如果双方向都匹配了同一策略，对应的NpbActions Merge后会是TAPSIDE_ALL，
// 此时只保留TAPSIDE_SRC方向，即对应只处理src为true的tx流量
func (d *PolicyData) FormatNpbAction() {
	for index, _ := range d.NpbActions {
		if d.NpbActions[index].TapSide() == TAPSIDE_ALL {
			d.NpbActions[index].SetTapSide(TAPSIDE_SRC)
		}
	}
}

func (d *PolicyData) CheckNpbAction(packet *LookupKey, endpointData *EndpointData) []NpbAction {
	if len(d.NpbActions) == 0 {
		return nil
	}

	validActions := make([]NpbAction, 0, len(d.NpbActions))
	for _, action := range d.NpbActions {
		if (action.TapSideCompare(TAPSIDE_SRC) == true && packet.L2End0 == true) ||
			(action.TapSideCompare(TAPSIDE_DST) == true && packet.L2End1 == true) {
			if action.ResourceGroupTypeCompare(RESOURCE_GROUP_TYPE_DEV) {
				validActions = append(validActions, action)
			} else if (action.TapSideCompare(TAPSIDE_SRC) == true && endpointData.SrcInfo.L3End == true) ||
				(action.TapSideCompare(TAPSIDE_DST) == true && endpointData.DstInfo.L3End == true) {
				validActions = append(validActions, action)
			}
		}
	}
	return validActions
}

func (d *PolicyData) CheckNpbPolicy(packet *LookupKey, endpointData *EndpointData) *PolicyData {
	if len(d.NpbActions) == 0 {
		return d
	}
	validActions := d.CheckNpbAction(packet, endpointData)
	if len(validActions) == 0 && d.ActionFlags == 0 {
		return INVALID_POLICY_DATA
	}

	validPolicyData := new(PolicyData)
	*validPolicyData = *d
	validPolicyData.NpbActions = append(validPolicyData.NpbActions[:0], validActions...)
	return validPolicyData
}

func (d *PolicyData) MergeNpbAction(actions []NpbAction, directions ...DirectionType) {
	for _, n := range actions {
		repeat := false
		for index, m := range d.NpbActions {
			if m == n {
				repeat = true
				break
			}

			if m.TunnelIp() != n.TunnelIp() {
				continue
			}
			if n.PayloadSlice() == 0 ||
				n.PayloadSlice() > m.PayloadSlice() {
				d.NpbActions[index].SetPayloadSlice(n.PayloadSlice())
			}
			if n.TunnelId() > m.TunnelId() {
				d.NpbActions[index].SetTunnelId(n.TunnelId())
			}
			d.NpbActions[index].AddResourceGroupType(n.ResourceGroupType())
			if len(directions) > 0 {
				d.NpbActions[index].SetTapSide(int(directions[0]))
			} else {
				d.NpbActions[index].AddTapSide(n.TapSide())
			}
			repeat = true
		}
		if !repeat {
			npbAction := n
			if len(directions) > 0 {
				npbAction.SetTapSide(int(directions[0]))
			}
			d.NpbActions = append(d.NpbActions, npbAction)
		}
	}
}

func (d *PolicyData) Merge(aclActions []AclAction, npbActions []NpbAction, aclID ACLID, directions ...DirectionType) {
	if d.ACLID == 0 {
		d.ACLID = aclID
	}
	for _, newAclAction := range aclActions {
		if len(directions) > 0 {
			newAclAction = newAclAction.SetDirections(directions[0])
		}

		exist := false
		for j, existAclAction := range d.AclActions { // 按ACLGID和TagTemplates合并
			if newAclAction.GetACLGID() == existAclAction.GetACLGID() &&
				newAclAction.GetTagTemplates() == existAclAction.GetTagTemplates() {
				exist = true
				d.AclActions[j] = existAclAction.AddDirections(newAclAction.GetDirections()).
					AddActionFlags(newAclAction.GetActionFlags())
				d.ActionFlags |= newAclAction.GetActionFlags()
				break
			}
		}
		if exist {
			continue
		}
		// 无需再按照ACLGID和ActionFlags合并，因为他们的TagTemplates肯定相同

		d.AclActions = append(d.AclActions, newAclAction)
		d.ActionFlags |= newAclAction.GetActionFlags()
	}
	d.MergeNpbAction(npbActions, directions...)
}

func (d *PolicyData) MergeAndSwapDirection(aclActions []AclAction, npbActions []NpbAction, aclID ACLID) {
	newAclActions := make([]AclAction, len(aclActions))
	for i, _ := range aclActions {
		newAclActions[i] = aclActions[i].ReverseDirection()
	}
	newNpbActions := make([]NpbAction, len(npbActions))
	for i, _ := range npbActions {
		newNpbActions[i] = npbActions[i].ReverseTapSide()
	}
	d.Merge(newAclActions, newNpbActions, aclID)
}

func formatGroup(aclGidBitmap AclGidBitmap, endpointData *EndpointData) string {
	var formatStr string
	groupType := aclGidBitmap.GetGroupType()
	groupOffset := aclGidBitmap.GetMapOffset()
	groupMapBits := aclGidBitmap.GetMapBits()
	if groupType == GROUP_TYPE_SRC {
		formatStr += " SRC: "
	} else if groupType == GROUP_TYPE_DST {
		formatStr += " DST: "
	} else {
		return formatStr
	}
	for j := uint32(0); j < GROUP_MAPBITS_OFFSET; j++ {
		if (groupMapBits & (uint64(1) << j)) > 0 {
			if groupType == GROUP_TYPE_SRC {
				formatStr += GroupIdToString(endpointData.SrcInfo.GroupIds[groupOffset+j])
			} else {
				formatStr += GroupIdToString(endpointData.DstInfo.GroupIds[groupOffset+j])
			}
		}
	}
	return formatStr
}

func FormatAclGidBitmap(endpointData *EndpointData, policyData *PolicyData) string {
	var formatStr string
	for _, aclAction := range policyData.AclActions {
		if aclAction.GetACLGID() > ACLID(0) {
			formatStr += fmt.Sprintf("{ACLGID: %d ", aclAction.GetACLGID())
			mapOffset := aclAction.GetAclGidBitmapOffset()
			mapCount := aclAction.GetAclGidBitmapCount()
			for i := mapOffset; i < mapOffset+uint16(mapCount); i++ {
				formatStr += formatGroup(policyData.AclGidBitmaps[i], endpointData)
			}
			formatStr += "} "
		}
	}
	return formatStr
}

// 添加资源组bitmap
func (d *PolicyData) AddAclGidBitmap(addType uint32, aclGid uint32, endpointData *EndpointData, direction DirectionType, srcMap, dstMap map[uint32]bool) uint8 {
	addCount := uint8(0)
	bitmapFlag := false
	var groupIds []uint32
	var groupAclGidMap map[uint32]bool
	aclGidBitMap := AclGidBitmap(0)
	mapCount := GROUP_MAPBITS_OFFSET
	if addType == GROUP_TYPE_SRC {
		groupIds = endpointData.SrcInfo.GroupIds
		if direction&FORWARD == FORWARD {
			groupAclGidMap = srcMap
		} else {
			groupAclGidMap = dstMap
		}
		aclGidBitMap.SetSrcFlag()
	} else {
		groupIds = endpointData.DstInfo.GroupIds
		if direction&FORWARD == FORWARD {
			groupAclGidMap = dstMap
		} else {
			groupAclGidMap = srcMap
		}
		aclGidBitMap.SetDstFlag()
	}

	for i, groupId := range groupIds {
		if i >= mapCount {
			if aclGidBitMap.GetMapBits() > 0 {
				result := aclGidBitMap
				d.AclGidBitmaps = append(d.AclGidBitmaps, result)
				addCount += 1
			}
			mapCount += GROUP_MAPBITS_OFFSET
			aclGidBitMap = AclGidBitmap(0)
			if addType == GROUP_TYPE_SRC {
				aclGidBitMap.SetSrcFlag()
			} else {
				aclGidBitMap.SetDstFlag()
			}
			bitmapFlag = false
		}
		key := aclGid<<16 | FormatGroupId(groupId)
		if ok := groupAclGidMap[key]; ok {
			aclGidBitMap.SetMapOffset(uint32(i))
			aclGidBitMap.SetMapBits(uint32(i))
			bitmapFlag = true
		} else {
			// 查找资源组全采
			key = aclGid << 16
			if ok := groupAclGidMap[key]; ok {
				aclGidBitMap.SetMapOffset(uint32(i))
				aclGidBitMap.SetMapBits(uint32(i))
				bitmapFlag = true
			}
		}
	}
	if bitmapFlag && aclGidBitMap.GetMapBits() > 0 {
		d.AclGidBitmaps = append(d.AclGidBitmaps, aclGidBitMap)
		addCount += 1
	}
	return addCount
}

func (d *PolicyData) AddAclGidBitmaps(packet *LookupKey, endpointData *EndpointData, srcMap, dstMap map[uint32]bool) {
	if !packet.HasFeatureFlag(NPM) {
		return
	}
	mapOffset := uint16(0)
	for index, aclAction := range d.AclActions {
		aclGid := uint32(aclAction.GetACLGID())
		if aclGid == 0 {
			continue
		}
		mapCount := d.AddAclGidBitmap(GROUP_TYPE_SRC, aclGid, endpointData, aclAction.GetDirections(), srcMap, dstMap)
		mapCount += d.AddAclGidBitmap(GROUP_TYPE_DST, aclGid, endpointData, aclAction.GetDirections(), srcMap, dstMap)
		if mapCount > 0 {
			d.AclActions[index] = aclAction.SetAclGidBitmapOffset(mapOffset).SetAclGidBitmapCount(mapCount)
		}
		mapOffset += uint16(mapCount)
	}
}

func (d *PolicyData) String() string {
	return fmt.Sprintf("{ACLID: %d ActionFlags: %v AclActions: %v NpbActions: %v AclGidBitmaps: %v}",
		d.ACLID, d.ActionFlags, d.AclActions, d.NpbActions, d.AclGidBitmaps)
}

func FillGroupID(aclAction AclAction, aclGidBitmaps []AclGidBitmap, allGroupIDs [][]uint32, aclGroupIDs [][]int32) {
	if len(allGroupIDs) != 2 || len(aclGroupIDs) != 2 {
		panic("长度必须为2")
	}

	aclGroupIDs[0] = aclGroupIDs[0][:0]
	aclGroupIDs[1] = aclGroupIDs[1][:0]

	mapOffset := aclAction.GetAclGidBitmapOffset()
	mapEnd := mapOffset + uint16(aclAction.GetAclGidBitmapCount())
	for i := mapOffset; i < mapEnd; i++ {
		aclGidBitmap := aclGidBitmaps[i]
		groupOffset := aclGidBitmap.GetMapOffset()
		groupMapBits := aclGidBitmap.GetMapBits()

		ep := 0
		if aclGidBitmap.GetGroupType() == GROUP_TYPE_DST {
			ep = 1
		}
		for groupMapBits > 0 {
			j := bit.CountTrailingZeros64(groupMapBits)
			groupMapBits ^= 1 << uint64(j)
			aclGroupIDs[ep] = append(aclGroupIDs[ep], int32(FormatGroupId(allGroupIDs[ep][groupOffset+uint32(j)])))
		}
	}
}

var policyDataPool = pool.NewLockFreePool(func() interface{} {
	return new(PolicyData)
})

func AcquirePolicyData() *PolicyData {
	return policyDataPool.Get().(*PolicyData)
}

func ReleasePolicyData(d *PolicyData) {
	if d.AclActions != nil {
		d.AclActions = d.AclActions[:0]
	}
	*d = PolicyData{AclActions: d.AclActions}
	policyDataPool.Put(d)
}

func ClonePolicyData(d *PolicyData) *PolicyData {
	dup := AcquirePolicyData()
	*dup = *d
	dup.AclActions = make([]AclAction, len(d.AclActions))
	copy(dup.AclActions, d.AclActions)
	return dup
}
