package datatype

import (
	"fmt"

	"gitlab.x.lan/yunshan/droplet-libs/bit"
	"gitlab.x.lan/yunshan/droplet-libs/pool"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

var (
	INVALID_POLICY_DATA = new(PolicyData)
)

type ActionFlag uint16

type NpbAction uint64 // tunnel-ip | tunnel-type | tunnel-id | Dep/Ip | TapSide | payload-slice

const (
	NPB_TUNNEL_TYPE_VXLAN = iota
	NPB_TUNNEL_TYPE_GRE_ERSPAN
	NPB_TUNNEL_TYPE_PCAP
)

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
	return uint32((a >> 20) & 0x3ff)
}

func (a *NpbAction) SetTunnelId(id uint32) {
	*a &= ^NpbAction(0x3ff << 20)
	*a |= NpbAction((id & 0x3ff) << 20)
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

func (a NpbAction) TunnelType() uint8 {
	return uint8((a >> 30) & 0x3)
}

func (a NpbAction) String() string {
	return fmt.Sprintf("{%d@%s type: %d slice %d side: %d group: %d}", a.TunnelId(), IpFromUint32(a.TunnelIp()), a.TunnelType(), a.PayloadSlice(), a.TapSide(), a.ResourceGroupType())
}

func ToNpbAction(ip uint32, id uint16, tunnelType, group, tapSide uint8, slice uint16) NpbAction {
	return NpbAction(uint64(ip)<<32 | uint64(tunnelType&0x3)<<30 | uint64(id&0x3ff)<<20 | (uint64(group)&RESOURCE_GROUP_TYPE_MASK)<<18 | (uint64(tapSide)&TAPSIDE_MASK)<<16 | uint64(slice))
}

const (
	ACTION_PACKET_COUNTING ActionFlag = 1 << iota
	ACTION_FLOW_COUNTING
	ACTION_FLOW_STORING
	ACTION_TCP_FLOW_PERF_COUNTING
	ACTION_PACKET_CAPTURING
	ACTION_FLOW_MISC_COUNTING
	ACTION_PACKET_BROKERING
	_
	_
	_
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
	if f&ACTION_GEO_POSITIONING != 0 {
		s += "GP|"
	}
	return s
}

type ACLID uint16

type PolicyRawData struct {
	AclActions []AclAction
	NpbActions []NpbAction
	ACLID      ACLID // 匹配的第一个ACL
}

func (d *PolicyRawData) GobEncode() ([]byte, error) {
	return []byte{}, nil
}

func (d *PolicyRawData) GobDecode(in []byte) error {
	return nil
}

type PolicyData struct {
	AclActions    []AclAction
	NpbActions    []NpbAction
	AclGidBitmaps []AclGidBitmap
	ACLID         ACLID      // 匹配的第一个ACL
	ActionFlags   ActionFlag // bitwise OR
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
	TEMPLATE_EDGE_PORT_ALL
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
	if t&TEMPLATE_EDGE_PORT_ALL != 0 {
		s += "EP+|"
	}
	return s
}

const (
	GROUP_TYPE_OFFSET         = 62
	GROUP_TYPE_ALL            = 0x2
	GROUP_SRC_MAPOFFSET_SHIFT = 55
	GROUP_DST_MAPOFFSET_SHIFT = 48
	GROUP_SRC_MAPBITS_SHIFT   = 24
	GROUP_DST_MAPBITS_SHIFT   = 24
	GROUP_MAPBITS_CNT         = 24
	GROUP_ALL_MAPOFFSET_MASK  = 0x7f
	GROUP_ALL_MAPBITS_MASK    = 0xFFFFFF
	GROUP_TYPE_SRC            = 0x0
	GROUP_TYPE_DST            = 0x1
)

//  MSB       62             55            48           24            0
//  +---------+--------------+--------------+------------+------------+
//  | SRC/DST | SrcMapOffset | DstMapOffset | SrcMapBits | DstMapBits |
//  +-----------------------------------------------------------------+
// SRC/DST: 源或目的资源组，源目的资源组混合
// SrcMapOffset: AclGidBitmap在源资源组的起始偏移量
// DstMapOffset: AclGidBitmap在目的资源组的起始偏移量
// SrcMapBits: AclGidBitmap在源资源组相对起始值的偏移量，每个bit是对应一个资源组
// DstMapBits: AclGidBitmap在目的资源组相对起始值的偏移量，每个bit是对应一个资源组
type AclGidBitmap uint64

func (b AclGidBitmap) SetSrcAndDstFlag() AclGidBitmap {
	b |= AclGidBitmap(GROUP_TYPE_ALL << GROUP_TYPE_OFFSET)
	return b
}

func (b AclGidBitmap) SetSrcMapOffset(offset uint32) AclGidBitmap {
	realOffset := offset / GROUP_MAPBITS_CNT
	b &= ^(AclGidBitmap(GROUP_ALL_MAPOFFSET_MASK) << GROUP_SRC_MAPOFFSET_SHIFT)
	b |= AclGidBitmap(realOffset&GROUP_ALL_MAPOFFSET_MASK) << GROUP_SRC_MAPOFFSET_SHIFT
	return b
}

func (b AclGidBitmap) SetDstMapOffset(offset uint32) AclGidBitmap {
	realOffset := offset / GROUP_MAPBITS_CNT
	b &= ^(AclGidBitmap(GROUP_ALL_MAPOFFSET_MASK) << GROUP_DST_MAPOFFSET_SHIFT)
	b |= AclGidBitmap(realOffset&GROUP_ALL_MAPOFFSET_MASK) << GROUP_DST_MAPOFFSET_SHIFT
	return b
}

func (b AclGidBitmap) SetSrcMapBits(offset uint32) AclGidBitmap {
	realOffset := offset % GROUP_SRC_MAPBITS_SHIFT
	b |= AclGidBitmap(1) << (realOffset + GROUP_SRC_MAPBITS_SHIFT)
	return b
}

func (b AclGidBitmap) SetDstMapBits(offset uint32) AclGidBitmap {
	realOffset := offset % GROUP_DST_MAPBITS_SHIFT
	b |= AclGidBitmap(1) << realOffset
	return b
}

func (b AclGidBitmap) GetSrcAndDstFlag() uint8 {
	return uint8((b >> GROUP_TYPE_OFFSET) & GROUP_TYPE_ALL)
}

func (b AclGidBitmap) GetSrcMapOffset() uint32 {
	return uint32((b>>GROUP_SRC_MAPOFFSET_SHIFT)&GROUP_ALL_MAPOFFSET_MASK) * GROUP_SRC_MAPBITS_SHIFT
}

func (b AclGidBitmap) GetDstMapOffset() uint32 {
	return uint32((b>>GROUP_DST_MAPOFFSET_SHIFT)&GROUP_ALL_MAPOFFSET_MASK) * GROUP_DST_MAPBITS_SHIFT
}

func (b AclGidBitmap) GetSrcMapBits() uint32 {
	return uint32((uint64(b) >> GROUP_SRC_MAPBITS_SHIFT) & GROUP_ALL_MAPBITS_MASK)
}

func (b AclGidBitmap) GetDstMapBits() uint32 {
	return uint32(uint64(b) & GROUP_ALL_MAPBITS_MASK)
}

func (b *AclGidBitmap) ReverseGroupType() {
	rAclGidBitmap := AclGidBitmap(0).SetSrcAndDstFlag()
	rAclGidBitmap = rAclGidBitmap.SetSrcMapOffset(b.GetDstMapOffset())
	rAclGidBitmap = rAclGidBitmap.SetDstMapOffset(b.GetSrcMapOffset())
	rAclGidBitmap |= AclGidBitmap(b.GetSrcMapBits())
	rAclGidBitmap |= AclGidBitmap(b.GetDstMapBits() << GROUP_DST_MAPBITS_SHIFT)
	*b = rAclGidBitmap
}

func (b AclGidBitmap) String() string {
	return fmt.Sprintf("{Type: %d, SrcMapOffset: %d, SrcMapBitOffset: 0x%x, DstMapOffset: %d, DstMapBitOffset: 0x%x,RAW: 0x%x}",
		b.GetSrcAndDstFlag(), b.GetSrcMapOffset(), b.GetSrcMapBits(), b.GetDstMapOffset(), b.GetDstMapBits(), uint64(b))
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
		if d.NpbActions[index].TapSide() == TAPSIDE_ALL &&
			d.NpbActions[index].TunnelType() != NPB_TUNNEL_TYPE_PCAP {
			d.NpbActions[index].SetTapSide(TAPSIDE_SRC)
		}
	}
}

func (d *PolicyData) CheckNpbAction(packet *LookupKey) []NpbAction {
	if len(d.NpbActions) == 0 || packet.Tap != TAP_TOR {
		return d.NpbActions
	}

	validActions := make([]NpbAction, 0, len(d.NpbActions))
	for _, action := range d.NpbActions {
		if (action.TapSideCompare(TAPSIDE_SRC) == true && packet.L2End0 == true) ||
			(action.TapSideCompare(TAPSIDE_DST) == true && packet.L2End1 == true) {
			if action.ResourceGroupTypeCompare(RESOURCE_GROUP_TYPE_DEV) {
				validActions = append(validActions, action)
			} else if (action.TapSideCompare(TAPSIDE_SRC) == true && packet.L3End0 == true) ||
				(action.TapSideCompare(TAPSIDE_DST) == true && packet.L3End1 == true) {
				validActions = append(validActions, action)
			}
		}
	}
	return validActions
}

func (d *PolicyData) CheckNpbPolicy(packet *LookupKey) *PolicyData {
	if len(d.NpbActions) == 0 || packet.Tap != TAP_TOR {
		return d
	}
	validActions := d.CheckNpbAction(packet)
	if len(validActions) == 0 && d.ActionFlags == 0 {
		return INVALID_POLICY_DATA
	}

	validPolicyData := new(PolicyData)
	*validPolicyData = *d
	validPolicyData.NpbActions = append(validPolicyData.NpbActions[:0], validActions...)
	return validPolicyData
}

func (d *PolicyData) MergeNpbAction(actions []NpbAction, aclID ACLID, directions ...DirectionType) {
	if d.ACLID == 0 {
		d.ACLID = aclID
	}
	for _, n := range actions {
		repeat := false
		for index, m := range d.NpbActions {
			if m == n {
				repeat = true
				break
			}

			if m.TunnelIp() != n.TunnelIp() || m.TunnelId() != n.TunnelId() || m.TunnelType() != n.TunnelType() {
				continue
			}
			if n.PayloadSlice() == 0 ||
				n.PayloadSlice() > m.PayloadSlice() {
				d.NpbActions[index].SetPayloadSlice(n.PayloadSlice())
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

func (d *PolicyData) MergeAclAction(actions []AclAction, aclID ACLID, directions ...DirectionType) {
	if d.ACLID == 0 {
		d.ACLID = aclID
	}
	for _, newAclAction := range actions {
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
}

func (d *PolicyData) Merge(aclActions []AclAction, npbActions []NpbAction, aclID ACLID, directions ...DirectionType) {
	d.MergeAclAction(aclActions, aclID, directions...)
	d.MergeNpbAction(npbActions, aclID, directions...)
}

func (d *PolicyData) MergeNpbAndSwapDirection(actions []NpbAction, aclID ACLID) {
	newNpbActions := make([]NpbAction, len(actions))
	for i, _ := range actions {
		newNpbActions[i] = actions[i].ReverseTapSide()
	}

	d.MergeNpbAction(newNpbActions, aclID)
}

func (d *PolicyData) MergeAclAndSwapDirection(actions []AclAction, aclID ACLID) {
	newAclActions := make([]AclAction, len(actions))
	for i, _ := range actions {
		newAclActions[i] = actions[i].ReverseDirection()
	}

	d.MergeAclAction(newAclActions, aclID)
}

func (d *PolicyData) MergeAndSwapDirection(aclActions []AclAction, npbActions []NpbAction, aclID ACLID) {
	d.MergeAclAndSwapDirection(aclActions, aclID)
	d.MergeNpbAndSwapDirection(npbActions, aclID)
}

// ReverseData will return a reversed replica of the current PolicyData
func (d *PolicyData) ReverseData() *PolicyData {
	newPolicyData := ClonePolicyData(d)
	for i, aclAction := range newPolicyData.AclActions {
		newPolicyData.AclActions[i] = aclAction.ReverseDirection()
	}
	for i, _ := range newPolicyData.AclGidBitmaps {
		newPolicyData.AclGidBitmaps[i].ReverseGroupType()
	}
	return newPolicyData
}

func formatGroup(aclGidBitmap AclGidBitmap, endpointData *EndpointData) string {
	var formatStr string
	srcGroupOffset := aclGidBitmap.GetSrcMapOffset()
	srcGroupMapBits := aclGidBitmap.GetSrcMapBits()
	dstGroupOffset := aclGidBitmap.GetDstMapOffset()
	dstGroupMapBits := aclGidBitmap.GetDstMapBits()
	srcLen := uint32(len(endpointData.SrcInfo.GroupIds))
	dstLen := uint32(len(endpointData.DstInfo.GroupIds))

	if srcGroupMapBits > 0 {
		formatStr += " SRC: "
		for srcGroupMapBits > 0 {
			j := bit.CountTrailingZeros32(srcGroupMapBits)
			srcGroupMapBits ^= 1 << uint32(j)
			if srcGroupOffset+uint32(j) >= srcLen {
				formatStr += " SRCERR "
				continue
			}
			formatStr += GroupIdToString(endpointData.SrcInfo.GroupIds[srcGroupOffset+uint32(j)])
		}
	}

	if dstGroupMapBits > 0 {
		formatStr += " DST: "
		for dstGroupMapBits > 0 {
			j := bit.CountTrailingZeros32(dstGroupMapBits)
			dstGroupMapBits ^= 1 << uint32(j)
			if dstGroupOffset+uint32(j) >= dstLen {
				formatStr += " DSTERR "
				continue
			}
			formatStr += GroupIdToString(endpointData.DstInfo.GroupIds[dstGroupOffset+uint32(j)])
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
			mapEnd := mapOffset + uint16(aclAction.GetAclGidBitmapCount())
			if mapEnd > uint16(len(policyData.AclGidBitmaps)) {
				mapEnd = uint16(len(policyData.AclGidBitmaps))
			}
			for i := mapOffset; i < mapEnd; i++ {
				formatStr += formatGroup(policyData.AclGidBitmaps[i], endpointData)
			}
			formatStr += "} "
		}
	}
	return formatStr
}

func AclGidAndGroupIdInMap(aclGid uint32, groupId uint16, groupAclGidMap, groupAclGidMapOther map[uint32]bool) bool {
	addFlag := false
	key := (aclGid << 16) | uint32(groupId)
	if groupAclGidMap != nil {
		if ok := groupAclGidMap[key]; ok {
			addFlag = true
		}
	}
	if addFlag != true && groupAclGidMapOther != nil {
		if ok := groupAclGidMapOther[key]; ok {
			addFlag = true
		}
	}
	return addFlag
}

// 添加资源组bitmap
func (d *PolicyData) AddAclGidBitmap(aclGid uint32, packet *LookupKey, direction DirectionType, swap bool, srcMap, dstMap map[uint32]bool, addType uint32) []AclGidBitmap {
	aclGidBitmaps := []AclGidBitmap{}
	bitmapFlag := false
	groupIds := packet.SrcAllGroupIds
	var groupAclGidMap map[uint32]bool
	var groupAclGidMapOther map[uint32]bool
	aclGidBitMap := AclGidBitmap(0).SetSrcAndDstFlag()
	mapCount := GROUP_MAPBITS_CNT

	if addType == GROUP_TYPE_SRC {
		if swap {
			groupIds = packet.DstAllGroupIds
		}
	} else {
		if !swap {
			groupIds = packet.DstAllGroupIds
		}
	}
	if addType == GROUP_TYPE_SRC {
		if direction&FORWARD == FORWARD {
			groupAclGidMap = srcMap
		}
		if direction&BACKWARD == BACKWARD {
			groupAclGidMapOther = dstMap
		}
	} else {
		if direction&FORWARD == FORWARD {
			groupAclGidMap = dstMap
		}
		if direction&BACKWARD == BACKWARD {
			groupAclGidMapOther = srcMap
		}
	}

	for i, groupId := range groupIds {
		if i >= mapCount {
			if aclGidBitMap.GetSrcMapBits() > 0 || aclGidBitMap.GetDstMapBits() > 0 {
				result := aclGidBitMap
				aclGidBitmaps = append(aclGidBitmaps, result)
			}
			mapCount += GROUP_MAPBITS_CNT
			aclGidBitMap = AclGidBitmap(0).SetSrcAndDstFlag()
			bitmapFlag = false
		}
		if AclGidAndGroupIdInMap(aclGid, groupId, groupAclGidMap, groupAclGidMapOther) {
			if addType == GROUP_TYPE_SRC {
				aclGidBitMap = aclGidBitMap.SetSrcMapOffset(uint32(i)).SetSrcMapBits(uint32(i))
			} else {
				aclGidBitMap = aclGidBitMap.SetDstMapOffset(uint32(i)).SetDstMapBits(uint32(i))
			}
			bitmapFlag = true
		}
	}
	if bitmapFlag {
		if aclGidBitMap.GetSrcMapBits() > 0 || aclGidBitMap.GetDstMapBits() > 0 {
			aclGidBitmaps = append(aclGidBitmaps, aclGidBitMap)
		}
	}
	return aclGidBitmaps
}

func mergeAclGidBitmaps(srcAclGIdBitmaps []AclGidBitmap, dstAclGIdBitmaps []AclGidBitmap) []AclGidBitmap {
	srcLen := len(srcAclGIdBitmaps)
	dstLen := len(dstAclGIdBitmaps)
	var fromAclGIdBitmaps []AclGidBitmap
	var toAclGIdBitmaps []AclGidBitmap

	if srcLen == 0 {
		return dstAclGIdBitmaps
	} else if dstLen == 0 {
		return srcAclGIdBitmaps
	}

	if srcLen > dstLen {
		toAclGIdBitmaps = srcAclGIdBitmaps
		fromAclGIdBitmaps = dstAclGIdBitmaps
	} else {
		toAclGIdBitmaps = dstAclGIdBitmaps
		fromAclGIdBitmaps = srcAclGIdBitmaps
	}

	for index, value := range fromAclGIdBitmaps {
		toAclGIdBitmaps[index] |= value
	}

	return toAclGIdBitmaps
}

func (d *PolicyData) AddAclGidBitmaps(packet *LookupKey, swap bool, srcMap, dstMap map[uint32]bool) {
	if !packet.HasFeatureFlag(NPM) {
		return
	}
	aclGidMap := map[ACLID]AclAction{}
	mapOffset := uint16(0)
	for index, aclAction := range d.AclActions {
		aclGid := uint32(aclAction.GetACLGID())
		if aclGid == 0 {
			continue
		}
		if action, ok := aclGidMap[ACLID(aclGid)]; ok {
			offset := action.GetAclGidBitmapOffset()
			count := action.GetAclGidBitmapCount()
			if count > 0 {
				d.AclActions[index] = aclAction.SetAclGidBitmapOffset(offset).SetAclGidBitmapCount(count)
			}
			continue
		}
		srcAclGIdBitmaps := d.AddAclGidBitmap(aclGid, packet, aclAction.GetDirections(), swap, srcMap, dstMap, GROUP_TYPE_SRC)
		dstAclGIdBitmaps := d.AddAclGidBitmap(aclGid, packet, aclAction.GetDirections(), swap, srcMap, dstMap, GROUP_TYPE_DST)
		aclGIdBitmaps := mergeAclGidBitmaps(srcAclGIdBitmaps, dstAclGIdBitmaps)
		if len(aclGIdBitmaps) > 0 {
			d.AclActions[index] = aclAction.SetAclGidBitmapOffset(mapOffset).SetAclGidBitmapCount(uint8(len(aclGIdBitmaps)))
			d.AclGidBitmaps = append(d.AclGidBitmaps, aclGIdBitmaps...)
		}
		aclGidMap[ACLID(aclGid)] = d.AclActions[index]
		mapOffset += uint16(len(aclGIdBitmaps))
	}
	//	log.Debug(endpointData, policyData)
}

func (d *PolicyData) String() string {
	return fmt.Sprintf("{ACLID: %d ActionFlags: %v AclActions: %v NpbActions: %v AclGidBitmaps: %v}",
		d.ACLID, d.ActionFlags, d.AclActions, d.NpbActions, d.AclGidBitmaps)
}

func FillGroupID(aclAction AclAction, aclGidBitmaps []AclGidBitmap, allGroupIDs [][]uint32, aclGroupIDs [][]int32) {
	if len(allGroupIDs) != 2 || len(aclGroupIDs) != 2 {
		panic("Length must be 2")
	}

	aclGroupIDs[0] = aclGroupIDs[0][:0]
	aclGroupIDs[1] = aclGroupIDs[1][:0]

	mapOffset := aclAction.GetAclGidBitmapOffset()
	mapEnd := mapOffset + uint16(aclAction.GetAclGidBitmapCount())
	srcLen := uint32(len(allGroupIDs[0]))
	dstLen := uint32(len(allGroupIDs[1]))
	if mapEnd > uint16(len(aclGidBitmaps)) {
		log.Warningf("AclActions' reference %v exceeds AclGidBitmaps' len %v",
			mapEnd, len(aclGidBitmaps))
		mapEnd = uint16(len(aclGidBitmaps))
	}
	for i := mapOffset; i < mapEnd; i++ {
		aclGidBitmap := aclGidBitmaps[i]
		srcGroupOffset := aclGidBitmap.GetSrcMapOffset()
		srcGroupMapBits := aclGidBitmap.GetSrcMapBits()
		dstGroupOffset := aclGidBitmap.GetDstMapOffset()
		dstGroupMapBits := aclGidBitmap.GetDstMapBits()
		for srcGroupMapBits > 0 {
			j := bit.CountTrailingZeros32(srcGroupMapBits)
			srcGroupMapBits ^= 1 << uint32(j)
			if srcGroupOffset+uint32(j) >= srcLen {
				log.Warningf("map bits and group id mismatch,, %v %v %v",
					aclAction, aclGidBitmaps, allGroupIDs)
				continue
			}
			aclGroupIDs[0] = append(aclGroupIDs[0], int32(FormatGroupId(allGroupIDs[0][srcGroupOffset+uint32(j)])))
		}
		for dstGroupMapBits > 0 {
			j := bit.CountTrailingZeros32(dstGroupMapBits)
			dstGroupMapBits ^= 1 << uint32(j)
			if dstGroupOffset+uint32(j) >= dstLen {
				log.Warningf("map bits and group id mismatch, %v %v %v",
					aclAction, aclGidBitmaps, allGroupIDs)
				continue
			}
			aclGroupIDs[1] = append(aclGroupIDs[1], int32(FormatGroupId(allGroupIDs[1][dstGroupOffset+uint32(j)])))
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
	if d.AclGidBitmaps != nil {
		d.AclGidBitmaps = d.AclGidBitmaps[:0]
	}
	*d = PolicyData{AclActions: d.AclActions, AclGidBitmaps: d.AclGidBitmaps}
	policyDataPool.Put(d)
}

func ClonePolicyData(d *PolicyData) *PolicyData {
	dup := AcquirePolicyData()
	*dup = *d
	dup.AclActions = make([]AclAction, len(d.AclActions))
	dup.AclGidBitmaps = make([]AclGidBitmap, len(d.AclGidBitmaps))
	copy(dup.AclActions, d.AclActions)
	copy(dup.AclGidBitmaps, d.AclGidBitmaps)
	return dup
}
