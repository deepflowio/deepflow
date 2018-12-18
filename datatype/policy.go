package datatype

import (
	"fmt"

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
	ACLID       ACLID      // 匹配的第一个ACL
	ActionFlags ActionFlag // bitwise OR
	AclActions  []AclAction
	NpbActions  []NpbAction
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

// keys (16b ACLGID + 16b ActionFlags), values (8b Directions + 16b TagTemplates)
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
	a &= ^AclAction(0xFF << 16)
	a |= AclAction(directions&0xFF) << 16
	return a
}

func (a AclAction) AddDirections(directions DirectionType) AclAction {
	a |= AclAction(directions&0xFF) << 16
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
	a &= ^AclAction(0xFFFF)
	a |= AclAction(tagTemplates & 0xFFFF)
	return a
}

func (a AclAction) AddTagTemplates(tagTemplates TagTemplate) AclAction {
	a |= AclAction(tagTemplates & 0xFFFF)
	return a
}

func (a AclAction) GetACLGID() ACLID {
	return ACLID((a >> 48) & 0xFFFF)
}

func (a AclAction) GetActionFlags() ActionFlag {
	return ActionFlag((a >> 32) & 0xFFFF)
}

func (a AclAction) GetDirections() DirectionType {
	return DirectionType((a >> 16) & 0xFF)
}

func (a AclAction) GetTagTemplates() TagTemplate {
	return TagTemplate(a & 0xFFFF)
}

func (a AclAction) String() string {
	return fmt.Sprintf("{GID: %d ActionFlags: %s Directions: %d TagTemplates: %s}",
		a.GetACLGID(), a.GetActionFlags().String(), a.GetDirections(), a.GetTagTemplates().String())
}

func (d *PolicyData) ReverseNpbActions() {
	for index, npb := range d.NpbActions {
		d.NpbActions[index] = npb.ReverseTapSide()
	}
}

func (d *PolicyData) DedupNpbAction() {
	validActions := make([]NpbAction, 0, len(d.NpbActions))
	for i := 0; i < len(d.NpbActions); i++ {
		repeat := false
		actionI := &d.NpbActions[i]
		for j := i + 1; j < len(d.NpbActions); j++ {
			actionJ := &d.NpbActions[j]
			if *actionJ == *actionI {
				repeat = true
				break
			}

			if actionI.TunnelIp() != actionJ.TunnelIp() {
				continue
			}
			if actionI.PayloadSlice() == 0 ||
				actionI.PayloadSlice() > actionJ.PayloadSlice() {
				actionJ.SetPayloadSlice(actionI.PayloadSlice())
			}
			if actionI.TunnelId() > actionJ.TunnelId() {
				actionJ.SetTunnelId(actionI.TunnelId())
			}
			actionJ.AddTapSide(actionI.TapSide())
			actionJ.AddResourceGroupType(actionI.ResourceGroupType())
			repeat = true
		}
		if !repeat {
			validActions = append(validActions, *actionI)
		}
	}
	d.NpbActions = append(d.NpbActions[:0], validActions...)
}

func (d *PolicyData) MergeNpbAction(actions []NpbAction) {
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
			d.NpbActions[index].SetTapSide(n.TapSide())
			repeat = true
		}
		if !repeat {
			d.NpbActions = append(d.NpbActions, n)
		}
	}
}

func (d *PolicyData) Merge(aclActions []AclAction, npbActions []NpbAction, aclID ACLID, directions ...DirectionType) {
	if d.ACLID == 0 {
		d.ACLID = aclID
	}
	d.MergeNpbAction(npbActions)
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

func (d *PolicyData) String() string {
	return fmt.Sprintf("{ACLID: %d ActionFlags: %v AclActions: %v NpbActions: %v}",
		d.ACLID, d.ActionFlags, d.AclActions, d.NpbActions)
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
