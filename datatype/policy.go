package datatype

import (
	"fmt"
)

var (
	INVALID_POLICY_DATA = &PolicyData{}
)

type ActionFlag uint16

const (
	ACTION_PACKET_STAT ActionFlag = 1 << iota
	ACTION_FLOW_STAT
	ACTION_FLOW_STORE
	ACTION_PERFORMANCE
	ACTION_PCAP
	ACTION_MISC
	_ // skip
	ACTION_PACKECT_COUNTER_PUB
	ACTION_FLOW_COUNTER_PUB
	ACTION_TCP_PERFORMANCE_PUB
	ACTION_GEO
)

type ACLID uint16

type PolicyData struct {
	ACLID       ACLID      // 匹配的第一个ACL
	ActionFlags ActionFlag // bitwise OR
	AclActions  []AclAction
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
)

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
	return fmt.Sprintf("AclAction{GID: %v ActionFlags: b%b Directions: b%b TagTemplates: b%b}",
		a.GetACLGID(), a.GetActionFlags(), a.GetDirections(), a.GetTagTemplates())
}

func (d *PolicyData) Merge(aclActions []AclAction, aclID ACLID, directions ...DirectionType) {
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
}

func (d *PolicyData) MergeAndSwapDirection(aclActions []AclAction, aclID ACLID) {
	newAclActions := make([]AclAction, len(aclActions))
	for i, _ := range aclActions {
		newAclActions[i] = aclActions[i].ReverseDirection()
	}
	d.Merge(newAclActions, aclID)
}

func (a *PolicyData) String() string {
	return fmt.Sprintf("%+v", *a)
}
