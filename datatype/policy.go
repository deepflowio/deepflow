package datatype

import (
	"fmt"
)

type PolicyData struct {
	ActionList ActionType // bitwise OR
	AclActions []*AclAction
}

type PolicyType uint16

const (
	LABEL PolicyType = iota + 1
	REPORT_POLICY
	ALARM_POLICY
	WHITELIST
	POLICY_MAX
)

type PolicyInfo struct {
	Id   uint32
	Type PolicyType
}

type ActionType uint32

const (
	ACTION_PACKET_STAT ActionType = 1 << iota
	ACTION_FLOW_STAT
	ACTION_FLOW_STORE
	ACTION_PERFORMANCE
	ACTION_PCAP
	ACTION_MISC
	ACTION_POLICY
	ACTION_PACKECT_COUNTER_PUB
	ACTION_FLOW_COUNTER_PUB
	ACTION_TCP_PERFORMANCE_PUB
)

type DirectionType uint8

const (
	NO_DIRECTION DirectionType = 0
)

const (
	FORWARD DirectionType = 1 << iota
	BACKWARD
)

type AclAction struct {
	AclId       uint32
	Type        ActionType
	Policy      []PolicyInfo
	TagTemplate uint32
	Direction   DirectionType
}

func (a *AclAction) String() string {
	return fmt.Sprintf("%+v", *a)
}

func (d *PolicyData) Merge(aclAction *AclAction) {
	d.ActionList |= aclAction.Type
	d.AclActions = append(d.AclActions, aclAction)
}

func (a *PolicyData) String() string {
	return fmt.Sprintf("%+v", *a)
}
