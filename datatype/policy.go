package datatype

import (
	"fmt"
)

type PolicyData struct {
	ActionList ActionType // bitwise OR
	AclActions []*AclAction
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
	ACTION_GEO
)

type DirectionType uint8

const (
	NO_DIRECTION DirectionType = 0
)

const (
	FORWARD DirectionType = 1 << iota
	BACKWARD
)

const (
	TEMPLATE_NODE uint32 = 1 << iota
	TEMPLATE_NODE_PORT
	TEMPLATE_EDGE
	TEMPLATE_EDGE_PORT
	TEMPLATE_PORT
	TEMPLATE_POLICY_NODE
	TEMPLATE_POLICY_NODE_PORT
	TEMPLATE_POLICY_EDGE
	TEMPLATE_POLICY_EDGE_PORT
	TEMPLATE_POLICY_PORT
)

type AclAction struct {
	AclId       uint32
	Type        ActionType
	ACLGIDs     []uint32
	TagTemplate uint32
	Direction   DirectionType
}

func (a *AclAction) String() string {
	return fmt.Sprintf("%+v", *a)
}

func (d *PolicyData) Merge(aclActions []*AclAction) {
	for _, aclAction := range aclActions {
		d.ActionList |= aclAction.Type
	}
	d.AclActions = aclActions
}

func (a *PolicyData) String() string {
	return fmt.Sprintf("%+v", *a)
}
