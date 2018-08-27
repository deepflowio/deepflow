package policy

import (
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

const (
	MAX_FASTPATH_LEN     = 1 << 18
	NETMASK_BUCKET_SHIFT = 16
	NETMASK_BUCKETS      = 1 << 16
)

type Acl struct {
	Id        uint32
	Type      TapType
	TapId     uint32
	SrcGroups map[uint32]uint32
	DstGroups map[uint32]uint32
	DstPorts  map[uint16]uint16
	Proto     uint8
	Vlan      uint32
	Action    []*AclAction
}

type FastPolicyKey uint64

type PolicyLabel struct {
	aclData        [TAP_MAX][]*Acl
	fastPolicyPath map[FastPolicyKey]*PolicyData
}

func NewAcl() *Acl {
	return &Acl{
		SrcGroups: make(map[uint32]uint32),
		DstGroups: make(map[uint32]uint32),
		DstPorts:  make(map[uint16]uint16),
	}
}

func judgeProto(basisProto uint8, proto uint8) bool {
	if basisProto == 0 || proto == basisProto {
		return true
	}
	return false
}

func judgeVlan(basisVlan uint32, vlan uint32) bool {
	if basisVlan == 0 || vlan == basisVlan {
		return true
	}
	return false
}

func judgePort(basisPort map[uint16]uint16, port uint16) bool {
	if len(basisPort) == 0 {
		return true
	}
	if _, ok := basisPort[port]; ok {
		return true
	}

	return false
}

func judgeGroup(basisGroup map[uint32]uint32, group uint32) bool {
	if _, ok := basisGroup[group]; ok {
		return true
	}

	return false
}

func getPolicyAction(srcGroups []uint32, dstGroups []uint32, acl *Acl) bool {
	srcAclGroupLen := len(acl.SrcGroups)
	dstAclGroupLen := len(acl.DstGroups)
	if srcAclGroupLen == 0 && dstAclGroupLen == 0 {
		return true
	}
	if srcAclGroupLen == 0 && dstAclGroupLen != 0 {
		for _, dstGroup := range dstGroups {
			if judgeGroup(acl.DstGroups, dstGroup) {
				return true
			}
		}
		return false
	}
	if srcAclGroupLen != 0 && dstAclGroupLen == 0 {
		for _, srcGroup := range srcGroups {
			if judgeGroup(acl.SrcGroups, srcGroup) {
				return true
			}
		}
		return false
	}
	for _, srcGroup := range srcGroups {
		for _, dstGroup := range dstGroups {
			if judgeGroup(acl.SrcGroups, srcGroup) && judgeGroup(acl.DstGroups, dstGroup) {
				return true
			}
		}
	}

	return false
}

func (l *PolicyLabel) GetPolicyFromPolicyTable(endpointData *EndpointData, key *LookupKey, acls []*Acl) []*AclAction {
	var aclActions []*AclAction
	for _, acl := range acls {
		if judgeProto(acl.Proto, key.Proto) && judgeVlan(acl.Vlan, uint32(key.Vlan)) {
			if judgePort(acl.DstPorts, key.DstPort) {
				if getPolicyAction(endpointData.SrcInfo.GroupIds, endpointData.DstInfo.GroupIds, acl) {
					aclActions = append(aclActions, acl.Action...)
				}
			} else if judgePort(acl.DstPorts, key.SrcPort) {
				if getPolicyAction(endpointData.DstInfo.GroupIds, endpointData.SrcInfo.GroupIds, acl) {
					aclActions = append(aclActions, acl.Action...)
				}
			}
		}
		continue
	}

	return aclActions
}

func (l *PolicyLabel) GenerateAcls(acls []*Acl) [TAP_MAX][]*Acl {
	var aclData [TAP_MAX][]*Acl
	for _, acl := range acls {
		if acl.Type.CheckTapType(acl.Type) {
			aclData[acl.Type] = append(aclData[acl.Type], acl)
		} else {
			log.Error("GENERATE ACLS TAPTYPE:%d IS ERR", acl.Type)
		}
	}

	return aclData
}

func (l *PolicyLabel) UpdateAcls(acl []*Acl) {
	l.aclData = l.GenerateAcls(acl)
}

func (l *PolicyLabel) GetPolicyData(endpointData *EndpointData, key *LookupKey) []*AclAction {
	aclActions := l.GetPolicyFromPolicyTable(endpointData, key, l.aclData[key.Tap])
	aclActions = append(aclActions, l.GetPolicyFromPolicyTable(endpointData, key, l.aclData[TAP_ANY])...)
	return aclActions
}
