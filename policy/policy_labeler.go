package policy

import (
	"time"

	"github.com/golang/groupcache/lru"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
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

type FastKey struct {
	SrcHash   uint64
	DstHash   uint64
	Ports     uint64
	ProtoVlan uint64
}

type FastPolicyData struct {
	policyData *PolicyData
	timestamp  time.Time
}

type FastPolicyTable struct {
	fastPolicy *lru.Cache
}

type FastPathPolicy struct {
	fastPolicyTable [TAP_MAX]*FastPolicyTable
}

type PolicyLabel struct {
	aclData  [TAP_MAX][]*Acl
	fastPath []*FastPathPolicy
}

func NewFastPathPolicy() *FastPathPolicy {
	var fastPathPolicy FastPathPolicy
	for i := uint32(0); i < uint32(TAP_MAX); i++ {
		fastPathPolicy.fastPolicyTable[i] = &FastPolicyTable{
			fastPolicy: lru.New(MAX_FASTPATH_LEN),
		}
	}

	return &fastPathPolicy
}

func NewPolicyLabel(queueCount int) *PolicyLabel {
	fastPath := make([]*FastPathPolicy, queueCount)
	for i := uint32(0); i < uint32(queueCount); i++ {
		fastPath[i] = NewFastPathPolicy()
	}

	return &PolicyLabel{
		fastPath: fastPath,
	}
}

func NewAcl() *Acl {
	return &Acl{
		SrcGroups: make(map[uint32]uint32),
		DstGroups: make(map[uint32]uint32),
		DstPorts:  make(map[uint16]uint16),
	}
}

func (l *PolicyLabel) InsertPolicyToFastPath(fastKey *FastKey, policyData *PolicyData, tapType TapType, fastIndex int) {
	fastPolicyData := &FastPolicyData{
		policyData: policyData,
		timestamp:  time.Now(),
	}
	l.fastPath[fastIndex].fastPolicyTable[tapType].fastPolicy.Add(*fastKey, fastPolicyData)
}

func (l *PolicyLabel) GetPolicyByFastPath(fastKey *FastKey, tapType TapType, fastIndex int) *PolicyData {
	if policy, ok := l.fastPath[fastIndex].fastPolicyTable[tapType].fastPolicy.Get(*fastKey); ok {
		fastPolicyData := policy.(*FastPolicyData)
		if DATA_VALID_TIME < time.Now().Sub(fastPolicyData.timestamp) {
			l.fastPath[fastIndex].fastPolicyTable[tapType].fastPolicy.Remove(*fastKey)
			return nil
		}
		return fastPolicyData.policyData
	}
	return nil
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
	aclActions := make([]*AclAction, 0, 32)
	for _, acl := range acls {
		direction := NO_DIRECTION
		if judgeProto(acl.Proto, key.Proto) && judgeVlan(acl.Vlan, uint32(key.Vlan)) {
			if judgePort(acl.DstPorts, key.DstPort) {
				if getPolicyAction(endpointData.SrcInfo.GroupIds, endpointData.DstInfo.GroupIds, acl) {
					direction |= FORWARD
				}
			}
			if judgePort(acl.DstPorts, key.SrcPort) {
				if getPolicyAction(endpointData.DstInfo.GroupIds, endpointData.SrcInfo.GroupIds, acl) {
					direction |= BACKWARD
				}
			}
			if direction != NO_DIRECTION {
				for _, action := range acl.Action {
					action.Direction = direction
					aclActions = append(aclActions, action)
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
