package policy

import (
	"sync"
	"time"

	"github.com/golang/groupcache/lru"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

const (
	MAX_FASTPATH_LEN = 1 << 20
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
	sync.Mutex
	fastPolicy *lru.Cache
}

type PolicyLabel struct {
	aclData  [TAP_MAX][]*Acl
	fastPath [TAP_MAX]*FastPolicyTable
}

func NewPolicyLabel() *PolicyLabel {
	var fastPath [TAP_MAX]*FastPolicyTable
	for i := uint32(0); i < uint32(TAP_MAX); i++ {
		fastPath[i] = &FastPolicyTable{
			fastPolicy: lru.New(MAX_FASTPATH_LEN),
		}
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

func (l *PolicyLabel) InsertPolicyToFastPath(fastKey *FastKey, policyData *PolicyData, tapType TapType) {
	fastPolicyData := &FastPolicyData{
		policyData: policyData,
		timestamp:  time.Now(),
	}
	l.fastPath[tapType].Lock()
	l.fastPath[tapType].fastPolicy.Add(*fastKey, fastPolicyData)
	l.fastPath[tapType].Unlock()
}

func (l *PolicyLabel) GetPolicyByFastPath(fastKey *FastKey, tapType TapType) *PolicyData {
	l.fastPath[tapType].Lock()
	if policy, ok := l.fastPath[tapType].fastPolicy.Get(*fastKey); ok {
		fastPolicyData := policy.(*FastPolicyData)
		if DATA_VALID_TIME < time.Now().Sub(fastPolicyData.timestamp) {
			l.fastPath[tapType].fastPolicy.Remove(*fastKey)
			l.fastPath[tapType].Unlock()
			return nil
		}
		l.fastPath[tapType].Unlock()
		return fastPolicyData.policyData
	}
	l.fastPath[tapType].Unlock()
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
	var aclActions []*AclAction
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
