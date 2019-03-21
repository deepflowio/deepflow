package policy

import (
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

type AclGidMap struct {
	SrcGroupAclGidMaps [TAP_MAX]map[uint32]bool
	DstGroupAclGidMaps [TAP_MAX]map[uint32]bool
}

func (m *AclGidMap) Init() {
	for i := TAP_MIN; i < TAP_MAX; i++ {
		m.SrcGroupAclGidMaps[i] = make(map[uint32]bool)
		m.DstGroupAclGidMaps[i] = make(map[uint32]bool)
	}
}

func toSliceUint16(raw []uint32) []uint16 {
	result := make([]uint16, 0, len(raw))
	for _, id := range raw {
		result = append(result, uint16(id&0xffff))
	}
	return result
}

func addGroupAclGidsToMap(acl *Acl, enable bool, aclGid uint32, srcMap map[uint32]bool, dstMap map[uint32]bool) {
	srcLen := len(acl.SrcGroups)
	dstLen := len(acl.DstGroups)
	srcGroups := acl.SrcGroupRelations
	dstGroups := acl.DstGroupRelations
	if !enable {
		srcGroups = toSliceUint16(acl.SrcGroups)
		dstGroups = toSliceUint16(acl.DstGroups)
	}

	for _, group := range srcGroups {
		key := aclGid<<16 | uint32(group)
		if ok := srcMap[key]; !ok {
			srcMap[key] = true
		}
		if dstLen == 0 {
			if ok := dstMap[key]; !ok {
				dstMap[key] = true
			}
		}
	}
	for _, group := range dstGroups {
		key := aclGid<<16 | uint32(group)
		if ok := dstMap[key]; !ok {
			dstMap[key] = true
		}
		if srcLen == 0 {
			if ok := srcMap[key]; !ok {
				srcMap[key] = true
			}
		}
	}
}

func (m *AclGidMap) GenerateGroupAclGidMaps(acls []*Acl, enable bool) {
	srcGroupAclGidMaps := [TAP_MAX]map[uint32]bool{}
	dstGroupAclGidMaps := [TAP_MAX]map[uint32]bool{}
	for i := TAP_MIN; i < TAP_MAX; i++ {
		dstGroupAclGidMaps[i] = make(map[uint32]bool)
		srcGroupAclGidMaps[i] = make(map[uint32]bool)
	}
	for _, acl := range acls {
		for _, action := range acl.Action {
			addGroupAclGidsToMap(acl, enable, uint32(action.GetACLGID()), srcGroupAclGidMaps[acl.Type], dstGroupAclGidMaps[acl.Type])
		}
	}
	m.SrcGroupAclGidMaps = srcGroupAclGidMaps
	m.DstGroupAclGidMaps = dstGroupAclGidMaps
}
