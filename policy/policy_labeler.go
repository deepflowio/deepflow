package policy

import (
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

const (
	ANY_GROUP = 0
	ANY_PROTO = 0
	ANY_PORT  = 0

	ACL_PROTO_MAX = 256 // 0 ~ 255
)

type PolicyLabeler struct {
	FastPath
	InterestTable
	AclGidMap

	RawAcls []*Acl

	FastPathDisable bool // 是否关闭快速路径，只使用慢速路径（FirstPath）
	queueCount      int

	GroupPortPolicyMaps [TAP_MAX][ACL_PROTO_MAX]map[uint64]*PolicyData // 慢速路径上资源组+协议+端口到Policy的映射表
	GroupVlanPolicyMaps [TAP_MAX]map[uint64]*PolicyData                // 慢速路径上资源组+Vlan到Policy的映射表

	FirstPathHit         uint64
	AclHitMax            uint32
	UnmatchedPacketCount uint64

	cloudPlatformLabeler *CloudPlatformLabeler
}

var STANDARD_NETMASK = MaskLenToNetmask(STANDARD_MASK_LEN)

func NewPolicyLabeler(queueCount int, mapSize uint32, fastPathDisable bool) TableOperator {
	policy := &PolicyLabeler{queueCount: queueCount, FastPathDisable: fastPathDisable}

	for i := TAP_MIN; i < TAP_MAX; i++ {
		policy.GroupVlanPolicyMaps[i] = make(map[uint64]*PolicyData)
		for j := 0; j < ACL_PROTO_MAX; j++ {
			policy.GroupPortPolicyMaps[i][j] = make(map[uint64]*PolicyData)
		}
	}

	policy.AclGidMap.Init()
	policy.InterestTable.Init(false)
	policy.FastPath.Init(mapSize, queueCount, policy.AclGidMap.SrcGroupAclGidMaps, policy.AclGidMap.DstGroupAclGidMaps)
	return policy
}

func (l *PolicyLabeler) SetCloudPlatform(cloudPlatformLabeler *CloudPlatformLabeler) {
	l.cloudPlatformLabeler = cloudPlatformLabeler
}

func (l *PolicyLabeler) GetHitStatus() (uint64, uint64) {
	return l.FirstPathHit, l.FastPathHit
}

func (l *PolicyLabeler) GetCounter() interface{} {
	counter := &PolicyCounter{
		MacTable:   uint32(len(l.cloudPlatformLabeler.macTable.macMap)),
		EpcIpTable: uint32(len(l.cloudPlatformLabeler.epcIpTable.epcIpMap)),
	}
	for i := MIN_MASK_LEN; i < MAX_MASK_LEN; i++ {
		counter.IpTable += uint32(len(l.cloudPlatformLabeler.ipTables[i].ipMap))
	}
	for i := TAP_MIN; i < TAP_MAX; i++ {
		counter.ArpTable += uint32(len(l.cloudPlatformLabeler.arpTable[i]))
	}

	counter.Acl += uint32(len(l.RawAcls))
	counter.FirstHit = l.FirstPathHit
	counter.FastHit = l.FastPathHit
	counter.AclHitMax = l.AclHitMax
	l.FirstPathHit = 0
	l.FastPathHit = 0
	l.AclHitMax = 0
	counter.FastPathMacCount = l.FastPathMacCount
	counter.FastPathPolicyCount = l.FastPathPolicyCount
	counter.UnmatchedPacketCount = l.UnmatchedPacketCount
	for i := 0; i < l.queueCount; i++ {
		for j := TAP_MIN; j < TAP_MAX; j++ {
			maps := l.FastPolicyMaps[i][j]
			if maps != nil {
				counter.FastPath += uint32(maps.Size())
			}
		}
	}
	return counter
}

func generateGroupPortKeys(srcGroups, dstGroups []uint16, srcPort, dstPort uint16) []uint64 {
	// port key:
	//  64         48            32           16            0
	//  +---------------------------------------------------+
	//  |   sport   |   dport     |     id0/1   |    id0/1   |
	//  +---------------------------------------------------+
	if len(srcGroups) == 0 {
		srcGroups = append(srcGroups, ANY_GROUP)
	}
	if len(dstGroups) == 0 {
		dstGroups = append(dstGroups, ANY_GROUP)
	}

	keys := make([]uint64, 0, len(srcGroups)*len(dstGroups))
	key := uint64(srcPort)<<48 | uint64(dstPort)<<32

	for _, src := range srcGroups {
		srcId := uint64(src & 0xffff)
		for _, dst := range dstGroups {
			dstId := uint64(dst & 0xffff)
			key |= srcId<<16 | dstId
			keys = append(keys, key)
			key &= 0xffffffff00000000
		}
	}
	return keys
}

func generateSearchPortKeys(srcGroups, dstGroups []uint16, srcPort, dstPort uint16) []uint64 {
	keys := generateGroupPortKeys(srcGroups, dstGroups, srcPort, dstPort)
	// 匹配port全采集的acl
	if srcPort != 0 {
		keys = append(keys, generateGroupPortKeys(srcGroups, dstGroups, ANY_PORT, dstPort)...)
	}
	if dstPort != 0 {
		keys = append(keys, generateGroupPortKeys(srcGroups, dstGroups, srcPort, ANY_PORT)...)
	}
	if srcPort != 0 && dstPort != 0 {
		keys = append(keys, generateGroupPortKeys(srcGroups, dstGroups, ANY_PORT, ANY_PORT)...)
	}
	return keys
}

func generateGroupPortsKeys(acl *Acl, direction DirectionType) []uint64 {
	srcGroups := acl.SrcGroupRelations
	dstGroups := acl.DstGroupRelations
	srcPorts := acl.SrcPorts
	dstPorts := acl.DstPorts
	if direction == BACKWARD {
		srcGroups, dstGroups = dstGroups, srcGroups
		srcPorts, dstPorts = dstPorts, srcPorts
	}

	// 策略配置端口全采集，则生成port为0的一条map
	if len(srcPorts) == 0 {
		srcPorts = append(srcPorts[:0], ANY_PORT)
	}
	if len(dstPorts) == 0 {
		dstPorts = append(dstPorts[:0], ANY_PORT)
	}

	keys := make([]uint64, 0, len(srcPorts)*len(dstPorts))

	for _, src := range srcPorts {
		for _, dst := range dstPorts {
			keys = append(keys, generateGroupPortKeys(srcGroups, dstGroups, src, dst)...)
		}
	}
	return keys
}

func (l *PolicyLabeler) GenerateGroupPortMaps(acls []*Acl) {
	portMaps := [TAP_MAX][ACL_PROTO_MAX]map[uint64]*PolicyData{}
	for i := TAP_MIN; i < TAP_MAX; i++ {
		for j := 0; j < ACL_PROTO_MAX; j++ {
			portMaps[i][j] = make(map[uint64]*PolicyData)
		}
	}

	for _, acl := range acls {
		if acl.Type.CheckTapType(acl.Type) && acl.Vlan == 0 {
			portMap := portMaps[acl.Type][acl.Proto]

			keys := generateGroupPortsKeys(acl, FORWARD)
			for _, key := range keys {
				if policy := portMap[key]; policy == nil {
					policy := new(PolicyData)
					policy.Merge(acl.Action, acl.NpbActions, acl.Id)
					portMap[key] = policy
				} else {
					// 策略存在则将action合入到现有策略
					policy.Merge(acl.Action, acl.NpbActions, acl.Id)
				}
			}
		}
	}

	for i := TAP_MIN; i < TAP_MAX; i++ {
		anyPortMap := portMaps[i][ANY_PROTO]
		for key, value := range anyPortMap {
			for j := 0; j < ACL_PROTO_MAX; j++ {
				if portMaps[i][j][key] == nil {
					portMaps[i][j][key] = value
				} else {
					portMaps[i][j][key].Merge(value.AclActions, value.NpbActions, value.ACLID)
				}
			}
		}
	}
	l.GroupPortPolicyMaps = portMaps
}

func generateGroupVlanKeys(srcGroups, dstGroups []uint16, vlan uint16) []uint64 {
	// vlan key:
	//  64         48            40           20            0
	//  +---------------------------------------------------+
	//  |    vlan  |             |     id0/1   |    id0/1   |
	//  +---------------------------------------------------+
	keys := make([]uint64, 0, 10)
	key := uint64(vlan) << 48

	if len(srcGroups) == 0 {
		srcGroups = append(srcGroups, ANY_GROUP)
	}

	if len(dstGroups) == 0 {
		dstGroups = append(dstGroups, ANY_GROUP)
	}

	for _, src := range srcGroups {
		srcId := uint64(src)
		for _, dst := range dstGroups {
			dstId := uint64(dst)
			key |= srcId<<20 | dstId
			keys = append(keys, key)
			key &= 0xffffff0000000000
		}
	}
	return keys
}

func (l *PolicyLabeler) GenerateGroupVlanMaps(acls []*Acl) {
	vlanMaps := [TAP_MAX]map[uint64]*PolicyData{}
	for i := TAP_MIN; i < TAP_MAX; i++ {
		vlanMaps[i] = make(map[uint64]*PolicyData)
	}

	for _, acl := range acls {
		if acl.Type.CheckTapType(acl.Type) && acl.Vlan > 0 {
			vlanMap := vlanMaps[acl.Type]

			keys := generateGroupVlanKeys(acl.SrcGroupRelations, acl.DstGroupRelations, uint16(acl.Vlan))
			for _, key := range keys {
				if policy := vlanMap[key]; policy == nil {
					policy := new(PolicyData)
					policy.Merge(acl.Action, acl.NpbActions, acl.Id, FORWARD)
					vlanMap[key] = policy
				} else {
					policy.Merge(acl.Action, acl.NpbActions, acl.Id, FORWARD)
				}
			}

			keys = generateGroupVlanKeys(acl.DstGroupRelations, acl.SrcGroupRelations, uint16(acl.Vlan))
			for _, key := range keys {
				if policy := vlanMap[key]; policy == nil {
					policy := new(PolicyData)
					policy.Merge(acl.Action, acl.NpbActions, acl.Id, BACKWARD)
					vlanMap[key] = policy
				} else {
					policy.Merge(acl.Action, acl.NpbActions, acl.Id, BACKWARD)
				}
			}
		}
	}
	l.GroupVlanPolicyMaps = vlanMaps
}

func (l *PolicyLabeler) GenerateGroupAclGidMaps(acls []*Acl) {
	l.AclGidMap.GenerateGroupAclGidMaps(acls, true)
	l.FastPath.UpdateGroupAclGidMaps(l.AclGidMap.SrcGroupAclGidMaps, l.AclGidMap.DstGroupAclGidMaps)
}

func (l *PolicyLabeler) UpdateAcls(acls []*Acl, _ ...bool) {
	l.RawAcls = acls

	generateAcls := make([]*Acl, 0, len(acls))
	for _, acl := range acls {
		// acl需要根据groupIdMaps更新里面的NpbActions
		if len(acl.NpbActions) > 0 {
			groupType := RESOURCE_GROUP_TYPE_IP | RESOURCE_GROUP_TYPE_DEV
			for _, id := range append(acl.SrcGroups, acl.DstGroups...) {
				// 带NPB的acl，资源组类型为全DEV或全IP两种情况
				if id != 0 && l.groupIdMaps[id] != 0 {
					groupType = l.groupIdMaps[id]
				}
				break
			}
			for index, _ := range acl.NpbActions {
				acl.NpbActions[index].AddResourceGroupType(groupType)
			}
		}

		if acl.Type == TAP_ANY {
			// 对于TAP_ANY策略，给其他每一个TAP类型都单独生成一个acl，来避免查找2次
			for i := TAP_MIN; i < TAP_MAX; i++ {
				generateAcl := &Acl{}
				*generateAcl = *acl
				generateAcl.Type = i
				generateAcls = append(generateAcls, generateAcl)
			}
		} else {
			generateAcls = append(generateAcls, acl)
		}
	}
	l.GenerateInterestMaps(generateAcls)
	l.GenerateGroupPortMaps(generateAcls)
	l.GenerateGroupVlanMaps(generateAcls)
	l.GenerateGroupAclGidMaps(generateAcls)
}

func (l *PolicyLabeler) FlushAcls() {
	l.FastPath.FlushAcls()
	l.UnmatchedPacketCount = 0
}

func (l *PolicyLabeler) AddAcl(acl *Acl) {
	acls := l.RawAcls

	acls = append(acls, acl)
	l.UpdateAcls(acls)
	l.FlushAcls()
}

func (l *PolicyLabeler) DelAcl(id int) {
	acls := l.RawAcls

	if id > len(acls) || id <= 0 {
		return
	}

	index := id - 1
	if id == len(acls) {
		l.UpdateAcls(acls[:index])
		l.FlushAcls()
	} else {
		newAcls := acls[0:index]
		newAcls = append(newAcls, acls[index+1:]...)
		l.UpdateAcls(newAcls)
		l.FlushAcls()
	}
}

func (l *PolicyLabeler) GetAcl() []*Acl {
	return l.RawAcls
}

func getAclId(ids ...ACLID) ACLID {
	for _, id := range ids {
		if id != 0 {
			return id
		}
	}
	return ACLID(0)
}

func (l *PolicyLabeler) GetPolicyByFirstPath(endpointData *EndpointData, packet *LookupKey) (*EndpointStore, *PolicyData) {
	l.generateInterestKeys(endpointData, packet, true)
	srcMacSuffix := uint16(packet.SrcMac & 0xffff)
	dstMacSuffix := uint16(packet.DstMac & 0xffff)
	portGroup := l.GroupPortPolicyMaps[packet.Tap][packet.Proto]
	vlanGroup := l.GroupVlanPolicyMaps[packet.Tap]
	// 对于内容全为0的findPolicy，统一采用INVALID_POLICY_DATA（同一块内存的数值）
	portForwardPolicy, portBackwardPolicy, vlanPolicy, findPolicy := INVALID_POLICY_DATA, INVALID_POLICY_DATA, INVALID_POLICY_DATA, INVALID_POLICY_DATA

	// 在port map中查找策略, 创建正方向key
	keys := generateSearchPortKeys(packet.SrcGroupIds, packet.DstGroupIds, packet.SrcPort, packet.DstPort)
	for _, key := range keys {
		if policy := portGroup[key]; policy != nil && policy.ACLID > 0 {
			if portForwardPolicy == INVALID_POLICY_DATA {
				portForwardPolicy = new(PolicyData)
				portForwardPolicy.AclActions = make([]AclAction, 0, 4)
			}
			portForwardPolicy.Merge(policy.AclActions, policy.NpbActions, policy.ACLID, FORWARD)
		}
	}
	// 在port map中查找策略, 创建反方向key
	keys = generateSearchPortKeys(packet.DstGroupIds, packet.SrcGroupIds, packet.DstPort, packet.SrcPort)
	for _, key := range keys {
		if policy := portGroup[key]; policy != nil && policy.ACLID > 0 {
			if portBackwardPolicy == INVALID_POLICY_DATA {
				portBackwardPolicy = new(PolicyData)
				portBackwardPolicy.AclActions = make([]AclAction, 0, 4)
			}
			// first层面存储的都是正方向的key, 在这里重新设置方向
			portBackwardPolicy.Merge(policy.AclActions, policy.NpbActions, policy.ACLID, BACKWARD)
		}
	}

	// 剔除匿名资源组ID
	endpointStore := &EndpointStore{}
	endpointStore.InitPointer(endpointData)
	l.cloudPlatformLabeler.RemoveAnonymousGroupIds(endpointStore, packet)
	packetEndpointData := l.cloudPlatformLabeler.UpdateEndpointData(endpointStore, packet)

	// 无论是否查找到policy，都需要向fastPath下发，避免重复走firstPath
	mapsForward, mapsBackward := l.addPortFastPolicy(endpointStore, packetEndpointData, srcMacSuffix, dstMacSuffix, packet, portForwardPolicy, portBackwardPolicy)

	// 在vlan map中查找单方向的策略
	if packet.Vlan > 0 {
		keys := generateGroupVlanKeys(packet.SrcGroupIds, packet.DstGroupIds, packet.Vlan)
		for _, key := range keys {
			if policy := vlanGroup[key]; policy != nil && policy.ACLID > 0 {
				if vlanPolicy == INVALID_POLICY_DATA {
					vlanPolicy = new(PolicyData)
					vlanPolicy.AclActions = make([]AclAction, 0, 4)
				}
				vlanPolicy.Merge(policy.AclActions, policy.NpbActions, policy.ACLID)
			}
		}
		// 无论是否查找到policy，都需要向fastPath下发，避免重复走firstPath
		l.addVlanFastPolicy(srcMacSuffix, dstMacSuffix, packet, vlanPolicy, endpointData, mapsForward, mapsBackward)
	}

	id := getAclId(vlanPolicy.ACLID, portForwardPolicy.ACLID, portBackwardPolicy.ACLID)
	if id > 0 {
		findPolicy = new(PolicyData)
		if packet.HasFeatureFlag(NPM) {
			length := len(portForwardPolicy.AclActions) + len(portBackwardPolicy.AclActions) + len(vlanPolicy.AclActions)
			findPolicy.AclActions = make([]AclAction, 0, length)
			findPolicy.MergeAclAction(append(vlanPolicy.AclActions, append(portForwardPolicy.AclActions, portBackwardPolicy.AclActions...)...), id)
			findPolicy.AddAclGidBitmaps(packet, false, l.AclGidMap.SrcGroupAclGidMaps[packet.Tap], l.AclGidMap.DstGroupAclGidMaps[packet.Tap])
		}
		if packet.HasFeatureFlag(NPB) {
			length := len(portForwardPolicy.NpbActions) + len(portBackwardPolicy.NpbActions)
			findPolicy.NpbActions = make([]NpbAction, 0, length)
			findPolicy.MergeNpbAction(append(portForwardPolicy.NpbActions, portBackwardPolicy.NpbActions...), id)
			findPolicy.FormatNpbAction()
			findPolicy.NpbActions = findPolicy.CheckNpbAction(packet, packetEndpointData)
		}
	} else {
		l.UnmatchedPacketCount++
	}

	l.FirstPathHit++
	if aclHit := uint32(len(findPolicy.AclActions) + len(findPolicy.NpbActions)); l.AclHitMax < aclHit {
		l.AclHitMax = aclHit
	}
	return endpointStore, findPolicy
}

func (l *PolicyLabeler) UpdateInterfaceData(data []*PlatformData) {
	l.GenerateIpNetmaskMapFromPlatformData(data)
	l.GenerateGroupIdMapByPlatformData(data)
}

func (l *PolicyLabeler) UpdateIpGroupData(data []*IpGroupData) {
	l.GenerateIpNetmaskMapFromIpGroupData(data)
	l.GenerateGroupIdMapByIpGroupData(data)
}

func (l *PolicyLabeler) GetPolicyByFastPath(packet *LookupKey) (*EndpointStore, *PolicyData) {
	if l.FastPathDisable {
		return nil, nil
	}

	var endpoint *EndpointStore
	var portPolicy *PolicyData
	vlanPolicy, policy := INVALID_POLICY_DATA, INVALID_POLICY_DATA

	if maps := l.getVlanAndPortMap(packet, FORWARD, false, nil); maps != nil {
		srcMacSuffix, dstMacSuffix := uint16(packet.SrcMac&0xffff), uint16(packet.DstMac&0xffff)
		// NOTE：会改变packet参数，但firstPath同样需要getFastInterestKeys，所以无影响
		l.getFastInterestKeys(packet)
		if endpoint, portPolicy = l.getFastPortPolicy(maps, srcMacSuffix, dstMacSuffix, packet); portPolicy == nil {
			return nil, nil
		}
		if packet.Vlan > 0 && packet.HasFeatureFlag(NPM) {
			if vlanPolicy = l.getFastVlanPolicy(maps, srcMacSuffix, dstMacSuffix, packet); vlanPolicy == nil {
				return nil, nil
			}
		}
	}
	if vlanPolicy.ACLID == 0 {
		policy = portPolicy
	} else if portPolicy.ACLID == 0 {
		policy = vlanPolicy
	} else {
		id := getAclId(vlanPolicy.ACLID, portPolicy.ACLID)
		policy = new(PolicyData)
		if packet.HasFeatureFlag(NPM) {
			l.generateInterestKeys(endpoint.Endpoints, packet, false)
			policy.AclActions = make([]AclAction, 0, len(vlanPolicy.AclActions)+len(portPolicy.AclActions))
			policy.MergeAclAction(append(vlanPolicy.AclActions, portPolicy.AclActions...), id)
			policy.AddAclGidBitmaps(packet, false, l.AclGidMap.SrcGroupAclGidMaps[packet.Tap], l.AclGidMap.DstGroupAclGidMaps[packet.Tap])
		}
		if packet.HasFeatureFlag(NPB) {
			policy.NpbActions = make([]NpbAction, 0, len(portPolicy.NpbActions))
			policy.MergeNpbAction(portPolicy.NpbActions, id)
			policy.FormatNpbAction()
		}
	}

	if policy != nil && endpoint != nil {
		policy = policy.CheckNpbPolicy(packet, endpoint.Endpoints)
	}

	if policy != nil && policy.ACLID == 0 {
		l.UnmatchedPacketCount++
	}

	l.FastPathHit++
	return endpoint, policy
}
