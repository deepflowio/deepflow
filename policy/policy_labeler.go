package policy

import (
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

type FastPathMapValue struct {
	endpoint *EndpointData
	policy   *PolicyData
}

type PolicyLabel struct {
	RawAcls []*Acl

	InterestProtoMaps [TAP_MAX]map[uint8]bool
	InterestPortMaps  [TAP_MAX]map[uint16]bool
	InterestGroupMaps [TAP_MAX]map[uint32]bool

	MacEpcMaps        map[uint64]uint32
	IpNetmaskMap      map[uint32]uint32
	FastPortPolicyMap *lru.Cache
	FastVlanPolicyMap *lru.Cache

	GroupPortPolicyMaps [TAP_MAX]map[uint64]*PolicyData
	GroupVlanPolicyMaps [TAP_MAX]map[uint64]*PolicyData
	maxHit              uint32
}

func NewPolicyLabel(queueCount int, mapSize uint32) *PolicyLabel {
	policy := &PolicyLabel{}

	for i := TAP_ANY; i < TAP_MAX; i++ {
		policy.InterestProtoMaps[i] = make(map[uint8]bool)
		policy.InterestPortMaps[i] = make(map[uint16]bool)
		policy.InterestGroupMaps[i] = make(map[uint32]bool)

		policy.GroupVlanPolicyMaps[i] = make(map[uint64]*PolicyData)
		policy.GroupPortPolicyMaps[i] = make(map[uint64]*PolicyData)
	}

	policy.MacEpcMaps = make(map[uint64]uint32)
	policy.IpNetmaskMap = make(map[uint32]uint32)
	policy.FastPortPolicyMap = lru.New(1024)
	policy.FastVlanPolicyMap = lru.New(1024)
	return policy
}

func mapToSlice(in map[uint32]uint32) []uint32 {
	out := make([]uint32, 0, 8)
	for _, item := range in {
		if item > 0 {
			out = append(out, item)
		}
	}
	return out
}

func (l *PolicyLabel) generateInterestKeys(endpointData *EndpointData, packet *LookupKey) {
	groupMap := l.InterestGroupMaps[packet.Tap]
	for _, id := range endpointData.SrcInfo.GroupIds {
		if groupMap[id] {
			packet.SrcGroupIds = append(packet.SrcGroupIds, id)
		}
	}
	for _, id := range endpointData.DstInfo.GroupIds {
		if groupMap[id] {
			packet.DstGroupIds = append(packet.DstGroupIds, id)
		}
	}
	if !l.InterestProtoMaps[packet.Tap][packet.Proto] {
		packet.Proto = 0
	}

	if !l.InterestPortMaps[packet.Tap][packet.SrcPort] {
		packet.SrcPort = 0
	}
	if !l.InterestPortMaps[packet.Tap][packet.DstPort] {
		packet.DstPort = 0
	}
}

func generateGroupPortKeys(srcGroups []uint32, dstGroups []uint32, port uint16, proto uint8) []uint64 {
	/* port key:
	    64         56            40           20            0
		+---------------------------------------------------+
		|   proto   |   port     |     id0/1   |    id0/1   |
		+---------------------------------------------------+
	*/
	keys := make([]uint64, 0, 10)
	key := uint64(port)<<40 | uint64(proto)<<56

	if len(srcGroups) == 0 {
		srcGroups = append(srcGroups, 0)
	}

	if len(dstGroups) == 0 {
		dstGroups = append(dstGroups, 0)
	}

	for _, src := range srcGroups {
		srcId := uint64(src & 0xfffff)
		for _, dst := range dstGroups {
			dstId := uint64(dst & 0xfffff)
			key |= srcId<<20 | dstId
			keys = append(keys, key)
		}
	}
	return keys
}

func generateGroupPortsKeys(acl *Acl, direction DirectionType) []uint64 {
	keys := make([]uint64, 0, 10)

	src := acl.SrcGroups
	dst := acl.DstGroups
	if direction == BACKWARD {
		src, dst = dst, src
	}

	// 策略配置端口全采集，则声称port为0的一条map
	if len(acl.DstPorts) == 65535 || len(acl.DstPorts) == 0 {
		keys = generateGroupPortKeys(mapToSlice(src), mapToSlice(dst), 0, acl.Proto)
	} else {
		// FIXME: 当很多条策略都配置了很多port,内存占用可能会很大
		for _, port := range acl.DstPorts {
			keys = append(keys, generateGroupPortKeys(mapToSlice(src), mapToSlice(dst), port, acl.Proto)...)
		}
	}
	return keys
}

func (l *PolicyLabel) GenerateGroupPortMaps(acls []*Acl) {
	portMaps := [TAP_MAX]map[uint64]*PolicyData{}
	for i := TAP_ANY; i < TAP_MAX; i++ {
		portMaps[i] = make(map[uint64]*PolicyData)
	}

	for _, acl := range acls {
		if acl.Type.CheckTapType(acl.Type) && acl.Vlan == 0 {
			portMap := portMaps[acl.Type]

			keys := generateGroupPortsKeys(acl, FORWARD)
			for _, key := range keys {
				if policy := portMap[key]; policy == nil {
					policy := &PolicyData{}
					policy.Merge(acl.Action, FORWARD)
					portMap[key] = policy
				} else {
					// 策略存在则将action合入到现有策略
					policy.Merge(acl.Action, FORWARD)
				}
			}

			keys = generateGroupPortsKeys(acl, BACKWARD)
			for _, key := range keys {
				if policy := portMap[key]; policy == nil {
					policy := &PolicyData{}
					policy.Merge(acl.Action, BACKWARD)
					portMap[key] = policy
				} else {
					// 策略存在则将action合入到现有策略
					policy.Merge(acl.Action, BACKWARD)
				}
			}
		}
	}
	l.GroupPortPolicyMaps = portMaps
}

func (l *PolicyLabel) GenerateIpNetmaskMap(platforms []*PlatformData) {
	maskMap := make(map[uint32]uint32, 32767)
	for _, platform := range platforms {
		for _, network := range platform.Ips {
			netIp := network.Ip & network.Netmask
			mask := uint32(0xffffffff) << (32 - network.Netmask)
			if maskMap[netIp] < mask {
				maskMap[netIp] = mask
			}
		}
	}
	l.IpNetmaskMap = maskMap
}

func generateGroupVlanKeys(srcGroups []uint32, dstGroups []uint32, vlan uint16) []uint64 {
	/* vlan key:
	    64         48            40           20            0
		+---------------------------------------------------+
		|    vlan  |             |     id0/1   |    id0/1   |
		+---------------------------------------------------+
	*/
	keys := make([]uint64, 0, 10)
	key := uint64(vlan) << 48

	if len(srcGroups) == 0 {
		srcGroups = append(srcGroups, 0)
	}

	if len(dstGroups) == 0 {
		dstGroups = append(dstGroups, 0)
	}

	for _, src := range srcGroups {
		srcId := uint64(src & 0xfffff)
		for _, dst := range dstGroups {
			dstId := uint64(dst & 0xfffff)
			key |= srcId<<20 | dstId
			keys = append(keys, key)
		}
	}
	return keys
}

func (l *PolicyLabel) GenerateGroupVlanMaps(acls []*Acl) {
	vlanMaps := [TAP_MAX]map[uint64]*PolicyData{}
	for i := TAP_ANY; i < TAP_MAX; i++ {
		vlanMaps[i] = make(map[uint64]*PolicyData)
	}

	for _, acl := range acls {
		if acl.Type.CheckTapType(acl.Type) && acl.Vlan > 0 {
			vlanMap := vlanMaps[acl.Type]

			keys := generateGroupVlanKeys(mapToSlice(acl.SrcGroups), mapToSlice(acl.DstGroups), uint16(acl.Vlan))
			for _, key := range keys {
				if policy := vlanMap[key]; policy == nil {
					policy := &PolicyData{}
					policy.Merge(acl.Action, FORWARD)
					vlanMap[key] = policy
				} else {
					policy.Merge(acl.Action, FORWARD)
				}
			}

			keys = generateGroupVlanKeys(mapToSlice(acl.DstGroups), mapToSlice(acl.SrcGroups), uint16(acl.Vlan))
			for _, key := range keys {
				if policy := vlanMap[key]; policy == nil {
					policy := &PolicyData{}
					policy.Merge(acl.Action, BACKWARD)
					vlanMap[key] = policy
				} else {
					policy.Merge(acl.Action, BACKWARD)
				}
			}
		}
	}
	l.GroupVlanPolicyMaps = vlanMaps
}

func (l *PolicyLabel) GenerateInterestMaps(acls []*Acl) {
	interestProtoMaps := [TAP_MAX]map[uint8]bool{}
	interestPortMaps := [TAP_MAX]map[uint16]bool{}
	interestGroupMaps := [TAP_MAX]map[uint32]bool{}
	for i := TAP_ANY; i < TAP_MAX; i++ {
		interestProtoMaps[i] = make(map[uint8]bool)
		interestPortMaps[i] = make(map[uint16]bool)
		interestGroupMaps[i] = make(map[uint32]bool)
	}
	// 将策略中存在的proto、port、group id存在map中
	for _, acl := range acls {
		if acl.Type.CheckTapType(acl.Type) {
			interestProtoMaps[acl.Type][acl.Proto] = true

			portMap := interestPortMaps[acl.Type]
			for _, port := range acl.DstPorts {
				portMap[port] = true
			}

			groupMap := interestGroupMaps[acl.Type]
			for _, group := range acl.DstGroups {
				groupMap[group] = true
			}
			for _, group := range acl.SrcGroups {
				groupMap[group] = true
			}
		}
	}
	l.InterestGroupMaps = interestGroupMaps
	l.InterestProtoMaps = interestProtoMaps
	l.InterestPortMaps = interestPortMaps
}

func (l *PolicyLabel) UpdateAcls(acl []*Acl) {
	l.RawAcls = acl
	l.GenerateGroupPortMaps(acl)
	l.GenerateGroupVlanMaps(acl)
	l.GenerateInterestMaps(acl)
}

func (l *PolicyLabel) AddAcl(acl *Acl) {
	acls := l.RawAcls

	acls = append(acls, acl)
	l.UpdateAcls(acls)
}

func (l *PolicyLabel) DelAcl(id int) {
	acls := l.RawAcls

	if id > len(acls) || id <= 0 {
		return
	}

	index := id - 1
	if id == len(acls) {
		l.UpdateAcls(acls[:index])
	} else {
		newAcls := acls[0:index]
		newAcls = append(newAcls, acls[index+1:]...)
		l.UpdateAcls(newAcls)
	}
}

func (l *PolicyLabel) GetPolicyByFirstPath(endpointData *EndpointData, packet *LookupKey) *PolicyData {
	// FIXME: 先fast在first，这里的可能和fast里面的冗余了
	l.generateInterestKeys(endpointData, packet)
	portGroup := l.GroupPortPolicyMaps[packet.Tap]
	vlanGroup := l.GroupVlanPolicyMaps[packet.Tap]
	findPolicy := &PolicyData{}
	findPolicy.AclActions = make([]*AclAction, 0, 8)

	// 在vlan map中查找双方向的策略
	if packet.Vlan > 0 {
		keys := generateGroupVlanKeys(packet.SrcGroupIds, packet.DstGroupIds, packet.Vlan)
		for _, key := range keys {
			if policy := vlanGroup[key]; policy != nil {
				findPolicy.Merge(policy.AclActions)
			}
		}

		if packet.DstGroupIds != nil || packet.SrcGroupIds != nil {
			keys = generateGroupVlanKeys(packet.DstGroupIds, packet.SrcGroupIds, packet.Vlan)
			for _, key := range keys {
				if policy := vlanGroup[key]; policy != nil {
					findPolicy.Merge(policy.AclActions)
				}
			}
		}
		// 无论是否差找到policy，都需要向fastPath下发，避免重复走firstPath
		l.addVlanFastPolicy(endpointData, packet, findPolicy)
	}

	// 在port map中查找策略
	keys := generateGroupPortKeys(packet.SrcGroupIds, packet.DstGroupIds, packet.DstPort, packet.Proto)
	for _, key := range keys {
		if policy := portGroup[key]; policy != nil {
			findPolicy.Merge(policy.AclActions)
		}
	}

	// port都是0的情况，只查询一次
	if packet.SrcPort != 0 || packet.DstPort != 0 {
		keys = generateGroupPortKeys(packet.DstGroupIds, packet.SrcGroupIds, packet.SrcPort, packet.Proto)
		for _, key := range keys {
			if policy := portGroup[key]; policy != nil {
				findPolicy.Merge(policy.AclActions)
			}
		}
	}

	// 无论是否差找到policy，都需要向fastPath下发，避免走firstPath
	l.addPortFastPolicy(endpointData, packet, findPolicy)
	return findPolicy
}

func (l *PolicyLabel) addEpcMap(endpointInfo *EndpointInfo, mac uint64) uint32 {
	id := uint32(0)
	if endpointInfo.L2EpcId > 0 {
		id = uint32(endpointInfo.L2EpcId)
	} else if endpointInfo.L2EpcId == 0 {
		if endpointInfo.L3EpcId > 0 {
			id = uint32(endpointInfo.L3EpcId)
		} else if endpointInfo.L3EpcId == -1 {
			id = 0xffffffff
		}
	}
	if id > 0 {
		l.MacEpcMaps[mac] = id
	}
	return id
}

func (l *PolicyLabel) addVlanFastPolicy(endpointData *EndpointData, packet *LookupKey, policy *PolicyData) {
	srcEpc := l.addEpcMap(endpointData.SrcInfo, packet.SrcMac)
	dstEpc := l.addEpcMap(endpointData.DstInfo, packet.DstMac)
	forward := &PolicyData{}
	backward := &PolicyData{}
	valueForward := &FastPathMapValue{endpoint: endpointData, policy: forward}
	valueBackward := &FastPathMapValue{endpoint: endpointData, policy: backward}

	forward.Merge(policy.AclActions)
	key := uint64(packet.Vlan) | uint64(srcEpc)<<32 | uint64(dstEpc)<<12
	l.FastVlanPolicyMap.Add(key, valueForward)

	backward.MergeAndSwapDirection(policy.AclActions)
	key = uint64(packet.Vlan) | uint64(dstEpc)<<32 | uint64(srcEpc)<<12
	l.FastVlanPolicyMap.Add(key, valueBackward)
}

func (l *PolicyLabel) addPortFastPolicy(endpointData *EndpointData, packet *LookupKey, policy *PolicyData) {
	srcEpc := l.addEpcMap(endpointData.SrcInfo, packet.SrcMac)
	dstEpc := l.addEpcMap(endpointData.DstInfo, packet.DstMac)
	forward := &PolicyData{}
	backward := &PolicyData{}
	valueForward := &FastPathMapValue{endpoint: endpointData, policy: forward}
	valueBackward := &FastPathMapValue{endpoint: endpointData, policy: backward}

	// 使用maskIp查找PortPolicyMap
	maskedSrcIp := l.IpNetmaskMap[packet.SrcIp] & packet.SrcIp
	maskedDstIp := l.IpNetmaskMap[packet.DstIp] & packet.DstIp
	ipKey := uint64(maskedDstIp)<<32 | uint64(maskedSrcIp)
	var portPolicyMap *lru.Cache
	data, ok := l.FastPortPolicyMap.Get(ipKey)
	if !ok {
		portPolicyMap = lru.New(1024)
		l.FastPortPolicyMap.Add(ipKey, portPolicyMap)
	} else {
		portPolicyMap = data.(*lru.Cache)
	}

	// 用epcid + proto + port做为key,将policy插入到PortPolicyMap
	forward.Merge(policy.AclActions)
	portKey := uint64(dstEpc)<<44 | uint64(srcEpc)<<24 | uint64(packet.Proto)<<16 | uint64(packet.SrcPort)
	portPolicyMap.Add(portKey, valueForward)

	backward.MergeAndSwapDirection(policy.AclActions)
	portKey = uint64(srcEpc)<<44 | uint64(dstEpc)<<24 | uint64(packet.Proto)<<16 | uint64(packet.DstPort)
	portPolicyMap.Add(portKey, valueBackward)
}

func (l *PolicyLabel) getFastInterestKeys(packet *LookupKey) {
	if packet.Proto == 6 || packet.Proto == 17 {
		if !l.InterestPortMaps[packet.Tap][packet.SrcPort] {
			packet.SrcPort = 0
		}
		if !l.InterestPortMaps[packet.Tap][packet.DstPort] {
			packet.SrcPort = 0
		}
	}

	if packet.Proto != 0 {
		if !l.InterestProtoMaps[packet.Tap][packet.Proto] {
			packet.Proto = 0
		}
	}
}

func (l *PolicyLabel) UpdateMaxHit(hitCount uint32) {
	if l.maxHit < hitCount {
		l.maxHit = hitCount
	}
}

func (l *PolicyLabel) getFastPortPolicy(packet *LookupKey) *FastPathMapValue {
	srcEpc := uint64(l.MacEpcMaps[packet.SrcMac])
	dstEpc := uint64(l.MacEpcMaps[packet.DstMac])
	if srcEpc == 0 && dstEpc == 0 {
		return nil
	}

	l.getFastInterestKeys(packet)

	maskedSrcIp := l.IpNetmaskMap[packet.SrcIp] & packet.SrcIp
	maskedDstIp := l.IpNetmaskMap[packet.DstIp] & packet.DstIp
	ipKey := uint64(maskedDstIp)<<32 | uint64(maskedSrcIp)
	if data, ok := l.FastPortPolicyMap.Get(ipKey); ok {
		portPolicyMap := data.(*lru.Cache)
		portKey := dstEpc<<44 | srcEpc<<24 | uint64(packet.Proto)<<16 | uint64(packet.SrcPort)
		if data, ok := portPolicyMap.Get(portKey); ok {
			return data.(*FastPathMapValue)
		}
		portKey = dstEpc<<44 | srcEpc<<24 | uint64(packet.Proto)<<16 | uint64(packet.DstPort)
		if data, ok := portPolicyMap.Get(portKey); ok {
			return data.(*FastPathMapValue)
		}
	}
	return nil
}

func (l *PolicyLabel) getFastVlanPolicy(packet *LookupKey) *FastPathMapValue {
	srcEpc := l.MacEpcMaps[packet.SrcMac]
	dstEpc := l.MacEpcMaps[packet.DstMac]
	if srcEpc == 0 && dstEpc == 0 {
		return nil
	}

	key := uint64(packet.Vlan) | uint64(srcEpc)<<32 | uint64(dstEpc)<<12
	if data, ok := l.FastVlanPolicyMap.Get(key); ok {
		return data.(*FastPathMapValue)
	}
	key = uint64(packet.Vlan) | uint64(dstEpc)<<32 | uint64(srcEpc)<<12
	if data, ok := l.FastVlanPolicyMap.Get(key); ok {
		return data.(*FastPathMapValue)
	}
	return nil
}

// FIXME：会改变packet参数，实际使用可能需要备份一下
func (l *PolicyLabel) GetPolicyByFastPath(packet *LookupKey) (*EndpointData, *PolicyData) {
	policy := &PolicyData{}
	policy.AclActions = make([]*AclAction, 0, 8)
	var endpoint *EndpointData
	if packet.Vlan > 0 {
		vlan := l.getFastVlanPolicy(packet)
		if vlan != nil && vlan.policy.ActionList > 0 {
			policy.Merge(vlan.policy.AclActions)
			endpoint = vlan.endpoint
		}
	}
	port := l.getFastPortPolicy(packet)
	if port != nil && port.policy.ActionList > 0 {
		policy.Merge(port.policy.AclActions)
		endpoint = port.endpoint
	}
	return endpoint, policy
}
