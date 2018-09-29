package policy

import (
	"math"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/golang/groupcache/lru"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

const (
	POLICY_TIMEOUT = 1 * time.Minute

	FAST_PATH_POLICY_LIMIT = 1024
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
	endpoint  *EndpointData
	policy    *PolicyData
	timestamp time.Duration
}

type VlanAndPortMap struct {
	vlanPolicyMap *lru.Cache
	portPolicyMap *lru.Cache
}

type PolicyLabel struct {
	RawAcls []*Acl

	InterestProtoMaps [TAP_MAX]map[uint8]bool
	InterestPortMaps  [TAP_MAX]map[uint16]bool
	InterestGroupMaps [TAP_MAX]map[uint32]bool

	MacEpcMaps     []map[uint64]uint32
	IpNetmaskMap   map[uint32]uint32
	FastPolicyMaps []*lru.Cache

	mapSize             uint32
	GroupPortPolicyMaps [TAP_MAX]map[uint64]*PolicyData
	GroupVlanPolicyMaps [TAP_MAX]map[uint64]*PolicyData

	FirstPathHit, FastPathHit         uint64
	FirstPathHitTick, FastPathHitTick uint64
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

	policy.IpNetmaskMap = make(map[uint32]uint32)

	policy.mapSize = mapSize
	for i := 0; i < queueCount; i++ {
		policy.FastPolicyMaps = append(policy.FastPolicyMaps, lru.New(int(mapSize)))

		macEpcMap := make(map[uint64]uint32)
		policy.MacEpcMaps = append(policy.MacEpcMaps, macEpcMap)
	}
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
	hasZero := false
	// 添加groupid 0匹配全采集的策略
	for _, id := range endpointData.SrcInfo.GroupIds {
		if groupMap[id] {
			packet.SrcGroupIds = append(packet.SrcGroupIds, id)
			if id == 0 {
				hasZero = true
			}
		}
	}
	if !hasZero {
		// 添加groupid 0匹配全采集的策略
		packet.SrcGroupIds = append(packet.SrcGroupIds, 0)
	}

	hasZero = false
	for _, id := range endpointData.DstInfo.GroupIds {
		if groupMap[id] {
			packet.DstGroupIds = append(packet.DstGroupIds, id)
			if id == 0 {
				hasZero = true
			}
		}
	}
	if !hasZero {
		// 添加groupid 0匹配全采集的策略
		packet.DstGroupIds = append(packet.DstGroupIds, 0)
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
	// port key:
	//  64         56            40           20            0
	//  +---------------------------------------------------+
	//  |   proto   |   port     |     id0/1   |    id0/1   |
	//  +---------------------------------------------------+
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
			key &= 0xffffff0000000000
		}
	}
	return keys
}

func generateSearchPortKeys(srcGroups []uint32, dstGroups []uint32, port uint16, proto uint8) []uint64 {
	keys := generateGroupPortKeys(srcGroups, dstGroups, port, proto)
	if port != 0 {
		// 匹配port全采集的acl
		keys = append(keys, generateGroupPortKeys(srcGroups, dstGroups, 0, proto)...)
	}
	if proto != 0 {
		// 匹配proto全采集的acl
		keys = append(keys, generateGroupPortKeys(srcGroups, dstGroups, 0, 0)...)
	}
	if proto != 0 && port != 0 {
		keys = append(keys, generateGroupPortKeys(srcGroups, dstGroups, port, 0)...)
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
					policy.Merge(acl.Action)
					portMap[key] = policy
				} else {
					// 策略存在则将action合入到现有策略
					policy.Merge(acl.Action)
				}
			}
		}
	}
	l.GroupPortPolicyMaps = portMaps
}

func (l *PolicyLabel) makeIpNetmaskMap() map[uint32]uint32 {
	maskMap := make(map[uint32]uint32, 32767)

	for netIp, mask := range l.IpNetmaskMap {
		if maskMap[netIp] < mask {
			maskMap[netIp] = mask
		}
	}

	return maskMap
}

func (l *PolicyLabel) GenerateIpNetmaskMap(platforms []*PlatformData) {
	maskMap := l.makeIpNetmaskMap()

	for _, platform := range platforms {
		for _, network := range platform.Ips {
			netIp := network.Ip & network.Netmask
			mask := uint32(math.MaxUint32) << (32 - network.Netmask)
			if maskMap[netIp] < mask {
				maskMap[netIp] = mask
			}
		}
	}
	l.IpNetmaskMap = maskMap
}

func (l *PolicyLabel) GenerateIpNetmaskMapFromIpResource(datas []*IpGroupData) {
	maskMap := l.makeIpNetmaskMap()

	for _, data := range datas {
		// raw = "1.2.3.4/24"
		// mask = 0xffffff00
		// netip = "1.2.3"
		for _, raw := range data.Ips {
			parts := strings.Split(raw, "/")
			if len(parts) != 2 {
				continue
			}
			ip := net.ParseIP(parts[0])
			maskSize, err := strconv.Atoi(parts[1])
			if err != nil {
				continue
			}

			mask := uint32(math.MaxUint32) << uint32(32-maskSize)
			netIp := IpToUint32(ip) & mask
			if maskMap[netIp] < mask {
				maskMap[netIp] = mask
			}
		}
	}
	l.IpNetmaskMap = maskMap
}

func generateGroupVlanKeys(srcGroups []uint32, dstGroups []uint32, vlan uint16) []uint64 {
	// vlan key:
	//  64         48            40           20            0
	//  +---------------------------------------------------+
	//  |    vlan  |             |     id0/1   |    id0/1   |
	//  +---------------------------------------------------+
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
			key &= 0xffffff0000000000
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

func (l *PolicyLabel) UpdateAcls(acls []*Acl) {
	if !reflect.DeepEqual(acls, l.RawAcls) {
		l.RawAcls = acls

		generateAcls := make([]*Acl, 0, len(acls))
		for _, acl := range acls {
			if acl.Type == TAP_ANY {
				// 对于TAP_ANY策略，给其他每一个TAP类型都单独生成一个acl，来避免查找2次
				for i := TAP_ANY + 1; i < TAP_MAX; i++ {
					generateAcl := &Acl{}
					*generateAcl = *acl
					generateAcl.Type = i
					generateAcls = append(generateAcls, generateAcl)
				}
			} else {
				generateAcls = append(generateAcls, acl)
			}
		}
		l.GenerateGroupPortMaps(generateAcls)
		l.GenerateGroupVlanMaps(generateAcls)
		l.GenerateInterestMaps(generateAcls)

		for i := 0; i < len(l.FastPolicyMaps); i++ {
			l.FastPolicyMaps[i].Clear()
			l.FastPolicyMaps[i] = lru.New(int(l.mapSize))
		}
	}
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
	vlanFound := false
	portFound := false

	// 在vlan map中查找单方向的策略
	if packet.Vlan > 0 {
		keys := generateGroupVlanKeys(packet.SrcGroupIds, packet.DstGroupIds, packet.Vlan)
		for _, key := range keys {
			if policy := vlanGroup[key]; policy != nil {
				findPolicy.Merge(policy.AclActions)
				vlanFound = true
			}
		}
		// 无论是否差找到policy，都需要向fastPath下发，避免重复走firstPath
		l.addVlanFastPolicy(endpointData, packet, findPolicy)
	}

	// 在port map中查找策略, 创建正方向key
	keys := generateSearchPortKeys(packet.SrcGroupIds, packet.DstGroupIds, packet.DstPort, packet.Proto)
	for _, key := range keys {
		if policy := portGroup[key]; policy != nil {
			findPolicy.Merge(policy.AclActions, FORWARD)
			l.addPortFastPolicy(endpointData, packet, policy, FORWARD)
			portFound = true
		}
	}

	// 在port map中查找策略, 创建反方向key
	keys = generateSearchPortKeys(packet.DstGroupIds, packet.SrcGroupIds, packet.SrcPort, packet.Proto)
	for _, key := range keys {
		if policy := portGroup[key]; policy != nil {
			// first层面存储的都是正方向的key, 在这里重新设置方向
			findPolicy.Merge(policy.AclActions, BACKWARD)
			l.addPortFastPolicy(endpointData, packet, policy, BACKWARD)
			portFound = true
		}
	}

	if !portFound {
		// 无论是否差找到policy，都需要向fastPath下发，避免走firstPath
		l.addPortFastPolicy(endpointData, packet, findPolicy, FORWARD)
		l.addPortFastPolicy(endpointData, packet, findPolicy, BACKWARD)
		if !vlanFound {
			findPolicy = INVALID_POLICY_DATA
		}
	}
	atomic.AddUint64(&l.FirstPathHit, 1)
	atomic.AddUint64(&l.FirstPathHitTick, 1)
	return findPolicy
}

func (l *PolicyLabel) addEpcMap(index int, endpointInfo *EndpointInfo, mac uint64) uint32 {
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
		l.MacEpcMaps[index][mac] = id
	}
	return id
}

func (l *PolicyLabel) addVlanFastPolicy(endpointData *EndpointData, packet *LookupKey, policy *PolicyData) {
	forward := &PolicyData{}
	backward := &PolicyData{}

	maps := l.getVlanAndPortMap(packet, true)

	srcEpc := l.addEpcMap(packet.FastIndex, endpointData.SrcInfo, packet.SrcMac)
	dstEpc := l.addEpcMap(packet.FastIndex, endpointData.DstInfo, packet.DstMac)

	forward.Merge(policy.AclActions)
	key := uint64(packet.Vlan) | uint64(srcEpc)<<32 | uint64(dstEpc)<<12
	valueForward := &FastPathMapValue{endpoint: endpointData, policy: forward, timestamp: packet.Timestamp}
	maps.vlanPolicyMap.Add(key, valueForward)

	backward.MergeAndSwapDirection(policy.AclActions)
	key = uint64(packet.Vlan) | uint64(dstEpc)<<32 | uint64(srcEpc)<<12
	valueBackward := &FastPathMapValue{endpoint: endpointData, policy: backward, timestamp: packet.Timestamp}
	maps.vlanPolicyMap.Add(key, valueBackward)
}

func (l *PolicyLabel) addPortFastPolicy(endpointData *EndpointData, packet *LookupKey, policy *PolicyData, direction DirectionType) {
	forward := &PolicyData{}

	maps := l.getVlanAndPortMap(packet, true)

	srcEpc := l.addEpcMap(packet.FastIndex, endpointData.SrcInfo, packet.SrcMac)
	dstEpc := l.addEpcMap(packet.FastIndex, endpointData.DstInfo, packet.DstMac)

	port := packet.DstPort
	if direction == BACKWARD {
		srcEpc, dstEpc = dstEpc, srcEpc
		port = packet.SrcPort
	}

	// 用epcid + proto + port做为key,将policy插入到PortPolicyMap
	forward.Merge(policy.AclActions)
	key := uint64(srcEpc)<<44 | uint64(dstEpc)<<24 | uint64(packet.Proto)<<16 | uint64(port)
	value := &FastPathMapValue{endpoint: endpointData, policy: forward, timestamp: packet.Timestamp}
	maps.portPolicyMap.Add(key, value)
}

func (l *PolicyLabel) getFastInterestKeys(packet *LookupKey) {
	if packet.Proto == 6 || packet.Proto == 17 {
		if !l.InterestPortMaps[packet.Tap][packet.SrcPort] {
			packet.SrcPort = 0
		}
		if !l.InterestPortMaps[packet.Tap][packet.DstPort] {
			packet.DstPort = 0
		}
	}

	if packet.Proto != 0 {
		if !l.InterestProtoMaps[packet.Tap][packet.Proto] {
			packet.Proto = 0
		}
	}
}

func (l *PolicyLabel) getFastPortPolicy(portPolicyMap *lru.Cache, packet *LookupKey, policy *PolicyData) *EndpointData {
	srcEpc := uint64(l.MacEpcMaps[packet.FastIndex][packet.SrcMac])
	dstEpc := uint64(l.MacEpcMaps[packet.FastIndex][packet.DstMac])
	var endpoint *EndpointData
	var value *FastPathMapValue

	key := srcEpc<<44 | dstEpc<<24 | uint64(packet.Proto)<<16 | uint64(packet.DstPort)
	if data, ok := portPolicyMap.Get(key); ok {
		value = data.(*FastPathMapValue)
		if value.timestamp < packet.Timestamp && packet.Timestamp-value.timestamp > POLICY_TIMEOUT {
			portPolicyMap.Remove(key)
			goto backward
		}
		policy.Merge(value.policy.AclActions, FORWARD)
		endpoint = value.endpoint
	}

backward:
	if dstEpc != srcEpc || packet.SrcPort != packet.DstPort {
		key = dstEpc<<44 | srcEpc<<24 | uint64(packet.Proto)<<16 | uint64(packet.SrcPort)
		if data, ok := portPolicyMap.Get(key); ok {
			value = data.(*FastPathMapValue)
			if value.timestamp < packet.Timestamp && packet.Timestamp-value.timestamp > POLICY_TIMEOUT {
				portPolicyMap.Remove(key)
				return endpoint
			}
			policy.Merge(value.policy.AclActions, BACKWARD)
			endpoint = value.endpoint
		}
	}
	return endpoint
}

func (l *PolicyLabel) getFastVlanPolicy(vlanPolicyMap *lru.Cache, packet *LookupKey) *FastPathMapValue {
	srcEpc := uint64(l.MacEpcMaps[packet.FastIndex][packet.SrcMac])
	dstEpc := uint64(l.MacEpcMaps[packet.FastIndex][packet.DstMac])

	var value *FastPathMapValue
	key := uint64(packet.Vlan) | uint64(srcEpc)<<32 | uint64(dstEpc)<<12
	if data, ok := vlanPolicyMap.Get(key); ok {
		value = data.(*FastPathMapValue)
		goto found
	}
	return nil
found:
	if value.timestamp < packet.Timestamp && packet.Timestamp-value.timestamp > POLICY_TIMEOUT {
		vlanPolicyMap.Remove(key)
		return nil
	}
	value.timestamp = packet.Timestamp
	return value
}

func (l *PolicyLabel) getVlanAndPortMap(packet *LookupKey, create bool) *VlanAndPortMap {
	maskedSrcIp := l.IpNetmaskMap[packet.SrcIp] & packet.SrcIp
	maskedDstIp := l.IpNetmaskMap[packet.DstIp] & packet.DstIp
	key := uint64(maskedDstIp)<<32 | uint64(maskedSrcIp)
	if data, ok := l.FastPolicyMaps[packet.FastIndex].Get(key); ok {
		return data.(*VlanAndPortMap)
	}
	if create {
		value := &VlanAndPortMap{lru.New(FAST_PATH_POLICY_LIMIT), lru.New(FAST_PATH_POLICY_LIMIT)}
		l.FastPolicyMaps[packet.FastIndex].Add(key, value)
		return value
	}
	return nil
}

// FIXME：会改变packet参数，实际使用可能需要备份一下
func (l *PolicyLabel) GetPolicyByFastPath(packet *LookupKey) (*EndpointData, *PolicyData) {
	policy := &PolicyData{}
	var endpoint *EndpointData
	found := false

	l.getFastInterestKeys(packet)
	if maps := l.getVlanAndPortMap(packet, false); maps != nil {
		if packet.Vlan > 0 {
			if vlan := l.getFastVlanPolicy(maps.vlanPolicyMap, packet); vlan != nil {
				policy.Merge(vlan.policy.AclActions)
				endpoint = vlan.endpoint
				found = true
			}
		}
		endpoint = l.getFastPortPolicy(maps.portPolicyMap, packet, policy)
		if endpoint != nil {
			found = true
		}
		if !found {
			goto unfound
		}
		atomic.AddUint64(&l.FastPathHit, 1)
		atomic.AddUint64(&l.FastPathHitTick, 1)
		return endpoint, policy
	}
unfound:
	return nil, INVALID_POLICY_DATA
}
