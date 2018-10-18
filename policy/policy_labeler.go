package policy

import (
	"fmt"
	"math"
	"net"
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

	FAST_PATH_POLICY_MAP_SIZE_LIMIT = 1024
	FAST_PATH_EPC_MAP_SIZE_LIMIT    = 128

	STANDARD_NETMASK = 0xffff0000

	ANY_GROUP = 0
	ANY_PROTO = 0
	ANY_PORT  = 0
)

type Acl struct {
	Id        ACLID
	Type      TapType
	TapId     uint32
	SrcGroups []uint32
	DstGroups []uint32
	DstPorts  []uint16
	Proto     uint8
	Vlan      uint32
	Action    []AclAction
}

type FastKey struct {
	SrcHash   uint64
	DstHash   uint64
	Ports     uint64
	ProtoVlan uint64
}

type FastPathMapValue struct {
	endpoint  EndpointData
	policy    *PolicyData
	timestamp time.Duration
}

type VlanAndPortMap struct {
	macEpcMap     *lru.Cache
	vlanPolicyMap *lru.Cache
	portPolicyMap *lru.Cache
}

type PolicyLabeler struct {
	RawAcls []*Acl

	InterestProtoMaps [TAP_MAX]map[uint8]bool
	InterestPortMaps  [TAP_MAX]map[uint16]bool
	InterestGroupMaps [TAP_MAX]map[uint32]bool

	IpNetmaskMap    map[uint32]uint32 // 根据IP地址查找对应的最大掩码
	FastPolicyMaps  [][]*lru.Cache    // 快速路径上的Policy映射表，Key为IP掩码对，Value为VlanAndPortMap
	FastPathDisable bool              // 是否关闭快速路径，只使用慢速路径（FirstPath）

	MapSize             uint32
	GroupPortPolicyMaps [TAP_MAX]map[uint64]*PolicyData // 慢速路径上资源组+协议+端口到Policy的映射表
	GroupVlanPolicyMaps [TAP_MAX]map[uint64]*PolicyData // 慢速路径上资源组+Vlan到Policy的映射表

	FirstPathHit, FastPathHit         uint64
	FirstPathHitTick, FastPathHitTick uint64
	AclHitMax                         uint64

	maskMapFromPlatformData map[uint32]uint32
	maskMapFromIpGroupData  map[uint32]uint32
}

func (a *Acl) String() string {
	if len(a.DstPorts) == 2 {
		return fmt.Sprintf("Id:%v Type:%v TapId:%v SrcGroups:%v DstGroups:%v DstPorts:%v-%v Proto:%v Vlan:%v Action:%v",
			a.Id, a.Type, a.TapId, a.SrcGroups, a.DstGroups, a.DstPorts[0], a.DstPorts[1], a.Proto, a.Vlan, a.Action)
	} else {
		return fmt.Sprintf("Id:%v Type:%v TapId:%v SrcGroups:%v DstGroups:%v DstPorts:%v Proto:%v Vlan:%v Action:%v",
			a.Id, a.Type, a.TapId, a.SrcGroups, a.DstGroups, a.DstPorts[0], a.Proto, a.Vlan, a.Action)
	}
}

func NewPolicyLabeler(queueCount int, mapSize uint32, fastPathDisable bool) *PolicyLabeler {
	policy := &PolicyLabeler{}

	for i := TAP_MIN; i < TAP_MAX; i++ {
		policy.InterestProtoMaps[i] = make(map[uint8]bool)
		policy.InterestPortMaps[i] = make(map[uint16]bool)
		policy.InterestGroupMaps[i] = make(map[uint32]bool)

		policy.GroupVlanPolicyMaps[i] = make(map[uint64]*PolicyData)
		policy.GroupPortPolicyMaps[i] = make(map[uint64]*PolicyData)
	}

	policy.IpNetmaskMap = make(map[uint32]uint32)
	policy.maskMapFromPlatformData = make(map[uint32]uint32, 1<<16)
	policy.maskMapFromIpGroupData = make(map[uint32]uint32, 1<<16)

	policy.MapSize = mapSize
	policy.FastPathDisable = fastPathDisable
	policy.FastPolicyMaps = make([][]*lru.Cache, queueCount)
	for i := 0; i < queueCount; i++ {
		policy.FastPolicyMaps[i] = make([]*lru.Cache, TAP_MAX)
		for j := TAP_MIN; j < TAP_MAX; j++ {
			policy.FastPolicyMaps[i][j] = lru.New(int(mapSize))
		}
	}
	return policy
}

func (l *PolicyLabeler) generateInterestKeys(endpointData *EndpointData, packet *LookupKey) {
	groupMap := l.InterestGroupMaps[packet.Tap]
	hasAnyGroup := false
	// 添加groupid 0匹配全采集的策略
	for _, id := range endpointData.SrcInfo.GroupIds {
		id = FormatGroupId(id)
		if groupMap[id] {
			packet.SrcGroupIds = append(packet.SrcGroupIds, id)
			if id == ANY_GROUP {
				hasAnyGroup = true
			}
		}
	}
	if !hasAnyGroup {
		// 添加groupid 0匹配全采集的策略
		packet.SrcGroupIds = append(packet.SrcGroupIds, ANY_GROUP)
	}

	hasAnyGroup = false
	for _, id := range endpointData.DstInfo.GroupIds {
		id = FormatGroupId(id)
		if groupMap[id] {
			packet.DstGroupIds = append(packet.DstGroupIds, id)
			if id == ANY_GROUP {
				hasAnyGroup = true
			}
		}
	}
	if !hasAnyGroup {
		// 添加groupid 0匹配全采集的策略
		packet.DstGroupIds = append(packet.DstGroupIds, ANY_GROUP)
	}

	l.getFastInterestKeys(packet)
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
		srcGroups = append(srcGroups, ANY_GROUP)
	}

	if len(dstGroups) == 0 {
		dstGroups = append(dstGroups, ANY_GROUP)
	}

	for _, src := range srcGroups {
		srcId := uint64(FormatGroupId(src) & 0xfffff)
		for _, dst := range dstGroups {
			dstId := uint64(FormatGroupId(dst) & 0xfffff)
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
		keys = append(keys, generateGroupPortKeys(srcGroups, dstGroups, ANY_PORT, proto)...)
	}
	if proto != 0 {
		// 匹配proto全采集的acl
		keys = append(keys, generateGroupPortKeys(srcGroups, dstGroups, ANY_PORT, ANY_PROTO)...)
	}
	if proto != 0 && port != 0 {
		keys = append(keys, generateGroupPortKeys(srcGroups, dstGroups, port, ANY_PROTO)...)
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

	// 策略配置端口全采集，则生成port为0的一条map
	if len(acl.DstPorts) >= 0xffff || len(acl.DstPorts) == 0 {
		keys = generateGroupPortKeys(src, dst, ANY_PORT, acl.Proto)
	} else {
		// FIXME: 当很多条策略都配置了很多port,内存占用可能会很大
		for _, port := range acl.DstPorts {
			keys = append(keys, generateGroupPortKeys(src, dst, port, acl.Proto)...)
		}
	}
	return keys
}

func (l *PolicyLabeler) GenerateGroupPortMaps(acls []*Acl) {
	portMaps := [TAP_MAX]map[uint64]*PolicyData{}
	for i := TAP_MIN; i < TAP_MAX; i++ {
		portMaps[i] = make(map[uint64]*PolicyData)
	}

	for _, acl := range acls {
		if acl.Type.CheckTapType(acl.Type) && acl.Vlan == 0 {
			portMap := portMaps[acl.Type]

			keys := generateGroupPortsKeys(acl, FORWARD)
			for _, key := range keys {
				if policy := portMap[key]; policy == nil {
					policy := NewPolicyData()
					policy.Merge(acl.Action, acl.Id)
					portMap[key] = policy
				} else {
					// 策略存在则将action合入到现有策略
					policy.Merge(acl.Action, acl.Id)
				}
			}
		}
	}
	l.GroupPortPolicyMaps = portMaps
}

func (l *PolicyLabeler) makeIpNetmaskMap() {
	maskMap := make(map[uint32]uint32, 1<<16)

	for netIp, mask := range l.maskMapFromPlatformData {
		if maskMap[netIp] < mask {
			maskMap[netIp] = mask
		}
	}
	for netIp, mask := range l.maskMapFromIpGroupData {
		if maskMap[netIp] < mask {
			maskMap[netIp] = mask
		}
	}

	l.IpNetmaskMap = maskMap
}

func (l *PolicyLabeler) GenerateIpNetmaskMapFromPlatformData(data []*PlatformData) {
	maskMap := l.maskMapFromPlatformData
	for key, _ := range maskMap {
		delete(maskMap, key)
	}

	for _, d := range data {
		for _, network := range d.Ips {
			minNetIp := network.Ip & STANDARD_NETMASK
			maxNetIp := minNetIp
			mask := uint32(math.MaxUint32) << (32 - network.Netmask)
			// netmask must be either 0 or STANDARD_NETMASK~math.MaxUint32
			if mask < STANDARD_NETMASK {
				minNetIp = network.Ip & mask
				maxNetIp = (minNetIp | ^mask) & STANDARD_NETMASK
				mask = STANDARD_NETMASK
			}
			for netIp := minNetIp; netIp <= maxNetIp && netIp >= minNetIp; netIp += 0x10000 {
				if maskMap[netIp] < mask {
					maskMap[netIp] = mask
				}
			}
		}
	}

	l.makeIpNetmaskMap()
}

func (l *PolicyLabeler) GenerateIpNetmaskMapFromIpGroupData(data []*IpGroupData) {
	maskMap := l.maskMapFromIpGroupData
	for key, _ := range maskMap {
		delete(maskMap, key)
	}

	for _, d := range data {
		// raw = "1.2.3.4/24"
		// mask = 0xffffff00
		// netip = "1.2.3"
		for _, raw := range d.Ips {
			parts := strings.Split(raw, "/")
			if len(parts) != 2 {
				continue
			}
			ip := net.ParseIP(parts[0])
			maskSize, err := strconv.Atoi(parts[1])
			if err != nil {
				continue
			}

			minNetIp := IpToUint32(ip) & STANDARD_NETMASK
			maxNetIp := minNetIp
			mask := uint32(math.MaxUint32) << uint32(32-maskSize)
			// netmask must be either 0 or STANDARD_NETMASK~math.MaxUint32
			if mask < STANDARD_NETMASK {
				minNetIp = IpToUint32(ip) & mask
				maxNetIp = (minNetIp | ^mask) & STANDARD_NETMASK
				mask = STANDARD_NETMASK
			}
			for netIp := minNetIp; netIp <= maxNetIp && netIp >= minNetIp; netIp += 0x10000 {
				if maskMap[netIp] < mask {
					maskMap[netIp] = mask
				}
			}
		}
	}

	l.makeIpNetmaskMap()
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
		srcGroups = append(srcGroups, ANY_GROUP)
	}

	if len(dstGroups) == 0 {
		dstGroups = append(dstGroups, ANY_GROUP)
	}

	for _, src := range srcGroups {
		srcId := uint64(FormatGroupId(src) & 0xfffff)
		for _, dst := range dstGroups {
			dstId := uint64(FormatGroupId(dst) & 0xfffff)
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

			keys := generateGroupVlanKeys(acl.SrcGroups, acl.DstGroups, uint16(acl.Vlan))
			for _, key := range keys {
				if policy := vlanMap[key]; policy == nil {
					policy := NewPolicyData()
					policy.Merge(acl.Action, acl.Id, FORWARD)
					vlanMap[key] = policy
				} else {
					policy.Merge(acl.Action, acl.Id, FORWARD)
				}
			}

			keys = generateGroupVlanKeys(acl.DstGroups, acl.SrcGroups, uint16(acl.Vlan))
			for _, key := range keys {
				if policy := vlanMap[key]; policy == nil {
					policy := NewPolicyData()
					policy.Merge(acl.Action, acl.Id, BACKWARD)
					vlanMap[key] = policy
				} else {
					policy.Merge(acl.Action, acl.Id, BACKWARD)
				}
			}
		}
	}
	l.GroupVlanPolicyMaps = vlanMaps
}

func (l *PolicyLabeler) GenerateInterestMaps(acls []*Acl) {
	interestProtoMaps := [TAP_MAX]map[uint8]bool{}
	interestPortMaps := [TAP_MAX]map[uint16]bool{}
	interestGroupMaps := [TAP_MAX]map[uint32]bool{}
	for i := TAP_MIN; i < TAP_MAX; i++ {
		interestProtoMaps[i] = make(map[uint8]bool)
		interestPortMaps[i] = make(map[uint16]bool)
		interestGroupMaps[i] = make(map[uint32]bool)
	}
	// 将策略中存在的proto、port、group id存在map中
	for _, acl := range acls {
		if acl.Type.CheckTapType(acl.Type) {
			interestProtoMaps[acl.Type][acl.Proto] = true

			portMap := interestPortMaps[acl.Type]
			if len(acl.DstPorts) < 0xffff {
				for _, port := range acl.DstPorts {
					portMap[port] = true
				}
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

func (l *PolicyLabeler) UpdateAcls(acls []*Acl) {
	l.RawAcls = acls

	generateAcls := make([]*Acl, 0, len(acls))
	for _, acl := range acls {
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
	l.GenerateGroupPortMaps(generateAcls)
	l.GenerateGroupVlanMaps(generateAcls)
	l.GenerateInterestMaps(generateAcls)
}

func (l *PolicyLabeler) FlushAcls() {
	for i := 0; i < len(l.FastPolicyMaps); i++ {
		for j := TAP_MIN; j < TAP_MAX; j++ {
			l.FastPolicyMaps[i][j].Clear()
			l.FastPolicyMaps[i][j] = lru.New(int(l.MapSize))
		}
	}
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

func (l *PolicyLabeler) GetPolicyByFirstPath(endpointData *EndpointData, packet *LookupKey) *PolicyData {
	l.generateInterestKeys(endpointData, packet)
	portGroup := l.GroupPortPolicyMaps[packet.Tap]
	vlanGroup := l.GroupVlanPolicyMaps[packet.Tap]
	// 对于内容全为0的findPolicy，统一采用INVALID_POLICY_DATA（同一块内存的数值）
	portForwardPolicy, portBackwardPolicy, vlanPolicy, findPolicy := INVALID_POLICY_DATA, INVALID_POLICY_DATA, INVALID_POLICY_DATA, INVALID_POLICY_DATA

	// 在port map中查找策略, 创建正方向key
	keys := generateSearchPortKeys(packet.SrcGroupIds, packet.DstGroupIds, packet.DstPort, packet.Proto)
	for _, key := range keys {
		if policy := portGroup[key]; policy != nil && len(policy.AclActions) > 0 {
			if portForwardPolicy == INVALID_POLICY_DATA {
				portForwardPolicy = NewPolicyData()
				portForwardPolicy.AclActions = make([]AclAction, 0, 4)
			}
			portForwardPolicy.Merge(policy.AclActions, policy.ACLID, FORWARD)
		}
	}
	// 无论是否差找到policy，都需要向fastPath下发，避免重复走firstPath
	mapsForward := l.addPortFastPolicy(endpointData, packet, portForwardPolicy, FORWARD, nil)

	// 在port map中查找策略, 创建反方向key
	keys = generateSearchPortKeys(packet.DstGroupIds, packet.SrcGroupIds, packet.SrcPort, packet.Proto)
	for _, key := range keys {
		if policy := portGroup[key]; policy != nil && len(policy.AclActions) > 0 {
			if portBackwardPolicy == INVALID_POLICY_DATA {
				portBackwardPolicy = NewPolicyData()
				portBackwardPolicy.AclActions = make([]AclAction, 0, 4)
			}
			// first层面存储的都是正方向的key, 在这里重新设置方向
			portBackwardPolicy.Merge(policy.AclActions, policy.ACLID, BACKWARD)
		}
	}
	// 无论是否差找到policy，都需要向fastPath下发，避免重复走firstPath
	mapsBackward := l.addPortFastPolicy(endpointData, packet, portBackwardPolicy, BACKWARD, mapsForward)

	// 在vlan map中查找单方向的策略
	if packet.Vlan > 0 {
		keys := generateGroupVlanKeys(packet.SrcGroupIds, packet.DstGroupIds, packet.Vlan)
		for _, key := range keys {
			if policy := vlanGroup[key]; policy != nil && len(policy.AclActions) > 0 {
				if vlanPolicy == INVALID_POLICY_DATA {
					vlanPolicy = NewPolicyData()
					vlanPolicy.AclActions = make([]AclAction, 0, 4)
				}
				vlanPolicy.Merge(policy.AclActions, policy.ACLID)
			}
		}
		// 无论是否差找到policy，都需要向fastPath下发，避免重复走firstPath
		l.addVlanFastPolicy(endpointData, packet, vlanPolicy, mapsForward, mapsBackward)
	}

	len := len(portForwardPolicy.AclActions) + len(portBackwardPolicy.AclActions) + len(vlanPolicy.AclActions)
	if len > 0 {
		findPolicy = NewPolicyData()
		findPolicy.AclActions = make([]AclAction, 0, len)
		findPolicy.Merge(vlanPolicy.AclActions, vlanPolicy.ACLID)
		findPolicy.Merge(portForwardPolicy.AclActions, portForwardPolicy.ACLID, FORWARD)
		findPolicy.Merge(portBackwardPolicy.AclActions, portBackwardPolicy.ACLID, BACKWARD)
	}

	atomic.AddUint64(&l.FirstPathHit, 1)
	atomic.AddUint64(&l.FirstPathHitTick, 1)
	aclHitMax := atomic.LoadUint64(&l.AclHitMax)
	if aclHit := uint64(len); aclHitMax < aclHit {
		atomic.CompareAndSwapUint64(&l.AclHitMax, aclHitMax, aclHit)
	}
	return findPolicy
}

func (l *PolicyLabeler) calcEpc(endpointInfo *EndpointInfo) uint32 {
	id := uint32(0)
	if endpointInfo.L2EpcId > 0 {
		id = uint32(endpointInfo.L2EpcId)
	} else if endpointInfo.L2EpcId == -1 {
		id = math.MaxUint32
	} else if endpointInfo.L2EpcId == 0 {
		if endpointInfo.L3EpcId > 0 {
			id = uint32(endpointInfo.L3EpcId)
		} else if endpointInfo.L3EpcId == -1 {
			id = math.MaxUint32
		}
	}
	return id
}

func (l *PolicyLabeler) addEpcMap(maps *VlanAndPortMap, endpoint *EndpointData, packet *LookupKey, direction DirectionType) (uint32, uint32) {
	ids, offset := uint64(0), uint64(0)
	var macs uint64
	var endpointInfos []*EndpointInfo
	if direction == FORWARD {
		macs = (packet.SrcMac << 32) | (packet.DstMac & math.MaxUint32)
		endpointInfos = []*EndpointInfo{endpoint.DstInfo, endpoint.SrcInfo}
	} else {
		macs = (packet.DstMac << 32) | (packet.SrcMac & math.MaxUint32)
		endpointInfos = []*EndpointInfo{endpoint.SrcInfo, endpoint.DstInfo}
	}
	for _, endpointInfo := range endpointInfos {
		id := uint64(l.calcEpc(endpointInfo))
		ids |= (id << offset)
		offset += 32
	}
	if ids != 0 {
		// 仅仅使用具有区分性的mac的后32bit
		maps.macEpcMap.Add(macs, ids)
		return uint32(ids >> 32), uint32(ids & math.MaxUint32)
	}
	return 0, 0
}

func (l *PolicyLabeler) addVlanFastPolicy(endpointData *EndpointData, packet *LookupKey, policy *PolicyData, mapsForward *VlanAndPortMap, mapsBackward *VlanAndPortMap) {
	forward, backward := INVALID_POLICY_DATA, INVALID_POLICY_DATA
	if len(policy.AclActions) > 0 {
		forward = policy
		backward = NewPolicyData()
		backward.AclActions = make([]AclAction, 0, len(policy.AclActions))
		backward.MergeAndSwapDirection(policy.AclActions, policy.ACLID)
	}
	srcEpc := l.calcEpc(endpointData.SrcInfo)
	dstEpc := l.calcEpc(endpointData.DstInfo)

	key := uint64(packet.Vlan) | uint64(srcEpc)<<32 | uint64(dstEpc)<<12
	valueForward := &FastPathMapValue{endpoint: *endpointData, policy: forward, timestamp: packet.Timestamp}
	mapsForward.vlanPolicyMap.Add(key, valueForward)

	key = uint64(packet.Vlan) | uint64(dstEpc)<<32 | uint64(srcEpc)<<12
	valueBackward := &FastPathMapValue{endpoint: *endpointData, policy: backward, timestamp: packet.Timestamp}
	valueBackward.endpoint.SrcInfo, valueBackward.endpoint.DstInfo = valueBackward.endpoint.DstInfo, valueBackward.endpoint.SrcInfo
	mapsBackward.vlanPolicyMap.Add(key, valueBackward)
}

func (l *PolicyLabeler) addPortFastPolicy(endpointData *EndpointData, packet *LookupKey, policy *PolicyData, direction DirectionType, mapsForward *VlanAndPortMap) *VlanAndPortMap {
	forward := INVALID_POLICY_DATA
	if len(policy.AclActions) > 0 {
		forward = policy
	}
	maps := l.getVlanAndPortMap(packet, direction, true, mapsForward)
	srcEpc, dstEpc := l.addEpcMap(maps, endpointData, packet, direction)
	port := packet.DstPort
	if direction == BACKWARD {
		port = packet.SrcPort
	}

	// 用epcid + proto + port做为key,将policy插入到portPolicyMap
	key := uint64(srcEpc)<<44 | uint64(dstEpc)<<24 | uint64(packet.Proto)<<16 | uint64(port)
	value := &FastPathMapValue{endpoint: *endpointData, policy: forward, timestamp: packet.Timestamp}
	if direction == BACKWARD {
		value.endpoint.SrcInfo, value.endpoint.DstInfo = value.endpoint.DstInfo, value.endpoint.SrcInfo
	}
	maps.portPolicyMap.Add(key, value)

	return maps
}

func (l *PolicyLabeler) getFastInterestKeys(packet *LookupKey) {
	if !l.InterestPortMaps[packet.Tap][packet.SrcPort] {
		packet.SrcPort = ANY_PORT
	}
	if !l.InterestPortMaps[packet.Tap][packet.DstPort] {
		packet.DstPort = ANY_PORT
	}
	if !l.InterestProtoMaps[packet.Tap][packet.Proto] {
		packet.Proto = ANY_PROTO
	}
}

func (l *PolicyLabeler) getFastEpcs(maps *VlanAndPortMap, packet *LookupKey, direction DirectionType) (uint32, uint32) {
	var macs uint64
	if direction == FORWARD {
		macs = (packet.SrcMac << 32) | (packet.DstMac & math.MaxUint32)
	} else {
		macs = (packet.DstMac << 32) | (packet.SrcMac & math.MaxUint32)
	}
	if data, ok := maps.macEpcMap.Get(macs); ok {
		epcs := data.(uint64)
		return uint32(epcs >> 32), uint32(epcs & math.MaxUint32)
	}
	return 0, 0
}

func (l *PolicyLabeler) getFastVlanPolicy(maps *VlanAndPortMap, srcEpc, dstEpc uint32, packet *LookupKey, policy *PolicyData) *EndpointData {
	key := uint64(packet.Vlan) | uint64(srcEpc)<<32 | uint64(dstEpc)<<12
	vlanPolicyMap := maps.vlanPolicyMap
	if data, ok := vlanPolicyMap.Get(key); ok {
		value := data.(*FastPathMapValue)
		if value.timestamp < packet.Timestamp && packet.Timestamp-value.timestamp > POLICY_TIMEOUT {
			vlanPolicyMap.Remove(key)
			return nil
		}
		value.timestamp = packet.Timestamp
		// vlanMap存储的是有方向的policy，在这里不用更改
		policy.Merge(value.policy.AclActions, value.policy.ACLID)
		endpoint := value.endpoint
		return &endpoint
	}
	return nil
}

func (l *PolicyLabeler) getFastPortPolicy(maps *VlanAndPortMap, srcEpc, dstEpc uint32, packet *LookupKey, policy *PolicyData, direction DirectionType) *EndpointData {
	port := packet.DstPort
	if direction == BACKWARD {
		srcEpc, dstEpc = dstEpc, srcEpc
		port = packet.SrcPort
	}

	key := uint64(srcEpc)<<44 | uint64(dstEpc)<<24 | uint64(packet.Proto)<<16 | uint64(port)
	portPolicyMap := maps.portPolicyMap
	if data, ok := portPolicyMap.Get(key); ok {
		value := data.(*FastPathMapValue)
		if value.timestamp < packet.Timestamp && packet.Timestamp-value.timestamp > POLICY_TIMEOUT {
			portPolicyMap.Remove(key)
			return nil
		}
		value.timestamp = packet.Timestamp
		policy.Merge(value.policy.AclActions, value.policy.ACLID, direction)
		endpoint := value.endpoint
		if direction == BACKWARD {
			endpoint.SrcInfo, endpoint.DstInfo = endpoint.DstInfo, endpoint.SrcInfo
		}
		return &endpoint
	}
	return nil
}

func (l *PolicyLabeler) getVlanAndPortMap(packet *LookupKey, direction DirectionType, create bool, mapsForward *VlanAndPortMap) *VlanAndPortMap {
	maskSrc := l.IpNetmaskMap[packet.SrcIp&STANDARD_NETMASK]
	maskDst := l.IpNetmaskMap[packet.DstIp&STANDARD_NETMASK]
	maskedSrcIp := packet.SrcIp & maskSrc
	maskedDstIp := packet.DstIp & maskDst
	if direction == BACKWARD {
		if maskedSrcIp == maskedDstIp {
			return mapsForward
		}
		maskedSrcIp, maskedDstIp = maskedDstIp, maskedSrcIp
	}
	key := uint64(maskedSrcIp)<<32 | uint64(maskedDstIp)
	if data, ok := l.FastPolicyMaps[packet.FastIndex][packet.Tap].Get(key); ok {
		return data.(*VlanAndPortMap)
	}
	if create {
		value := &VlanAndPortMap{lru.New(FAST_PATH_EPC_MAP_SIZE_LIMIT), lru.New(FAST_PATH_POLICY_MAP_SIZE_LIMIT), lru.New(FAST_PATH_POLICY_MAP_SIZE_LIMIT)}
		l.FastPolicyMaps[packet.FastIndex][packet.Tap].Add(key, value)
		return value
	}
	return nil
}

func (l *PolicyLabeler) GetPolicyByFastPath(packet *LookupKey) (*EndpointData, *PolicyData) {
	if l.FastPathDisable {
		return nil, nil
	}

	var maps *VlanAndPortMap
	var policy *PolicyData
	var endpoint *EndpointData
	var srcEpc, dstEpc uint32
	var vlanFound, portFound bool

	for _, direction := range []DirectionType{FORWARD, BACKWARD} {
		portFound = false
		if packet.Vlan > 0 && direction == FORWARD {
			vlanFound = false
		} else {
			vlanFound = true
		}
		if maps = l.getVlanAndPortMap(packet, direction, false, maps); maps != nil {
			if policy == nil {
				srcEpc, dstEpc = l.getFastEpcs(maps, packet, direction)
				// NOTE：会改变packet参数，但firstPath同样需要getFastInterestKeys，所以无影响
				l.getFastInterestKeys(packet)
				policy = NewPolicyData()
				policy.AclActions = make([]AclAction, 0, 8)
			}
			// vlan不需要查找BACKWARD方向
			if !vlanFound {
				if endpoint = l.getFastVlanPolicy(maps, srcEpc, dstEpc, packet, policy); endpoint != nil {
					vlanFound = true
				}
			}
			if endpoint = l.getFastPortPolicy(maps, srcEpc, dstEpc, packet, policy, direction); endpoint != nil {
				portFound = true
			}
		}
		if !portFound || !vlanFound {
			return nil, nil
		}
	}
	if len(policy.AclActions) == 0 {
		// 对于内容全为0的policy，统一采用INVALID_POLICY_DATA（同一块内存的数值）
		policy = INVALID_POLICY_DATA
	}

	atomic.AddUint64(&l.FastPathHit, 1)
	atomic.AddUint64(&l.FastPathHitTick, 1)
	return endpoint, policy
}
