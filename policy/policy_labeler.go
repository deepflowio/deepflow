package policy

import (
	"fmt"
	"math"
	"sync/atomic"
	"time"

	"github.com/golang/groupcache/lru"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

const (
	FAST_PATH_SOFT_TIMEOUT = 30 * time.Minute

	ANY_GROUP = 0
	ANY_PROTO = 0
	ANY_PORT  = 0
)

const (
	ACL_PROTO_ALL = iota
	ACL_PROTO_TCP
	ACL_PROTO_UDP
	ACL_PROTO_MAX
	ACL_PROTO_MIN = ACL_PROTO_ALL + 1
)

type Acl struct {
	Id         ACLID
	Type       TapType
	TapId      uint32
	SrcGroups  []uint32
	DstGroups  []uint32
	SrcPorts   []uint16
	DstPorts   []uint16
	Proto      uint8
	Vlan       uint32
	Action     []AclAction
	NpbActions []NpbAction
}

type PortPolicyValue struct {
	endpoint       EndpointData
	protoPolicyMap map[uint8]*PolicyData
	timestamp      time.Duration
}

type VlanAndPortMap struct {
	macEpcMap     map[uint64]uint32
	vlanPolicyMap map[uint64]*PolicyData
	portPolicyMap map[uint64]*PortPolicyValue
}

type PolicyLabeler struct {
	RawAcls     []*Acl
	aclProtoMap [math.MaxUint8 + 1]uint8

	groupIdMaps         map[uint32]int
	groupIdFromPlatform []uint32
	groupIdFromIpGroup  []uint32

	InterestProtoMaps [TAP_MAX]map[uint8]bool
	InterestPortMaps  [TAP_MAX]map[uint16]bool
	InterestGroupMaps [TAP_MAX]map[uint32]bool

	IpNetmaskMap       *[math.MaxUint16 + 1]uint32 // 根据IP地址查找对应的最大掩码
	FastPolicyMaps     [][]*lru.Cache              // 快速路径上的Policy映射表，Key为IP掩码对，Value为VlanAndPortMap
	FastPolicyMapsMini [][]*lru.Cache              // 同FastPolicyMaps，不过Key为32bit
	FastPathDisable    bool                        // 是否关闭快速路径，只使用慢速路径（FirstPath）

	MapSize             uint32
	GroupPortPolicyMaps [TAP_MAX][ACL_PROTO_MAX]map[uint64]*PolicyData // 慢速路径上资源组+协议+端口到Policy的映射表
	GroupVlanPolicyMaps [TAP_MAX]map[uint64]*PolicyData                // 慢速路径上资源组+Vlan到Policy的映射表

	FirstPathHit, FastPathHit         uint64
	FirstPathHitTick, FastPathHitTick uint64
	AclHitMax                         uint32

	maskMapFromPlatformData [math.MaxUint16 + 1]uint32
	maskMapFromIpGroupData  [math.MaxUint16 + 1]uint32
	cloudPlatformLabeler    *CloudPlatformLabeler
}

func (a *Acl) getPorts(rawPorts []uint16) string {
	// IN: rawPorts: 1,3,4,5,7,10,11,12,15,17
	// OUT: ports: "1,3-5,7,10-12,15,17"
	end := uint16(0)
	hasDash := false
	ports := ""
	for index, port := range rawPorts {
		if index == 0 {
			ports += fmt.Sprintf("%d", port)
			end = port
			continue
		}

		if port == end+1 {
			end = port
			hasDash = true
			if index == len(rawPorts)-1 {
				ports += fmt.Sprintf("-%d", port)
			}
		} else {
			if hasDash {
				ports += fmt.Sprintf("-%d", end)
				hasDash = false
			}
			ports += fmt.Sprintf(",%d", port)
			end = port
		}
	}
	return ports
}

func (a *Acl) String() string {
	return fmt.Sprintf("Id:%v Type:%v TapId:%v SrcGroups:%v DstGroups:%v SrcPorts:[%s] DstPorts:[%s] Proto:%v Vlan:%v Action:%v NpbActions:%s",
		a.Id, a.Type, a.TapId, a.SrcGroups, a.DstGroups, a.getPorts(a.SrcPorts), a.getPorts(a.DstPorts), a.Proto, a.Vlan, a.Action, a.NpbActions)
}

func NewPolicyLabeler(queueCount int, mapSize uint32, fastPathDisable bool) *PolicyLabeler {
	policy := &PolicyLabeler{}

	policy.aclProtoMap[6] = ACL_PROTO_TCP
	policy.aclProtoMap[17] = ACL_PROTO_UDP

	for i := TAP_MIN; i < TAP_MAX; i++ {
		policy.InterestProtoMaps[i] = make(map[uint8]bool)
		policy.InterestPortMaps[i] = make(map[uint16]bool)
		policy.InterestGroupMaps[i] = make(map[uint32]bool)

		policy.GroupVlanPolicyMaps[i] = make(map[uint64]*PolicyData)
		for j := 0; j < ACL_PROTO_MAX; j++ {
			policy.GroupPortPolicyMaps[i][j] = make(map[uint64]*PolicyData)
		}
	}

	policy.IpNetmaskMap = &[math.MaxUint16 + 1]uint32{0}

	policy.MapSize = mapSize
	policy.FastPathDisable = fastPathDisable
	policy.FastPolicyMaps = make([][]*lru.Cache, queueCount)
	policy.FastPolicyMapsMini = make([][]*lru.Cache, queueCount)
	for i := 0; i < queueCount; i++ {
		policy.FastPolicyMaps[i] = make([]*lru.Cache, TAP_MAX)
		policy.FastPolicyMapsMini[i] = make([]*lru.Cache, TAP_MAX)
		for j := TAP_MIN; j < TAP_MAX; j++ {
			policy.FastPolicyMaps[i][j] = lru.New((int(mapSize) >> 3) * 7)
			policy.FastPolicyMapsMini[i][j] = lru.New(int(mapSize) >> 3)
		}
	}
	return policy
}

func (l *PolicyLabeler) generateGroupIdMap() {
	groupIdMaps := make(map[uint32]int, len(l.groupIdFromPlatform)+len(l.groupIdFromIpGroup))

	for _, id := range l.groupIdFromPlatform {
		groupIdMaps[id] = RESOURCE_GROUP_TYPE_DEV
	}

	// 资源组ID一致的情况，设备资源组优先
	for _, id := range l.groupIdFromIpGroup {
		if groupIdMaps[id] != RESOURCE_GROUP_TYPE_DEV {
			groupIdMaps[id] = RESOURCE_GROUP_TYPE_IP
		}
	}
	l.groupIdMaps = groupIdMaps
}

func (l *PolicyLabeler) generateGroupIdMapByIpGroupData(datas []*IpGroupData) {
	l.groupIdFromIpGroup = make([]uint32, len(datas))
	for _, data := range datas {
		l.groupIdFromIpGroup = append(l.groupIdFromIpGroup, data.Id)
	}
	l.generateGroupIdMap()
}

func (l *PolicyLabeler) generateGroupIdMapByPlatformData(datas []*PlatformData) {
	l.groupIdFromPlatform = make([]uint32, 1024)
	for _, data := range datas {
		l.groupIdFromPlatform = append(l.groupIdFromPlatform, data.GroupIds...)
	}
	l.generateGroupIdMap()
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

func generateGroupPortKeys(srcGroups []uint32, dstGroups []uint32, srcPort uint16, dstPort uint16) []uint64 {
	// port key:
	//  64         48            32           16            0
	//  +---------------------------------------------------+
	//  |   sport   |   dport     |     id0/1   |    id0/1   |
	//  +---------------------------------------------------+
	keys := make([]uint64, 0, 10)
	key := uint64(srcPort)<<48 | uint64(dstPort)<<32

	if len(srcGroups) == 0 {
		srcGroups = append(srcGroups, ANY_GROUP)
	}

	if len(dstGroups) == 0 {
		dstGroups = append(dstGroups, ANY_GROUP)
	}

	for _, src := range srcGroups {
		srcId := uint64(FormatGroupId(src) & 0xffff)
		for _, dst := range dstGroups {
			dstId := uint64(FormatGroupId(dst) & 0xffff)
			key |= srcId<<16 | dstId
			keys = append(keys, key)
			key &= 0xffffffff00000000
		}
	}
	return keys
}

func generateSearchPortKeys(srcGroups []uint32, dstGroups []uint32, srcPort, dstPort uint16) []uint64 {
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
	keys := make([]uint64, 0, 10)

	srcGroups := acl.SrcGroups
	dstGroups := acl.DstGroups
	srcPorts := acl.SrcPorts
	dstPorts := acl.DstPorts
	if direction == BACKWARD {
		srcGroups, dstGroups = dstGroups, srcGroups
		srcPorts, dstPorts = dstPorts, srcPorts
	}

	// 策略配置端口全采集，则生成port为0的一条map
	if len(srcPorts) >= 0xffff || len(srcPorts) == 0 {
		srcPorts = append(srcPorts[:0], ANY_PORT)
	}
	if len(dstPorts) >= 0xffff || len(dstPorts) == 0 {
		dstPorts = append(dstPorts[:0], ANY_PORT)
	}

	for _, src := range srcPorts {
		for _, dst := range dstPorts {
			// FIXME: 当很多条策略都配置了很多port,内存占用可能会很大
			keys = append(keys, generateGroupPortKeys(srcGroups, dstGroups, src, dst)...)
		}
	}
	return keys
}

func (l *PolicyLabeler) getAclProto(proto uint8) uint8 {
	return l.aclProtoMap[proto]
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
			portMap := portMaps[acl.Type][l.getAclProto(acl.Proto)]

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
			for j := ACL_PROTO_MIN; j < ACL_PROTO_MAX; j++ {
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

func (l *PolicyLabeler) makeIpNetmaskMap() {
	maskMap := &[math.MaxUint16 + 1]uint32{0}

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
	maskMap := &l.maskMapFromPlatformData
	for key, _ := range maskMap {
		maskMap[key] = 0
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
			count := 0
			for netIp := minNetIp; netIp <= maxNetIp && netIp >= minNetIp; netIp += 0x10000 {
				if count > 0xffff {
					break
				}
				count++
				if maskMap[uint16(netIp>>16)] < mask {
					maskMap[uint16(netIp>>16)] = mask
				}
			}
		}
	}

	l.makeIpNetmaskMap()
}

func (l *PolicyLabeler) GenerateIpNetmaskMapFromIpGroupData(data []*IpGroupData) {
	maskMap := &l.maskMapFromIpGroupData
	for key, _ := range maskMap {
		maskMap[key] = 0
	}

	for _, d := range data {
		// raw = "1.2.3.4/24"
		// mask = 0xffffff00
		// netip = "1.2.3"
		for _, raw := range d.Ips {
			ip, maskSize, err := IpNetmaskFromStringCIDR(raw)
			if err != nil {
				log.Warning(err)
				continue
			}

			minNetIp := ip & STANDARD_NETMASK
			maxNetIp := minNetIp
			mask := uint32(math.MaxUint32) << uint32(32-maskSize)
			// netmask must be either 0 or STANDARD_NETMASK~math.MaxUint32
			if mask < STANDARD_NETMASK {
				minNetIp = ip & mask
				maxNetIp = (minNetIp | ^mask) & STANDARD_NETMASK
				mask = STANDARD_NETMASK
			}
			count := 0
			for netIp := minNetIp; netIp <= maxNetIp && netIp >= minNetIp; netIp += 0x10000 {
				if count > 0xffff {
					break
				}
				count++
				if maskMap[uint16(netIp>>16)] < mask {
					maskMap[uint16(netIp>>16)] = mask
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
					policy := new(PolicyData)
					policy.Merge(acl.Action, acl.NpbActions, acl.Id, FORWARD)
					vlanMap[key] = policy
				} else {
					policy.Merge(acl.Action, acl.NpbActions, acl.Id, FORWARD)
				}
			}

			keys = generateGroupVlanKeys(acl.DstGroups, acl.SrcGroups, uint16(acl.Vlan))
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

			if len(acl.SrcPorts) < 0xffff {
				for _, port := range acl.SrcPorts {
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
			for _, action := range acl.NpbActions {
				action.SetResourceGroupType(groupType)
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
	l.GenerateGroupPortMaps(generateAcls)
	l.GenerateGroupVlanMaps(generateAcls)
	l.GenerateInterestMaps(generateAcls)
}

func (l *PolicyLabeler) FlushAcls() {
	for i := 0; i < len(l.FastPolicyMaps); i++ {
		for j := TAP_MIN; j < TAP_MAX; j++ {
			l.FastPolicyMaps[i][j] = lru.New((int(l.MapSize) >> 3) * 7)
			l.FastPolicyMapsMini[i][j] = lru.New(int(l.MapSize) >> 3)
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

func (l *PolicyLabeler) checkNpbAction(endpointData *EndpointData, npbActions []NpbAction) []NpbAction {
	if len(npbActions) == 0 {
		return nil
	}

	validActions := make([]NpbAction, 0, len(npbActions))
	for _, action := range npbActions {
		if (action.TapSideCompare(TAPSIDE_SRC) == true && endpointData.SrcInfo.L2End == true) ||
			(action.TapSideCompare(TAPSIDE_DST) == true && endpointData.DstInfo.L2End == true) {
			if action.ResourceGroupTypeCompare(RESOURCE_GROUP_TYPE_DEV) {
				validActions = append(validActions, action)
			} else if (action.TapSideCompare(TAPSIDE_SRC) == true && endpointData.SrcInfo.L3End == true) ||
				(action.TapSideCompare(TAPSIDE_DST) == true && endpointData.DstInfo.L3End == true) {
				validActions = append(validActions, action)
			}
		}
	}
	return validActions
}

func (l *PolicyLabeler) checkNpbPolicy(endpointData *EndpointData, policy *PolicyData) *PolicyData {
	if policy == nil || len(policy.NpbActions) == 0 {
		return policy
	}

	validActions := l.checkNpbAction(endpointData, policy.NpbActions)
	if len(validActions) == 0 {
		if policy.ActionFlags == 0 {
			return INVALID_POLICY_DATA
		}
		policy.NpbActions = policy.NpbActions[:0]
		return policy
	}

	result := new(PolicyData)
	*result = *policy
	result.NpbActions = append(result.NpbActions[:0], validActions...)
	return result
}

func (l *PolicyLabeler) GetPolicyByFirstPath(endpointData *EndpointData, packet *LookupKey) (*EndpointData, *PolicyData) {
	l.generateInterestKeys(endpointData, packet)
	srcEpc := l.calcEpc(endpointData.SrcInfo)
	dstEpc := l.calcEpc(endpointData.DstInfo)
	portGroup := l.GroupPortPolicyMaps[packet.Tap][l.getAclProto(packet.Proto)]
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
	portBackwardPolicy.ReverseNpbActions()
	// 剔除匿名资源组ID
	if l.cloudPlatformLabeler != nil {
		l.cloudPlatformLabeler.RemoveAnonymousId(endpointData)
	}

	packetEndpointData := l.cloudPlatformLabeler.UpdateEndpointData(endpointData, packet)
	// 无论是否差找到policy，都需要向fastPath下发，避免重复走firstPath
	mapsForward, mapsBackward := l.addPortFastPolicy(endpointData, packetEndpointData, srcEpc, dstEpc, packet, portForwardPolicy, portBackwardPolicy)

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
		// 无论是否差找到policy，都需要向fastPath下发，避免重复走firstPath
		l.addVlanFastPolicy(srcEpc, dstEpc, packet, vlanPolicy, mapsForward, mapsBackward)
	}

	id := portForwardPolicy.ACLID + portBackwardPolicy.ACLID + vlanPolicy.ACLID
	if id > 0 {
		findPolicy = new(PolicyData)
		length := len(portForwardPolicy.AclActions) + len(portBackwardPolicy.AclActions) + len(vlanPolicy.AclActions)
		findPolicy.AclActions = make([]AclAction, 0, length)
		findPolicy.Merge(vlanPolicy.AclActions, vlanPolicy.NpbActions, vlanPolicy.ACLID)
		findPolicy.Merge(portForwardPolicy.AclActions, portForwardPolicy.NpbActions, portForwardPolicy.ACLID, FORWARD)
		findPolicy.Merge(portBackwardPolicy.AclActions, portBackwardPolicy.NpbActions, portBackwardPolicy.ACLID, BACKWARD)
	}

	atomic.AddUint64(&l.FirstPathHit, 1)
	atomic.AddUint64(&l.FirstPathHitTick, 1)
	aclHitMax := atomic.LoadUint32(&l.AclHitMax)
	if aclHit := uint32(len(findPolicy.AclActions) + len(findPolicy.NpbActions)); aclHitMax < aclHit {
		atomic.CompareAndSwapUint32(&l.AclHitMax, aclHitMax, aclHit)
	}
	return packetEndpointData, findPolicy
}

func (l *PolicyLabeler) calcEpc(endpointInfo *EndpointInfo) uint16 {
	id := uint16(0)
	if endpointInfo.L2EpcId > 0 {
		id = uint16(endpointInfo.L2EpcId)
	} else if endpointInfo.L2EpcId == -1 {
		// 和L3的EpcId == -1进行区分
		id = math.MaxUint16 - 1
	} else if endpointInfo.L2EpcId == 0 {
		if endpointInfo.L3EpcId > 0 {
			id = uint16(endpointInfo.L3EpcId)
		} else if endpointInfo.L3EpcId == -1 {
			id = math.MaxUint16
		}
	}
	return id
}

func (l *PolicyLabeler) addEpcMap(maps *VlanAndPortMap, srcEpc, dstEpc uint16, srcMac, dstMac uint64) {
	if srcEpc != 0 || dstEpc != 0 {
		// 仅仅使用具有区分性的mac的后32bit
		maps.macEpcMap[(srcMac<<32)|(dstMac&0xffffffff)] = uint32(srcEpc)<<16 | uint32(dstEpc)&0xffff
	}
}

func (l *PolicyLabeler) addVlanFastPolicy(srcEpc, dstEpc uint16, packet *LookupKey, policy *PolicyData, mapsForward, mapsBackward *VlanAndPortMap) {
	forward, backward := INVALID_POLICY_DATA, INVALID_POLICY_DATA

	if mapsForward == nil || mapsBackward == nil {
		return
	}

	if policy.ACLID > 0 {
		forward = policy
	}
	key := uint64(srcEpc)<<48 | uint64(dstEpc)<<32 | uint64(packet.Vlan)
	mapsForward.vlanPolicyMap[key] = forward

	if mapsBackward == mapsForward && srcEpc == dstEpc {
		return
	}
	if policy.ACLID > 0 {
		backward = new(PolicyData)
		backward.AclActions = make([]AclAction, 0, len(policy.AclActions))
		backward.MergeAndSwapDirection(policy.AclActions, policy.NpbActions, policy.ACLID)
	}
	key = uint64(dstEpc)<<48 | uint64(srcEpc)<<32 | uint64(packet.Vlan)
	mapsBackward.vlanPolicyMap[key] = backward
}

func (l *PolicyLabeler) addPortFastPolicy(endpointData *EndpointData, packetEndpointData *EndpointData, srcEpc, dstEpc uint16, packet *LookupKey, policyForward, policyBackward *PolicyData) (*VlanAndPortMap, *VlanAndPortMap) {
	forward, backward := INVALID_POLICY_DATA, INVALID_POLICY_DATA
	npbActions := make([]NpbAction, 0, len(policyBackward.NpbActions)+len(policyForward.NpbActions))
	npbActions = append(npbActions, policyForward.NpbActions...)
	npbActions = append(npbActions, policyBackward.NpbActions...)

	mapsForward := l.getVlanAndPortMap(packet, FORWARD, true, nil)
	if mapsForward == nil {
		return nil, nil
	}
	l.addEpcMap(mapsForward, srcEpc, dstEpc, packet.SrcMac, packet.DstMac)
	if id := policyForward.ACLID + policyBackward.ACLID; id > 0 {
		forward = new(PolicyData)
		forward.AclActions = make([]AclAction, 0, len(policyForward.AclActions)+len(policyBackward.AclActions))
		if len(npbActions) > 0 {
			npbActions = l.checkNpbAction(packetEndpointData, npbActions)
			if policyForward.ACLID > 0 {
				policyForward.NpbActions = append(policyForward.NpbActions[:0], npbActions...)
			}
			if policyBackward.ACLID > 0 {
				policyBackward.NpbActions = append(policyBackward.NpbActions[:0], npbActions...)
			}
		}
		forward.Merge(policyForward.AclActions, nil, policyForward.ACLID)
		forward.Merge(policyBackward.AclActions, npbActions, policyBackward.ACLID)
	}
	key := uint64(srcEpc)<<48 | uint64(dstEpc)<<32 | uint64(packet.SrcPort)<<16 | uint64(packet.DstPort)
	if portPolicyValue := mapsForward.portPolicyMap[key]; portPolicyValue == nil {
		value := &PortPolicyValue{endpoint: *endpointData, protoPolicyMap: make(map[uint8]*PolicyData), timestamp: packet.Timestamp}
		value.protoPolicyMap[packet.Proto] = forward
		mapsForward.portPolicyMap[key] = value
	} else {
		portPolicyValue.endpoint = *endpointData
		portPolicyValue.protoPolicyMap[packet.Proto] = forward
		portPolicyValue.timestamp = packet.Timestamp
	}

	mapsBackward := l.getVlanAndPortMap(packet, BACKWARD, true, mapsForward)
	if mapsBackward == nil {
		return nil, nil
	}
	if mapsBackward != mapsForward {
		l.addEpcMap(mapsBackward, dstEpc, srcEpc, packet.DstMac, packet.SrcMac)
	} else {
		if srcEpc == dstEpc && packet.SrcPort == packet.DstPort {
			return mapsForward, mapsBackward
		}
	}
	if id := policyForward.ACLID + policyBackward.ACLID; id > 0 {
		backward = new(PolicyData)
		backward.AclActions = make([]AclAction, 0, len(policyForward.AclActions)+len(policyBackward.AclActions))
		backward.MergeAndSwapDirection(forward.AclActions, forward.NpbActions, forward.ACLID)
	}
	key = uint64(dstEpc)<<48 | uint64(srcEpc)<<32 | uint64(packet.DstPort)<<16 | uint64(packet.SrcPort)
	if portPolicyValue := mapsBackward.portPolicyMap[key]; portPolicyValue == nil {
		value := &PortPolicyValue{endpoint: *endpointData, protoPolicyMap: make(map[uint8]*PolicyData), timestamp: packet.Timestamp}
		value.endpoint.SrcInfo, value.endpoint.DstInfo = value.endpoint.DstInfo, value.endpoint.SrcInfo
		value.protoPolicyMap[packet.Proto] = backward
		mapsBackward.portPolicyMap[key] = value
	} else {
		portPolicyValue.endpoint = EndpointData{SrcInfo: endpointData.DstInfo, DstInfo: endpointData.SrcInfo}
		portPolicyValue.protoPolicyMap[packet.Proto] = backward
		portPolicyValue.timestamp = packet.Timestamp
	}

	return mapsForward, mapsBackward
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

func (l *PolicyLabeler) getFastEpcs(maps *VlanAndPortMap, packet *LookupKey) (uint16, uint16) {
	epcs := maps.macEpcMap[(packet.SrcMac<<32)|(packet.DstMac&0xffffffff)]
	if epcs != 0 {
		return uint16(epcs >> 16), uint16(epcs & 0xffff)
	}
	return 0, 0
}

func (l *PolicyLabeler) getFastVlanPolicy(maps *VlanAndPortMap, srcEpc, dstEpc uint16, packet *LookupKey) *PolicyData {
	key := uint64(srcEpc)<<48 | uint64(dstEpc)<<32 | uint64(packet.Vlan)
	// vlanMap存储的是有方向的policy，在这里不用更改
	return maps.vlanPolicyMap[key]
}

func (l *PolicyLabeler) getFastPortPolicy(maps *VlanAndPortMap, srcEpc, dstEpc uint16, packet *LookupKey) (*EndpointData, *PolicyData) {
	key := uint64(srcEpc)<<48 | uint64(dstEpc)<<32 | uint64(packet.SrcPort)<<16 | uint64(packet.DstPort)
	if value := maps.portPolicyMap[key]; value != nil {
		if policy := value.protoPolicyMap[packet.Proto]; policy != nil {
			if packet.Timestamp-value.timestamp > FAST_PATH_SOFT_TIMEOUT && packet.Timestamp > value.timestamp {
				return nil, nil
			}
			value.timestamp = packet.Timestamp
			return &value.endpoint, policy
		}
	}
	return nil, nil
}

func (l *PolicyLabeler) getVlanAndPortMap(packet *LookupKey, direction DirectionType, create bool, mapsForward *VlanAndPortMap) *VlanAndPortMap {
	maskSrc := l.IpNetmaskMap[uint16(packet.SrcIp>>16)]
	maskDst := l.IpNetmaskMap[uint16(packet.DstIp>>16)]
	maskedSrcIp := packet.SrcIp & maskSrc
	maskedDstIp := packet.DstIp & maskDst
	if direction == BACKWARD {
		if maskedSrcIp == maskedDstIp {
			return mapsForward
		}
		maskedSrcIp, maskedDstIp = maskedDstIp, maskedSrcIp
	}
	if maskSrc > STANDARD_NETMASK || maskDst > STANDARD_NETMASK {
		key := uint64(maskedSrcIp)<<32 | uint64(maskedDstIp)
		maps := l.FastPolicyMaps[packet.FastIndex][packet.Tap]
		if maps == nil {
			return nil
		}
		if data, ok := maps.Get(key); ok {
			return data.(*VlanAndPortMap)
		}
		if create {
			value := &VlanAndPortMap{make(map[uint64]uint32), make(map[uint64]*PolicyData), make(map[uint64]*PortPolicyValue)}
			maps.Add(key, value)
			return value
		}
	} else {
		key := (maskedSrcIp & STANDARD_NETMASK) | (maskedDstIp >> 16)
		maps := l.FastPolicyMapsMini[packet.FastIndex][packet.Tap]
		if maps == nil {
			return nil
		}
		if data, ok := maps.Get(key); ok {
			return data.(*VlanAndPortMap)
		}
		if create {
			value := &VlanAndPortMap{make(map[uint64]uint32), make(map[uint64]*PolicyData), make(map[uint64]*PortPolicyValue)}
			maps.Add(key, value)
			return value
		}
	}
	return nil
}

func (l *PolicyLabeler) GetPolicyByFastPath(packet *LookupKey) (*EndpointData, *PolicyData) {
	if l.FastPathDisable {
		return nil, nil
	}

	var endpoint *EndpointData
	var portPolicy *PolicyData
	vlanPolicy, policy := INVALID_POLICY_DATA, INVALID_POLICY_DATA

	if maps := l.getVlanAndPortMap(packet, FORWARD, false, nil); maps != nil {
		srcEpc, dstEpc := l.getFastEpcs(maps, packet)
		// NOTE：会改变packet参数，但firstPath同样需要getFastInterestKeys，所以无影响
		l.getFastInterestKeys(packet)
		if endpoint, portPolicy = l.getFastPortPolicy(maps, srcEpc, dstEpc, packet); portPolicy == nil {
			return nil, nil
		}
		if packet.Vlan > 0 {
			if vlanPolicy = l.getFastVlanPolicy(maps, srcEpc, dstEpc, packet); vlanPolicy == nil {
				return nil, nil
			}
		}
	}
	if vlanPolicy.ACLID == 0 {
		policy = portPolicy
	} else if portPolicy.ACLID == 0 {
		policy = vlanPolicy
	} else {
		policy = new(PolicyData)
		policy.AclActions = make([]AclAction, 0, len(vlanPolicy.AclActions)+len(portPolicy.AclActions))
		policy.Merge(vlanPolicy.AclActions, vlanPolicy.NpbActions, vlanPolicy.ACLID)
		policy.Merge(portPolicy.AclActions, portPolicy.NpbActions, portPolicy.ACLID)
	}

	if endpoint != nil {
		endpoint = l.cloudPlatformLabeler.UpdateEndpointData(endpoint, packet)
		policy = l.checkNpbPolicy(endpoint, policy)
	}

	atomic.AddUint64(&l.FastPathHit, 1)
	atomic.AddUint64(&l.FastPathHitTick, 1)
	return endpoint, policy
}
