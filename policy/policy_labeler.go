package policy

import (
	"fmt"
	"math"
	"sync/atomic"
	"time"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/lru"
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
	Id                ACLID
	Type              TapType
	TapId             uint32
	SrcGroups         []uint32
	DstGroups         []uint32
	SrcGroupRelations []uint16
	DstGroupRelations []uint16
	SrcPortRange      []PortRange
	DstPortRange      []PortRange
	SrcPorts          []uint16
	DstPorts          []uint16
	Proto             uint8
	Vlan              uint32
	Action            []AclAction
	NpbActions        []NpbAction
}

type PortPolicyValue struct {
	endpoint    EndpointData
	protoPolicy []*PolicyData
	timestamp   time.Duration
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

	InterestProtoMaps *[TAP_MAX][math.MaxUint8 + 1]bool
	InterestPortMaps  *[TAP_MAX][math.MaxUint16 + 1]PortRange

	fromInterestGroupMaps *[TAP_MAX][math.MaxUint16 + 1]uint16

	IpNetmaskMap       *[math.MaxUint16 + 1]uint32 // 根据IP地址查找对应的最大掩码
	FastPolicyMaps     [][]*lru.Cache64            // 快速路径上的Policy映射表，Key为IP掩码对，Value为VlanAndPortMap
	FastPolicyMapsMini [][]*lru.Cache32            // 同FastPolicyMaps，不过Key为32bit
	FastPathDisable    bool                        // 是否关闭快速路径，只使用慢速路径（FirstPath）

	MapSize             uint32
	GroupPortPolicyMaps [TAP_MAX][ACL_PROTO_MAX]map[uint64]*PolicyData // 慢速路径上资源组+协议+端口到Policy的映射表
	GroupVlanPolicyMaps [TAP_MAX]map[uint64]*PolicyData                // 慢速路径上资源组+Vlan到Policy的映射表

	FirstPathHit, FastPathHit             uint64
	FirstPathHitTick, FastPathHitTick     uint64
	AclHitMax                             uint32
	FastPathMacCount, FastPathPolicyCount uint32
	UnmatchedPacketCount                  uint64

	maskMapFromPlatformData [math.MaxUint16 + 1]uint32
	maskMapFromIpGroupData  [math.MaxUint16 + 1]uint32
	SrcGroupAclGidMaps      [TAP_MAX]map[uint32]bool
	DstGroupAclGidMaps      [TAP_MAX]map[uint32]bool
	cloudPlatformLabeler    *CloudPlatformLabeler
}

var STANDARD_NETMASK = MaskLenToNetmask(STANDARD_MASK_LEN)

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
	return fmt.Sprintf("Id:%v Type:%v TapId:%v SrcGroups:%v DstGroups:%v SrcPortRange:[%v] SrcPorts:[%s] DstPortRange:[%v] DstPorts:[%s] Proto:%v Vlan:%v Action:%v NpbActions:%s",
		a.Id, a.Type, a.TapId, a.SrcGroups, a.DstGroups, a.SrcPortRange, a.getPorts(a.SrcPorts), a.DstPortRange, a.getPorts(a.DstPorts), a.Proto, a.Vlan, a.Action, a.NpbActions)
}

func NewPolicyLabeler(queueCount int, mapSize uint32, fastPathDisable bool) *PolicyLabeler {
	policy := &PolicyLabeler{}

	policy.aclProtoMap[6] = ACL_PROTO_TCP
	policy.aclProtoMap[17] = ACL_PROTO_UDP

	policy.InterestProtoMaps = &[TAP_MAX][math.MaxUint8 + 1]bool{}
	policy.InterestPortMaps = &[TAP_MAX][math.MaxUint16 + 1]PortRange{}
	policy.fromInterestGroupMaps = &[TAP_MAX][math.MaxUint16 + 1]uint16{}

	for i := TAP_MIN; i < TAP_MAX; i++ {
		policy.GroupVlanPolicyMaps[i] = make(map[uint64]*PolicyData)
		for j := 0; j < ACL_PROTO_MAX; j++ {
			policy.GroupPortPolicyMaps[i][j] = make(map[uint64]*PolicyData)
		}
		policy.SrcGroupAclGidMaps[i] = make(map[uint32]bool)
		policy.DstGroupAclGidMaps[i] = make(map[uint32]bool)

	}

	policy.IpNetmaskMap = &[math.MaxUint16 + 1]uint32{0}

	policy.MapSize = mapSize
	policy.FastPathDisable = fastPathDisable
	policy.FastPolicyMaps = make([][]*lru.Cache64, queueCount)
	policy.FastPolicyMapsMini = make([][]*lru.Cache32, queueCount)
	for i := 0; i < queueCount; i++ {
		policy.FastPolicyMaps[i] = make([]*lru.Cache64, TAP_MAX)
		policy.FastPolicyMapsMini[i] = make([]*lru.Cache32, TAP_MAX)
		for j := TAP_MIN; j < TAP_MAX; j++ {
			policy.FastPolicyMaps[i][j] = lru.NewCache64((int(mapSize) >> 3) * 7)
			policy.FastPolicyMapsMini[i][j] = lru.NewCache32(int(mapSize) >> 3)
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
	groupMap := l.fromInterestGroupMaps[packet.Tap]
	hasAnyGroup := false
	// 添加groupid 0匹配全采集的策略
	for _, id := range endpointData.SrcInfo.GroupIds {
		id = FormatGroupId(id)
		if relations := groupMap[id]; relations > 0 {
			packet.SrcGroupIds = l.appendNoRepeat(packet.SrcGroupIds, relations)
			packet.SrcAllGroupIds = append(packet.SrcAllGroupIds, relations)
			if id == ANY_GROUP {
				hasAnyGroup = true
			}
		} else {
			packet.SrcAllGroupIds = append(packet.SrcAllGroupIds, 0)
		}
	}
	if !hasAnyGroup {
		// 添加groupid 0匹配全采集的策略
		packet.SrcGroupIds = l.appendNoRepeat(packet.SrcGroupIds, ANY_GROUP)
	}

	hasAnyGroup = false
	for _, id := range endpointData.DstInfo.GroupIds {
		id = FormatGroupId(id)
		if relations := groupMap[id]; relations > 0 {
			packet.DstGroupIds = l.appendNoRepeat(packet.DstGroupIds, relations)
			packet.DstAllGroupIds = append(packet.DstAllGroupIds, relations)
			if id == ANY_GROUP {
				hasAnyGroup = true
			}
		} else {
			packet.DstAllGroupIds = append(packet.DstAllGroupIds, 0)
		}
	}
	if !hasAnyGroup {
		// 添加groupid 0匹配全采集的策略
		packet.DstGroupIds = l.appendNoRepeat(packet.DstGroupIds, ANY_GROUP)
	}

	l.getFastInterestKeys(packet)
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

func (l *PolicyLabeler) generateInterestPortMap(acls []*Acl) {
	interestPortMaps := &[TAP_MAX][math.MaxUint16 + 1]PortRange{}
	ports := make([]PortRange, 0, 1000)

	for tapType := TAP_MIN; tapType < TAP_MAX; tapType++ {
		ports = ports[:0]
		for _, acl := range acls {
			if acl.Type == tapType {
				ports = append(ports, acl.SrcPortRange...)
				ports = append(ports, acl.DstPortRange...)
			}
		}

		ports = GetPortRanges(ports)

		for _, port := range ports {
			for i := int(port.Min()); i <= int(port.Max()); i++ {
				interestPortMaps[tapType][i] = port
			}
		}
	}

	for _, acl := range acls {
		for _, port := range acl.SrcPortRange {
			for i := int(port.Min()); i <= int(port.Max()); {
				portRangs := interestPortMaps[acl.Type][i]
				acl.SrcPorts = append(acl.SrcPorts, portRangs.Min())
				i = int(portRangs.Max()) + 1
			}
		}

		for _, port := range acl.DstPortRange {
			for i := int(port.Min()); i <= int(port.Max()); {
				portRangs := interestPortMaps[acl.Type][i]
				acl.DstPorts = append(acl.DstPorts, portRangs.Min())
				i = int(portRangs.Max()) + 1
			}
		}
	}
	l.InterestPortMaps = interestPortMaps
}

func (l *PolicyLabeler) splitGroups(raw []uint16, keys []uint32) ([]uint16, []uint16) {
	both := make([]uint16, 0, len(raw))
	last := make([]uint16, 0, len(raw))
	for _, id := range raw {
		repeat := false
		for _, key := range keys {
			if uint16(key&0xffff) == id {
				repeat = true
				break
			}
		}
		if !repeat {
			last = append(last, id)
		} else {
			both = append(both, id)
		}
	}

	return both, last
}

func (l *PolicyLabeler) appendNoRepeat(raws []uint16, key uint16) []uint16 {
	for _, raw := range raws {
		if raw == key {
			return raws
		}
	}
	return append(raws, key)
}

// 使用策略中的资源组，根据资源组Map结构获取资源组对应的组ID，存入Src/DstGroupRelations字段
// 后面的策略Map生成使用Src/DstGroupRelations字段
func (l *PolicyLabeler) getGroupRelation(acls []*Acl, from *[TAP_MAX][math.MaxUint16 + 1]uint16) {
	for _, acl := range acls {
		relationIds := make([]uint16, 0, len(acl.SrcGroups))
		for _, group := range acl.SrcGroups {
			relationIds = l.appendNoRepeat(relationIds, from[acl.Type][group])
		}
		acl.SrcGroupRelations = relationIds

		relationIds = make([]uint16, 0, len(acl.DstGroups))
		for _, group := range acl.DstGroups {
			relationIds = l.appendNoRepeat(relationIds, from[acl.Type][group])
		}
		acl.DstGroupRelations = relationIds
	}
}

func (l *PolicyLabeler) generateGroupRelationByGroups(groups []uint32, tapType TapType, id *uint16, to *[TAP_MAX][math.MaxUint16 + 1][]uint16, from *[TAP_MAX][math.MaxUint16 + 1]uint16) {
	insert := make([]uint16, 0, len(groups))
	for _, group := range groups {
		if group == 0 {
			continue
		}
		relateId := from[tapType][uint16(group&0xffff)]
		if relateId == 0 {
			insert = append(insert, uint16(group&0xffff))
			continue
		}
		both, raw := l.splitGroups(to[tapType][relateId], groups)
		if len(raw) != 0 {
			to[tapType][*id] = both
			to[tapType][relateId] = raw
			for _, gid := range both {
				from[tapType][gid] = *id
			}
			from[tapType][uint16(group&0xffff)] = *id
			*id++
		}
	}
	if len(insert) > 0 {
		for _, group := range insert {
			from[tapType][group] = *id
		}
		to[tapType][*id] = insert
		*id++
	}
}

// 将策略中的资源组ID进行再分组，存储在资源组Map结构
// 例如所有策略中原资源组都是[1, 2], 目的资源组为[3, 4]
// 原算法：
//     key个数 = 2 * 2 = 4
// 资源组再分组后， [1, 2]为组m，[3, 4]为组n:
//     key个数 = m * n = 1
func (l *PolicyLabeler) generateGroupRelation(acls []*Acl, to *[TAP_MAX][math.MaxUint16 + 1][]uint16, from *[TAP_MAX][math.MaxUint16 + 1]uint16) {
	for tapType := TAP_MIN; tapType < TAP_MAX; tapType++ {
		id := uint16(1)
		for _, acl := range acls {
			if acl.Type != tapType {
				continue
			}
			for _, groups := range [][]uint32{acl.SrcGroups, acl.DstGroups} {
				l.generateGroupRelationByGroups(groups, acl.Type, &id, to, from)
			}
		}
	}
}

func (l *PolicyLabeler) generateInterestGroupMap(acls []*Acl) {
	to := &[TAP_MAX][math.MaxUint16 + 1][]uint16{}
	from := &[TAP_MAX][math.MaxUint16 + 1]uint16{}
	l.generateGroupRelation(acls, to, from)
	l.getGroupRelation(acls, from)
	l.fromInterestGroupMaps = from
}

func (l *PolicyLabeler) generateInterestProtoMaps(acls []*Acl) {
	interestProtoMaps := &[TAP_MAX][math.MaxUint8 + 1]bool{}

	for _, acl := range acls {
		if acl.Type.CheckTapType(acl.Type) {
			interestProtoMaps[acl.Type][acl.Proto] = true
		}
	}
	l.InterestProtoMaps = interestProtoMaps
}

func (l *PolicyLabeler) GenerateInterestMaps(acls []*Acl) {
	l.generateInterestPortMap(acls)
	l.generateInterestGroupMap(acls)
	l.generateInterestProtoMaps(acls)
}

func addGroupAclGidsToMap(acl *Acl, aclGid uint32, srcMap map[uint32]bool, dstMap map[uint32]bool) {
	srcLen := len(acl.SrcGroups)
	dstLen := len(acl.DstGroups)
	for _, group := range acl.SrcGroupRelations {
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
	for _, group := range acl.DstGroupRelations {
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

func (l *PolicyLabeler) GenerateGroupAclGidMaps(acls []*Acl) {
	srcGroupAclGidMaps := [TAP_MAX]map[uint32]bool{}
	dstGroupAclGidMaps := [TAP_MAX]map[uint32]bool{}
	for i := TAP_MIN; i < TAP_MAX; i++ {
		dstGroupAclGidMaps[i] = make(map[uint32]bool)
		srcGroupAclGidMaps[i] = make(map[uint32]bool)
	}
	for _, acl := range acls {
		for _, action := range acl.Action {
			addGroupAclGidsToMap(acl, uint32(action.GetACLGID()), srcGroupAclGidMaps[acl.Type], dstGroupAclGidMaps[acl.Type])
		}
	}
	l.SrcGroupAclGidMaps = srcGroupAclGidMaps
	l.DstGroupAclGidMaps = dstGroupAclGidMaps
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
	for i := 0; i < len(l.FastPolicyMaps); i++ {
		for j := TAP_MIN; j < TAP_MAX; j++ {
			l.FastPolicyMaps[i][j] = lru.NewCache64((int(l.MapSize) >> 3) * 7)
			l.FastPolicyMapsMini[i][j] = lru.NewCache32(int(l.MapSize) >> 3)
		}
	}
	atomic.StoreUint32(&l.FastPathMacCount, 0)
	atomic.StoreUint32(&l.FastPathPolicyCount, 0)
	atomic.StoreUint64(&l.UnmatchedPacketCount, 0)
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

func (l *PolicyLabeler) getAclId(ids ...ACLID) ACLID {
	for _, id := range ids {
		if id != 0 {
			return id
		}
	}
	return ACLID(0)
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

	// 剔除匿名资源组ID
	l.cloudPlatformLabeler.RemoveAnonymousGroupIds(endpointData, packet)
	packetEndpointData := l.cloudPlatformLabeler.UpdateEndpointData(endpointData, packet)

	// 无论是否查找到policy，都需要向fastPath下发，避免重复走firstPath
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
		// 无论是否查找到policy，都需要向fastPath下发，避免重复走firstPath
		l.addVlanFastPolicy(srcEpc, dstEpc, packet, vlanPolicy, endpointData, mapsForward, mapsBackward)
	}

	id := l.getAclId(vlanPolicy.ACLID, portForwardPolicy.ACLID, portBackwardPolicy.ACLID)
	if id > 0 {
		findPolicy = new(PolicyData)
		if packet.HasFeatureFlag(NPM) {
			length := len(portForwardPolicy.AclActions) + len(portBackwardPolicy.AclActions) + len(vlanPolicy.AclActions)
			findPolicy.AclActions = make([]AclAction, 0, length)
			findPolicy.MergeAclAction(append(vlanPolicy.AclActions, append(portForwardPolicy.AclActions, portBackwardPolicy.AclActions...)...), id)
			findPolicy.AddAclGidBitmaps(packet, false, l.SrcGroupAclGidMaps[packet.Tap], l.DstGroupAclGidMaps[packet.Tap])
		}
		if packet.HasFeatureFlag(NPB) {
			length := len(portForwardPolicy.NpbActions) + len(portBackwardPolicy.NpbActions)
			findPolicy.NpbActions = make([]NpbAction, 0, length)
			findPolicy.MergeNpbAction(append(portForwardPolicy.NpbActions, portBackwardPolicy.NpbActions...), id)
			findPolicy.FormatNpbAction()
			findPolicy.NpbActions = findPolicy.CheckNpbAction(packet, packetEndpointData)
		}
	} else {
		atomic.AddUint64(&l.UnmatchedPacketCount, 1)
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
		key := srcMac<<32 | dstMac&math.MaxUint32
		if epc := maps.macEpcMap[key]; epc == 0 {
			atomic.AddUint32(&l.FastPathMacCount, 1)
		}
		// 仅仅使用具有区分性的mac的后32bit
		maps.macEpcMap[key] = uint32(srcEpc)<<16 | uint32(dstEpc)&math.MaxUint16
	}
}

func (l *PolicyLabeler) addVlanFastPolicy(srcEpc, dstEpc uint16, packet *LookupKey, policy *PolicyData, endpointData *EndpointData, mapsForward, mapsBackward *VlanAndPortMap) {
	forward, backward := INVALID_POLICY_DATA, INVALID_POLICY_DATA

	if mapsForward == nil || mapsBackward == nil {
		return
	}

	if policy.ACLID > 0 {
		forward = policy
	}

	key := uint64(srcEpc)<<48 | uint64(dstEpc)<<32 | uint64(packet.Vlan)
	vlanPolicy := mapsForward.vlanPolicyMap[key]
	if vlanPolicy == nil {
		atomic.AddUint32(&l.FastPathPolicyCount, 1)
		// 添加forward方向bitmap
		forward.AddAclGidBitmaps(packet, false, l.SrcGroupAclGidMaps[packet.Tap], l.DstGroupAclGidMaps[packet.Tap])
		mapsForward.vlanPolicyMap[key] = forward
	} else {
		// 添加forward方向bitmap
		forward.AddAclGidBitmaps(packet, false, l.SrcGroupAclGidMaps[packet.Tap], l.DstGroupAclGidMaps[packet.Tap])
		*vlanPolicy = *forward
	}

	if mapsBackward == mapsForward && srcEpc == dstEpc {
		return
	}
	if policy.ACLID > 0 {
		backward = new(PolicyData)
		backward.AclActions = make([]AclAction, 0, len(policy.AclActions))
		backward.MergeAndSwapDirection(policy.AclActions, policy.NpbActions, policy.ACLID)
	}
	key = uint64(dstEpc)<<48 | uint64(srcEpc)<<32 | uint64(packet.Vlan)
	vlanPolicy = mapsBackward.vlanPolicyMap[key]
	if vlanPolicy == nil {
		atomic.AddUint32(&l.FastPathPolicyCount, 1)
		// 添加backward方向bitmap
		backward.AddAclGidBitmaps(packet, true, l.SrcGroupAclGidMaps[packet.Tap], l.DstGroupAclGidMaps[packet.Tap])
		mapsBackward.vlanPolicyMap[key] = backward
	} else {
		// 添加backward方向bitmap
		backward.AddAclGidBitmaps(packet, true, l.SrcGroupAclGidMaps[packet.Tap], l.DstGroupAclGidMaps[packet.Tap])
		*vlanPolicy = *backward
	}
}

func (l *PolicyLabeler) addPortFastPolicy(endpointData *EndpointData, packetEndpointData *EndpointData, srcEpc, dstEpc uint16, packet *LookupKey, policyForward, policyBackward *PolicyData) (*VlanAndPortMap, *VlanAndPortMap) {
	forward, backward := INVALID_POLICY_DATA, INVALID_POLICY_DATA

	mapsForward := l.getVlanAndPortMap(packet, FORWARD, true, nil)
	if mapsForward == nil {
		return nil, nil
	}
	l.addEpcMap(mapsForward, srcEpc, dstEpc, packet.SrcMac, packet.DstMac)
	id := l.getAclId(policyForward.ACLID, policyBackward.ACLID)
	if id > 0 {
		forward = new(PolicyData)
		if packet.HasFeatureFlag(NPM) {
			forward.AclActions = make([]AclAction, 0, len(policyForward.AclActions)+len(policyBackward.AclActions))
			forward.MergeAclAction(append(policyForward.AclActions, policyBackward.AclActions...), id)
		}
		if packet.HasFeatureFlag(NPB) {
			forward.NpbActions = make([]NpbAction, 0, len(policyForward.NpbActions)+len(policyBackward.NpbActions))
			forward.MergeNpbAction(append(policyForward.NpbActions, policyBackward.NpbActions...), id)
			forward.FormatNpbAction()
		}
	}
	key := uint64(srcEpc)<<48 | uint64(dstEpc)<<32 | uint64(packet.SrcPort)<<16 | uint64(packet.DstPort)
	index := l.aclProtoMap[packet.Proto]
	if portPolicyValue := mapsForward.portPolicyMap[key]; portPolicyValue == nil {
		value := &PortPolicyValue{endpoint: *endpointData, protoPolicy: make([]*PolicyData, 3), timestamp: packet.Timestamp}
		value.endpoint.InitPointer()
		// 添加forward方向bitmap
		forward.AddAclGidBitmaps(packet, false, l.SrcGroupAclGidMaps[packet.Tap], l.DstGroupAclGidMaps[packet.Tap])
		value.protoPolicy[index] = forward
		mapsForward.portPolicyMap[key] = value
		atomic.AddUint32(&l.FastPathPolicyCount, 1)
	} else {
		portPolicyValue.endpoint = *endpointData
		portPolicyValue.endpoint.InitPointer()
		// 添加forward方向bitmap
		forward.AddAclGidBitmaps(packet, false, l.SrcGroupAclGidMaps[packet.Tap], l.DstGroupAclGidMaps[packet.Tap])
		portPolicyValue.protoPolicy[index] = forward
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
	if id > 0 {
		backward = new(PolicyData)
		if packet.HasFeatureFlag(NPM) {
			backward.AclActions = make([]AclAction, 0, len(policyForward.AclActions)+len(policyBackward.AclActions))
			backward.MergeAclAndSwapDirection(append(policyForward.AclActions, policyBackward.AclActions...), id)
		}
		if packet.HasFeatureFlag(NPB) {
			backward.NpbActions = make([]NpbAction, 0, len(policyForward.NpbActions)+len(policyBackward.NpbActions))
			backward.MergeNpbAndSwapDirection(append(policyForward.NpbActions, policyBackward.NpbActions...), id)
			backward.FormatNpbAction()
		}
	}
	key = uint64(dstEpc)<<48 | uint64(srcEpc)<<32 | uint64(packet.DstPort)<<16 | uint64(packet.SrcPort)
	if portPolicyValue := mapsBackward.portPolicyMap[key]; portPolicyValue == nil {
		value := &PortPolicyValue{endpoint: *endpointData, protoPolicy: make([]*PolicyData, 3), timestamp: packet.Timestamp}
		value.endpoint.SrcInfo, value.endpoint.DstInfo = value.endpoint.DstInfo, value.endpoint.SrcInfo
		value.endpoint.InitPointer()
		// 添加backward方向bitmap
		backward.AddAclGidBitmaps(packet, true, l.SrcGroupAclGidMaps[packet.Tap], l.DstGroupAclGidMaps[packet.Tap])
		value.protoPolicy[index] = backward
		mapsBackward.portPolicyMap[key] = value
		atomic.AddUint32(&l.FastPathPolicyCount, 1)
	} else {
		portPolicyValue.endpoint = EndpointData{SrcInfo: endpointData.DstInfo, DstInfo: endpointData.SrcInfo}
		portPolicyValue.endpoint.InitPointer()
		// 添加backward方向bitmap
		backward.AddAclGidBitmaps(packet, true, l.SrcGroupAclGidMaps[packet.Tap], l.DstGroupAclGidMaps[packet.Tap])
		portPolicyValue.protoPolicy[index] = backward
		portPolicyValue.timestamp = packet.Timestamp
	}

	return mapsForward, mapsBackward
}

func (l *PolicyLabeler) getFastInterestKeys(packet *LookupKey) {
	ports := l.InterestPortMaps[packet.Tap][packet.SrcPort]
	packet.SrcPort = ports.Min()
	ports = l.InterestPortMaps[packet.Tap][packet.DstPort]
	packet.DstPort = ports.Min()
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
		index := l.aclProtoMap[packet.Proto]
		if policy := value.protoPolicy[index]; policy != nil {
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
		if packet.Vlan > 0 && packet.HasFeatureFlag(NPM) {
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
		id := l.getAclId(vlanPolicy.ACLID, portPolicy.ACLID)
		policy = new(PolicyData)
		if packet.HasFeatureFlag(NPM) {
			policy.AclActions = make([]AclAction, 0, len(vlanPolicy.AclActions)+len(portPolicy.AclActions))
			policy.MergeAclAction(append(vlanPolicy.AclActions, portPolicy.AclActions...), id)
			policy.AddAclGidBitmaps(packet, false, l.SrcGroupAclGidMaps[packet.Tap], l.DstGroupAclGidMaps[packet.Tap])
		}
		if packet.HasFeatureFlag(NPB) {
			policy.NpbActions = make([]NpbAction, 0, len(portPolicy.NpbActions))
			policy.MergeNpbAction(portPolicy.NpbActions, id)
			policy.FormatNpbAction()
		}
	}

	if policy != nil && endpoint != nil {
		policy = policy.CheckNpbPolicy(packet, endpoint)
	}

	if policy != nil && policy.ACLID == 0 {
		atomic.AddUint64(&l.UnmatchedPacketCount, 1)
	}

	atomic.AddUint64(&l.FastPathHit, 1)
	atomic.AddUint64(&l.FastPathHitTick, 1)
	return endpoint, policy
}
