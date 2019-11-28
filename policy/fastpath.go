package policy

import (
	"fmt"
	"math"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/hmap/lru"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

const (
	MAX_QUEUE_COUNT = 16
)

type PortPolicyValue struct {
	endpoint    EndpointStore
	protoPolicy [ACL_PROTO_MAX]*PolicyData
}

type VlanAndPortMap struct {
	// 使用源目的MAC的后两个字节（共4字节）和vlan作为查询key
	// FIXME: 为什么没有EndpointStore和timestamp，timestamp作用域EndpointStore还是PolicyData
	vlanPolicyMap map[uint64]*PolicyData
	// 使用源目的MAC的后两个字节（共4字节）和源目的端口作为查询key
	portPolicyMap map[uint64]*PortPolicyValue
}

type Padding [8]uint64

type FastPath struct {
	maskMapFromPlatformData [math.MaxUint16 + 1]uint32
	maskMapFromIpGroupData  [math.MaxUint16 + 1]uint32
	padding0                Padding                    // 避免cache miss
	IpNetmaskMap            [math.MaxUint16 + 1]uint32 // 根据IP地址查找对应的最大掩码
	padding1                Padding

	FastPortPolicyMaps  [MAX_QUEUE_COUNT + 1][TAP_MAX]*lru.U128LRU // 快速路径上的Policy映射表，Key为IP掩码对 + MAC + PORT，Value为PortPolicyValue
	padding2            Padding
	FastVlanPolicyMaps  [MAX_QUEUE_COUNT + 1][TAP_MAX]*lru.U128LRU // 快速路径上的Policy映射表，Key为IP掩码对 + MAC + VLAN，Value为PolicyData
	padding3            Padding
	fastPolicyMapsFlush [MAX_QUEUE_COUNT + 1]bool // 标记对应的LRU是否需要Clear

	padding4                              Padding
	FastPathHit                           uint64
	padding5                              Padding
	FastPathMacCount, FastPathPolicyCount uint32

	padding6               Padding
	MapSize                uint32
	padding7               Padding
	flushCount, queueCount int

	padding8           Padding
	SrcGroupAclGidMaps [TAP_MAX]map[uint32]bool
	DstGroupAclGidMaps [TAP_MAX]map[uint32]bool
}

func (f *FastPath) Init(mapSize uint32, queueCount int, srcGroupAclGidMaps, dstGroupAclGidMaps [TAP_MAX]map[uint32]bool) {
	if queueCount > MAX_QUEUE_COUNT {
		panic(fmt.Sprintf("queueCount超出最大限制%d", MAX_QUEUE_COUNT))
	}
	f.UpdateGroupAclGidMaps(srcGroupAclGidMaps, dstGroupAclGidMaps)
	soltSize := 1 << 16
	if mapSize >= 1<<20 {
		soltSize = 1 << 20
	} else if mapSize >= 1<<16 {
		soltSize = 1 << 16
	} else {
		soltSize = 1 << 12
	}
	for i := 0; i < queueCount; i++ {
		for j := TapType(0); j < TAP_MAX; j++ {
			f.FastPortPolicyMaps[i][j] = lru.NewU128LRU(soltSize, int(mapSize))
			f.FastVlanPolicyMaps[i][j] = lru.NewU128LRU(soltSize, int(mapSize))
		}
	}

	f.MapSize = mapSize
	f.queueCount = queueCount
}

func (f *FastPath) UpdateGroupAclGidMaps(srcGroupAclGidMaps, dstGroupAclGidMaps [TAP_MAX]map[uint32]bool) {
	f.SrcGroupAclGidMaps = srcGroupAclGidMaps
	f.DstGroupAclGidMaps = dstGroupAclGidMaps
}

func (f *FastPath) FlushAcls() {
	for i := 0; i < f.queueCount; i++ {
		f.fastPolicyMapsFlush[i] = true
	}
	f.flushCount = f.queueCount
	f.FastPathMacCount = 0
	f.FastPathPolicyCount = 0
}

func (f *FastPath) generateMaskedIp(packet *LookupKey, maskedSrcIp, maskedDstIp *uint32) {
	if len(packet.Src6Ip) == 0 {
		*maskedSrcIp = packet.SrcIp & f.IpNetmaskMap[uint16(packet.SrcIp>>16)]
		*maskedDstIp = packet.DstIp & f.IpNetmaskMap[uint16(packet.DstIp>>16)]
	} else {
		*maskedSrcIp = GetIpHash(packet.Src6Ip)
		*maskedDstIp = GetIpHash(packet.Dst6Ip)
	}
}

func (f *FastPath) GenerateMapKey(packet *LookupKey, direction DirectionType, vlan bool, key1, key2 *uint64) {
	maskedSrcIp, maskedDstIp := uint32(0), uint32(0)
	srcPort, dstPort := uint64(packet.SrcPort), uint64(packet.DstPort)
	srcMacSuffix, dstMacSuffix := uint64(packet.SrcMac&0xffff), uint64(packet.DstMac&0xffff)
	f.generateMaskedIp(packet, &maskedSrcIp, &maskedDstIp)
	if direction == BACKWARD {
		srcMacSuffix, dstMacSuffix = dstMacSuffix, srcMacSuffix
		maskedSrcIp, maskedDstIp = maskedDstIp, maskedSrcIp
		srcPort, dstPort = dstPort, srcPort
	}
	if !vlan {
		*key1 = uint64(maskedSrcIp)<<32 | srcMacSuffix<<16 | srcPort
		*key2 = uint64(maskedDstIp)<<32 | dstMacSuffix<<16 | dstPort
	} else {
		*key1 = uint64(maskedSrcIp)<<32 | srcMacSuffix<<16 | uint64(packet.Vlan)
		*key2 = uint64(maskedDstIp)<<32 | dstMacSuffix<<16 | uint64(packet.Vlan)
	}
}

func (f *FastPath) getPortFastPolicy(packet *LookupKey) (*EndpointStore, *PolicyData) {
	if f.flushCount > 0 && f.fastPolicyMapsFlush[packet.FastIndex] {
		for i := TAP_MIN; i < TAP_MAX; i++ {
			f.FastPortPolicyMaps[packet.FastIndex][i].Clear()
			f.FastVlanPolicyMaps[packet.FastIndex][i].Clear()
		}
		f.flushCount -= 1
		f.fastPolicyMapsFlush[packet.FastIndex] = false
		return nil, nil
	}
	key1, key2 := uint64(0), uint64(0)
	f.GenerateMapKey(packet, FORWARD, false, &key1, &key2)
	value, ok := f.FastPortPolicyMaps[packet.FastIndex][packet.Tap].Get(key1, key2, true)
	if ok {
		portPolicy := value.(*PortPolicyValue)
		if policy := portPolicy.protoPolicy[packet.Proto]; policy != nil {
			return &portPolicy.endpoint, policy
		}
	}
	return nil, nil
}

func (f *FastPath) getVlanFastPolicy(packet *LookupKey) *PolicyData {
	key1, key2 := uint64(0), uint64(0)
	f.GenerateMapKey(packet, FORWARD, true, &key1, &key2)
	value, ok := f.FastVlanPolicyMaps[packet.FastIndex][packet.Tap].Get(key1, key2, true)
	if ok {
		policy := value.(*PolicyData)
		return policy
	}
	return nil
}

func (f *FastPath) addVlanFastPolicy(packet *LookupKey, policy *PolicyData) {
	forward, backward := INVALID_POLICY_DATA, INVALID_POLICY_DATA
	key1, key2 := uint64(0), uint64(0)

	f.GenerateMapKey(packet, FORWARD, true, &key1, &key2)

	if policy.ACLID > 0 {
		forward = policy
	}

	if value, ok := f.FastVlanPolicyMaps[packet.FastIndex][packet.Tap].Get(key1, key2, true); ok {
		policy := value.(*PolicyData)
		*policy = *forward
	} else {
		f.FastVlanPolicyMaps[packet.FastIndex][packet.Tap].Add(key1, key2, forward)
		f.FastPathPolicyCount++
	}
	// 添加forward方向bitmap
	forward.AddAclGidBitmaps(packet, false, f.SrcGroupAclGidMaps[packet.Tap], f.DstGroupAclGidMaps[packet.Tap])

	if key1 == key2 {
		return
	}
	key1, key2 = key2, key1

	if policy.ACLID > 0 {
		backward = new(PolicyData)
		backward.AclActions = make([]AclAction, 0, len(policy.AclActions))
		backward.MergeAndSwapDirection(policy.AclActions, policy.NpbActions, policy.ACLID)
	}

	if value, ok := f.FastVlanPolicyMaps[packet.FastIndex][packet.Tap].Get(key1, key2, true); ok {
		policy := value.(*PolicyData)
		*policy = *backward
	} else {
		f.FastVlanPolicyMaps[packet.FastIndex][packet.Tap].Add(key1, key2, backward)
		f.FastPathPolicyCount++
	}
	backward.AddAclGidBitmaps(packet, true, f.SrcGroupAclGidMaps[packet.Tap], f.DstGroupAclGidMaps[packet.Tap])
}

func (f *FastPath) addPortFastPolicy(endpointStore *EndpointStore, packetEndpointData *EndpointData, packet *LookupKey, policyForward, policyBackward *PolicyData) {
	if f.flushCount > 0 && f.fastPolicyMapsFlush[packet.FastIndex] {
		for i := TAP_MIN; i < TAP_MAX; i++ {
			f.FastPortPolicyMaps[packet.FastIndex][i].Clear()
			f.FastVlanPolicyMaps[packet.FastIndex][i].Clear()
		}
		f.flushCount -= 1
		f.fastPolicyMapsFlush[packet.FastIndex] = false
	}

	forward, backward := INVALID_POLICY_DATA, INVALID_POLICY_DATA
	key1, key2 := uint64(0), uint64(0)

	f.GenerateMapKey(packet, FORWARD, false, &key1, &key2)

	id := getAclId(policyForward.ACLID, policyBackward.ACLID)
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

	if value, ok := f.FastPortPolicyMaps[packet.FastIndex][packet.Tap].Get(key1, key2, true); !ok {
		value := &PortPolicyValue{}
		value.endpoint.InitPointer(endpointStore.Endpoints)
		// 添加forward方向bitmap
		forward.AddAclGidBitmaps(packet, false, f.SrcGroupAclGidMaps[packet.Tap], f.DstGroupAclGidMaps[packet.Tap])
		value.protoPolicy[packet.Proto] = forward
		f.FastPortPolicyMaps[packet.FastIndex][packet.Tap].Add(key1, key2, value)
		f.FastPathPolicyCount++
	} else {
		portPolicyValue := value.(*PortPolicyValue)
		portPolicyValue.endpoint.InitPointer(endpointStore.Endpoints)
		// 添加forward方向bitmap
		forward.AddAclGidBitmaps(packet, false, f.SrcGroupAclGidMaps[packet.Tap], f.DstGroupAclGidMaps[packet.Tap])
		portPolicyValue.protoPolicy[packet.Proto] = forward
	}

	if key1 == key2 {
		return
	}
	key1, key2 = key2, key1

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
	endpoints := &EndpointData{SrcInfo: endpointStore.Endpoints.DstInfo, DstInfo: endpointStore.Endpoints.SrcInfo}
	if value, ok := f.FastPortPolicyMaps[packet.FastIndex][packet.Tap].Get(key1, key2, true); !ok {
		value := &PortPolicyValue{}
		value.endpoint.InitPointer(endpoints)
		// 添加backward方向bitmap
		backward.AddAclGidBitmaps(packet, true, f.SrcGroupAclGidMaps[packet.Tap], f.DstGroupAclGidMaps[packet.Tap])
		value.protoPolicy[packet.Proto] = backward
		f.FastPortPolicyMaps[packet.FastIndex][packet.Tap].Add(key1, key2, value)
		f.FastPathPolicyCount++
	} else {
		portPolicyValue := value.(*PortPolicyValue)
		portPolicyValue.endpoint.InitPointer(endpoints)
		// 添加backward方向bitmap
		backward.AddAclGidBitmaps(packet, true, f.SrcGroupAclGidMaps[packet.Tap], f.DstGroupAclGidMaps[packet.Tap])
		portPolicyValue.protoPolicy[packet.Proto] = backward
	}
}

func (f *FastPath) makeIpNetmaskMap() {
	// CPU会通过多个指令完成替换，但由于此数组的各个元素之间无逻辑关系，这样也是线程安全的
	// FIXME: 现在的更新方法会更新两次，不太好
	for i := 0; i <= math.MaxUint16; i++ {
		f.IpNetmaskMap[i] = f.maskMapFromPlatformData[i]
		if f.IpNetmaskMap[i] < f.maskMapFromIpGroupData[i] {
			f.IpNetmaskMap[i] = f.maskMapFromIpGroupData[i]
		}
	}
}

func (f *FastPath) GenerateIpNetmaskMapFromPlatformData(data []*PlatformData) {
	maskMap := &f.maskMapFromPlatformData
	for key, _ := range maskMap {
		maskMap[key] = 0
	}

	for _, d := range data {
		for _, network := range d.Ips {
			// TODO: 支持IPV6
			if len(network.RawIp) == 4 {
				ip := IpToUint32(network.RawIp)
				minNetIp := ip & STANDARD_NETMASK
				maxNetIp := minNetIp
				mask := uint32(math.MaxUint32) << (32 - network.Netmask)
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
	}

	f.makeIpNetmaskMap()
}

func (f *FastPath) GenerateIpNetmaskMapFromIpGroupData(data []*IpGroupData) {
	maskMap := &f.maskMapFromIpGroupData
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
			if len(ip) == 16 {
				continue
			}
			ip4 := IpToUint32(ip)
			// internet资源因为匹配左右IP, 不需要加在这里
			if ip4 == 0 && d.EpcId == 0 && maskSize == 0 {
				continue
			}

			minNetIp := ip4 & STANDARD_NETMASK
			maxNetIp := minNetIp
			mask := uint32(math.MaxUint32) << uint32(32-maskSize)
			// netmask must be either 0 or STANDARD_NETMASK~math.MaxUint32
			if mask < STANDARD_NETMASK {
				minNetIp = ip4 & mask
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

	f.makeIpNetmaskMap()
}
