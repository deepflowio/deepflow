package policy

import (
	"fmt"
	"math"
	"time"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/hmap/lru"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

const (
	MAX_QUEUE_COUNT        = 16
	FAST_PATH_SOFT_TIMEOUT = 30 * time.Minute
)

type PortPolicyValue struct {
	endpoint    EndpointStore
	protoPolicy [ACL_PROTO_MAX]*PolicyData
	timestamp   time.Duration
}

type VlanAndPortMap struct {
	// 使用源目的MAC的后两个字节（共4字节）和vlan作为查询key
	// FIXME: 为什么没有EndpointStore和timestamp，timestamp作用域EndpointStore还是PolicyData
	vlanPolicyMap map[uint64]*PolicyData
	// 使用源目的MAC的后两个字节（共4字节）和源目的端口作为查询key
	portPolicyMap map[uint64]*PortPolicyValue
}

type FastPath struct {
	maskMapFromPlatformData [math.MaxUint16 + 1]uint32
	maskMapFromIpGroupData  [math.MaxUint16 + 1]uint32
	IpNetmaskMap            [math.MaxUint16 + 1]uint32 // 根据IP地址查找对应的最大掩码

	FastPolicyMaps      [MAX_QUEUE_COUNT + 1][TAP_MAX]*lru.U64LRU // 快速路径上的Policy映射表，Key为IP掩码对，Value为VlanAndPortMap
	fastPolicyMapsFlush [MAX_QUEUE_COUNT + 1][TAP_MAX]bool        // 标记对应的LRU是否需要Clear

	FastPathHit                           uint64
	FastPathMacCount, FastPathPolicyCount uint32

	MapSize uint32

	SrcGroupAclGidMaps [TAP_MAX]map[uint32]bool
	DstGroupAclGidMaps [TAP_MAX]map[uint32]bool
}

func (f *FastPath) Init(mapSize uint32, queueCount int, srcGroupAclGidMaps, dstGroupAclGidMaps [TAP_MAX]map[uint32]bool) {
	if queueCount > MAX_QUEUE_COUNT {
		panic(fmt.Sprintf("queueCount超出最大限制%d", MAX_QUEUE_COUNT))
	}
	f.UpdateGroupAclGidMaps(srcGroupAclGidMaps, dstGroupAclGidMaps)

	f.MapSize = mapSize
}

func (f *FastPath) UpdateGroupAclGidMaps(srcGroupAclGidMaps, dstGroupAclGidMaps [TAP_MAX]map[uint32]bool) {
	f.SrcGroupAclGidMaps = srcGroupAclGidMaps
	f.DstGroupAclGidMaps = dstGroupAclGidMaps
}

func (f *FastPath) FlushAcls() {
	for i := 0; i < len(f.FastPolicyMaps); i++ {
		for j := TAP_MIN; j < TAP_MAX; j++ {
			if f.FastPolicyMaps[i][j] != nil {
				f.fastPolicyMapsFlush[i][j] = true
			}
		}
	}
	f.FastPathMacCount = 0
	f.FastPathPolicyCount = 0
}

func (l *FastPath) getFastVlanPolicy(maps *VlanAndPortMap, srcMacSuffix, dstMacSuffix uint16, packet *LookupKey) *PolicyData {
	key := uint64(srcMacSuffix)<<48 | uint64(dstMacSuffix)<<32 | uint64(packet.Vlan)
	// vlanMap存储的是有方向的policy，在这里不用更改
	return maps.vlanPolicyMap[key]
}

func (l *FastPath) getFastPortPolicy(maps *VlanAndPortMap, srcMacSuffix, dstMacSuffix uint16, packet *LookupKey) (*EndpointStore, *PolicyData) {
	key := uint64(srcMacSuffix)<<48 | uint64(dstMacSuffix)<<32 | uint64(packet.SrcPort)<<16 | uint64(packet.DstPort)
	if value := maps.portPolicyMap[key]; value != nil {
		if policy := value.protoPolicy[packet.Proto]; policy != nil {
			if packet.Timestamp-value.timestamp > FAST_PATH_SOFT_TIMEOUT && packet.Timestamp > value.timestamp {
				return nil, nil
			}
			value.timestamp = packet.Timestamp
			return &value.endpoint, policy
		}
	}
	return nil, nil
}

func (f *FastPath) generateMaskedIp(packet *LookupKey) (uint32, uint32) {
	if len(packet.Src6Ip) == 0 {
		maskSrc := f.IpNetmaskMap[uint16(packet.SrcIp>>16)]
		maskDst := f.IpNetmaskMap[uint16(packet.DstIp>>16)]
		maskedSrcIp := packet.SrcIp & maskSrc
		maskedDstIp := packet.DstIp & maskDst
		return maskedSrcIp, maskedDstIp
	} else {
		srcIpHash := GetIpHash(packet.Src6Ip)
		dstIpHash := GetIpHash(packet.Dst6Ip)
		return srcIpHash, dstIpHash
	}
}

func (f *FastPath) getVlanAndPortMap(packet *LookupKey, direction DirectionType, create bool, mapsForward *VlanAndPortMap) *VlanAndPortMap {
	maskedSrcIp, maskedDstIp := f.generateMaskedIp(packet)
	if direction == BACKWARD {
		if maskedSrcIp == maskedDstIp {
			return mapsForward
		}
		maskedSrcIp, maskedDstIp = maskedDstIp, maskedSrcIp
	}

	key := uint64(maskedSrcIp)<<32 | uint64(maskedDstIp)
	maps := f.FastPolicyMaps[packet.FastIndex][packet.Tap]
	if maps == nil {
		maps = lru.NewU64LRU(int(f.MapSize>>2), int(f.MapSize))
		f.FastPolicyMaps[packet.FastIndex][packet.Tap] = maps
	} else if f.fastPolicyMapsFlush[packet.FastIndex][packet.Tap] {
		f.fastPolicyMapsFlush[packet.FastIndex][packet.Tap] = false
		maps.Clear()
	}
	if data, ok := maps.Get(key, false); ok {
		return data.(*VlanAndPortMap)
	}
	if create {
		value := &VlanAndPortMap{make(map[uint64]*PolicyData), make(map[uint64]*PortPolicyValue)}
		maps.Add(key, value)
		return value
	}

	return nil
}

func (f *FastPath) addVlanFastPolicy(srcMacSuffix, dstMacSuffix uint16, packet *LookupKey, policy *PolicyData, endpointData *EndpointData, mapsForward, mapsBackward *VlanAndPortMap) {
	forward, backward := INVALID_POLICY_DATA, INVALID_POLICY_DATA

	if mapsForward == nil || mapsBackward == nil {
		return
	}

	if policy.ACLID > 0 {
		forward = policy
	}

	key := uint64(srcMacSuffix)<<48 | uint64(dstMacSuffix)<<32 | uint64(packet.Vlan)
	vlanPolicy := mapsForward.vlanPolicyMap[key]
	if vlanPolicy == nil {
		f.FastPathPolicyCount++
		// 添加forward方向bitmap
		forward.AddAclGidBitmaps(packet, false, f.SrcGroupAclGidMaps[packet.Tap], f.DstGroupAclGidMaps[packet.Tap])
		mapsForward.vlanPolicyMap[key] = forward
	} else {
		// 添加forward方向bitmap
		forward.AddAclGidBitmaps(packet, false, f.SrcGroupAclGidMaps[packet.Tap], f.DstGroupAclGidMaps[packet.Tap])
		*vlanPolicy = *forward
	}

	if mapsBackward == mapsForward && srcMacSuffix == dstMacSuffix {
		return
	}
	if policy.ACLID > 0 {
		backward = new(PolicyData)
		backward.AclActions = make([]AclAction, 0, len(policy.AclActions))
		backward.MergeAndSwapDirection(policy.AclActions, policy.NpbActions, policy.ACLID)
	}
	key = uint64(dstMacSuffix)<<48 | uint64(srcMacSuffix)<<32 | uint64(packet.Vlan)
	vlanPolicy = mapsBackward.vlanPolicyMap[key]
	if vlanPolicy == nil {
		f.FastPathPolicyCount++
		// 添加backward方向bitmap
		backward.AddAclGidBitmaps(packet, true, f.SrcGroupAclGidMaps[packet.Tap], f.DstGroupAclGidMaps[packet.Tap])
		mapsBackward.vlanPolicyMap[key] = backward
	} else {
		// 添加backward方向bitmap
		backward.AddAclGidBitmaps(packet, true, f.SrcGroupAclGidMaps[packet.Tap], f.DstGroupAclGidMaps[packet.Tap])
		*vlanPolicy = *backward
	}
}

func (f *FastPath) addPortFastPolicy(endpointStore *EndpointStore, packetEndpointData *EndpointData, srcMacSuffix, dstMacSuffix uint16, packet *LookupKey, policyForward, policyBackward *PolicyData) (*VlanAndPortMap, *VlanAndPortMap) {
	forward, backward := INVALID_POLICY_DATA, INVALID_POLICY_DATA

	mapsForward := f.getVlanAndPortMap(packet, FORWARD, true, nil)
	if mapsForward == nil {
		return nil, nil
	}
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
	key := uint64(srcMacSuffix)<<48 | uint64(dstMacSuffix)<<32 | uint64(packet.SrcPort)<<16 | uint64(packet.DstPort)
	if portPolicyValue := mapsForward.portPolicyMap[key]; portPolicyValue == nil {
		value := &PortPolicyValue{timestamp: packet.Timestamp}
		value.endpoint.InitPointer(endpointStore.Endpoints)
		// 添加forward方向bitmap
		forward.AddAclGidBitmaps(packet, false, f.SrcGroupAclGidMaps[packet.Tap], f.DstGroupAclGidMaps[packet.Tap])
		value.protoPolicy[packet.Proto] = forward
		mapsForward.portPolicyMap[key] = value
		f.FastPathPolicyCount++
	} else {
		portPolicyValue.endpoint.InitPointer(endpointStore.Endpoints)
		// 添加forward方向bitmap
		forward.AddAclGidBitmaps(packet, false, f.SrcGroupAclGidMaps[packet.Tap], f.DstGroupAclGidMaps[packet.Tap])
		portPolicyValue.protoPolicy[packet.Proto] = forward
		portPolicyValue.timestamp = packet.Timestamp
	}

	mapsBackward := f.getVlanAndPortMap(packet, BACKWARD, true, mapsForward)
	if mapsBackward == nil {
		return nil, nil
	}
	if mapsBackward == mapsForward && srcMacSuffix == dstMacSuffix && packet.SrcPort == packet.DstPort {
		return mapsForward, mapsBackward
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
	endpoints := &EndpointData{SrcInfo: endpointStore.Endpoints.DstInfo, DstInfo: endpointStore.Endpoints.SrcInfo}
	key = uint64(dstMacSuffix)<<48 | uint64(srcMacSuffix)<<32 | uint64(packet.DstPort)<<16 | uint64(packet.SrcPort)
	if portPolicyValue := mapsBackward.portPolicyMap[key]; portPolicyValue == nil {
		value := &PortPolicyValue{timestamp: packet.Timestamp}
		value.endpoint.InitPointer(endpoints)
		// 添加backward方向bitmap
		backward.AddAclGidBitmaps(packet, true, f.SrcGroupAclGidMaps[packet.Tap], f.DstGroupAclGidMaps[packet.Tap])
		value.protoPolicy[packet.Proto] = backward
		mapsBackward.portPolicyMap[key] = value
		f.FastPathPolicyCount++
	} else {
		portPolicyValue.endpoint.InitPointer(endpoints)
		// 添加backward方向bitmap
		backward.AddAclGidBitmaps(packet, true, f.SrcGroupAclGidMaps[packet.Tap], f.DstGroupAclGidMaps[packet.Tap])
		portPolicyValue.protoPolicy[packet.Proto] = backward
		portPolicyValue.timestamp = packet.Timestamp
	}

	return mapsForward, mapsBackward
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
