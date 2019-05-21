package policy

import (
	"math"
	"sync/atomic"
	"time"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/lru"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

const (
	FAST_PATH_SOFT_TIMEOUT = 30 * time.Minute
)

type PortPolicyValue struct {
	endpoint    EndpointStore
	protoPolicy []*PolicyData
	timestamp   time.Duration
}

type VlanAndPortMap struct {
	macEpcMap     map[uint64]uint32
	vlanPolicyMap map[uint64]*PolicyData
	portPolicyMap map[uint64]*PortPolicyValue
}

type FastPath struct {
	aclProtoMap [math.MaxUint8 + 1]uint8

	maskMapFromPlatformData [math.MaxUint16 + 1]uint32
	maskMapFromIpGroupData  [math.MaxUint16 + 1]uint32
	IpNetmaskMap            *[math.MaxUint16 + 1]uint32 // 根据IP地址查找对应的最大掩码

	FastPolicyMaps     [][]*lru.Cache64 // 快速路径上的Policy映射表，Key为IP掩码对，Value为VlanAndPortMap
	FastPolicyMapsMini [][]*lru.Cache32 // 同FastPolicyMaps，不过Key为32bit

	FastPathHit, FastPathHitTick          uint64
	FastPathMacCount, FastPathPolicyCount uint32

	MapSize uint32

	SrcGroupAclGidMaps [TAP_MAX]map[uint32]bool
	DstGroupAclGidMaps [TAP_MAX]map[uint32]bool
}

func (f *FastPath) Init(mapSize uint32, queueCount int, srcGroupAclGidMaps, dstGroupAclGidMaps [TAP_MAX]map[uint32]bool) {
	f.IpNetmaskMap = &[math.MaxUint16 + 1]uint32{0}

	f.aclProtoMap[6] = ACL_PROTO_TCP
	f.aclProtoMap[17] = ACL_PROTO_UDP

	f.FastPolicyMaps = make([][]*lru.Cache64, queueCount)
	f.FastPolicyMapsMini = make([][]*lru.Cache32, queueCount)
	for i := 0; i < queueCount; i++ {
		f.FastPolicyMaps[i] = make([]*lru.Cache64, TAP_MAX)
		f.FastPolicyMapsMini[i] = make([]*lru.Cache32, TAP_MAX)
		for j := TAP_MIN; j < TAP_MAX; j++ {
			f.FastPolicyMaps[i][j] = lru.NewCache64((int(mapSize) >> 3) * 7)
			f.FastPolicyMapsMini[i][j] = lru.NewCache32(int(mapSize) >> 3)
		}
	}
	f.UpdateGroupAclGidMaps(srcGroupAclGidMaps, dstGroupAclGidMaps)

	f.MapSize = mapSize
}

func (f *FastPath) UpdateGroupAclGidMaps(srcGroupAclGidMaps, dstGroupAclGidMaps [TAP_MAX]map[uint32]bool) {
	f.SrcGroupAclGidMaps = srcGroupAclGidMaps
	f.DstGroupAclGidMaps = dstGroupAclGidMaps
}

func (f *FastPath) getAclProto(proto uint8) uint8 {
	return f.aclProtoMap[proto]
}

func (f *FastPath) FlushAcls() {
	for i := 0; i < len(f.FastPolicyMaps); i++ {
		for j := TAP_MIN; j < TAP_MAX; j++ {
			f.FastPolicyMaps[i][j] = lru.NewCache64((int(f.MapSize) >> 3) * 7)
			f.FastPolicyMapsMini[i][j] = lru.NewCache32(int(f.MapSize) >> 3)
		}
	}
	atomic.StoreUint32(&f.FastPathMacCount, 0)
	atomic.StoreUint32(&f.FastPathPolicyCount, 0)
}

func (l *FastPath) getFastEpcs(maps *VlanAndPortMap, packet *LookupKey) (uint16, uint16) {
	epcs := maps.macEpcMap[(packet.SrcMac<<32)|(packet.DstMac&0xffffffff)]
	if epcs != 0 {
		return uint16(epcs >> 16), uint16(epcs & 0xffff)
	}
	return 0, 0
}

func (l *FastPath) getFastVlanPolicy(maps *VlanAndPortMap, srcEpc, dstEpc uint16, packet *LookupKey) *PolicyData {
	key := uint64(srcEpc)<<48 | uint64(dstEpc)<<32 | uint64(packet.Vlan)
	// vlanMap存储的是有方向的policy，在这里不用更改
	return maps.vlanPolicyMap[key]
}

func (l *FastPath) getFastPortPolicy(maps *VlanAndPortMap, srcEpc, dstEpc uint16, packet *LookupKey) (*EndpointStore, *PolicyData) {
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

func (f *FastPath) getVlanAndPortMap(packet *LookupKey, direction DirectionType, create bool, mapsForward *VlanAndPortMap) *VlanAndPortMap {
	maskSrc := f.IpNetmaskMap[uint16(packet.SrcIp>>16)]
	maskDst := f.IpNetmaskMap[uint16(packet.DstIp>>16)]
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
		maps := f.FastPolicyMaps[packet.FastIndex][packet.Tap]
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
		maps := f.FastPolicyMapsMini[packet.FastIndex][packet.Tap]
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

func (f *FastPath) addEpcMap(maps *VlanAndPortMap, srcEpc, dstEpc uint16, srcMac, dstMac uint64) {
	if srcEpc != 0 || dstEpc != 0 {
		key := srcMac<<32 | dstMac&math.MaxUint32
		if epc := maps.macEpcMap[key]; epc == 0 {
			atomic.AddUint32(&f.FastPathMacCount, 1)
		}
		// 仅仅使用具有区分性的mac的后32bit
		maps.macEpcMap[key] = uint32(srcEpc)<<16 | uint32(dstEpc)&math.MaxUint16
	}
}

func (f *FastPath) addVlanFastPolicy(srcEpc, dstEpc uint16, packet *LookupKey, policy *PolicyData, endpointData *EndpointData, mapsForward, mapsBackward *VlanAndPortMap) {
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
		atomic.AddUint32(&f.FastPathPolicyCount, 1)
		// 添加forward方向bitmap
		forward.AddAclGidBitmaps(packet, false, f.SrcGroupAclGidMaps[packet.Tap], f.DstGroupAclGidMaps[packet.Tap])
		mapsForward.vlanPolicyMap[key] = forward
	} else {
		// 添加forward方向bitmap
		forward.AddAclGidBitmaps(packet, false, f.SrcGroupAclGidMaps[packet.Tap], f.DstGroupAclGidMaps[packet.Tap])
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
		atomic.AddUint32(&f.FastPathPolicyCount, 1)
		// 添加backward方向bitmap
		backward.AddAclGidBitmaps(packet, true, f.SrcGroupAclGidMaps[packet.Tap], f.DstGroupAclGidMaps[packet.Tap])
		mapsBackward.vlanPolicyMap[key] = backward
	} else {
		// 添加backward方向bitmap
		backward.AddAclGidBitmaps(packet, true, f.SrcGroupAclGidMaps[packet.Tap], f.DstGroupAclGidMaps[packet.Tap])
		*vlanPolicy = *backward
	}
}

func (f *FastPath) addPortFastPolicy(endpointStore *EndpointStore, packetEndpointData *EndpointData, srcEpc, dstEpc uint16, packet *LookupKey, policyForward, policyBackward *PolicyData) (*VlanAndPortMap, *VlanAndPortMap) {
	forward, backward := INVALID_POLICY_DATA, INVALID_POLICY_DATA

	mapsForward := f.getVlanAndPortMap(packet, FORWARD, true, nil)
	if mapsForward == nil {
		return nil, nil
	}
	f.addEpcMap(mapsForward, srcEpc, dstEpc, packet.SrcMac, packet.DstMac)
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
	key := uint64(srcEpc)<<48 | uint64(dstEpc)<<32 | uint64(packet.SrcPort)<<16 | uint64(packet.DstPort)
	index := f.aclProtoMap[packet.Proto]
	if portPolicyValue := mapsForward.portPolicyMap[key]; portPolicyValue == nil {
		value := &PortPolicyValue{protoPolicy: make([]*PolicyData, 3), timestamp: packet.Timestamp}
		value.endpoint.InitPointer(endpointStore.Endpoints)
		// 添加forward方向bitmap
		forward.AddAclGidBitmaps(packet, false, f.SrcGroupAclGidMaps[packet.Tap], f.DstGroupAclGidMaps[packet.Tap])
		value.protoPolicy[index] = forward
		mapsForward.portPolicyMap[key] = value
		atomic.AddUint32(&f.FastPathPolicyCount, 1)
	} else {
		portPolicyValue.endpoint.InitPointer(endpointStore.Endpoints)
		// 添加forward方向bitmap
		forward.AddAclGidBitmaps(packet, false, f.SrcGroupAclGidMaps[packet.Tap], f.DstGroupAclGidMaps[packet.Tap])
		portPolicyValue.protoPolicy[index] = forward
		portPolicyValue.timestamp = packet.Timestamp
	}

	mapsBackward := f.getVlanAndPortMap(packet, BACKWARD, true, mapsForward)
	if mapsBackward == nil {
		return nil, nil
	}
	if mapsBackward != mapsForward {
		f.addEpcMap(mapsBackward, dstEpc, srcEpc, packet.DstMac, packet.SrcMac)
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
	endpoints := &EndpointData{SrcInfo: endpointStore.Endpoints.DstInfo, DstInfo: endpointStore.Endpoints.SrcInfo}
	key = uint64(dstEpc)<<48 | uint64(srcEpc)<<32 | uint64(packet.DstPort)<<16 | uint64(packet.SrcPort)
	if portPolicyValue := mapsBackward.portPolicyMap[key]; portPolicyValue == nil {
		value := &PortPolicyValue{protoPolicy: make([]*PolicyData, 3), timestamp: packet.Timestamp}
		value.endpoint.InitPointer(endpoints)
		// 添加backward方向bitmap
		backward.AddAclGidBitmaps(packet, true, f.SrcGroupAclGidMaps[packet.Tap], f.DstGroupAclGidMaps[packet.Tap])
		value.protoPolicy[index] = backward
		mapsBackward.portPolicyMap[key] = value
		atomic.AddUint32(&f.FastPathPolicyCount, 1)
	} else {
		portPolicyValue.endpoint.InitPointer(endpoints)
		// 添加backward方向bitmap
		backward.AddAclGidBitmaps(packet, true, f.SrcGroupAclGidMaps[packet.Tap], f.DstGroupAclGidMaps[packet.Tap])
		portPolicyValue.protoPolicy[index] = backward
		portPolicyValue.timestamp = packet.Timestamp
	}

	return mapsForward, mapsBackward
}

func (f *FastPath) makeIpNetmaskMap() {
	maskMap := &[math.MaxUint16 + 1]uint32{0}

	for netIp, mask := range f.maskMapFromPlatformData {
		if maskMap[netIp] < mask {
			maskMap[netIp] = mask
		}
	}
	for netIp, mask := range f.maskMapFromIpGroupData {
		if maskMap[netIp] < mask {
			maskMap[netIp] = mask
		}
	}

	f.IpNetmaskMap = maskMap
}

func (f *FastPath) GenerateIpNetmaskMapFromPlatformData(data []*PlatformData) {
	maskMap := &f.maskMapFromPlatformData
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
			// internet资源因为匹配左右IP, 不需要加在这里
			if ip == 0 && d.EpcId == 0 && maskSize == 0 {
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

	f.makeIpNetmaskMap()
}
