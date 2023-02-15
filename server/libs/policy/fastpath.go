/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package policy

import (
	"fmt"
	"math"
	"strconv"

	. "github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/hmap/lru"
	"github.com/deepflowio/deepflow/server/libs/stats"
	. "github.com/deepflowio/deepflow/server/libs/utils"
)

const (
	MAX_QUEUE_COUNT = 16
)

type PortPolicyValue struct {
	endpoint    EndpointStore
	protoPolicy [ACL_PROTO_MAX]*PolicyData
}

type VlanAndPortMap struct {
	// 使用源目的MAC的后两个字节（共4字节）和源目的端口作为查询key
	portPolicyMap map[uint64]*PortPolicyValue
}

type Padding [8]uint64

type FastPath struct {
	maskMapFromPlatformData [math.MaxUint16 + 1]uint32
	maskMapFromIpGroupData  [math.MaxUint16 + 1]uint32
	maskMapFromCidrData     [math.MaxUint16 + 1]uint32
	padding0                Padding                    // 避免cache miss
	IpNetmaskMap            [math.MaxUint16 + 1]uint32 // 根据IP地址查找对应的最大掩码
	padding1                Padding

	FastPortPolicyMaps  [MAX_QUEUE_COUNT + 1][TAP_MAX]*lru.U128LRU // 快速路径上的Policy映射表，Key为IP掩码对 + MAC + PORT，Value为PortPolicyValue
	padding2            Padding
	fastPolicyMapsFlush [MAX_QUEUE_COUNT + 1]bool // 标记对应的LRU是否需要Clear

	padding3                              Padding
	FastPathHit                           uint64
	padding4                              Padding
	FastPathMacCount, FastPathPolicyCount uint32

	padding5               Padding
	MapSize                uint32
	padding6               Padding
	flushCount, queueCount int
}

func (f *FastPath) Init(mapSize uint32, queueCount int) {
	if queueCount > MAX_QUEUE_COUNT {
		panic(fmt.Sprintf("queueCount超出最大限制%d", MAX_QUEUE_COUNT))
	}
	f.MapSize = mapSize
	f.queueCount = queueCount
}

func (f *FastPath) FlushAcls() {
	for i := 0; i < f.queueCount; i++ {
		f.fastPolicyMapsFlush[i] = true
	}
	f.flushCount = f.queueCount
	f.FastPathMacCount = 0
	f.FastPathPolicyCount = 0
}

func (f *FastPath) generateMaskedIp(packet *LookupKey) (uint32, uint32) {
	if len(packet.Src6Ip) == 0 {
		maskedSrcIp := packet.SrcIp & f.IpNetmaskMap[uint16(packet.SrcIp>>16)]
		maskedDstIp := packet.DstIp & f.IpNetmaskMap[uint16(packet.DstIp>>16)]
		return maskedSrcIp, maskedDstIp
	} else {
		return GetIpHash(packet.Src6Ip), GetIpHash(packet.Dst6Ip)
	}
}

func (f *FastPath) GenerateMapKey(packet *LookupKey, direction DirectionType) (uint64, uint64) {
	maskedSrcIp, maskedDstIp := f.generateMaskedIp(packet)
	srcPort, dstPort := uint64(packet.SrcPort), uint64(packet.DstPort)
	srcMacSuffix, dstMacSuffix := uint64(packet.SrcMac&0xffff), uint64(packet.DstMac&0xffff)
	if direction == BACKWARD {
		srcMacSuffix, dstMacSuffix = dstMacSuffix, srcMacSuffix
		maskedSrcIp, maskedDstIp = maskedDstIp, maskedSrcIp
		srcPort, dstPort = dstPort, srcPort
	}

	key1 := uint64(maskedSrcIp)<<32 | srcMacSuffix<<16 | srcPort
	key2 := uint64(maskedDstIp)<<32 | dstMacSuffix<<16 | dstPort
	return key1, key2
}

func (f *FastPath) getPortFastPolicy(packet *LookupKey) (*EndpointStore, *PolicyData) {
	if f.flushCount > 0 && f.fastPolicyMapsFlush[packet.FastIndex] {
		for i := TAP_MIN; i < TAP_MAX; i++ {
			if f.FastPortPolicyMaps[packet.FastIndex][i] != nil {
				f.FastPortPolicyMaps[packet.FastIndex][i].Clear()
			}
		}
		f.flushCount -= 1
		f.fastPolicyMapsFlush[packet.FastIndex] = false
		return nil, nil
	}
	if f.FastPortPolicyMaps[packet.FastIndex][packet.TapType] == nil {
		f.FastPortPolicyMaps[packet.FastIndex][packet.TapType] = lru.NewU128LRU(
			"policy-fastpath-port", int(f.MapSize/8), int(f.MapSize),
			stats.OptionStatTags{"index": strconv.Itoa((packet.FastIndex * int(TAP_MAX-1)) + int(packet.TapType))})
		return nil, nil
	}
	key1, key2 := f.GenerateMapKey(packet, FORWARD)
	value, ok := f.FastPortPolicyMaps[packet.FastIndex][packet.TapType].Get(key1, key2, true)
	if ok {
		portPolicy := value.(*PortPolicyValue)
		if policy := portPolicy.protoPolicy[packet.Proto]; policy != nil {
			return &portPolicy.endpoint, policy
		}
	}
	return nil, nil
}

func (f *FastPath) addPortFastPolicy(endpointStore *EndpointStore, packetEndpointData *EndpointData, packet *LookupKey, policyForward, policyBackward *PolicyData) {
	if f.flushCount > 0 && f.fastPolicyMapsFlush[packet.FastIndex] {
		for i := TAP_MIN; i < TAP_MAX; i++ {
			if f.FastPortPolicyMaps[packet.FastIndex][i] != nil {
				f.FastPortPolicyMaps[packet.FastIndex][i].Clear()
			}
		}
		f.flushCount -= 1
		f.fastPolicyMapsFlush[packet.FastIndex] = false
	}

	if f.FastPortPolicyMaps[packet.FastIndex][packet.TapType] == nil {
		f.FastPortPolicyMaps[packet.FastIndex][packet.TapType] = lru.NewU128LRU(
			"policy-fastpath-port", int(f.MapSize/8), int(f.MapSize),
			stats.OptionStatTags{"index": strconv.Itoa((packet.FastIndex * int(TAP_MAX-1)) + int(packet.TapType))})
	}

	forward, backward := INVALID_POLICY_DATA, INVALID_POLICY_DATA
	key1, key2 := f.GenerateMapKey(packet, FORWARD)

	id := getAclId(policyForward.AclId, policyBackward.AclId)
	if id > 0 {
		forward = new(PolicyData)
		forward.NpbActions = make([]NpbActions, 0, len(policyForward.NpbActions)+len(policyBackward.NpbActions))
		forward.MergeNpbAction(append(policyForward.NpbActions, policyBackward.NpbActions...), id)
		if packet.HasFeatureFlag(NPB) {
			forward.FormatNpbAction()
		}
	}

	if value, ok := f.FastPortPolicyMaps[packet.FastIndex][packet.TapType].Get(key1, key2, true); !ok {
		value := &PortPolicyValue{}
		value.endpoint.InitPointer(endpointStore.Endpoints)
		value.protoPolicy[packet.Proto] = forward
		f.FastPortPolicyMaps[packet.FastIndex][packet.TapType].Add(key1, key2, value)
		f.FastPathPolicyCount++
	} else {
		portPolicyValue := value.(*PortPolicyValue)
		portPolicyValue.endpoint.InitPointer(endpointStore.Endpoints)
		portPolicyValue.protoPolicy[packet.Proto] = forward
	}

	if key1 == key2 {
		return
	}
	key1, key2 = key2, key1

	if id > 0 {
		backward = new(PolicyData)
		backward.NpbActions = make([]NpbActions, 0, len(policyForward.NpbActions)+len(policyBackward.NpbActions))
		backward.MergeNpbAndSwapDirection(append(policyForward.NpbActions, policyBackward.NpbActions...), id)
		if packet.HasFeatureFlag(NPB) {
			backward.FormatNpbAction()
		}
	}
	endpoints := &EndpointData{SrcInfo: endpointStore.Endpoints.DstInfo, DstInfo: endpointStore.Endpoints.SrcInfo}
	if value, ok := f.FastPortPolicyMaps[packet.FastIndex][packet.TapType].Get(key1, key2, true); !ok {
		value := &PortPolicyValue{}
		value.endpoint.InitPointer(endpoints)
		value.protoPolicy[packet.Proto] = backward
		f.FastPortPolicyMaps[packet.FastIndex][packet.TapType].Add(key1, key2, value)
		f.FastPathPolicyCount++
	} else {
		portPolicyValue := value.(*PortPolicyValue)
		portPolicyValue.endpoint.InitPointer(endpoints)
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
		if f.IpNetmaskMap[i] < f.maskMapFromCidrData[i] {
			f.IpNetmaskMap[i] = f.maskMapFromCidrData[i]
		}
	}
}

func (f *FastPath) GenerateIpNetmaskMapFromPlatformData(data []PlatformData) {
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

func (f *FastPath) GenerateIpNetmaskMapFromCidrData(data []*Cidr) {
	maskMap := &f.maskMapFromCidrData
	for key, _ := range maskMap {
		maskMap[key] = 0
	}
	for _, d := range data {
		ip := d.IpNet.IP
		netmask := d.IpNet.Mask

		if ip = ip.To4(); ip == nil {
			// IPv6不支持
			continue
		}
		maskSize, bits := netmask.Size()
		if maskSize == 0 && bits == 0 {
			continue
		}

		ip4 := IpToUint32(ip)
		if ip4 == 0 {
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

	f.makeIpNetmaskMap()
}

func (f *FastPath) Close() {
	// 从statsd中移除，避免内存泄露
	for i := 0; i < f.queueCount; i++ {
		for j := TAP_MIN; j < TAP_MAX; j++ {
			if f.FastPortPolicyMaps[i][j] != nil {
				f.FastPortPolicyMaps[i][j].Close()
			}
		}
	}
}
