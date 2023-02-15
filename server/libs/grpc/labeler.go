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

package grpc

import (
	"encoding/binary"
	"net"
	"sort"
	"strings"

	"github.com/google/gopacket/layers"

	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/hmap/idmap"
	"github.com/deepflowio/deepflow/server/libs/hmap/lru"
	"github.com/deepflowio/deepflow/server/libs/logger"
	"github.com/deepflowio/deepflow/server/libs/policy"
	api "github.com/deepflowio/deepflow/server/libs/reciter-api"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

const (
	GROUP_CACHE_IPV6_KEYLEN        = 160 / 8
	SERVER_GROUP_CACHE_IPV6_KEYLEN = 192 / 8
	GROUP_CACHE_SIZE               = 65536
)

type GroupLabeler struct {
	ipCacheLocation   map[uint64]int
	ipv6CacheLocation *idmap.U160IDMap
	cache             [][]uint16

	serverIpCacheLocation   *idmap.U128IDMap
	serverIpv6CacheLocation *idmap.U192IDMap
	serverCache             [][]uint16

	ipGroup        *policy.IpResourceGroup
	internetGroups []uint16

	podGroup map[uint16]uint32

	*portFilter

	indexToGroupID []uint16
}

func NewGroupLabeler(log *logger.PrefixLogger, idMaps []api.GroupIDMap, portFilterLruCap int, moduleName string) *GroupLabeler {
	ipGroupData := make([]*policy.IpGroupData, 0, len(idMaps))
	internetGroups := make([]uint16, 0, 1)
	podGroup := make(map[uint16]uint32)
	indexToGroupID := make([]uint16, len(idMaps))
	for i, idMap := range idMaps {
		indexToGroupID[i] = idMap.GroupID
		if pod := idMap.PodGroupID; pod > 0 {
			podGroup[pod] = uint32(i)
			continue
		}
		if int16(idMap.L3EpcID) == datatype.EPC_FROM_INTERNET {
			internetGroups = append(internetGroups, uint16(idMap.GroupID))
			continue
		}
		ips := idMap.CIDRs
		for _, r := range idMap.IPRanges {
			startEnd := strings.Split(r, "-")
			if len(startEnd) != 2 {
				log.Warningf("invalid ip range %s", r)
				continue
			}
			ipStart := utils.ParserStringIp(startEnd[0])
			ipEnd := utils.ParserStringIp(startEnd[1])
			for _, cidr := range datatype.IpRangeConvert2CIDR(ipStart, ipEnd) {
				ips = append(ips, cidr.String())
			}
		}
		ipGroupData = append(ipGroupData, &policy.IpGroupData{
			Id:    uint32(i),
			EpcId: idMap.L3EpcID,
			Type:  policy.NAMED,
			Ips:   ips,
		})
	}
	ipGroup := policy.NewIpResourceGroup()
	ipGroup.Update(ipGroupData)
	return &GroupLabeler{
		ipCacheLocation:         make(map[uint64]int),
		ipv6CacheLocation:       idmap.NewU160IDMap(moduleName, GROUP_CACHE_SIZE).NoStats(),
		cache:                   make([][]uint16, 0, GROUP_CACHE_SIZE),
		serverIpCacheLocation:   idmap.NewU128IDMap(moduleName, GROUP_CACHE_SIZE).NoStats(),
		serverIpv6CacheLocation: idmap.NewU192IDMap(moduleName, GROUP_CACHE_SIZE).NoStats(),
		serverCache:             make([][]uint16, 0, GROUP_CACHE_SIZE),
		ipGroup:                 ipGroup,
		internetGroups:          internetGroups,
		podGroup:                podGroup,
		portFilter:              newPortFilter(log, idMaps, portFilterLruCap, moduleName),
		indexToGroupID:          indexToGroupID,
	}
}

func dedup(xs []uint16) []uint16 {
	if len(xs) == 0 {
		return xs
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i] < xs[j] })
	i, j := 0, 1
	for ; i < len(xs)-1; i++ {
		for j < len(xs) && xs[j] == xs[i] {
			j++
		}
		if j == len(xs) {
			break
		}
		xs[i+1] = xs[j]
	}
	return xs[:i+1]
}

func (l *GroupLabeler) backMapAndDedup(gs []uint16) []uint16 {
	if len(gs) == 0 {
		return gs
	}
	// 这里必须copy，否则会改变cache中的值
	newGroups := make([]uint16, len(gs))
	for i, g := range gs {
		newGroups[i] = l.indexToGroupID[g]
	}
	return dedup(newGroups)
}

func (l *GroupLabeler) innerQuery(l3EpcID int16, ip uint32, podGroupID uint16) []uint16 {
	if l3EpcID == datatype.EPC_FROM_INTERNET {
		return l.internetGroups
	}
	key := (uint64(podGroupID) << 48) | (uint64(uint16(l3EpcID)) << 32) | uint64(ip)
	if loc, in := l.ipCacheLocation[key]; in {
		return l.cache[loc]
	}
	groups := l.ipGroup.GetGroupIds(ip, &datatype.EndpointInfo{L3EpcId: int32(l3EpcID)})
	if gid, in := l.podGroup[podGroupID]; in {
		groups = append(groups, uint16(gid))
	}
	l.ipCacheLocation[key] = len(l.cache)
	l.cache = append(l.cache, groups)
	return groups
}

func (l *GroupLabeler) Query(l3EpcID int16, ip uint32, podGroupID uint16) []uint16 {
	return l.backMapAndDedup(l.innerQuery(l3EpcID, ip, podGroupID))
}

func (l *GroupLabeler) QueryService(l3EpcID int16, ip uint32, podGroupID uint16, protocol layers.IPProtocol, serverPort uint16) []uint16 {
	if l3EpcID == datatype.EPC_FROM_INTERNET {
		return l.internetGroups
	}
	key0 := (uint64(podGroupID) << 48) | (uint64(uint16(l3EpcID)) << 32) | uint64(ip)
	key1 := (uint64(serverPort) << 8) | uint64(protocol)
	if loc, added := l.serverIpCacheLocation.AddOrGet(key0, key1, uint32(len(l.serverCache)), false); !added {
		return l.backMapAndDedup(l.serverCache[loc])
	}
	all := l.innerQuery(l3EpcID, ip, podGroupID)
	filtered := make([]uint16, 0, len(all))
	for _, group := range all {
		if l.check(int16(group), protocol, serverPort) {
			filtered = append(filtered, group)
		}
	}
	l.serverCache = append(l.serverCache, filtered)
	return l.backMapAndDedup(filtered)
}

func (l *GroupLabeler) innerQueryIPv6(key []byte, hash uint32, l3EpcID int16, ip net.IP, podGroupID uint16) []uint16 {
	if loc, added := l.ipv6CacheLocation.AddOrGet(key, hash, uint32(len(l.cache)), false); !added {
		return l.cache[loc]
	}
	groups := l.ipGroup.GetGroupIdsByIpv6(ip, &datatype.EndpointInfo{L3EpcId: int32(l3EpcID)})
	if gid, in := l.podGroup[podGroupID]; in {
		groups = append(groups, uint16(gid))
	}
	l.cache = append(l.cache, groups)
	return groups
}

func (l *GroupLabeler) QueryIPv6(l3EpcID int16, ip net.IP, podGroupID uint16) []uint16 {
	if l3EpcID == datatype.EPC_FROM_INTERNET {
		return l.internetGroups
	}
	var key [GROUP_CACHE_IPV6_KEYLEN]byte
	binary.BigEndian.PutUint16(key[:], uint16(l3EpcID))
	binary.BigEndian.PutUint16(key[2:], podGroupID)
	copy(key[4:], ip)
	var hash uint32
	for i := 0; i < len(key); i += 4 {
		hash ^= binary.BigEndian.Uint32(key[i:])
	}
	return l.backMapAndDedup(l.innerQueryIPv6(key[:], hash, l3EpcID, ip, podGroupID))
}

func (l *GroupLabeler) QueryServiceIPv6(l3EpcID int16, ip net.IP, podGroupID uint16, protocol layers.IPProtocol, serverPort uint16) []uint16 {
	if l3EpcID == datatype.EPC_FROM_INTERNET {
		return l.internetGroups
	}
	// server侧查询用的key多protocol和serverPort，放在key前部4字节，这样key后20字节和client侧查询一致
	// 在计算hash时也利用这一点，减少重复计算
	var key [SERVER_GROUP_CACHE_IPV6_KEYLEN]byte
	binary.BigEndian.PutUint16(key[:], uint16(protocol))
	binary.BigEndian.PutUint16(key[2:], serverPort)
	binary.BigEndian.PutUint16(key[4:], uint16(l3EpcID))
	binary.BigEndian.PutUint16(key[6:], podGroupID)
	copy(key[8:], ip)
	var hash uint32
	for i := 0; i < len(key); i += 4 {
		hash ^= binary.BigEndian.Uint32(key[i:])
	}
	if loc, added := l.serverIpv6CacheLocation.AddOrGet(key[:], hash, uint32(len(l.serverCache)), false); !added {
		return l.backMapAndDedup(l.serverCache[loc])
	}
	// 排除掉前4字节就是client查询的key
	hash ^= binary.BigEndian.Uint32(key[:])
	all := l.innerQueryIPv6(key[4:], hash, l3EpcID, ip, podGroupID)
	filtered := make([]uint16, 0, len(all))
	for _, group := range all {
		if l.check(int16(group), protocol, serverPort) {
			filtered = append(filtered, group)
		}
	}
	l.serverCache = append(l.serverCache, filtered)
	return l.backMapAndDedup(filtered)
}

type portFilter struct {
	// key = group 16 bit + protocol 8bit + server_port 16bit
	fastMap *lru.U64LRU

	// key = group 16 bit + protocol 9bit
	portRanges map[uint32][]datatype.PortRange

	hasAnyProtocol bool
}

func newPortFilter(log *logger.PrefixLogger, groupIDMaps []api.GroupIDMap, lruCap int, moduleName string) *portFilter {
	hasAnyProtocol := false
	groupProtocolMap := make(map[uint32][]datatype.PortRange)
	for i, entry := range groupIDMaps {
		if entry.Protocol == policy.PROTO_ALL {
			hasAnyProtocol = true
		}
		ports := []datatype.PortRange{datatype.NewPortRange(0, 65535)}
		if entry.ServerPorts != "" {
			ports = datatype.SplitPort2Int(entry.ServerPorts)
		}
		key := (uint32(i&0xFFFF) << 9) | uint32(entry.Protocol)&0x1FF
		if _, in := groupProtocolMap[key]; !in {
			groupProtocolMap[key] = ports
		} else {
			groupProtocolMap[key] = append(groupProtocolMap[key], ports...)
		}
	}
	return &portFilter{fastMap: lru.NewU64LRU(moduleName+"_port_filter", lruCap>>3, lruCap), portRanges: groupProtocolMap, hasAnyProtocol: hasAnyProtocol}
}

func (l *portFilter) check(group int16, protocol layers.IPProtocol, serverPort uint16) bool {
	// key = group 16bit + protocol 8bit + server_port 16bit
	fastKey := ((uint64(group) & 0xFFFF) << 24) | ((uint64(protocol) & 0xFF) << 16) | (uint64(serverPort) & 0xFFFF)
	if lruValue, in := l.fastMap.Get(fastKey, true); in {
		return lruValue.(bool)
	}
	if result := l.rawCheck(group, uint16(protocol), serverPort); result {
		l.fastMap.Add(fastKey, true)
		return true
	}
	if l.hasAnyProtocol {
		if result := l.rawCheck(group, policy.PROTO_ALL, serverPort); result {
			l.fastMap.Add(fastKey, true)
			return true
		}
	}
	l.fastMap.Add(fastKey, false)
	return false
}

func (l *portFilter) rawCheck(group int16, protocol uint16, serverPort uint16) bool {
	// key = group 16 bit + protocol 9bit
	key := ((uint32(group) & 0xFFFF) << 9) | (uint32(protocol) & 0x1FF)
	for _, portRange := range l.portRanges[key] {
		// 使用serverPort为0 查询时可匹配任意端口，即支持利用 VPC + IP 匹配任意端口的服务
		if serverPort == 0 || serverPort >= portRange.Min() && serverPort <= portRange.Max() {
			return true
		}
	}
	return false
}
