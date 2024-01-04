/*
 * Copyright (c) 2024 Yunshan Networks
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
	"container/list"
	"math"
	"net"
	"sort"

	. "github.com/google/gopacket/layers"

	"github.com/deepflowio/deepflow/server/libs/bit"
	. "github.com/deepflowio/deepflow/server/libs/datatype"
	. "github.com/deepflowio/deepflow/server/libs/utils"
)

const (
	_BROADCAST_MAC = uint64(0xffffffffffff)
	_MULTICAST_MAC = uint64(0x010000000000)
)

type IpMapDatas []map[IpKey]*PlatformData
type IpMapData map[IpKey]*PlatformData
type Ip6MapData map[IpKey]*list.List
type MacMapData map[MacKey]*PlatformData
type EpcIpMapData map[EpcIpKey]*PlatformData
type EpcIp6MapData map[EpcIpKey]*list.List
type MacForIpTable map[uint64]net.IP

type MacTable struct {
	macMap MacMapData
}

type IpTable struct {
	ipMap IpMapData
}

type Ip6Table struct {
	ip6Map Ip6MapData
}

type EpcIpTable struct {
	epcIpMap  EpcIpMapData
	epcIp6Map EpcIp6MapData
}

type CloudPlatformLabeler struct {
	macTable            *MacTable
	macForIpTable       MacForIpTable
	ipTables            [MASK_LEN_NUM]*IpTable
	ip6Tables           *Ip6Table // TODO: 因为目前IPv6不支持IP资源组类型的，掩码都是128，所以不用建数组
	epcIpTable          *EpcIpTable
	netmaskBitmap       uint32
	peerConnectionTable map[int32][]int32
	epcCidrMapData      map[int32][]*Cidr
	tunnelIdCidrMapData map[uint32][]*Cidr
}

func NewCloudPlatformLabeler(queueCount int, mapSize uint32) *CloudPlatformLabeler {
	macTable := &MacTable{
		macMap: make(MacMapData),
	}
	var ipTables [MASK_LEN_NUM]*IpTable
	for i := uint32(MIN_MASK_LEN); i <= MAX_MASK_LEN; i++ {
		ipTables[i] = &IpTable{
			ipMap: make(IpMapData),
		}
	}
	ip6Tables := &Ip6Table{
		ip6Map: make(Ip6MapData),
	}
	epcIpTable := &EpcIpTable{
		epcIpMap:  make(EpcIpMapData),
		epcIp6Map: make(EpcIp6MapData),
	}
	cloud := &CloudPlatformLabeler{
		macTable:            macTable,
		macForIpTable:       make(MacForIpTable),
		ipTables:            ipTables,
		ip6Tables:           ip6Tables,
		epcIpTable:          epcIpTable,
		netmaskBitmap:       uint32(0),
		peerConnectionTable: make(map[int32][]int32),
	}
	return cloud
}

func PortInDeepflowExporter(inPort uint32) bool {
	return PACKET_SOURCE_TOR == ((inPort) & PACKET_SOURCE_TOR)
}

// FIXME: 需要验证是否有冲突
func calcHashKey(mac uint64, ip uint32) uint64 {
	return uint64(mac<<32) | uint64(ip)
}

func (l *CloudPlatformLabeler) GetDataByMac(key MacKey) *PlatformData {
	if info, ok := l.macTable.macMap[key]; ok {
		return info
	}

	return nil
}

func (l *CloudPlatformLabeler) UpdateMacTable(macmap MacMapData) {
	if macmap != nil {
		l.macTable.macMap = macmap
	}
}

func (l *CloudPlatformLabeler) GenerateMacData(platformDatas []PlatformData) MacMapData {
	macMap := make(MacMapData)
	for i, _ := range platformDatas {
		platformData := &platformDatas[i]
		if platformData.SkipMac {
			continue
		}

		if platformData.Mac != 0 {
			macMap[MacKey(platformData.Mac)] = platformData
		}
	}
	return macMap
}

func (l *CloudPlatformLabeler) GetRealIpByMac(mac uint64, isIpv6 bool) net.IP {
	key := mac
	if isIpv6 {
		key |= 1 << 56
	}
	if ip, ok := l.macForIpTable[key]; ok {
		return ip
	}
	return nil
}

func (l *CloudPlatformLabeler) GenerateMacForIpTable(platformDatas []PlatformData) MacForIpTable {
	macForIpTable := make(MacForIpTable)
	for i, _ := range platformDatas {
		platformData := &platformDatas[i]
		if platformData.SkipMac {
			continue
		}

		if platformData.Mac != 0 {
			hasIpv4, hasIpv6 := false, false
			for i, _ := range platformData.Ips {
				ipNet := &platformData.Ips[i]
				ipLength := len(ipNet.RawIp) // platformData中保证IPv4地址但是长度为16的已经转化为长度4
				if !hasIpv4 && ipLength == net.IPv4len {
					key := platformData.Mac
					macForIpTable[key] = ipNet.RawIp
					hasIpv4 = true
				}
				if !hasIpv6 && ipLength == net.IPv6len {
					key := uint64(1<<56) | platformData.Mac
					macForIpTable[key] = ipNet.RawIp
					hasIpv6 = true
				}
				if hasIpv4 && hasIpv6 {
					break
				}
			}
		}
	}
	return macForIpTable
}

func (l *CloudPlatformLabeler) UpdateMacForIpTable(macForIpTable MacForIpTable) {
	if macForIpTable != nil {
		l.macForIpTable = macForIpTable
	}
}

func IfHasNetmaskBit(bitmap uint32, k uint32) bool {
	return (bitmap & (1 << k)) != 0
}

func (l *CloudPlatformLabeler) GetDataByIp4(ip uint32) *PlatformData {
	netmaskBitmap := l.netmaskBitmap
	for netmaskBitmap > 0 {
		i := uint32(bit.CountTrailingZeros32(netmaskBitmap))
		netmaskBitmap ^= 1 << i
		subip := IpKey(ip & (math.MaxUint32 << i))
		if info, ok := l.ipTables[i].ipMap[subip]; ok {
			return info
		}
	}
	return nil
}

func (l *CloudPlatformLabeler) GetDataByIp6(ip net.IP) *PlatformData {
	hash := GetIpHash(ip)
	if platformList, ok := l.ip6Tables.ip6Map[IpKey(hash)]; ok {
		for e := platformList.Front(); e != nil; e = e.Next() {
			platformData := e.Value.(*PlatformData)
			for _, ipData := range platformData.Ips {
				if ipData.RawIp.Equal(ip) {
					return platformData
				}
			}
		}
	}
	return nil
}

func (l *CloudPlatformLabeler) GetDataByIp(ip net.IP) *PlatformData {
	if len(ip) == 4 {
		return l.GetDataByIp4(IpToUint32(ip))
	} else {
		return l.GetDataByIp6(ip)
	}
}

func (l *CloudPlatformLabeler) GenerateIpData(platformDatas []PlatformData) (IpMapDatas, Ip6MapData) {
	ips := make(IpMapDatas, MASK_LEN_NUM)
	ip6s := make(Ip6MapData)

	for i := uint32(MIN_MASK_LEN); i <= MAX_MASK_LEN; i++ {
		ips[i] = make(IpMapData)
	}
	for i, _ := range platformDatas {
		platformData := &platformDatas[i]
		if platformData.IfType != IF_TYPE_WAN {
			continue
		}
		for _, ipData := range platformData.Ips {
			if len(ipData.RawIp) == 4 {
				netmask := MAX_MASK_LEN - ipData.Netmask
				ips[netmask][IpKey(IpToUint32(ipData.RawIp))] = platformData
				l.netmaskBitmap |= 1 << netmask
			} else {
				hash := GetIpHash(ipData.RawIp)
				platformList, exist := ip6s[IpKey(hash)]
				if !exist {
					platformList = list.New()
					ip6s[IpKey(hash)] = platformList
				}
				platformList.PushBack(platformData)
			}
		}
	}

	return ips, ip6s
}

func (l *CloudPlatformLabeler) UpdateIpTable(ipDatas IpMapDatas, ip6Data Ip6MapData) {
	for index, ipMap := range ipDatas {
		l.ipTables[IpKey(index)].UpdateIpMap(ipMap)
	}
	l.ip6Tables.ip6Map = ip6Data
}

func (t *IpTable) UpdateIpMap(ipMap IpMapData) {
	if ipMap != nil {
		t.ipMap = ipMap
	}
}

func (l *CloudPlatformLabeler) GetDataByEpcIp(epc int32, ip net.IP) *PlatformData {
	if len(ip) == 4 {
		key := EpcIpKey((uint64(epc) << 32) | uint64(IpToUint32(ip)))
		if info, ok := l.epcIpTable.epcIpMap[key]; ok {
			return info
		}
	} else {
		var value *PlatformData
		hash := GetIpHash(ip)
		key := EpcIpKey((uint64(epc) << 32) | uint64(hash))
		if platformList, ok := l.epcIpTable.epcIp6Map[key]; ok {
			for e := platformList.Front(); e != nil; e = e.Next() {
				platformData := e.Value.(*PlatformData)
				for _, ipData := range platformData.Ips {
					if ipData.RawIp.Equal(ip) {
						value = platformData
						break
					}
				}
				// LB可能存在多个LB主机，对应的相同的epc+ip可能有多个，这里优先返回本地的以获取IsLocal
				if value != nil && value.IsLocal {
					return value
				}
			}
		}
		return value
	}
	return nil
}

func (l *CloudPlatformLabeler) GenerateEpcIpData(platformDatas []PlatformData) (EpcIpMapData, EpcIp6MapData) {
	epcIpMap := make(EpcIpMapData)
	epcIp6Map := make(EpcIp6MapData)
	for i, _ := range platformDatas {
		platformData := &platformDatas[i]
		for _, ipData := range platformData.Ips {
			epcId := uint64(platformData.EpcId)
			if platformData.EpcId == EPC_FROM_DEEPFLOW {
				epcId = 0
			}
			if len(ipData.RawIp) == 4 {
				key := EpcIpKey((epcId << 32) | uint64(IpToUint32(ipData.RawIp)))
				// LB可能存在多个LB主机，对应的相同的epc+ip可能有多个，本地的优先存储以获取IsLocal
				value, exist := epcIpMap[key]
				if !exist || !value.IsLocal {
					epcIpMap[key] = platformData
				}
			} else {
				hash := GetIpHash(ipData.RawIp)
				key := EpcIpKey((epcId << 32) | uint64(hash))
				platformList, exist := epcIp6Map[key]
				if !exist {
					platformList = list.New()
					epcIp6Map[key] = platformList
				}
				platformList.PushBack(platformData)
			}
		}
	}

	return epcIpMap, epcIp6Map
}

func (l *CloudPlatformLabeler) UpdateEpcIpTable(epcIpMap EpcIpMapData, epcIp6Map EpcIp6MapData) {
	if epcIpMap != nil {
		l.epcIpTable.epcIpMap = epcIpMap
	}
	if epcIp6Map != nil {
		l.epcIpTable.epcIp6Map = epcIp6Map
	}
}

func (l *CloudPlatformLabeler) UpdatePeerConnectionTable(connections []*PeerConnection) {
	peerConnectionTable := make(map[int32][]int32, 1000)
	for _, connection := range connections {
		// local
		peerEpcs := peerConnectionTable[connection.LocalEpc]
		if peerEpcs == nil {
			peerEpcs = make([]int32, 0, 2)
		}
		peerConnectionTable[connection.LocalEpc] = append(peerEpcs, connection.RemoteEpc)

		// reomte
		peerEpcs = peerConnectionTable[connection.RemoteEpc]
		if peerEpcs == nil {
			peerEpcs = make([]int32, 0, 2)
		}
		peerConnectionTable[connection.RemoteEpc] = append(peerEpcs, connection.LocalEpc)
	}
	l.peerConnectionTable = peerConnectionTable
}

func (l *CloudPlatformLabeler) UpdateInterfaceTable(platformDatas []PlatformData) {
	if platformDatas != nil {
		l.UpdateMacTable(l.GenerateMacData(platformDatas))
		l.UpdateIpTable(l.GenerateIpData(platformDatas))
		l.UpdateEpcIpTable(l.GenerateEpcIpData(platformDatas))
		l.UpdateMacForIpTable(l.GenerateMacForIpTable(platformDatas))
	}
}

func (l *CloudPlatformLabeler) UpdateCidr(cidrs []*Cidr) {
	epcCidr := make(map[int32][]*Cidr, len(cidrs))
	tunnelCidr := make(map[uint32][]*Cidr, len(cidrs))
	for _, cidr := range cidrs {
		epc := cidr.EpcId
		// WAN的CIDR都存在EPC_FROM_DEEPFLOW表中
		if cidr.Type == CIDR_TYPE_WAN {
			epc = EPC_FROM_DEEPFLOW
		}
		cidrs := epcCidr[epc]
		if cidrs == nil {
			cidrs = make([]*Cidr, 0, 2)
		}
		epcCidr[epc] = append(cidrs, cidr)

		if cidr.TunnelId > 0 {
			cidrs := tunnelCidr[cidr.TunnelId]
			if cidrs == nil {
				cidrs = make([]*Cidr, 0, 2)
			}
			tunnelCidr[cidr.TunnelId] = append(cidrs, cidr)
		}
	}

	for _, cidrs := range epcCidr {
		sort.SliceStable(cidrs, func(i, j int) bool {
			n, _ := cidrs[i].IpNet.Mask.Size()
			m, _ := cidrs[j].IpNet.Mask.Size()
			return n > m
		})
	}

	for _, cidrs := range tunnelCidr {
		sort.SliceStable(cidrs, func(i, j int) bool {
			n, _ := cidrs[i].IpNet.Mask.Size()
			m, _ := cidrs[j].IpNet.Mask.Size()
			return n > m
		})
	}
	l.epcCidrMapData = epcCidr
	l.tunnelIdCidrMapData = tunnelCidr
}

// 函数通过EPC+IP查询对应的CIDR，获取EPC标记
// 注意当查询外网时必须给epc参数传递EPC_FROM_DEEPFLOW值，表示在所有WAN CIDR范围内搜索，并返回该CIDR的真实EPC
func (l *CloudPlatformLabeler) setEpcByCidr(ip net.IP, epc int32, endpointInfo *EndpointInfo) bool {
	for _, cidr := range l.epcCidrMapData[epc] {
		if cidr.IpNet.Contains(ip) {
			endpointInfo.L3EpcId = cidr.EpcId
			endpointInfo.IsVIP = cidr.IsVIP
			return true
		}
	}
	return false
}

// 函数通过EPC+IP查询对应的CIDR，获取EPC和VIP标记
// 注意当查询外网时必须给epc参数传递EPC_FROM_DEEPFLOW值，表示在所有WAN CIDR范围内搜索，并返回该CIDR的真实EPC
func (l *CloudPlatformLabeler) setEpcAndVIPByTunnelCidr(ip net.IP, tunnelId uint32, endpointInfo *EndpointInfo) (bool, bool) {
	cidrs := l.tunnelIdCidrMapData[tunnelId]
	for _, cidr := range cidrs {
		if cidr.IpNet.Contains(ip) {
			endpointInfo.L3EpcId = cidr.EpcId
			endpointInfo.IsVIP = cidr.IsVIP
			return true, cidr.Type == CIDR_TYPE_WAN
		}
	}
	// 在光大青云环境中跨VPC通信时，在dvr master宿主机上bond口采集流量的vni为dvr master和
	// dvr slave自管网络的vni，和overlay ip对应的vni不一致，目前因为自管网络的EPC和overlay
	// ip所在子网的EPC相同，所以这里通过vni查询失败后再通过EPC查询
	lastEpc := int32(0)
	for _, cidr := range cidrs {
		// 这里只需要找不重复的EpcID即可
		if cidr.EpcId == lastEpc {
			continue
		}
		lastEpc = cidr.EpcId
		if ok := l.setEpcByCidr(ip, cidr.EpcId, endpointInfo); ok {
			return true, cidr.Type == CIDR_TYPE_WAN
		}
	}
	return false, false
}

func (l *CloudPlatformLabeler) GetEndpointInfo(mac uint64, ip net.IP, tapType TapType, l3End bool, tunnelId uint32) (*EndpointInfo, bool) {
	isWAN := false
	endpointInfo := new(EndpointInfo)
	// 如下场景无法直接查询隧道内层的MAC地址确定EPC：
	// 1. 腾讯TCE：使用GRE做隧道封装，内层没有MAC
	// 2. 使用VXLAN隧道但内层MAC已无法识别
	//    目前发现青云私有云属于这种情况，VXLAN内层的MAC可能不是任何一个实际存在的虚拟网卡MAC
	// 采集器并不关心具体的云平台差异，只要控制器下发隧道ID，都会优先使用它进行查询
	if tunnelId > 0 {
		// step 1: 查询tunnelID监控网段(cidr)
		_, isWAN = l.setEpcAndVIPByTunnelCidr(ip, tunnelId, endpointInfo)
		if IsGrePseudoInnerMac(mac) {
			// 腾讯TCE使用GRE封装场景下，此处拿到是伪造MAC，无法用于查询云平台信息，直接在此分支中返回即可
			if endpointInfo.L3EpcId == 0 {
				// step 2: 查询平台数据WAN接口
				if platformData := l.GetDataByIp(ip); platformData != nil {
					endpointInfo.SetL3Data(platformData)
					isWAN = platformData.IfType == IF_TYPE_WAN
				} else {
					// step 3: 查询DEEPFLOW添加的WAN监控网段(cidr)
					isWAN = l.setEpcByCidr(ip, EPC_FROM_DEEPFLOW, endpointInfo)
				}
			}
			return endpointInfo, isWAN
		} else {
			// 其他云如果使用TunnelID没有查询到，还需要继续用MAC查询
		}
	}
	// step 1: 使用mac查询L2
	platformData := l.GetDataByMac(MacKey(mac))
	if platformData != nil {
		endpointInfo.SetL2Data(platformData)
		// L2End为真时，可通过流量中的Mac判断是否为VIP设备
		endpointInfo.IsVIPInterface = platformData.IsVIPInterface
		// IP为0，则取MAC对应的二层数据作为三层数据
		if l3End || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			endpointInfo.SetL3Data(platformData)
			isWAN = platformData.IfType == IF_TYPE_WAN
			return endpointInfo, isWAN
		}
	}
	// step 2: 使用L2EpcId + IP查询L3，如果L2EpcId为0，会查询到DEEPFLOW添加的监控IP
	if platformData = l.GetDataByEpcIp(endpointInfo.L2EpcId, ip); platformData != nil {
		endpointInfo.SetL3Data(platformData)
		isWAN = platformData.IfType == IF_TYPE_WAN
	}
	return endpointInfo, isWAN
}

// 检查L2End和L3End是否有可能进行修正
func (l *CloudPlatformLabeler) CheckEndpointDataIfNeedCopy(store *EndpointStore, key *LookupKey) *EndpointData {
	// store初始化的时候, 当L2End和L3End为TRUE会修正L3EpcId,
	return store.UpdatePointer(key.L2End0, key.L2End1, key.L3End0, key.L3End1)
}

func (l *CloudPlatformLabeler) UpdateEndpointData(endpoint *EndpointStore, key *LookupKey) *EndpointData {
	return l.CheckEndpointDataIfNeedCopy(endpoint, key)
}

func (l *CloudPlatformLabeler) ModifyEndpointData(endpointData *EndpointData, key *LookupKey) {
	srcData, dstData := endpointData.SrcInfo, endpointData.DstInfo
	srcIp, dstIp := IpFromUint32(key.SrcIp), IpFromUint32(key.DstIp)
	if key.EthType == EthernetTypeIPv6 || len(key.Src6Ip) > 0 {
		srcIp, dstIp = key.Src6Ip, key.Dst6Ip
	}
	// 默认L2End为false时L3EpcId == 0，L2End为true时L2EpcId不为0
	if dstData.L3EpcId == 0 && srcData.L3EpcId > 0 {
		if key.DstMac == _BROADCAST_MAC || key.DstMac&_MULTICAST_MAC == _MULTICAST_MAC {
			dstData.L3EpcId = srcData.L3EpcId
			dstData.L2EpcId = srcData.L2EpcId
			dstData.IsDevice = true
		} else if platformData := l.GetDataByEpcIp(srcData.L3EpcId, dstIp); platformData != nil {
			// 本端IP + 对端EPC查询EPC-IP表
			dstData.SetL3Data(platformData)
		} else {
			// 本端IP + 对端EPC查询CIDR表
			l.setEpcByCidr(dstIp, srcData.L3EpcId, dstData)
		}
	}

	if srcData.L3EpcId == 0 && dstData.L3EpcId > 0 {
		if platformData := l.GetDataByEpcIp(dstData.L3EpcId, srcIp); platformData != nil {
			// 本端IP + 对端EPC查询EPC-IP表
			srcData.SetL3Data(platformData)
		} else {
			// 本端IP + 对端EPC查询CIDR表
			l.setEpcByCidr(srcIp, dstData.L3EpcId, srcData)
		}
	}
}

func (l *CloudPlatformLabeler) peerConnection(ip net.IP, epc int32, endpointInfo *EndpointInfo) {
	for _, peerEpc := range l.peerConnectionTable[epc] {
		if platformData := l.GetDataByEpcIp(peerEpc, ip); platformData != nil {
			endpointInfo.SetL3Data(platformData)
			return
		}
	}
	for _, peerEpc := range l.peerConnectionTable[epc] {
		if l.setEpcByCidr(ip, peerEpc, endpointInfo) {
			break
		}
	}
}

func (l *CloudPlatformLabeler) GetL3ByIp(src, dst net.IP, endpoints *EndpointData) {
	if endpoints.SrcInfo.L3EpcId <= 0 {
		if platformData := l.GetDataByIp(src); platformData != nil {
			endpoints.SrcInfo.SetL3Data(platformData)
		}
	}
	if endpoints.DstInfo.L3EpcId <= 0 {
		if platformData := l.GetDataByIp(dst); platformData != nil {
			endpoints.DstInfo.SetL3Data(platformData)
		}
	}
}

func (l *CloudPlatformLabeler) GetL3ByPeerConnection(src, dst net.IP, endpoints *EndpointData) {
	if endpoints.SrcInfo.L3EpcId <= 0 && endpoints.DstInfo.L3EpcId > 0 {
		l.peerConnection(src, endpoints.DstInfo.L3EpcId, endpoints.SrcInfo)
	} else if endpoints.DstInfo.L3EpcId <= 0 && endpoints.SrcInfo.L3EpcId > 0 {
		l.peerConnection(dst, endpoints.SrcInfo.L3EpcId, endpoints.DstInfo)
	}
}

func (l *CloudPlatformLabeler) ModifyInternetEpcId(endpoints *EndpointData) {
	srcData, dstData := endpoints.SrcInfo, endpoints.DstInfo
	if srcData.L3EpcId == 0 {
		srcData.L3EpcId = EPC_FROM_INTERNET
	}
	if dstData.L3EpcId == 0 {
		dstData.L3EpcId = EPC_FROM_INTERNET
	}
}

func (l *CloudPlatformLabeler) GetL3ByWanIp(srcIp, dstIp net.IP, endpointData *EndpointData) (bool, bool) {
	srcData, dstData := endpointData.SrcInfo, endpointData.DstInfo
	found0, found1 := false, false
	if srcData.L3EpcId == 0 {
		// step 1: 查询平台数据WAN接口
		if platformData := l.GetDataByIp(srcIp); platformData != nil {
			srcData.SetL3Data(platformData)
			found0 = true
		} else {
			// step 2: 查询DEEPFLOW添加的WAN监控网段(cidr)
			found0 = l.setEpcByCidr(srcIp, EPC_FROM_DEEPFLOW, srcData)
		}
	}
	if dstData.L3EpcId == 0 {
		// step 1: 查询平台数据WAN接口
		if platformData := l.GetDataByIp(dstIp); platformData != nil {
			dstData.SetL3Data(platformData)
			found1 = true
		} else {
			// step 2: 查询DEEPFLOW添加的WAN监控网段(cidr)
			found1 = l.setEpcByCidr(dstIp, EPC_FROM_DEEPFLOW, dstData)
		}
	}
	return found0, found1
}

func (l *CloudPlatformLabeler) setVIPByCidr(ip net.IP, epc int32, endpointInfo *EndpointInfo) bool {
	for _, cidr := range l.epcCidrMapData[epc] {
		if cidr.IpNet.Contains(ip) {
			endpointInfo.IsVIP = cidr.IsVIP
			return true
		}
	}
	return false
}

func (l *CloudPlatformLabeler) GetVIP(mac uint64, ip net.IP, isWAN bool, endpoint *EndpointInfo) {
	if !endpoint.IsVIP && endpoint.L3EpcId > 0 {
		// 平台数据中仅CIDR有VIP信息，当平台数据不是通过CIDR计算出来时，这里还需要再补充查询CIDR数据以确认是否为VIP。
		// 注意WAN IP可在所有WAN CIDR中搜索，LAN IP必须在对应EPC的CIDR中搜索。
		if !isWAN {
			l.setVIPByCidr(ip, endpoint.L3EpcId, endpoint)
		} else {
			l.setVIPByCidr(ip, EPC_FROM_DEEPFLOW, endpoint)
		}
	}
	if endpoint.IsVIP {
		// VIP时根据MAC地址获取真实IP
		endpoint.RealIP = l.GetRealIpByMac(mac, ip.To4() == nil)
	}
}

func (l *CloudPlatformLabeler) GetEndpointData(key *LookupKey) *EndpointData {
	srcIp, dstIp := IpFromUint32(key.SrcIp), IpFromUint32(key.DstIp)
	// 测试用例key.EthType值未填写，需要通过len(key.Src6Ip)
	if key.EthType == EthernetTypeIPv6 || len(key.Src6Ip) > 0 {
		srcIp, dstIp = key.Src6Ip, key.Dst6Ip
	}
	// l2: mac查询
	// l3: l2epc+ip查询
	srcData, srcWAN := l.GetEndpointInfo(key.SrcMac, srcIp, key.TapType, key.L3End0, key.TunnelId)
	dstData, dstWAN := l.GetEndpointInfo(key.DstMac, dstIp, key.TapType, key.L3End1, key.TunnelId)
	endpoint := &EndpointData{SrcInfo: srcData, DstInfo: dstData}
	// l3: 私有网络 VPC内部路由
	// 1) 本端IP + 对端EPC查询EPC-IP表
	// 2) 本端IP + 对端EPC查询CIDR表
	l.ModifyEndpointData(endpoint, key)
	// l3: 对等连接查询, 以下两种查询
	// 1) peer epc + ip查询对等连接表
	// 2) peer epc + ip查询CIDR表
	l.GetL3ByPeerConnection(srcIp, dstIp, endpoint)
	// l3: WAN查询，包括以下两种查询
	// 1) ip查询平台数据WAN接口
	// 2) ip查询DEEPFLOW添加的WAN监控网段(cidr)
	found0, found1 := l.GetL3ByWanIp(srcIp, dstIp, endpoint)
	if found0 || found1 {
		// 成功查询到WAN后，重新在内部路由和对等连接中查询
		l.ModifyEndpointData(endpoint, key)
		l.GetL3ByPeerConnection(srcIp, dstIp, endpoint)
	}
	if found0 {
		srcWAN = true
	}
	if found1 {
		dstWAN = true
	}
	// vip: vip查询，如果是VIP查询mac对应的实际IP
	//
	// XXX: VIP查询是否使用WAN的逻辑中：
	// 1. EPC通过另一端EPC查询时统一按照LAN处理
	l.GetVIP(key.SrcMac, srcIp, srcWAN, srcData)
	l.GetVIP(key.DstMac, dstIp, dstWAN, dstData)
	l.ModifyInternetEpcId(endpoint)

	return endpoint
}
