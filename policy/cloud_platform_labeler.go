package policy

import (
	"container/list"
	"math"
	"net"
	"sort"

	. "github.com/google/gopacket/layers"

	"gitlab.x.lan/yunshan/droplet-libs/bit"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
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
	ipTables            [MASK_LEN_NUM]*IpTable
	ip6Tables           *Ip6Table // TODO: 因为目前IPv6不支持IP资源组类型的，掩码都是128，所以不用建数组
	epcIpTable          *EpcIpTable
	ipGroup             *IpResourceGroup
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
		ipTables:            ipTables,
		ip6Tables:           ip6Tables,
		epcIpTable:          epcIpTable,
		ipGroup:             NewIpResourceGroup(),
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

func (l *CloudPlatformLabeler) GenerateMacData(platformDatas []*PlatformData) MacMapData {
	macMap := make(MacMapData)
	for _, platformData := range platformDatas {
		if platformData.SkipMac {
			continue
		}

		if platformData.Mac != 0 {
			macMap[MacKey(platformData.Mac)] = platformData
		}
	}
	return macMap
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

func (l *CloudPlatformLabeler) GenerateIpData(platformDatas []*PlatformData) (IpMapDatas, Ip6MapData) {
	ips := make(IpMapDatas, MASK_LEN_NUM)
	ip6s := make(Ip6MapData)

	for i := uint32(MIN_MASK_LEN); i <= MAX_MASK_LEN; i++ {
		ips[i] = make(IpMapData)
	}
	for _, platformData := range platformDatas {
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
		hash := GetIpHash(ip)
		key := EpcIpKey((uint64(epc) << 32) | uint64(hash))
		if platformList, ok := l.epcIpTable.epcIp6Map[key]; ok {
			for e := platformList.Front(); e != nil; e = e.Next() {
				platformData := e.Value.(*PlatformData)
				for _, ipData := range platformData.Ips {
					if ipData.RawIp.Equal(ip) {
						return platformData
					}
				}
			}
		}
	}
	return nil
}

func (l *CloudPlatformLabeler) GenerateEpcIpData(platformDatas []*PlatformData) (EpcIpMapData, EpcIp6MapData) {
	epcIpMap := make(EpcIpMapData)
	epcIp6Map := make(EpcIp6MapData)
	for _, platformData := range platformDatas {
		for _, ipData := range platformData.Ips {
			epcId := uint64(platformData.EpcId)
			if platformData.EpcId == EPC_FROM_DEEPFLOW {
				epcId = 0
			}
			if len(ipData.RawIp) == 4 {
				key := EpcIpKey((epcId << 32) | uint64(IpToUint32(ipData.RawIp)))
				epcIpMap[key] = platformData
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

func (l *CloudPlatformLabeler) UpdateInterfaceTable(platformDatas []*PlatformData) {
	if platformDatas != nil {
		l.UpdateMacTable(l.GenerateMacData(platformDatas))
		l.UpdateIpTable(l.GenerateIpData(platformDatas))
		l.UpdateEpcIpTable(l.GenerateEpcIpData(platformDatas))
	}
}

func (l *CloudPlatformLabeler) UpdateGroupTree(ipGroupDatas []*IpGroupData) {
	l.ipGroup.Update(ipGroupDatas)
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

func (l *CloudPlatformLabeler) setEpcByCidr(ip net.IP, epc int32, endpointInfo *EndpointInfo) bool {
	for _, cidr := range l.epcCidrMapData[epc] {
		if cidr.IpNet.Contains(ip) {
			// 获取的EPC以CIDR实际存储的为主
			// 使用EPC_FROM_DEEPFLOW查表, 会获取WAN的CIDR, 但是其EPC可能不是EPC_FROM_DEEPFLOW
			endpointInfo.L3EpcId = cidr.EpcId
			return true
		}
	}
	return false
}

func (l *CloudPlatformLabeler) setEpcByTunnelCidr(ip net.IP, tunnelId uint32, endpointInfo *EndpointInfo) bool {
	for _, cidr := range l.tunnelIdCidrMapData[tunnelId] {
		if cidr.IpNet.Contains(ip) {
			endpointInfo.L3EpcId = cidr.EpcId
			return true
		}
	}
	return false
}

func (l *CloudPlatformLabeler) GetEndpointInfo(mac uint64, ip net.IP, tapType TapType, l3End bool, tunnelId uint32) *EndpointInfo {
	endpointInfo := new(EndpointInfo)
	// 腾讯的GRE场景，MAC为0
	if tunnelId > 0 {
		// step 1: 查询DEEPFLOW添加的WAN监控网段(cidr)
		l.setEpcByCidr(ip, EPC_FROM_DEEPFLOW, endpointInfo)
		if endpointInfo.L3EpcId == 0 {
			// step 2: 查询tunnelID监控网段(cidr)
			l.setEpcByTunnelCidr(ip, tunnelId, endpointInfo)
		}
		return endpointInfo
	}
	// step 1: 使用mac查询L2
	platformData := l.GetDataByMac(MacKey(mac))
	if platformData != nil {
		endpointInfo.SetL2Data(platformData)
		// L2End为真时，可通过流量中的Mac判断是否为VIP设备
		endpointInfo.IsVIPInterface = platformData.IsVIPInterface
		// IP为0，则取MAC对应的二层数据作为三层数据
		if l3End || ip.IsUnspecified() {
			endpointInfo.SetL3Data(platformData)
			return endpointInfo
		}
	}
	// step 2: 使用L2EpcId + IP查询L3，如果L2EpcId为0，会查询到DEEPFLOW添加的监控IP
	if platformData = l.GetDataByEpcIp(endpointInfo.L2EpcId, ip); platformData != nil {
		endpointInfo.SetL3Data(platformData)
	} else if endpointInfo.L3EpcId == 0 {
		// step 3: 查询平台数据WAN接口
		if platformData := l.GetDataByIp(ip); platformData != nil {
			endpointInfo.SetL3Data(platformData)
		} else {
			// step 4: 查询DEEPFLOW添加的WAN监控网段(cidr)
			l.setEpcByCidr(ip, EPC_FROM_DEEPFLOW, endpointInfo)
		}
	}
	return endpointInfo
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

func (l *CloudPlatformLabeler) GetEndpointData(key *LookupKey) *EndpointData {
	srcIp, dstIp := IpFromUint32(key.SrcIp), IpFromUint32(key.DstIp)
	// 测试用例key.EthType值未填写，需要通过len(key.Src6Ip)
	if key.EthType == EthernetTypeIPv6 || len(key.Src6Ip) > 0 {
		srcIp, dstIp = key.Src6Ip, key.Dst6Ip
	}
	// l2: mac查询
	// l3: l2epc+ip查询
	// l3: ip查询平台数据WAN接口
	// l3: ip查询DEEPFLOW添加的WAN监控网段(cidr)
	srcData := l.GetEndpointInfo(key.SrcMac, srcIp, key.TapType, key.L3End0, key.TunnelId)
	dstData := l.GetEndpointInfo(key.DstMac, dstIp, key.TapType, key.L3End1, key.TunnelId)
	// ip地址是否为VIP
	srcData.IsVIP, dstData.IsVIP = key.IsVIP0, key.IsVIP1
	endpoint := &EndpointData{SrcInfo: srcData, DstInfo: dstData}
	// l3: 对等连接查询, 以下两种查询
	// 1). peer epc + ip查询对等连接表
	// 2). peer epc + ip查询CIDR表
	l.GetL3ByPeerConnection(srcIp, dstIp, endpoint)
	// l3: 私有网络 VPC内部路由
	// 1) 本端IP + 对端EPC查询EPC-IP表
	// 2) 本端IP + 对端EPC查询CIDR表
	l.ModifyEndpointData(endpoint, key)
	l.ModifyInternetEpcId(endpoint)
	return endpoint
}
