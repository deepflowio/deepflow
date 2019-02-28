package policy

import (
	"encoding/binary"
	"math"
	"sync"
	"time"

	. "github.com/google/gopacket/layers"

	"gitlab.x.lan/yunshan/droplet-libs/bit"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

type IpMapDatas []map[IpKey]*PlatformData
type IpMapData map[IpKey]*PlatformData
type MacMapData map[MacKey]*PlatformData
type EpcIpMapData map[EpcIpKey]*PlatformData

type MacTable struct {
	macMap MacMapData
}

type IpTable struct {
	ipMap IpMapData
}

type EpcIpTable struct {
	epcIpMap EpcIpMapData
}

type CloudPlatformLabeler struct {
	macTable      *MacTable
	ipTables      [MASK_LEN_NUM]*IpTable
	epcIpTable    *EpcIpTable
	ipGroup       *IpResourceGroup
	netmaskBitmap uint32

	arpMutex        [TAP_MAX]sync.Mutex
	lastArpSwapTime time.Duration
	arpTable        [TAP_MAX]map[MacIpKey]bool
	tempArpTable    [TAP_MAX]map[MacIpKey]bool
}

var PRIVATE_PREFIXS = [][2]uint32{
	{binary.BigEndian.Uint32([]byte{10, 0, 0, 0}), 0xff000000},
	{binary.BigEndian.Uint32([]byte{172, 16, 0, 0}), 0xfff00000},
	{binary.BigEndian.Uint32([]byte{192, 168, 0, 0}), 0xffff0000},
	{binary.BigEndian.Uint32([]byte{255, 255, 255, 255}), 0xffffffff},
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
	epcIpTable := &EpcIpTable{
		epcIpMap: make(EpcIpMapData),
	}
	cloud := &CloudPlatformLabeler{
		macTable:        macTable,
		ipTables:        ipTables,
		epcIpTable:      epcIpTable,
		ipGroup:         NewIpResourceGroup(),
		netmaskBitmap:   uint32(0),
		lastArpSwapTime: time.Duration(time.Now().UnixNano()),
	}
	for i := TAP_MIN; i < TAP_MAX; i++ {
		cloud.tempArpTable[i] = make(map[MacIpKey]bool)
		cloud.arpTable[i] = make(map[MacIpKey]bool)
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
		if platformData.Mac != 0 {
			macMap[MacKey(platformData.Mac)] = platformData
		}
	}
	return macMap
}

func IfHasNetmaskBit(bitmap uint32, k uint32) bool {
	return (bitmap & (1 << k)) != 0
}

func (l *CloudPlatformLabeler) GetDataByIp(ip uint32) *PlatformData {
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

func (l *CloudPlatformLabeler) GenerateIpData(platformDatas []*PlatformData) IpMapDatas {
	ips := make(IpMapDatas, MASK_LEN_NUM)

	for i := uint32(MIN_MASK_LEN); i <= MAX_MASK_LEN; i++ {
		ips[i] = make(IpMapData)
	}
	for _, platformData := range platformDatas {
		if platformData.IfType != IF_TYPE_WAN {
			continue
		}
		for _, ipData := range platformData.Ips {
			netmask := MAX_MASK_LEN - ipData.Netmask
			ips[netmask][IpKey(ipData.Ip)] = platformData
			l.netmaskBitmap |= 1 << netmask
		}
	}

	return ips
}

func (l *CloudPlatformLabeler) UpdateIpTable(ipDatas IpMapDatas) {
	for index, ipMap := range ipDatas {
		l.ipTables[IpKey(index)].UpdateIpMap(ipMap)
	}
}

func (t *IpTable) UpdateIpMap(ipMap IpMapData) {
	if ipMap != nil {
		t.ipMap = ipMap
	}
}

func (l *CloudPlatformLabeler) GetDataByEpcIp(epc int32, ip uint32) *PlatformData {
	key := EpcIpKey((uint64(epc) << 32) | uint64(ip))
	if info, ok := l.epcIpTable.epcIpMap[key]; ok {
		return info
	}

	return nil
}

func (l *CloudPlatformLabeler) GenerateEpcIpData(platformDatas []*PlatformData) EpcIpMapData {
	epcIpMap := make(EpcIpMapData)
	for _, platformData := range platformDatas {
		for _, ipData := range platformData.Ips {
			key := EpcIpKey((uint64(platformData.EpcId) << 32) | uint64(ipData.Ip))
			epcIpMap[key] = platformData
		}
	}

	return epcIpMap
}

func (l *CloudPlatformLabeler) UpdateEpcIpTable(epcIpMap EpcIpMapData) {
	if epcIpMap != nil {
		l.epcIpTable.epcIpMap = epcIpMap
	}
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

func (l *CloudPlatformLabeler) GetArpTable(hash MacIpKey, tapType TapType) bool {
	return l.arpTable[tapType][hash]
}

// 只更新源mac+ip的arp
func (l *CloudPlatformLabeler) CheckAndUpdateArpTable(key *LookupKey, hash MacIpKey, timestamp time.Duration) {
	if key.EthType == EthernetTypeARP && !key.Invalid {
		l.arpMutex[key.Tap].Lock()
		l.tempArpTable[key.Tap][hash] = true
		l.arpMutex[key.Tap].Unlock()
	}

	if timestamp-l.lastArpSwapTime >= ARP_VALID_TIME {
		for i := TAP_MIN; i < TAP_MAX; i++ {
			table := make(map[MacIpKey]bool)
			l.arpMutex[key.Tap].Lock()
			l.arpTable[i] = l.tempArpTable[i]
			l.tempArpTable[i] = table
			l.arpMutex[key.Tap].Unlock()
		}
		l.lastArpSwapTime = timestamp
	}
}

// 依据arp表和ttl修正L3End，若arp存在mac+ip对应关系L3End为true，ttl只对源mac+ip有效,包含在(64,128,255)则为true
func (l *CloudPlatformLabeler) GetL3End(endpointInfo *EndpointInfo, key *LookupKey, hash MacIpKey, direction bool) bool {
	if endpointInfo.L3End {
		return endpointInfo.L3End
	}
	end := l.GetArpTable(hash, key.Tap)
	if !end {
		if direction && key.EthType == EthernetTypeIPv4 {
			end = endpointInfo.GetL3EndByTtl(key.Ttl)
		}
	}
	return end
}

func (l *CloudPlatformLabeler) GetEndpointInfo(mac uint64, ip uint32, tapType TapType) *EndpointInfo {
	endpointInfo := new(EndpointInfo)
	platformData := l.GetDataByMac(MacKey(mac))
	if platformData != nil {
		endpointInfo.SetL2Data(platformData)
		endpointInfo.SetL3EndByIp(platformData, ip)
		// IP为0，则取MAC对应的二层数据作为三层数据
		if ip == 0 {
			endpointInfo.SetL3DataByMac(platformData)
		}
	}
	if platformData = l.GetDataByEpcIp(endpointInfo.L2EpcId, ip); platformData == nil {
		platformData = l.GetDataByIp(ip)
	}
	if platformData != nil {
		endpointInfo.SetL3Data(platformData, ip)
	}
	return endpointInfo
}

func (l *CloudPlatformLabeler) ModifyDeviceInfo(endpointInfo *EndpointInfo) {
	if endpointInfo.L2End && endpointInfo.L3End {
		if endpointInfo.L2DeviceId == 0 {
			endpointInfo.L2DeviceId = endpointInfo.L3DeviceId
		}
		if endpointInfo.L3DeviceId == 0 {
			endpointInfo.L3DeviceId = endpointInfo.L2DeviceId
		}
		if endpointInfo.L2DeviceType == 0 {
			endpointInfo.L2DeviceType = endpointInfo.L3DeviceType
		}
		if endpointInfo.L3DeviceType == 0 {
			endpointInfo.L3DeviceType = endpointInfo.L2DeviceType
		}
		if endpointInfo.L2EpcId == 0 {
			endpointInfo.L2EpcId = endpointInfo.L3EpcId
		}
		if endpointInfo.L3EpcId == 0 {
			endpointInfo.L3EpcId = endpointInfo.L2EpcId
		}
	}
}

func isPrivateAddress(ip uint32) bool {
	for _, prefix := range PRIVATE_PREFIXS {
		if prefix[0] == (prefix[1] & ip) {
			return true
		}
	}
	return false
}

func (l *CloudPlatformLabeler) ModifyPrivateIp(endpoint *EndpointData, key *LookupKey) {
	if key.Tap != TAP_TOR {
		return
	}
	if endpoint.SrcInfo.L3EpcId == 0 && isPrivateAddress(key.SrcIp) {
		endpoint.SrcInfo.L3EpcId = -1
	}
	if endpoint.DstInfo.L3EpcId == 0 && isPrivateAddress(key.DstIp) {
		endpoint.DstInfo.L3EpcId = -1
	}
}

// 检查L2End和L3End是否有可能进行修正
func (l *CloudPlatformLabeler) CheckEndpointDataIfNeedCopy(store *EndpointStore, key *LookupKey) *EndpointData {
	srcHash := MacIpKey(calcHashKey(key.SrcMac, key.SrcIp))
	dstHash := MacIpKey(calcHashKey(key.DstMac, key.DstIp))
	l.CheckAndUpdateArpTable(key, srcHash, key.Timestamp)
	endpoint := store.Endpoints
	l2End0, l3End0, l2End1, l3End1 := endpoint.SrcInfo.L2End, endpoint.SrcInfo.L3End, endpoint.DstInfo.L2End, endpoint.DstInfo.L3End
	if key.Tap == TAP_TOR && ((key.L2End0 != endpoint.SrcInfo.L2End) ||
		(key.L2End1 != endpoint.DstInfo.L2End)) {
		l2End0, l2End1 = key.L2End0, key.L2End1
	}
	// 根据Ttl、Arp request、L2End来判断endpoint是否为最新
	l3End0 = l.GetL3End(endpoint.SrcInfo, key, srcHash, true)
	l3End1 = l.GetL3End(endpoint.DstInfo, key, dstHash, false)
	newEndpoints := store.UpdatePointer(l2End0, l2End1, l3End0, l3End1)
	l.ModifyDeviceInfo(newEndpoints.SrcInfo)
	l.ModifyDeviceInfo(newEndpoints.DstInfo)

	return newEndpoints
}

func (l *CloudPlatformLabeler) UpdateEndpointData(endpoint *EndpointStore, key *LookupKey) *EndpointData {
	return l.CheckEndpointDataIfNeedCopy(endpoint, key)
}

func (l *CloudPlatformLabeler) ModifyEndpointData(endpointData *EndpointData, key *LookupKey) {
	srcData, dstData := endpointData.SrcInfo, endpointData.DstInfo
	// 默认L2End为false时L3EpcId == 0，L2End为true时L2EpcId不为0
	if dstData.L3EpcId == 0 && srcData.L2EpcId != 0 {
		if platformData := l.GetDataByEpcIp(srcData.L2EpcId, key.DstIp); platformData != nil {
			dstData.SetL3Data(platformData, key.DstIp)
		}
	}

	if srcData.L3EpcId == 0 && dstData.L2EpcId != 0 {
		if platformData := l.GetDataByEpcIp(dstData.L2EpcId, key.SrcIp); platformData != nil {
			srcData.SetL3Data(platformData, key.SrcIp)
		}
	}
}

func (l *CloudPlatformLabeler) GetEndpointData(key *LookupKey) *EndpointData {
	srcData := l.GetEndpointInfo(key.SrcMac, key.SrcIp, key.Tap)
	dstData := l.GetEndpointInfo(key.DstMac, key.DstIp, key.Tap)
	endpoint := &EndpointData{SrcInfo: srcData, DstInfo: dstData}
	l.ModifyEndpointData(endpoint, key)
	l.ModifyPrivateIp(endpoint, key)
	l.ipGroup.Populate(key.SrcIp, endpoint.SrcInfo)
	l.ipGroup.Populate(key.DstIp, endpoint.DstInfo)
	return endpoint
}

func (l *CloudPlatformLabeler) RemoveAnonymousGroupIds(store *EndpointStore, key *LookupKey) {
	if len(l.ipGroup.anonymousGroupIds) == 0 {
		return
	}
	endpoint := store.Endpoints
	endpoint.SrcInfo.GroupIds, key.SrcAllGroupIds = l.ipGroup.RemoveAnonymousGroupIds(endpoint.SrcInfo.GroupIds, key.SrcAllGroupIds)
	endpoint.DstInfo.GroupIds, key.DstAllGroupIds = l.ipGroup.RemoveAnonymousGroupIds(endpoint.DstInfo.GroupIds, key.DstAllGroupIds)
	for i := L3_L2_END_FALSE_FALSE; i < L3_L2_END_MAX; i++ {
		store.SrcInfos[i].GroupIds = endpoint.SrcInfo.GroupIds
		store.DstInfos[i].GroupIds = endpoint.DstInfo.GroupIds
	}
}
