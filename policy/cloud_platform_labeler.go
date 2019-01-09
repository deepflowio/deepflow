package policy

import (
	"encoding/binary"
	"math"
	"sync"
	"time"

	. "github.com/google/gopacket/layers"

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

type ArpTable struct {
	sync.RWMutex
	arpMap map[MacIpKey]time.Time
}

type CloudPlatformLabeler struct {
	macTable      *MacTable
	ipTables      [MASK_LEN_NUM]*IpTable
	epcIpTable    *EpcIpTable
	ipGroup       *IpResourceGroup
	netmaskBitmap uint32
	arpTable      [TAP_MAX]*ArpTable
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
	var arpTable [TAP_MAX]*ArpTable
	for i := TAP_MIN; i < TAP_MAX; i++ {
		arpTable[i] = &ArpTable{
			arpMap: make(map[MacIpKey]time.Time),
		}
	}
	return &CloudPlatformLabeler{
		macTable:      macTable,
		ipTables:      ipTables,
		epcIpTable:    epcIpTable,
		ipGroup:       NewIpResourceGroup(),
		netmaskBitmap: uint32(0),
		arpTable:      arpTable,
	}
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
	for i := uint32(MIN_MASK_LEN); i <= MAX_MASK_LEN; i++ {
		if !IfHasNetmaskBit(l.netmaskBitmap, i) {
			continue
		}
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

//FIXME: 后续考虑时间可以从metpacket获取
func (l *CloudPlatformLabeler) UpdateArpTable(hash MacIpKey, tapType TapType) {
	l.arpTable[tapType].Lock()
	l.arpTable[tapType].arpMap[hash] = time.Now()
	l.arpTable[tapType].Unlock()
}

func (l *CloudPlatformLabeler) DeleteArpData(hash MacIpKey, tapType TapType) {
	l.arpTable[tapType].Lock()
	delete(l.arpTable[tapType].arpMap, hash)
	l.arpTable[tapType].Unlock()
}

func (l *CloudPlatformLabeler) GetArpTable(hash MacIpKey, tapType TapType) bool {
	l.arpTable[tapType].RLock()
	if data, ok := l.arpTable[tapType].arpMap[hash]; ok {
		l.arpTable[tapType].RUnlock()
		if ARP_VALID_TIME < time.Now().Sub(data) {
			l.DeleteArpData(hash, tapType)
			return false
		}
		return true
	}
	l.arpTable[tapType].RUnlock()
	return false
}

// 只更新源mac+ip的arp
func (l *CloudPlatformLabeler) CheckAndUpdateArpTable(key *LookupKey, hash MacIpKey) {
	if key.EthType == EthernetTypeARP && !key.Invalid {
		l.UpdateArpTable(hash, key.Tap)
	}
}

// 依据arp表和ttl修正L3End，若arp存在mac+ip对应关系L3End为true，ttl只对源mac+ip有效,包含在(64,128,255)则为true
func (l *CloudPlatformLabeler) ModifyL3End(endpointInfo *EndpointInfo, key *LookupKey, hash MacIpKey, direction bool) {
	if endpointInfo.L3End {
		return
	}
	if endpointInfo.L3End = l.GetArpTable(hash, key.Tap); !endpointInfo.L3End {
		if direction && key.EthType == EthernetTypeIPv4 {
			endpointInfo.SetL3EndByTtl(key.Ttl)
		}
	}
}

func (l *CloudPlatformLabeler) GetEndpointInfo(mac uint64, ip uint32, tapType TapType) *EndpointInfo {
	endpointInfo := new(EndpointInfo)
	platformData := l.GetDataByMac(MacKey(mac))
	if platformData != nil {
		endpointInfo.SetL2Data(platformData)
		endpointInfo.SetL3EndByIp(platformData, ip)
	}
	if platformData = l.GetDataByEpcIp(endpointInfo.L2EpcId, ip); platformData == nil {
		platformData = l.GetDataByIp(ip)
	}
	if platformData != nil {
		endpointInfo.SetL3Data(platformData, ip)
	}
	l.ipGroup.Populate(ip, endpointInfo)
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
func (l *CloudPlatformLabeler) CheckEndpointDataIfNeedCopy(endpoint *EndpointData, key *LookupKey) *EndpointData {
	srcHash := MacIpKey(calcHashKey(key.SrcMac, key.SrcIp))
	dstHash := MacIpKey(calcHashKey(key.DstMac, key.DstIp))
	l.CheckAndUpdateArpTable(key, srcHash)
	if key.Tap == TAP_TOR && ((key.L2End0 != endpoint.SrcInfo.L2End) ||
		(key.L2End1 != endpoint.DstInfo.L2End)) {
		endpoint = ShallowCopyEndpointData(endpoint)
		endpoint.SetL2End(key)
	} else if !endpoint.SrcInfo.L3End || !endpoint.DstInfo.L3End {
		endpoint = ShallowCopyEndpointData(endpoint)
	}
	// 根据Ttl、Arp request、L2End来判断endpoint是否为最新
	l.ModifyL3End(endpoint.SrcInfo, key, srcHash, true)
	l.ModifyL3End(endpoint.DstInfo, key, dstHash, false)
	l.ModifyDeviceInfo(endpoint.SrcInfo)
	l.ModifyDeviceInfo(endpoint.DstInfo)

	return endpoint
}

func (l *CloudPlatformLabeler) UpdateEndpointData(endpoint *EndpointData, key *LookupKey) *EndpointData {
	invalidSrc, invalidDst := false, false
	if endpoint == INVALID_ENDPOINT_DATA {
		invalidSrc, invalidDst = true, true
	} else {
		if endpoint.SrcInfo == INVALID_ENDPOINT_INFO {
			invalidSrc = true
		}
		if endpoint.DstInfo == INVALID_ENDPOINT_INFO {
			invalidDst = true
		}
	}
	endpoint = l.CheckEndpointDataIfNeedCopy(endpoint, key)
	srcData, dstData := endpoint.SrcInfo, endpoint.DstInfo
	// 优化内存占用
	if invalidSrc {
		if srcData.L2End {
			if srcData.L3End {
				endpoint.SrcInfo = INVALID_ENDPOINT_INFO_L2AND3END
				if srcData.L3EpcId == -1 {
					endpoint.SrcInfo = INVALID_ENDPOINT_INFO_L2AND3END_L3EPCID
				}
			} else {
				endpoint.SrcInfo = INVALID_ENDPOINT_INFO_L2END
				if srcData.L3EpcId == -1 {
					endpoint.SrcInfo = INVALID_ENDPOINT_INFO_L2END_L3EPCID
				}
			}
		} else {
			if srcData.L3End {
				endpoint.SrcInfo = INVALID_ENDPOINT_INFO_L3END
				if srcData.L3EpcId == -1 {
					endpoint.SrcInfo = INVALID_ENDPOINT_INFO_L3END_L3EPCID
				}
			} else {
				endpoint.SrcInfo = INVALID_ENDPOINT_INFO
				if srcData.L3EpcId == -1 {
					endpoint.SrcInfo = INVALID_ENDPOINT_INFO_L3EPCID
				}
			}
		}
	}
	if invalidDst {
		if dstData.L2End {
			if dstData.L3End {
				endpoint.DstInfo = INVALID_ENDPOINT_INFO_L2AND3END
				if dstData.L3EpcId == -1 {
					endpoint.DstInfo = INVALID_ENDPOINT_INFO_L2AND3END_L3EPCID
				}
			} else {
				endpoint.DstInfo = INVALID_ENDPOINT_INFO_L2END
				if dstData.L3EpcId == -1 {
					endpoint.DstInfo = INVALID_ENDPOINT_INFO_L2END_L3EPCID
				}
			}
		} else {
			if dstData.L3End {
				endpoint.DstInfo = INVALID_ENDPOINT_INFO_L3END
				if dstData.L3EpcId == -1 {
					endpoint.DstInfo = INVALID_ENDPOINT_INFO_L3END_L3EPCID
				}
			} else {
				endpoint.DstInfo = INVALID_ENDPOINT_INFO
				if dstData.L3EpcId == -1 {
					endpoint.DstInfo = INVALID_ENDPOINT_INFO_L3EPCID
				}
			}
		}
	}
	if endpoint.SrcInfo == INVALID_ENDPOINT_INFO && endpoint.DstInfo == INVALID_ENDPOINT_INFO {
		endpoint = INVALID_ENDPOINT_DATA
	}
	if endpoint.SrcInfo == INVALID_ENDPOINT_INFO_L3EPCID && endpoint.DstInfo == INVALID_ENDPOINT_INFO_L3EPCID {
		endpoint = INVALID_ENDPOINT_DATA_L3EPCID
	}
	return endpoint
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
	// 优化内存占用
	if !srcData.L2End && !srcData.L3End && srcData.L2EpcId == 0 && srcData.L3EpcId == 0 && len(srcData.GroupIds) == 0 {
		endpoint.SrcInfo = INVALID_ENDPOINT_INFO
	}
	if !dstData.L2End && !dstData.L3End && dstData.L2EpcId == 0 && dstData.L3EpcId == 0 && len(dstData.GroupIds) == 0 {
		endpoint.DstInfo = INVALID_ENDPOINT_INFO
	}
	if endpoint.SrcInfo == INVALID_ENDPOINT_INFO && endpoint.DstInfo == INVALID_ENDPOINT_INFO {
		endpoint = INVALID_ENDPOINT_DATA
	}
	return endpoint
}

func (l *CloudPlatformLabeler) RemoveAnonymousGroupIds(endpoint *EndpointData) {
	if len(l.ipGroup.anonymousGroupIds) == 0 {
		return
	}
	endpoint.SrcInfo.GroupIds = l.ipGroup.RemoveAnonymousGroupIds(endpoint.SrcInfo.GroupIds)
	endpoint.DstInfo.GroupIds = l.ipGroup.RemoveAnonymousGroupIds(endpoint.DstInfo.GroupIds)
}
