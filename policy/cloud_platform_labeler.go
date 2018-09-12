package policy

import (
	"sync"
	"time"

	"github.com/golang/groupcache/lru"
	. "github.com/google/gopacket/layers"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

type FastPlatformData struct {
	endpointInfo *EndpointInfo
	timestamp    time.Time
	hash         MacIpInportKey
}

type IpMapDatas []map[IpKey]*PlatformData
type IpMapData map[IpKey]*PlatformData
type MacMapData map[MacKey]*PlatformData
type EpcIpMapData map[EpcIpKey]*PlatformData
type FastMapData map[MacIpInportKey]*FastPlatformData

type MacTable struct {
	macMap MacMapData
}

type IpTable struct {
	ipMap IpMapData
}

type EpcIpTable struct {
	epcIpMap EpcIpMapData
}

type FastTable struct {
	sync.Mutex
	fastPlatform *lru.Cache
}

type ArpTable struct {
	sync.RWMutex
	arpMap map[MacIpInportKey]time.Time
}

type CloudPlatformData struct {
	macTable      *MacTable
	ipTables      [MASK_LEN]*IpTable
	epcIpTable    *EpcIpTable
	ipGroup       *IpResourceGroup
	netmaskBitmap uint32
	fastPath      [TAP_MAX]*FastTable
	arpTable      [TAP_MAX]*ArpTable
}

func NewCloudPlatformData() *CloudPlatformData {
	macTable := &MacTable{
		macMap: make(MacMapData),
	}
	var ipTables [MASK_LEN]*IpTable
	for i := uint32(0); i < MASK_LEN; i++ {
		ipTables[i] = &IpTable{
			ipMap: make(IpMapData),
		}
	}
	epcIpTable := &EpcIpTable{
		epcIpMap: make(EpcIpMapData),
	}
	var fastPath [TAP_MAX]*FastTable
	for i := uint32(0); i < uint32(TAP_MAX); i++ {
		fastPath[i] = &FastTable{
			fastPlatform: lru.New(MAX_FASTPATH_LEN),
		}
	}
	var arpTable [TAP_MAX]*ArpTable
	for i := uint32(0); i < uint32(TAP_MAX); i++ {
		arpTable[i] = &ArpTable{
			arpMap: make(map[MacIpInportKey]time.Time),
		}
	}
	return &CloudPlatformData{
		macTable:      macTable,
		ipTables:      ipTables,
		epcIpTable:    epcIpTable,
		ipGroup:       NewIpResourceGroup(),
		netmaskBitmap: uint32(0),
		fastPath:      fastPath,
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

func (d *CloudPlatformData) GetDataByMac(key MacKey) *PlatformData {
	if info, ok := d.macTable.macMap[key]; ok {
		return info
	}

	return nil
}

func (d *CloudPlatformData) UpdateMacTable(macmap MacMapData) {
	if macmap != nil {
		d.macTable.macMap = macmap
	}
}

func (d *CloudPlatformData) GenerateMacData(platformDatas []*PlatformData) MacMapData {
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

func (d *CloudPlatformData) GetDataByIp(ip uint32) *PlatformData {
	for i := uint32(0); i < MASK_LEN; i++ {
		if !IfHasNetmaskBit(d.netmaskBitmap, i) {
			continue
		}
		subip := IpKey(ip & (NETMASK << i))
		if info, ok := d.ipTables[i].ipMap[subip]; ok {
			return info
		}
	}
	return nil
}

func (d *CloudPlatformData) GenerateIpData(platformDatas []*PlatformData) IpMapDatas {
	ips := make(IpMapDatas, MASK_LEN)

	for i := uint32(0); i < MASK_LEN; i++ {
		ips[i] = make(IpMapData)
	}
	for _, platformData := range platformDatas {
		if platformData.IfType != IF_TYPE_WAN {
			continue
		}
		for _, ipData := range platformData.Ips {
			netmask := MAX_MASK_LEN - ipData.Netmask
			ips[netmask][IpKey(ipData.Ip)] = platformData
			d.netmaskBitmap |= 1 << netmask
		}
	}

	return ips
}

func (d *CloudPlatformData) UpdateIpTable(ipDatas IpMapDatas) {
	for index, ipMap := range ipDatas {
		d.ipTables[IpKey(index)].UpdateIpMap(ipMap)
	}
}

func (t *IpTable) UpdateIpMap(ipMap IpMapData) {
	if ipMap != nil {
		t.ipMap = ipMap
	}
}

func (d *CloudPlatformData) GetDataByEpcIp(epc int32, ip uint32) *PlatformData {
	key := EpcIpKey((uint64(epc) << 32) | uint64(ip))
	if info, ok := d.epcIpTable.epcIpMap[key]; ok {
		return info
	}

	return nil
}

func (d *CloudPlatformData) GenerateEpcIpData(platformDatas []*PlatformData) EpcIpMapData {
	epcIpMap := make(EpcIpMapData)
	for _, platformData := range platformDatas {
		for _, ipData := range platformData.Ips {
			key := EpcIpKey((uint64(platformData.EpcId) << 32) | uint64(ipData.Ip))
			epcIpMap[key] = platformData
		}
	}

	return epcIpMap
}

func (d *CloudPlatformData) UpdateEpcIpTable(epcIpMap EpcIpMapData) {
	if epcIpMap != nil {
		d.epcIpTable.epcIpMap = epcIpMap
	}
}

func (d *CloudPlatformData) InsertInfoToFastPath(hash MacIpInportKey, endpointInfo *EndpointInfo, tapType TapType) {
	fastPlatformData := &FastPlatformData{
		endpointInfo: endpointInfo,
		hash:         hash,
		timestamp:    time.Now(),
	}
	d.fastPath[tapType].Lock()
	d.fastPath[tapType].fastPlatform.Add(hash, fastPlatformData)
	d.fastPath[tapType].Unlock()
}

func (d *CloudPlatformData) DeleteFastPathData(hash MacIpInportKey, tapType TapType) {
	d.fastPath[tapType].Lock()
	d.fastPath[tapType].fastPlatform.Remove(hash)
	d.fastPath[tapType].Unlock()
}

func (d *CloudPlatformData) GetInfoByFastPath(hash MacIpInportKey, tapType TapType) *EndpointInfo {
	d.fastPath[tapType].Lock()
	if data, ok := d.fastPath[tapType].fastPlatform.Get(hash); ok {
		fastPlatformData := data.(*FastPlatformData)
		if DATA_VALID_TIME < time.Now().Sub(fastPlatformData.timestamp) {
			d.fastPath[tapType].fastPlatform.Remove(hash)
			d.fastPath[tapType].Unlock()
			return nil
		}
		d.fastPath[tapType].Unlock()
		return fastPlatformData.endpointInfo
	}
	d.fastPath[tapType].Unlock()
	return nil
}

func (d *CloudPlatformData) UpdateInterfaceTable(platformDatas []*PlatformData) {
	if platformDatas != nil {
		d.UpdateMacTable(d.GenerateMacData(platformDatas))
		d.UpdateIpTable(d.GenerateIpData(platformDatas))
		d.UpdateEpcIpTable(d.GenerateEpcIpData(platformDatas))
	}
}

//FIXME: 后续考虑时间可以从metpacket获取
func (d *CloudPlatformData) UpdateArpTable(hash MacIpInportKey, tapType TapType) {
	d.arpTable[tapType].Lock()
	d.arpTable[tapType].arpMap[hash] = time.Now()
	d.arpTable[tapType].Unlock()
}

func (d *CloudPlatformData) DeleteArpData(hash MacIpInportKey, tapType TapType) {
	d.arpTable[tapType].Lock()
	delete(d.arpTable[tapType].arpMap, hash)
	d.arpTable[tapType].Unlock()
}

func (d *CloudPlatformData) GetArpTable(hash MacIpInportKey, tapType TapType) bool {
	d.arpTable[tapType].RLock()
	if data, ok := d.arpTable[tapType].arpMap[hash]; ok {
		d.arpTable[tapType].RUnlock()
		if ARP_VALID_TIME < time.Now().Sub(data) {
			d.DeleteArpData(hash, tapType)
			return false
		}
		return true
	}
	d.arpTable[tapType].RUnlock()
	return false
}

// 只更新源mac+ip的arp
func (d *CloudPlatformData) CheckAndUpdateArpTable(key *LookupKey, hash MacIpInportKey) {
	if key.EthType == EthernetTypeARP && !key.Invalid {
		d.UpdateArpTable(hash, key.Tap)
	}
}

// 依据arp表和ttl修正L3End，若arp存在mac+ip对应关系L3End为true，ttl只对源mac+ip有效,包含在(64,128,255)则为true
func (d *CloudPlatformData) ModifyL3End(endpointInfo *EndpointInfo, key *LookupKey, hash MacIpInportKey, direction bool) {
	if endpointInfo.L3End {
		return
	}
	if endpointInfo.L3End = d.GetArpTable(hash, key.Tap); !endpointInfo.L3End {
		if direction && key.EthType == EthernetTypeIPv4 {
			endpointInfo.SetL3EndByTtl(key.Ttl)
		}
	}
}

func (d *CloudPlatformData) GetEndpointInfo(mac uint64, ip uint32, tapType TapType) *EndpointInfo {
	endpointInfo := &EndpointInfo{}
	if tapType == TAP_TOR {
		platformData := d.GetDataByMac(MacKey(mac))
		if platformData != nil {
			endpointInfo.SetL2Data(platformData)
			endpointInfo.SetL3EndByIp(platformData, ip)
			if platformData = d.GetDataByEpcIp(endpointInfo.L2EpcId, ip); platformData == nil {
				platformData = d.GetDataByIp(ip)
			}
			if platformData != nil {
				endpointInfo.SetL3Data(platformData, ip)
			}
		}
		d.ipGroup.Populate(ip, endpointInfo)
	} else {
		platformData := d.GetDataByIp(ip)
		if platformData != nil {
			endpointInfo.SetL3Data(platformData, ip)
			endpointInfo.SetL3EndByMac(platformData, mac)
		}
		d.ipGroup.Populate(ip, endpointInfo)
	}
	return endpointInfo
}

func (d *CloudPlatformData) ModifyDeviceInfo(endpointInfo *EndpointInfo) {
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
	}
}

func (d *CloudPlatformData) GetEndpointData(key *LookupKey) (*EndpointData, *FastKey) {
	srcHash := MacIpInportKey(calcHashKey(key.SrcMac, key.SrcIp))
	d.CheckAndUpdateArpTable(key, srcHash)
	srcData := d.GetInfoByFastPath(srcHash, key.Tap)
	if srcData == nil {
		srcData = d.GetEndpointInfo(key.SrcMac, key.SrcIp, key.Tap)
		d.ModifyL3End(srcData, key, srcHash, true)
		d.ModifyDeviceInfo(srcData)
		d.InsertInfoToFastPath(srcHash, srcData, key.Tap)
	}
	dstHash := MacIpInportKey(calcHashKey(key.DstMac, key.DstIp))
	dstData := d.GetInfoByFastPath(dstHash, key.Tap)
	if dstData == nil {
		dstData = d.GetEndpointInfo(key.DstMac, key.DstIp, key.Tap)
		d.ModifyL3End(dstData, key, dstHash, false)
		d.ModifyDeviceInfo(dstData)
		d.InsertInfoToFastPath(dstHash, dstData, key.Tap)
	}

	return &EndpointData{SrcInfo: srcData, DstInfo: dstData},
		&FastKey{SrcHash: uint64(srcHash), DstHash: uint64(dstHash)}
}
