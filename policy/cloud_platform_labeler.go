package policy

import (
	"encoding/binary"
	"sync"
	"time"

	"github.com/cespare/xxhash"
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
	sync.RWMutex
	fastMap FastMapData
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
	fastTable     *FastTable
	arpTable      *ArpTable
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
	fastTable := &FastTable{
		fastMap: make(FastMapData),
	}
	arpTable := &ArpTable{
		arpMap: make(map[MacIpInportKey]time.Time),
	}

	return &CloudPlatformData{
		macTable:      macTable,
		ipTables:      ipTables,
		epcIpTable:    epcIpTable,
		ipGroup:       NewIpResourceGroup(),
		netmaskBitmap: uint32(0),
		fastTable:     fastTable,
		arpTable:      arpTable,
	}
}

func PortInDeepflowExporter(inPort uint32) bool {
	return DEEPFLOW_POSITION_EXPORTER == ((inPort) & DEEPFLOW_POSITION_EXPORTER)
}

// FIXME: 后续性能问题，可以考虑用异或来做hash
func calcHashKey(mac uint64, ip uint32, inPort uint32) uint64 {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf, mac)
	binary.BigEndian.PutUint32(buf[8:], ip)
	binary.BigEndian.PutUint32(buf[12:], inPort)
	return xxhash.Sum64(buf[2:])
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

func (d *CloudPlatformData) InsertInfoToFastPath(hash MacIpInportKey, endpointInfo *EndpointInfo) {
	fastPlatformData := &FastPlatformData{
		endpointInfo: endpointInfo,
		hash:         hash,
		timestamp:    time.Now(),
	}
	d.fastTable.Lock()
	d.fastTable.fastMap[hash] = fastPlatformData
	d.fastTable.Unlock()
}

func (d *CloudPlatformData) DeleteFastPathData(hash MacIpInportKey) {
	d.fastTable.Lock()
	delete(d.fastTable.fastMap, hash)
	d.fastTable.Unlock()
}

func (d *CloudPlatformData) GetInfoByFastPath(hash MacIpInportKey) *EndpointInfo {
	d.fastTable.RLock()
	if data, ok := d.fastTable.fastMap[hash]; ok {
		d.fastTable.RUnlock()
		if DATA_VALID_TIME < time.Now().Sub(data.timestamp) {
			d.DeleteFastPathData(hash)
			return nil
		}
		return data.endpointInfo
	}
	d.fastTable.RUnlock()
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
func (d *CloudPlatformData) UpdateArpTable(hash MacIpInportKey) {
	d.arpTable.Lock()
	d.arpTable.arpMap[hash] = time.Now()
	d.arpTable.Unlock()
}

func (d *CloudPlatformData) DeleteArpData(hash MacIpInportKey) {
	d.arpTable.Lock()
	delete(d.arpTable.arpMap, hash)
	d.arpTable.Unlock()
}

func (d *CloudPlatformData) GetArpTable(hash MacIpInportKey) bool {
	d.arpTable.RLock()
	if data, ok := d.arpTable.arpMap[hash]; ok {
		d.arpTable.RUnlock()
		if ARP_VALID_TIME < time.Now().Sub(data) {
			d.DeleteArpData(hash)
			return false
		}
		return true
	}
	d.arpTable.RUnlock()
	return false
}

// 只更新源mac+ip的arp
func (d *CloudPlatformData) CheckAndUpdateArpTable(key *LookupKey, hash MacIpInportKey) {
	if key.EthType == EthernetTypeARP {
		d.UpdateArpTable(hash)
	}
}

// 依据arp表和ttl修正L3End，若arp存在mac+ip对应关系L3End为true，ttl只对源mac+ip有效,包含在(64,128,255)则为true
func (d *CloudPlatformData) ModifyL3End(endpointInfo *EndpointInfo, key *LookupKey, hash MacIpInportKey, direction bool) {
	if endpointInfo.L3End {
		return
	}
	if endpointInfo.L3End = d.GetArpTable(hash); !endpointInfo.L3End {
		if direction && key.EthType == EthernetTypeIPv4 {
			endpointInfo.SetL3EndByTtl(key.Ttl)
		}
	}
}

func (d *CloudPlatformData) GetEndpointInfo(mac uint64, ip uint32, inPort uint32) (*EndpointInfo, bool) {
	endpointInfo := &EndpointInfo{}
	if PortInDeepflowExporter(inPort) {
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
			d.ipGroup.Populate(ip, endpointInfo)
		} else {
			return endpointInfo, d.ipGroup.Populate(ip, endpointInfo)
		}
	} else {
		platformData := d.GetDataByIp(ip)
		if platformData != nil {
			endpointInfo.SetL3Data(platformData, ip)
			endpointInfo.SetL3EndByMac(platformData, mac)
			d.ipGroup.Populate(ip, endpointInfo)
		} else {
			return endpointInfo, d.ipGroup.Populate(ip, endpointInfo)
		}
	}
	return endpointInfo, true
}

func (d *CloudPlatformData) GetEndpointData(key *LookupKey) *EndpointData {
	ok := false
	srcHash := MacIpInportKey(calcHashKey(key.SrcMac, key.SrcIp, key.RxInterface))
	d.CheckAndUpdateArpTable(key, srcHash)
	srcData := d.GetInfoByFastPath(srcHash)
	if srcData == nil {
		srcData, ok = d.GetEndpointInfo(key.SrcMac, key.SrcIp, key.RxInterface)
		d.ModifyL3End(srcData, key, srcHash, true)
		if ok {
			d.InsertInfoToFastPath(srcHash, srcData)
		}
	}
	dstHash := MacIpInportKey(calcHashKey(key.DstMac, key.DstIp, key.RxInterface))
	dstData := d.GetInfoByFastPath(dstHash)
	if dstData == nil {
		dstData, ok = d.GetEndpointInfo(key.DstMac, key.DstIp, key.RxInterface)
		d.ModifyL3End(dstData, key, dstHash, false)
		if ok {
			d.InsertInfoToFastPath(dstHash, dstData)
		}
	}

	return &EndpointData{
		SrcInfo: srcData,
		DstInfo: dstData,
	}
}
