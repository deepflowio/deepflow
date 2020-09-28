package grpc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/hmap/lru"
	"gitlab.x.lan/yunshan/droplet-libs/receiver"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	"gitlab.x.lan/yunshan/message/trident"
)

// 以最后一次NewPlatformInfoTable() table作为全局的platformInfoTable
var platformInfoTable *PlatformInfoTable

const (
	DEFAULT_SYNC_INTERVAL = time.Minute
	EpcIDIPV6_LEN         = 20
	LruSlotSize           = 1 << 14
	LruCap                = 1 << 17
)

type BaseInfo struct {
	RegionID uint32
	HitCount uint64
}

type Info struct {
	L2EpcID    uint32
	Host       uint32
	HostStr    string
	HostID     uint32
	Mac        uint64
	RegionID   uint32
	DeviceType uint32
	DeviceID   uint32
	SubnetID   uint32
	PodNodeID  uint32
	PodNSID    uint32
	PodGroupID uint32
	PodID      uint32
	AZID       uint32
	IsVip      bool
	HitCount   *uint64
}

type CidrInfo struct {
	Cidr     *net.IPNet
	EpcID    int32
	RegionID uint32
	SubnetID uint32
	AZID     uint32
	HitCount *uint64
}

type PlatformInfoTable struct {
	receiver     *receiver.Receiver
	regionID     uint32
	epcIDIPV4Lru *lru.U64LRU
	epcIDIPV6Lru *lru.U160LRU

	epcIDIPV4Infos     map[uint64]*Info
	epcIDIPV6Infos     map[[EpcIDIPV6_LEN]byte]*Info
	epcIDIPV4CidrInfos map[int32][]*CidrInfo
	epcIDIPV6CidrInfos map[int32][]*CidrInfo

	macInfos     map[uint64]*Info
	macMissCount map[uint64]*uint64

	epcIDBaseInfos     map[int32]*BaseInfo
	epcIDBaseMissCount map[int32]*uint64

	bootTime            uint32
	processName         string
	versionPlatformData uint64

	*GrpcSession
	ipv4Lock  *sync.RWMutex
	ipv6Lock  *sync.RWMutex
	macLock   *sync.RWMutex
	epcIDLock *sync.RWMutex
}

func ClosePlatformInfoTable() {
	platformInfoTable.Close()
}

func QueryRegionID() uint32 {
	return platformInfoTable.regionID
}

func QueryEpcIDBaseInfo(epcID int32) *BaseInfo {
	return platformInfoTable.QueryEpcIDBaseInfo(epcID)
}

func QueryEpcIDBaseInfosPair(epcID0, epcID1 int32) (*BaseInfo, *BaseInfo) {
	return platformInfoTable.QueryEpcIDBaseInfosPair(epcID0, epcID1)
}

func QueryMacInfo(mac uint64) *Info {
	return platformInfoTable.QueryMacInfo(mac)
}

func QueryMacInfosPair(mac0, mac1 uint64) (*Info, *Info) {
	return platformInfoTable.QueryMacInfosPair(mac0, mac1)
}

func QueryIPV4Infos(epcID int16, ipv4 uint32) *Info {
	if epcID == datatype.EPC_FROM_INTERNET {
		return nil
	}
	info := platformInfoTable.QueryIPV4Infos(epcID, ipv4)
	if info != nil {
		return info
	}

	baseInfo := QueryEpcIDBaseInfo(int32(epcID))
	if baseInfo == nil {
		return nil
	}
	return &Info{
		RegionID: baseInfo.RegionID,
	}
}

func QueryIPV6Infos(epcID int16, ipv6 net.IP) *Info {
	if epcID == datatype.EPC_FROM_INTERNET {
		return nil
	}
	info := platformInfoTable.QueryIPV6Infos(epcID, ipv6)
	if info != nil {
		return info
	}

	baseInfo := QueryEpcIDBaseInfo(int32(epcID))
	if baseInfo == nil {
		return nil
	}
	return &Info{
		RegionID: baseInfo.RegionID,
	}
}

func QueryIPV4InfosPair(epcID0 int16, ipv40 uint32, epcID1 int16, ipv41 uint32) (info0 *Info, info1 *Info) {
	if epcID0 == datatype.EPC_FROM_INTERNET {
		return nil, QueryIPV4Infos(epcID1, ipv41)
	} else if epcID1 == datatype.EPC_FROM_INTERNET {
		return QueryIPV4Infos(epcID0, ipv40), nil
	}
	info0, info1 = platformInfoTable.QueryIPV4InfosPair(epcID0, ipv40, epcID1, ipv41)
	if info0 == nil {
		if baseInfo := QueryEpcIDBaseInfo(int32(epcID0)); baseInfo != nil {
			info0 = &Info{
				RegionID: baseInfo.RegionID,
			}
		}
	}
	if info1 == nil {
		if baseInfo := QueryEpcIDBaseInfo(int32(epcID1)); baseInfo != nil {
			info1 = &Info{
				RegionID: baseInfo.RegionID,
			}
		}
	}
	return
}

func QueryIPV6InfosPair(epcID0 int16, ipv60 net.IP, epcID1 int16, ipv61 net.IP) (info0 *Info, info1 *Info) {
	if epcID0 == datatype.EPC_FROM_INTERNET {
		return nil, QueryIPV6Infos(epcID1, ipv61)
	} else if epcID1 == datatype.EPC_FROM_INTERNET {
		return QueryIPV6Infos(epcID0, ipv60), nil
	}
	info0, info1 = platformInfoTable.QueryIPV6InfosPair(epcID0, ipv60, epcID1, ipv61)
	if info0 == nil {
		if baseInfo := QueryEpcIDBaseInfo(int32(epcID0)); baseInfo != nil {
			info0 = &Info{
				RegionID: baseInfo.RegionID,
			}
		}
	}
	if info1 == nil {
		if baseInfo := QueryEpcIDBaseInfo(int32(epcID1)); baseInfo != nil {
			info1 = &Info{
				RegionID: baseInfo.RegionID,
			}
		}
	}
	return
}

// 单例模式，只启动一次
func NewPlatformInfoTable(ips []net.IP, port int, processName string, receiver *receiver.Receiver) *PlatformInfoTable {
	table := &PlatformInfoTable{
		receiver:           receiver,
		bootTime:           uint32(time.Now().Unix()),
		GrpcSession:        &GrpcSession{},
		ipv4Lock:           &sync.RWMutex{},
		ipv6Lock:           &sync.RWMutex{},
		macLock:            &sync.RWMutex{},
		epcIDLock:          &sync.RWMutex{},
		epcIDIPV4Lru:       lru.NewU64LRU("epcIDIPV4", LruSlotSize, LruCap),
		epcIDIPV6Lru:       lru.NewU160LRU("epcIDIPV6", LruSlotSize, LruCap),
		epcIDIPV4Infos:     make(map[uint64]*Info),
		epcIDIPV6Infos:     make(map[[EpcIDIPV6_LEN]byte]*Info),
		macInfos:           make(map[uint64]*Info),
		macMissCount:       make(map[uint64]*uint64),
		epcIDIPV4CidrInfos: make(map[int32][]*CidrInfo),
		epcIDIPV6CidrInfos: make(map[int32][]*CidrInfo),
		epcIDBaseInfos:     make(map[int32]*BaseInfo),
		epcIDBaseMissCount: make(map[int32]*uint64),
		processName:        processName,
	}
	runOnce := func() {
		if err := table.Reload(); err != nil {
			log.Warning(err)
		}
	}
	table.Init(ips, uint16(port), DEFAULT_SYNC_INTERVAL, runOnce)
	platformInfoTable = table
	return table
}

func (t *PlatformInfoTable) IPV4InfoAddLru(info *Info, key uint64) {
	if info != nil {
		t.epcIDIPV4Lru.Add(key, info)
		atomic.AddUint64(info.HitCount, 1)
		return
	}
	var missCount uint64 = 1
	// 可能导致并行时覆盖写，比正常统计结果少一
	t.epcIDIPV4Lru.Add(key, &missCount)
	log.Infof("can't find IPV4Info from epcID(%d) ip(%s)", key>>32, utils.IpFromUint32(uint32(key)).String())
}

func (t *PlatformInfoTable) IPV4InfoStat(lruItem interface{}) {
	switch t := lruItem.(type) {
	case *Info:
		atomic.AddUint64(lruItem.(*Info).HitCount, 1)
	case *uint64:
		atomic.AddUint64(lruItem.(*uint64), 1)
	default:
		log.Warningf("Unexpected type %T\n", t)
	}
}

func (t *PlatformInfoTable) QueryIPV4Infos(epcID int16, ipv4 uint32) (info *Info) {
	var ok bool
	var lruValue interface{}
	key := uint64(epcID)<<32 | uint64(ipv4)
	t.ipv4Lock.Lock()
	if lruValue, ok = t.epcIDIPV4Lru.Get(key, false); !ok {
		if info, ok = t.epcIDIPV4Infos[key]; !ok {
			info = t.QueryIPV4Cidr(epcID, ipv4)
		}
		t.IPV4InfoAddLru(info, key)
		t.ipv4Lock.Unlock()
	} else {
		t.ipv4Lock.Unlock()
		t.IPV4InfoStat(lruValue)
		info, _ = lruValue.(*Info)
	}
	return
}

func (t *PlatformInfoTable) InfoMissStat(mac uint64) {
	t.macLock.RLock()
	if missCountAddr, exist := t.macMissCount[mac]; exist {
		t.macLock.RUnlock()
		atomic.AddUint64(missCountAddr, 1)
	} else {
		t.macLock.RUnlock()
		var missCount uint64 = 1
		t.macLock.Lock()
		// 可能导致并行时覆盖写，比正常统计结果少一
		t.macMissCount[mac] = &missCount
		t.macLock.Unlock()
		log.Infof("can't find info from mac(%x)", mac)
	}
}

// 只有当l3_epc_id为正数时，才能查到info
func (t *PlatformInfoTable) QueryMacInfo(mac uint64) *Info {
	t.macLock.RLock()
	info, ok := t.macInfos[mac]
	t.macLock.RUnlock()
	if !ok {
		t.InfoMissStat(mac)
	} else {
		atomic.AddUint64(info.HitCount, 1)
	}
	return info
}

func (t *PlatformInfoTable) QueryMacInfosPair(mac0, mac1 uint64) (info0 *Info, info1 *Info) {
	var ok0, ok1 bool
	t.macLock.RLock()
	if info0, ok0 = t.macInfos[mac0]; ok0 {
		atomic.AddUint64(info0.HitCount, 1)
	}
	if info1, ok1 = t.macInfos[mac1]; ok1 {
		atomic.AddUint64(info1.HitCount, 1)
	}
	t.macLock.RUnlock()

	if !ok0 {
		t.InfoMissStat(mac0)
	}

	if !ok1 {
		t.InfoMissStat(mac1)
	}

	return
}

func (t *PlatformInfoTable) BaseInfoMissStat(epcID int32) {
	t.epcIDLock.RLock()
	if missCountAddr, exist := t.epcIDBaseMissCount[epcID]; exist {
		t.epcIDLock.RUnlock()
		atomic.AddUint64(missCountAddr, 1)
	} else {
		t.epcIDLock.RUnlock()
		var missCount uint64 = 1
		t.epcIDLock.Lock()
		// 可能导致并行时覆盖写，比正常统计结果少一
		t.epcIDBaseMissCount[epcID] = &missCount
		t.epcIDLock.Unlock()
		log.Infof("can't find baseInfo from epcID(%d)", epcID)
	}
}

func (t *PlatformInfoTable) QueryEpcIDBaseInfo(epcID int32) *BaseInfo {
	t.epcIDLock.RLock()
	baseInfo, ok := t.epcIDBaseInfos[epcID]
	t.epcIDLock.RUnlock()
	if !ok {
		t.BaseInfoMissStat(epcID)
	} else {
		atomic.AddUint64(&baseInfo.HitCount, 1)
	}
	return baseInfo
}

func (t *PlatformInfoTable) QueryEpcIDBaseInfosPair(epcID0, epcID1 int32) (baseInfo0 *BaseInfo, baseInfo1 *BaseInfo) {
	var ok0, ok1 bool
	t.epcIDLock.RLock()
	if baseInfo0, ok0 = t.epcIDBaseInfos[epcID0]; ok0 {
		atomic.AddUint64(&baseInfo0.HitCount, 1)
	}
	if baseInfo1, ok1 = t.epcIDBaseInfos[epcID1]; ok1 {
		atomic.AddUint64(&baseInfo1.HitCount, 1)
	}
	t.epcIDLock.RUnlock()

	if !ok0 {
		t.BaseInfoMissStat(epcID0)
	}

	if !ok1 {
		t.BaseInfoMissStat(epcID1)
	}

	return
}

// 需要一起查询, 防止查询时，平台信息更新
func (t *PlatformInfoTable) QueryIPV4InfosPair(epcID0 int16, ipv40 uint32, epcID1 int16, ipv41 uint32) (info0 *Info, info1 *Info) {
	var ok0, ok1 bool
	var lruValue0, lruValue1 interface{}
	key0 := uint64(epcID0)<<32 | uint64(ipv40)
	key1 := uint64(epcID1)<<32 | uint64(ipv41)
	t.ipv4Lock.Lock()
	if lruValue0, ok0 = t.epcIDIPV4Lru.Get(key0, false); !ok0 {
		if info0, ok0 = t.epcIDIPV4Infos[key0]; !ok0 {
			info0 = t.QueryIPV4Cidr(epcID0, ipv40)
		}
	} else {
		t.IPV4InfoStat(lruValue0)
		info0, _ = lruValue0.(*Info)
	}
	if lruValue1, ok1 = t.epcIDIPV4Lru.Get(key1, false); !ok1 {
		if info1, ok1 = t.epcIDIPV4Infos[key1]; !ok1 {
			info1 = t.QueryIPV4Cidr(epcID1, ipv41)
		}
	} else {
		t.IPV4InfoStat(lruValue1)
		info1, _ = lruValue1.(*Info)
	}

	if !ok0 {
		t.IPV4InfoAddLru(info0, key0)
	}
	if !ok1 {
		t.IPV4InfoAddLru(info1, key1)
	}
	t.ipv4Lock.Unlock()

	return
}

func (t *PlatformInfoTable) IPV6InfoAddLru(info *Info, key []byte) {
	if info != nil {
		t.epcIDIPV6Lru.Add(key, info)
		atomic.AddUint64(info.HitCount, 1)
		return
	}
	var missCount uint64 = 1
	// 可能导致并行时覆盖写，比正常统计结果少一
	t.epcIDIPV6Lru.Add(key, &missCount)
	log.Infof("can't find IPV6Info from epcID(%d) ip(%s)", int32(binary.LittleEndian.Uint16(key[:4])), net.IP(key[4:]).String())
}

func (t *PlatformInfoTable) IPV6InfoStat(lruItem interface{}) {
	switch t := lruItem.(type) {
	case *Info:
		atomic.AddUint64(lruItem.(*Info).HitCount, 1)
	case *uint64:
		atomic.AddUint64(lruItem.(*uint64), 1)
	default:
		log.Warningf("Unexpected type %T\n", t)
	}
}

func (t *PlatformInfoTable) QueryIPV6Infos(epcID int16, ipv6 net.IP) (info *Info) {
	var ok bool
	var lruValue interface{}
	var key [EpcIDIPV6_LEN]byte
	binary.LittleEndian.PutUint32(key[:], uint32(epcID))
	copy(key[4:], ipv6)

	t.ipv6Lock.Lock()
	if lruValue, ok = t.epcIDIPV6Lru.Get(key[:], false); !ok {
		if info, ok = t.epcIDIPV6Infos[key]; !ok {
			info = t.QueryIPV6Cidr(epcID, ipv6)
		}
		t.IPV6InfoAddLru(info, key[:])
		t.ipv6Lock.Unlock()
	} else {
		t.ipv6Lock.Unlock()
		t.IPV6InfoStat(lruValue)
		info, _ = lruValue.(*Info)
	}
	return
}

func (t *PlatformInfoTable) QueryIPV6InfosPair(epcID0 int16, ipv60 net.IP, epcID1 int16, ipv61 net.IP) (info0 *Info, info1 *Info) {
	var key0, key1 [EpcIDIPV6_LEN]byte
	binary.LittleEndian.PutUint32(key0[:], uint32(epcID0))
	copy(key0[4:], ipv60)
	binary.LittleEndian.PutUint32(key1[:], uint32(epcID1))
	copy(key1[4:], ipv61)

	var ok0, ok1 bool
	var lruValue0, lruValue1 interface{}
	t.ipv6Lock.Lock()
	if lruValue0, ok0 = t.epcIDIPV6Lru.Get(key0[:], false); !ok0 {
		if info0, ok0 = t.epcIDIPV6Infos[key0]; !ok0 {
			info0 = t.QueryIPV6Cidr(epcID0, ipv60)
		}
	} else {
		t.IPV6InfoStat(lruValue0)
		info0, _ = lruValue0.(*Info)
	}

	if lruValue1, ok1 = t.epcIDIPV6Lru.Get(key1[:], false); !ok1 {
		if info1, ok1 = t.epcIDIPV6Infos[key1]; !ok1 {
			info1 = t.QueryIPV6Cidr(epcID1, ipv61)
		}
	} else {
		t.IPV6InfoStat(lruValue1)
		info1, _ = lruValue1.(*Info)
	}

	if !ok0 {
		// 加入到map中，下次查该ip，无需遍历cidr
		t.IPV6InfoAddLru(info0, key0[:])
	}
	if !ok1 {
		t.IPV6InfoAddLru(info1, key1[:])
	}
	t.ipv6Lock.Unlock()
	return
}

// 查询Cidr之前，需要先查询过epcip表, 否则会覆盖epcip表的内容
func (t *PlatformInfoTable) QueryIPV4Cidr(epcID int16, ipv4 uint32) *Info {
	var info *Info
	if cidrInfos, exist := t.epcIDIPV4CidrInfos[int32(epcID)]; exist {
		ip := utils.IpFromUint32(ipv4)
		for _, cidrInfo := range cidrInfos {
			if cidrInfo.Cidr.Contains(ip) {
				info = &Info{
					SubnetID: cidrInfo.SubnetID,
					RegionID: cidrInfo.RegionID,
					AZID:     cidrInfo.AZID,
					HitCount: cidrInfo.HitCount,
				}
				break
			}
		}
	}
	return info
}

// 查询Cidr之前，需要先查询过epcip表, 否则会覆盖epcip表的内容
func (t *PlatformInfoTable) QueryIPV6Cidr(epcID int16, ipv6 net.IP) *Info {
	var info *Info
	if cidrInfos, exist := t.epcIDIPV6CidrInfos[int32(epcID)]; exist {
		for _, cidrInfo := range cidrInfos {
			if cidrInfo.Cidr.Contains(ipv6) {
				info = &Info{
					SubnetID: cidrInfo.SubnetID,
					RegionID: cidrInfo.RegionID,
					AZID:     cidrInfo.AZID,
					HitCount: cidrInfo.HitCount,
				}
				break
			}
		}
	}
	return info
}

func (t *PlatformInfoTable) String() string {
	sb := &strings.Builder{}

	sb.WriteString(fmt.Sprintf("RegionID: %d\n", t.regionID))
	t.ipv4Lock.RLock()
	if len(t.epcIDIPV4Infos) > 0 {
		sb.WriteString("\nepcID   ipv4            mac          host            hostID  regionID  deviceType  deviceID    subnetID  podNodeID podNSID podGroupID podID azID isVip hitCount\n")
		sb.WriteString("-----------------------------------------------------------------------------------------------------------------------------------------------------------------\n")
	}
	epcIP4s := make([]uint64, 0)
	for epcIP, _ := range t.epcIDIPV4Infos {
		epcIP4s = append(epcIP4s, epcIP)
	}
	sort.Slice(epcIP4s, func(i, j int) bool {
		return epcIP4s[i] < epcIP4s[j]
	})
	for _, epcIP := range epcIP4s {
		info := t.epcIDIPV4Infos[epcIP]
		if info == nil {
			continue
		}
		fmt.Fprintf(sb, "%-6d  %-15s %-12x %-15s %-6d  %-7d   %-10d   %-7d    %-8d  %-9d %-7d %-10d %-5d %-4d %-5t %d\n", epcIP>>32, utils.IpFromUint32(uint32(epcIP)).String(),
			info.Mac, info.HostStr, info.HostID, info.RegionID, info.DeviceType, info.DeviceID, info.SubnetID, info.PodNodeID, info.PodNSID, info.PodGroupID, info.PodID, info.AZID, info.IsVip, *info.HitCount)
	}
	t.ipv4Lock.RUnlock()

	t.ipv6Lock.RLock()
	if len(t.epcIDIPV6Infos) > 0 {
		sb.WriteString("\n\n")
		sb.WriteString("epcID   ipv6                                         mac          host            hostID  regionID deviceType  deviceID subnetID  podNodeID podNSID podGroupID podID azID isVip hitCount\n")
		sb.WriteString("---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")
	}
	epcIP6s := make([][EpcIDIPV6_LEN]byte, 0)
	for epcIP, _ := range t.epcIDIPV6Infos {
		epcIP6s = append(epcIP6s, epcIP)
	}
	sort.Slice(epcIP6s, func(i, j int) bool {
		return bytes.Compare(epcIP6s[i][:4], epcIP6s[j][:4]) < 0
	})
	for _, epcIP := range epcIP6s {
		info := t.epcIDIPV6Infos[epcIP]
		if info == nil {
			continue
		}
		fmt.Fprintf(sb, "%-6d  %-44s %-12x %-15s %-6d  %-7d  %-10d  %-7d  %-8d  %-9d %-7d %-10d %-5d %-4d %-5t %d\n", int32(binary.LittleEndian.Uint32(epcIP[:4])), net.IP(epcIP[4:]).String(),
			info.Mac, info.HostStr, info.HostID, info.RegionID, info.DeviceType, info.DeviceID, info.SubnetID, info.PodNodeID, info.PodNSID, info.PodGroupID, info.PodID, info.AZID, info.IsVip, *info.HitCount)
	}
	t.ipv6Lock.RUnlock()
	if len(t.epcIDIPV4CidrInfos) > 0 || len(t.epcIDIPV6CidrInfos) > 0 {
		sb.WriteString("\nepcID   cidr                                           regionID  subnetID   azID  hitCount\n")
		sb.WriteString("--------------------------------------------------------------------------------------------\n")
	}

	CidrInfos := make([]*CidrInfo, 0)

	t.ipv4Lock.RLock()
	for _, cidrInfo := range t.epcIDIPV4CidrInfos {
		CidrInfos = append(CidrInfos, cidrInfo...)
	}
	t.ipv4Lock.RUnlock()
	t.ipv6Lock.RLock()
	for _, cidrInfo := range t.epcIDIPV6CidrInfos {
		CidrInfos = append(CidrInfos, cidrInfo...)
	}
	t.ipv6Lock.RUnlock()

	sort.Slice(CidrInfos, func(i, j int) bool {
		return CidrInfos[i].EpcID < CidrInfos[j].EpcID
	})
	for _, cidrInfo := range CidrInfos {
		fmt.Fprintf(sb, "%-6d  %-44s   %-7d   %-8d   %-5d %d\n",
			cidrInfo.EpcID, cidrInfo.Cidr, cidrInfo.RegionID, cidrInfo.SubnetID, cidrInfo.AZID, *cidrInfo.HitCount)
	}

	sb.WriteString("\nepcID   ip                                           miss\n")
	sb.WriteString("-------------------------------------------------------------\n")
	epcIP4s = epcIP4s[:0]
	t.ipv4Lock.RLock()
	t.epcIDIPV4Lru.Walk(func(key uint64, value interface{}) {
		if _, ok := value.(*uint64); ok {
			epcIP4s = append(epcIP4s, key)
		}
	})
	sort.Slice(epcIP4s, func(i, j int) bool {
		return epcIP4s[i] < epcIP4s[j]
	})
	for _, epcIP := range epcIP4s {
		info, _ := t.epcIDIPV4Lru.Get(epcIP, true)
		missCount, _ := info.(*uint64)
		fmt.Fprintf(sb, "%-6d  %-44s %d\n", epcIP>>32, utils.IpFromUint32(uint32(epcIP)).String(), *missCount)
	}
	t.ipv4Lock.RUnlock()

	epcIP6s = make([][EpcIDIPV6_LEN]byte, 0)
	t.ipv6Lock.RLock()
	t.epcIDIPV6Lru.Walk(func(key [EpcIDIPV6_LEN]byte, value interface{}) bool {
		if _, ok := value.(*uint64); ok {
			epcIP6s = append(epcIP6s, key)
		}
		return false
	})

	sort.Slice(epcIP6s, func(i, j int) bool {
		return bytes.Compare(epcIP6s[i][:4], epcIP6s[j][:4]) < 0
	})
	for _, epcIP := range epcIP6s {
		info, _ := t.epcIDIPV6Lru.Get(epcIP[:], true)
		fmt.Fprintf(sb, "%-6d  %-44s %d\n", int(binary.LittleEndian.Uint32(epcIP[:4])), net.IP(epcIP[4:]).String(), *(info.(*uint64)))
	}
	t.ipv6Lock.RUnlock()

	if len(t.macInfos) > 0 {
		sb.WriteString("\nmac              hit\n")
		sb.WriteString("------------------------\n")
	}
	t.macLock.RLock()
	for mac, hitCount := range t.macInfos {
		if *hitCount.HitCount > 0 {
			fmt.Fprintf(sb, "%-15x  %d\n", mac, *hitCount.HitCount)
		}
	}
	t.macLock.RUnlock()

	if len(t.macMissCount) > 0 {
		sb.WriteString("\nmac              miss\n")
		sb.WriteString("------------------------\n")
	}
	t.macLock.RLock()
	for mac, missCount := range t.macMissCount {
		fmt.Fprintf(sb, "%-15x  %d\n", mac, *missCount)
	}
	t.macLock.RUnlock()

	if len(t.epcIDBaseInfos) > 0 {
		sb.WriteString("\nepcID            regionID  hitcount\n")
		sb.WriteString("-------------------------------------\n")
		t.epcIDLock.RLock()
		epcIDs := make([]int32, 0, len(t.epcIDBaseInfos))
		for epcID, _ := range t.epcIDBaseInfos {
			epcIDs = append(epcIDs, epcID)
		}
		sort.Slice(epcIDs, func(i, j int) bool {
			return epcIDs[i] < epcIDs[j]
		})
		for _, epcID := range epcIDs {
			fmt.Fprintf(sb, "%-15d  %-8d  %-8d\n", epcID, t.epcIDBaseInfos[epcID].RegionID, t.epcIDBaseInfos[epcID].HitCount)
		}
		t.epcIDLock.RUnlock()
	}

	if len(t.epcIDBaseMissCount) > 0 {
		sb.WriteString("\nepcID         miss\n")
		sb.WriteString("------------------------\n")
	}
	t.epcIDLock.RLock()
	for epcID, missCount := range t.epcIDBaseMissCount {
		fmt.Fprintf(sb, "%-15d  %d\n", epcID, *missCount)
	}
	t.epcIDLock.RUnlock()

	return sb.String()
}

func (t *PlatformInfoTable) HandleSimpleCommand(op uint16) string {
	return t.String()
}

func lookup(host net.IP) (net.IP, error) {
	routes, err := netlink.RouteGet(host)
	if err != nil {
		return nil, fmt.Errorf("RouteGet %v %s", host, err)
	}
	route := routes[0]
	src := route.Src
	if route.Src.To4() != nil {
		src = route.Src.To4()
	}
	return src, nil
}

func (t *PlatformInfoTable) Reload() error {
	var response *trident.SyncResponse
	err := t.Request(func(ctx context.Context, remote net.IP) error {
		var err error
		var local net.IP
		// 根据remote ip获取本端ip
		if local, err = lookup(remote); err != nil {
			return err
		}

		hostname, err := os.Hostname()
		if err != nil {
			log.Infof("get hostname failed. %s", err)
		}

		var communicationVtaps []*trident.CommunicationVtap
		if t.receiver != nil {
			status := t.receiver.GetTridentStatus()
			for _, s := range status {
				communicationVtaps = append(communicationVtaps, &trident.CommunicationVtap{
					VtapId:         proto.Uint32(uint32(s.VTAPID)),
					LastActiveTime: proto.Uint32(s.LastLocalTimestamp),
				})
			}
		}

		request := trident.SyncRequest{
			BootTime:            proto.Uint32(t.bootTime),
			VersionPlatformData: proto.Uint64(t.versionPlatformData),
			CtrlIp:              proto.String(local.String()),
			ProcessName:         proto.String(t.processName),
			Host:                proto.String(hostname),
			CommunicationVtaps:  communicationVtaps,
		}
		client := trident.NewSynchronizerClient(t.GetClient())
		// 分析器请求消息接口，用于stream, roze
		response, err = client.AnalyzerSync(ctx, &request)
		return err
	})
	if err != nil {
		return err
	}

	if status := response.GetStatus(); status != trident.Status_SUCCESS {
		return fmt.Errorf("grpc response failed. responseStatus is %v", status)
	}

	newVersion := response.GetVersionPlatformData()
	if newVersion == t.versionPlatformData {
		return nil
	}

	platformData := trident.PlatformData{}
	if plarformCompressed := response.GetPlatformData(); plarformCompressed != nil {
		if err := platformData.Unmarshal(plarformCompressed); err != nil {
			log.Warningf("unmarshal grpc compressed platformData failed as %v", err)
			return err
		}
	}

	if config := response.GetConfig(); config != nil {
		t.regionID = config.GetRegionId()
	} else {
		log.Warning("get regionID failed")
	}

	log.Infof("Update rpc platformdata version %d -> %d  regionID=%d", t.versionPlatformData, newVersion, t.regionID)
	t.versionPlatformData = newVersion

	newEpcIDIPV4Infos := make(map[uint64]*Info)
	newEpcIDIPV6Infos := make(map[[EpcIDIPV6_LEN]byte]*Info)
	newMacInfos := make(map[uint64]*Info)
	newEpcIDBaseInfos := make(map[int32]*BaseInfo)
	newEpcIDIPV4CidrInfos := make(map[int32][]*CidrInfo)
	newEpcIDIPV6CidrInfos := make(map[int32][]*CidrInfo)
	for _, intf := range platformData.GetInterfaces() {
		updateInterfaceInfos(newEpcIDIPV4Infos, newEpcIDIPV6Infos, newMacInfos, newEpcIDBaseInfos, intf)
	}
	for _, cidr := range platformData.GetCidrs() {
		updateCidrInfos(newEpcIDIPV4CidrInfos, newEpcIDIPV6CidrInfos, newEpcIDBaseInfos, cidr)
	}
	t.ipv4Lock.Lock()
	t.epcIDIPV4Infos = newEpcIDIPV4Infos
	t.epcIDIPV4CidrInfos = newEpcIDIPV4CidrInfos
	t.epcIDIPV4Lru.Clear()
	t.ipv4Lock.Unlock()

	t.ipv6Lock.Lock()
	t.epcIDIPV6Infos = newEpcIDIPV6Infos
	t.epcIDIPV6CidrInfos = newEpcIDIPV6CidrInfos
	t.epcIDIPV6Lru.Clear()
	t.ipv6Lock.Unlock()

	t.macLock.Lock()
	t.macInfos = newMacInfos
	t.macMissCount = make(map[uint64]*uint64)
	t.macLock.Unlock()

	t.epcIDLock.Lock()
	t.epcIDBaseInfos = newEpcIDBaseInfos
	t.epcIDBaseMissCount = make(map[int32]*uint64)
	t.epcIDLock.Unlock()

	return nil
}

func isIPV4(ipStr string) bool {
	for i := 0; i < len(ipStr); i++ {
		switch ipStr[i] {
		case '.':
			return true
		case ':':
			return false
		}
	}
	return false
}

func updateCidrInfos(IPV4CidrInfos, IPV6CidrInfos map[int32][]*CidrInfo, epcIDBaseInfos map[int32]*BaseInfo, tridentCidr *trident.Cidr) {
	prefix := tridentCidr.GetPrefix()
	_, cidr, err := net.ParseCIDR(prefix)
	if err != nil {
		log.Warningf("parse cidr(%s) failed. err=%s", err)
		return
	}

	epcID := tridentCidr.GetEpcId()
	// 由于doc中epcID为-1，对应trisolaris的epcID为0.故在此统一将收到epcID为0的，修改为-1，便于doc数据查找
	if epcID == 0 {
		epcID = datatype.EPC_FROM_DEEPFLOW
	}
	cidrInfo := &CidrInfo{
		Cidr:     cidr,
		EpcID:    epcID,
		AZID:     tridentCidr.GetAzId(),
		RegionID: tridentCidr.GetRegionId(),
		SubnetID: tridentCidr.GetSubnetId(),
		HitCount: new(uint64),
	}
	if _, exist := epcIDBaseInfos[int32(epcID)]; !exist {
		epcIDBaseInfos[int32(epcID)] = &BaseInfo{
			RegionID: tridentCidr.GetRegionId(),
		}
	}
	if isIPV4(prefix) {
		if _, ok := IPV4CidrInfos[epcID]; !ok {
			IPV4CidrInfos[epcID] = make([]*CidrInfo, 0, 1)
		}
		IPV4CidrInfos[epcID] = append(IPV4CidrInfos[epcID], cidrInfo)
	} else {
		if _, ok := IPV6CidrInfos[epcID]; !ok {
			IPV6CidrInfos[epcID] = make([]*CidrInfo, 0, 1)
		}
		IPV6CidrInfos[epcID] = append(IPV6CidrInfos[epcID], cidrInfo)
	}

	// 对结果排序，如果存在相同的网络，保证先匹配到小网段，再匹配大网段
	// 例如, 优先匹配 192.168.0.0/24 再匹配 192.168.0.0/16
	for _, cidrs := range IPV4CidrInfos {
		sort.Slice(cidrs, func(i, j int) bool {
			ci, _ := cidrs[i].Cidr.Mask.Size()
			cj, _ := cidrs[j].Cidr.Mask.Size()
			return ci > cj
		})
	}
	for _, cidrs := range IPV6CidrInfos {
		sort.Slice(cidrs, func(i, j int) bool {
			ci, _ := cidrs[i].Cidr.Mask.Size()
			cj, _ := cidrs[j].Cidr.Mask.Size()
			return ci > cj
		})
	}
}

func updateInterfaceInfos(epcIDIPV4Infos map[uint64]*Info, epcIDIPV6Infos map[[EpcIDIPV6_LEN]byte]*Info, macInfos map[uint64]*Info, epcIDBaseInfos map[int32]*BaseInfo, intf *trident.Interface) {
	epcID := intf.GetEpcId()
	// 由于doc中epcID为-1，对应trisolaris的epcID为0.故在此统一将收到epcID为0的，修改为-1，便于doc数据查找
	if epcID == 0 {
		tmp := datatype.EPC_FROM_DEEPFLOW
		epcID = uint32(tmp)
	}
	deviceType := intf.GetDeviceType()
	deviceID := intf.GetDeviceId()
	podNodeID := intf.GetPodNodeId()
	podNSID := intf.GetPodNsId()
	podGroupID := intf.GetPodGroupId()
	podID := intf.GetPodId()
	azID := intf.GetAzId()
	regionID := intf.GetRegionId()
	mac := intf.GetMac()
	if _, exist := epcIDBaseInfos[int32(epcID)]; !exist {
		epcIDBaseInfos[int32(epcID)] = &BaseInfo{
			RegionID: regionID,
		}
	}

	hostStr := intf.GetLaunchServer()
	host := uint32(0)
	if hostStr != "" {
		host = utils.IpToUint32(utils.ParserStringIpV4(hostStr))
	}
	hostID := intf.GetLaunchServerId()

	firstSubnetID := uint32(0)
	var epcIDIPV6 [EpcIDIPV6_LEN]byte
	for _, ipRes := range intf.GetIpResources() {
		subnetID := ipRes.GetSubnetId()
		if firstSubnetID == 0 {
			firstSubnetID = subnetID
		}
		isVip := ipRes.GetIsVip()
		ipStr := ipRes.GetIp()
		if isIPV4(ipStr) {
			ipU32 := utils.IpToUint32(utils.ParserStringIpV4(ipStr))
			epcIDIPV4Infos[uint64(epcID)<<32|uint64(ipU32)] = &Info{
				Host:       host,
				HostStr:    hostStr,
				HostID:     hostID,
				Mac:        mac,
				RegionID:   regionID,
				DeviceType: deviceType,
				DeviceID:   deviceID,
				SubnetID:   subnetID,
				PodNodeID:  podNodeID,
				PodNSID:    podNSID,
				PodGroupID: podGroupID,
				PodID:      podID,
				AZID:       azID,
				IsVip:      isVip,
				HitCount:   new(uint64),
			}
		} else {
			netIP := net.ParseIP(ipStr)
			if netIP == nil {
				log.Warningf("IP(%s) parse failed", ipStr)
				continue
			}
			binary.LittleEndian.PutUint32(epcIDIPV6[:4], epcID)
			copy(epcIDIPV6[4:], netIP)
			epcIDIPV6Infos[epcIDIPV6] = &Info{
				Host:       host,
				HostStr:    hostStr,
				HostID:     hostID,
				Mac:        mac,
				RegionID:   regionID,
				DeviceType: deviceType,
				DeviceID:   deviceID,
				SubnetID:   subnetID,
				PodNodeID:  podNodeID,
				PodNSID:    podNSID,
				PodGroupID: podGroupID,
				PodID:      podID,
				AZID:       azID,
				IsVip:      isVip,
				HitCount:   new(uint64),
			}
		}
	}
	macInfos[mac] = &Info{
		L2EpcID:    epcID,
		DeviceType: deviceType,
		DeviceID:   deviceID,
		HostID:     hostID,
		Mac:        mac,
		RegionID:   regionID,
		SubnetID:   firstSubnetID,
		PodNodeID:  podNodeID,
		PodGroupID: podGroupID,
		PodID:      podID,
		AZID:       azID,
		HitCount:   new(uint64),
	}
}

func RegisterPlatformDataCommand(ips []net.IP, port int) *cobra.Command {
	root := &cobra.Command{
		Use:   "rpc",
		Short: "pull policy from controller by rpc",
	}
	root.AddCommand(&cobra.Command{
		Use:   "platformData",
		Short: "get platformData from controller",
		Run: func(cmd *cobra.Command, args []string) {
			table := NewPlatformInfoTable(ips, port, "debug", nil)
			table.Reload()
			fmt.Println(table)
		},
	})

	return root
}
