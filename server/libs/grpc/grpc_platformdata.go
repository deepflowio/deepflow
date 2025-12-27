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
	"github.com/google/gopacket/layers"
	"github.com/spf13/cobra"

	"golang.org/x/net/context"

	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/debug"
	"github.com/deepflowio/deepflow/server/libs/hmap/lru"
	"github.com/deepflowio/deepflow/server/libs/logger"
	"github.com/deepflowio/deepflow/server/libs/receiver"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

const (
	DEFAULT_SYNC_INTERVAL = time.Minute
	EpcIDIPV6_LEN         = 20
	LruSlotSize           = 1 << 14
	LruCap                = 1 << 17
	GROUPID_MAX           = 1 << 16

	MASTER_TABLE_MOUDLE_NANE = "ingester"
	MAX_ORG_COUNT            = ckdb.MAX_ORG_ID + 1
)

type BaseInfo struct {
	RegionID uint32
	HitCount uint64
}

type Info struct {
	EpcID        int32
	L2EpcID      int32
	Host         uint32
	HostStr      string
	HostID       uint32
	Mac          uint64
	RegionID     uint32
	DeviceType   uint32
	DeviceID     uint32
	SubnetID     uint32
	PodNodeID    uint32
	PodNSID      uint32
	PodGroupID   uint32
	PodGroupType uint8
	PodID        uint32
	PodClusterID uint32
	AZID         uint32
	IsVip        bool
	IsWan        bool
	VtapID       uint32
	IsIPv4       bool
	IP4          uint32
	IP6          net.IP
	HitCount     *uint64
	DupCount     uint32
}

type CidrInfo struct {
	Cidr     *net.IPNet
	EpcID    int32
	RegionID uint32
	SubnetID uint32
	AZID     uint32
	IsWan    bool
	HitCount *uint64
}

type PodInfo struct {
	PodId        uint32
	PodName      string
	Ip           string
	EpcId        int32
	PodClusterId uint32
	ContainerIds []string
	PodNodeIp    string
	PodNsId      uint32
	PodGroupId   uint32
	PodGroupType uint8
}

type VtapInfo struct {
	VtapId       uint16
	EpcId        int32
	Ip           string
	IsIPv4       bool
	IP4          uint32
	IP6          net.IP
	PodClusterId uint32
	OrgId        uint16
	TeamId       uint16
}

type Counter struct {
	GrpcRequestTime     int64 `statsd:"grpc-request-time"`
	UpdateServiceTime   int64 `statsd:"update-service-time"`
	UpdatePlatformTime  int64 `statsd:"update-platform-time"`
	UpdateCount         int64 `statsd:"update-count"`
	UpdateServicesCount int64 `statsd:"update-services-count"`

	IP4TotalCount       int64 `statsd:"ip4-total-count"`
	IP4HitCount         int64 `statsd:"ip4-hit-count"`
	IP6TotalCount       int64 `statsd:"ip6-total-count"`
	IP6HitCount         int64 `statsd:"ip6-hit-count"`
	IP4MissCount        int64 `statsd:"ip4-miss-count"`
	IP6MissCount        int64 `statsd:"ip6-miss-count"`
	MacMissCount        int64 `statsd:"mac-miss-count"`
	EpcMissCount        int64 `statsd:"epc-miss-count"`
	ContainerTotalCount int64 `statsd:"container-total-count"`
	ContainerHitCount   int64 `statsd:"container-hit-count"`
	ContainerMissCount  int64 `statsd:"container-miss-count"`
}

type PlatformInfoTable struct {
	manager  *PlatformDataManager
	isMaster bool
	index    int

	receiver         *receiver.Receiver
	regionID         [MAX_ORG_COUNT]uint32
	analyzerID       uint32
	otherRegionCount [MAX_ORG_COUNT]int64
	epcIDIPV4Lru     [MAX_ORG_COUNT]*lru.U64LRU
	epcIDIPV6Lru     [MAX_ORG_COUNT]*lru.U160LRU

	epcIDIPV4Infos     [MAX_ORG_COUNT]map[uint64]*Info
	epcIDIPV6Infos     [MAX_ORG_COUNT]map[[EpcIDIPV6_LEN]byte]*Info
	epcIDIPV4CidrInfos [MAX_ORG_COUNT]map[int32][]*CidrInfo
	epcIDIPV6CidrInfos [MAX_ORG_COUNT]map[int32][]*CidrInfo

	macInfos     [MAX_ORG_COUNT]map[uint64]*Info
	macMissCount [MAX_ORG_COUNT]map[uint64]*uint64

	epcIDBaseInfos     [MAX_ORG_COUNT]map[int32]*BaseInfo
	epcIDBaseMissCount [MAX_ORG_COUNT]map[int32]*uint64

	gprocessInfos      [MAX_ORG_COUNT]map[uint32]uint64
	vtapIDProcessInfos [MAX_ORG_COUNT]map[uint64]uint32

	podIDInfosPlatformData [MAX_ORG_COUNT]map[uint32]*Info
	// podIPInfos is first obtained from podIDInfosPlatformData and needs to be supplemented by podIPs information.
	podIDInfos [MAX_ORG_COUNT]map[uint32]*Info

	bootTime            uint32
	moduleName          string
	versionPlatformData [MAX_ORG_COUNT]uint64
	ctlIP               string

	hostname   string
	runtimeEnv utils.RuntimeEnv

	versionGroups [MAX_ORG_COUNT]uint64
	ServiceTable  [MAX_ORG_COUNT]*ServiceTable

	podNameInfos       [MAX_ORG_COUNT]map[string][]*PodInfo
	vtapIdInfos        [MAX_ORG_COUNT]map[uint16]*VtapInfo
	orgIds             []uint16
	orgIdsUpdateTime   uint32
	orgIdExists        [MAX_ORG_COUNT]bool
	containerInfos     [MAX_ORG_COUNT]map[string][]*PodInfo
	containerHitCount  [MAX_ORG_COUNT]map[string]*uint64
	containerMissCount [MAX_ORG_COUNT]map[string]*uint64

	peerConnections [MAX_ORG_COUNT]map[int32][]int32

	// resource event infos
	resourceInfos [MAX_ORG_COUNT]map[uint64]*Info
	podNodeInfos  [MAX_ORG_COUNT]map[uint32]*Info
	hostInfos     [MAX_ORG_COUNT]map[uint32]*Info
	vmInfos       [MAX_ORG_COUNT]map[uint32]*Info

	*GrpcSession

	counter *Counter
	utils.Closable
}

func QueryAllOrgIDs() []uint16 {
	// wait until get orgIDs
	for true {
		if platformDataManager != nil {
			orgIDs := platformDataManager.GetMasterPlatformInfoTable().orgIds
			if len(orgIDs) > 0 {
				return orgIDs
			}
		}
		log.Infof("waiting for get org ids")
		time.Sleep(time.Second)
	}
	return nil
}

func QueryOrgIDExist(orgID uint16) (uint32, bool) {
	if orgID == ckdb.INVALID_ORG_ID {
		return 0, true
	}
	if orgID > ckdb.MAX_ORG_ID {
		return 0, false
	}
	if platformDataManager == nil {
		return 0, false
	}
	masterTable := platformDataManager.GetMasterPlatformInfoTable()
	return masterTable.orgIdsUpdateTime, masterTable.orgIdExists[orgID]
}

func QueryVtapOrgAndTeamID(orgId, vtapId uint16) (uint16, uint16) {
	if platformDataManager == nil {
		return ckdb.DEFAULT_ORG_ID, ckdb.INVALID_TEAM_ID
	}
	return platformDataManager.GetMasterPlatformInfoTable().QueryVtapOrgAndTeamID(orgId, vtapId)
}

func (t *PlatformInfoTable) GetCounter() interface{} {
	var counter *Counter
	counter, t.counter = t.counter, &Counter{}
	return counter
}

func (t *PlatformInfoTable) ClosePlatformInfoTable() {
	t.GrpcSession.Close()
	t.Closable.Close()
	if t.isMaster {
		t.manager.masterTable = nil
	} else {
		t.manager.slaveTables[t.index] = nil
	}
}

func (t *PlatformInfoTable) QueryRegionID(orgId uint16) uint32 {
	return t.regionID[orgId]
}

func (t *PlatformInfoTable) QueryAnalyzerID() uint32 {
	return t.analyzerID
}

// 统计收到其他region的数据
func (t *PlatformInfoTable) AddOtherRegion(orgId uint16) {
	atomic.AddInt64(&t.otherRegionCount[orgId], 1)
}

func (t *PlatformInfoTable) QueryEpcIDBaseInfo(orgId uint16, epcID int32) *BaseInfo {
	return t.queryEpcIDBaseInfo(orgId, epcID)
}

func (t *PlatformInfoTable) QueryEpcIDBaseInfosPair(orgId uint16, epcID0, epcID1 int32) (*BaseInfo, *BaseInfo) {
	return t.queryEpcIDBaseInfosPair(orgId, epcID0, epcID1)
}

func (t *PlatformInfoTable) QueryMacInfo(orgId uint16, mac uint64) *Info {
	return t.queryMacInfo(orgId, mac)
}

func (t *PlatformInfoTable) QueryMacInfosPair(orgId uint16, mac0, mac1 uint64) (*Info, *Info) {
	return t.queryMacInfosPair(orgId, mac0, mac1)
}

func (t *PlatformInfoTable) QueryIPV4Infos(orgId uint16, epcID int32, ipv4 uint32) *Info {
	if epcID == datatype.EPC_FROM_INTERNET {
		return nil
	}
	info := t.queryIPV4Infos(orgId, epcID, ipv4)
	if info != nil {
		return info
	}

	baseInfo := t.queryEpcIDBaseInfo(orgId, int32(epcID))
	if baseInfo == nil {
		return nil
	}
	return &Info{
		RegionID: baseInfo.RegionID,
	}
}

func (t *PlatformInfoTable) QueryIPV6Infos(orgId uint16, epcID int32, ipv6 net.IP) *Info {
	if epcID == datatype.EPC_FROM_INTERNET {
		return nil
	}
	info := t.queryIPV6Infos(orgId, epcID, ipv6)
	if info != nil {
		return info
	}

	baseInfo := t.queryEpcIDBaseInfo(orgId, int32(epcID))
	if baseInfo == nil {
		return nil
	}
	return &Info{
		RegionID: baseInfo.RegionID,
	}
}

func (t *PlatformInfoTable) QueryIPV4InfosPair(orgId uint16, epcID0 int32, ipv40 uint32, epcID1 int32, ipv41 uint32) (info0 *Info, info1 *Info) {
	if epcID0 == datatype.EPC_FROM_INTERNET {
		return nil, t.QueryIPV4Infos(orgId, epcID1, ipv41)
	} else if epcID1 == datatype.EPC_FROM_INTERNET {
		return t.QueryIPV4Infos(orgId, epcID0, ipv40), nil
	}
	info0, info1 = t.queryIPV4InfosPair(orgId, epcID0, ipv40, epcID1, ipv41)
	if info0 == nil {
		if baseInfo := t.queryEpcIDBaseInfo(orgId, int32(epcID0)); baseInfo != nil {
			info0 = &Info{
				RegionID: baseInfo.RegionID,
			}
		}
	}
	if info1 == nil {
		if baseInfo := t.queryEpcIDBaseInfo(orgId, int32(epcID1)); baseInfo != nil {
			info1 = &Info{
				RegionID: baseInfo.RegionID,
			}
		}
	}
	return
}

func (t *PlatformInfoTable) QueryIPV6InfosPair(orgId uint16, epcID0 int32, ipv60 net.IP, epcID1 int32, ipv61 net.IP) (info0 *Info, info1 *Info) {
	if epcID0 == datatype.EPC_FROM_INTERNET {
		return nil, t.QueryIPV6Infos(orgId, epcID1, ipv61)
	} else if epcID1 == datatype.EPC_FROM_INTERNET {
		return t.QueryIPV6Infos(orgId, epcID0, ipv60), nil
	}
	info0, info1 = t.queryIPV6InfosPair(orgId, epcID0, ipv60, epcID1, ipv61)
	if info0 == nil {
		if baseInfo := t.queryEpcIDBaseInfo(orgId, int32(epcID0)); baseInfo != nil {
			info0 = &Info{
				RegionID: baseInfo.RegionID,
			}
		}
	}
	if info1 == nil {
		if baseInfo := t.queryEpcIDBaseInfo(orgId, int32(epcID1)); baseInfo != nil {
			info1 = &Info{
				RegionID: baseInfo.RegionID,
			}
		}
	}
	return
}

func (t *PlatformInfoTable) QueryPodIdInfo(orgId uint16, podId uint32) *Info {
	if info, ok := t.podIDInfos[orgId][podId]; ok {
		atomic.AddUint64(info.HitCount, 1)
		return info
	}
	return nil
}

func (t *PlatformInfoTable) QueryPodService(orgId uint16, podID, podNodeID, podClusterID, podGroupID uint32, epcID int32, isIPv6 bool, ipv4 uint32, ipv6 net.IP, protocol layers.IPProtocol, serverPort uint16) uint32 {
	return t.ServiceTable[orgId].QueryPodService(podID, podNodeID, podClusterID, podGroupID, epcID, isIPv6, ipv4, ipv6, protocol, serverPort)
}

func (t *PlatformInfoTable) QueryCustomService(orgId uint16, epcID int32, isIPv6 bool, ipv4 uint32, ipv6 net.IP, serverPort uint16, podServiceId, podGroupId, l3DeviceId, podId uint32, l3DeviceType uint8) uint32 {
	return t.ServiceTable[orgId].QueryCustomService(epcID, isIPv6, ipv4, ipv6, serverPort, podServiceId, podGroupId, l3DeviceId, podId, l3DeviceType)
}

func (t *PlatformInfoTable) QueryResourceInfo(orgId uint16, resourceType, resourceID, podID uint32) *Info {
	switch trident.DeviceType(resourceType) {
	case trident.DeviceType_DEVICE_TYPE_POD:
		return t.podIDInfos[orgId][resourceID]
	case trident.DeviceType_DEVICE_TYPE_POD_NODE:
		return t.podNodeInfos[orgId][resourceID]
	case trident.DeviceType_DEVICE_TYPE_HOST_DEVICE:
		return t.hostInfos[orgId][resourceID]
	case trident.DeviceType_DEVICE_TYPE_VM:
		return t.vmInfos[orgId][resourceID]
	case trident.DeviceType_DEVICE_TYPE_PROCESS:
		if podID > 0 {
			return t.QueryPodIdInfo(orgId, podID)
		}
		if _, podId := t.QueryGprocessInfo(orgId, resourceID); podId > 0 {
			return t.QueryPodIdInfo(orgId, podId)
		}
		return nil
	default:
		return t.resourceInfos[orgId][uint64(resourceType)<<32|uint64(resourceID)]
	}
}

type PlatformDataManager struct {
	masterTable       *PlatformInfoTable
	tableLock         sync.Mutex
	slaveTables       []*PlatformInfoTable
	slaveCount        uint32
	maxSlaveTableSize int

	ips           []net.IP
	port          int
	rpcMaxMsgSize int
	nodeIP        string
	receiver      *receiver.Receiver
}

var platformDataManager *PlatformDataManager

func NewPlatformDataManager(ips []net.IP, port, maxSlaveTableSize, rpcMaxMsgSize int, nodeIP string, receiver *receiver.Receiver) *PlatformDataManager {
	if platformDataManager != nil {
		return platformDataManager
	}
	platformDataManager = &PlatformDataManager{
		slaveTables:       make([]*PlatformInfoTable, maxSlaveTableSize),
		maxSlaveTableSize: maxSlaveTableSize,
		ips:               ips,
		port:              port,
		rpcMaxMsgSize:     rpcMaxMsgSize,
		nodeIP:            nodeIP,
		receiver:          receiver,
	}
	return platformDataManager
}

func (m *PlatformDataManager) NewPlatformInfoTable(moudleName string) (*PlatformInfoTable, error) {
	m.tableLock.Lock()
	if m.masterTable == nil {
		// the master table moudleName must be 'ingester', the Controller adds datanode information according to the name of the request is 'ingester'.
		m.masterTable = NewPlatformInfoTable(m.ips, m.port, 0, m.rpcMaxMsgSize, MASTER_TABLE_MOUDLE_NANE, m.nodeIP, m.receiver, true, m)
		m.masterTable.Start()
		if moudleName == MASTER_TABLE_MOUDLE_NANE {
			m.tableLock.Unlock()
			return m.masterTable, nil
		}
	}
	m.tableLock.Unlock()
	if moudleName == MASTER_TABLE_MOUDLE_NANE {
		return m.masterTable, nil
	}

	index := int(atomic.AddUint32(&m.slaveCount, 1)) - 1
	if index >= m.maxSlaveTableSize {
		err := fmt.Errorf("new platformData table %s failed, slave talbes has reached the maximum capacity(%d) and cannot be added", moudleName, m.maxSlaveTableSize)
		log.Error(err)
		return nil, err
	}
	m.slaveTables[index] = NewPlatformInfoTable(m.ips, m.port, index, m.rpcMaxMsgSize, moudleName, m.nodeIP, m.receiver, false, m)
	return m.slaveTables[index], nil
}

func (m *PlatformDataManager) GetMasterPlatformInfoTable() *PlatformInfoTable {
	if m.masterTable != nil {
		return m.masterTable
	}
	m.NewPlatformInfoTable(MASTER_TABLE_MOUDLE_NANE)
	return m.masterTable
}

func NewPlatformInfoTable(ips []net.IP, port, index, rpcMaxMsgSize int, moduleName, nodeIP string, receiver *receiver.Receiver, isMaster bool, manager *PlatformDataManager) *PlatformInfoTable {
	table := &PlatformInfoTable{
		manager:  manager,
		isMaster: isMaster,
		index:    index,

		receiver:    receiver,
		bootTime:    uint32(time.Now().Unix()),
		GrpcSession: &GrpcSession{},
		moduleName:  moduleName,
		runtimeEnv:  utils.GetRuntimeEnv(),

		orgIds:  []uint16{},
		ctlIP:   nodeIP,
		counter: &Counter{},
	}
	for i := 0; i < MAX_ORG_COUNT; i++ {
		table.epcIDIPV4Infos[i] = make(map[uint64]*Info)
		table.epcIDIPV6Infos[i] = make(map[[EpcIDIPV6_LEN]byte]*Info)
		table.macInfos[i] = make(map[uint64]*Info)
		table.macMissCount[i] = make(map[uint64]*uint64)
		table.epcIDIPV4CidrInfos[i] = make(map[int32][]*CidrInfo)
		table.epcIDIPV6CidrInfos[i] = make(map[int32][]*CidrInfo)
		table.epcIDBaseInfos[i] = make(map[int32]*BaseInfo)
		table.epcIDBaseMissCount[i] = make(map[int32]*uint64)
		table.gprocessInfos[i] = make(map[uint32]uint64)
		table.vtapIDProcessInfos[i] = make(map[uint64]uint32)
		table.podIDInfos[i] = make(map[uint32]*Info)
		table.ServiceTable[i] = NewServiceTable(nil)
		table.podNameInfos[i] = make(map[string][]*PodInfo)
		table.vtapIdInfos[i] = make(map[uint16]*VtapInfo)
		table.containerInfos[i] = make(map[string][]*PodInfo)
		table.containerMissCount[i] = make(map[string]*uint64)
		table.containerHitCount[i] = make(map[string]*uint64)
		table.peerConnections[i] = make(map[int32][]int32)

		table.resourceInfos[i] = make(map[uint64]*Info)
		table.podNodeInfos[i] = make(map[uint32]*Info)
		table.hostInfos[i] = make(map[uint32]*Info)
		table.vmInfos[i] = make(map[uint32]*Info)
	}

	runOnce := func() {
		var err error

		var orgIds []uint16
		if table.isMaster {
			// get orgIds from Controller
			orgIds = table.requestOrgIds()
		} else {
			// get orgIds from master table
			orgIds = QueryAllOrgIDs()
		}

		for _, orgId := range orgIds {
			if table.isMaster {
				err = table.ReloadMaster(orgId)
			} else {
				err = table.ReloadSlave(orgId)
			}
			if err != nil {
				log.Warningf("reload failed: %s", err, logger.NewORGPrefix(int(orgId)))
			}
		}
	}
	table.Init(ips, uint16(port), DEFAULT_SYNC_INTERVAL, rpcMaxMsgSize, runOnce)
	stats.RegisterCountable("platformdata", table, stats.OptionStatTags{"module": moduleName})
	return table
}

func (t *PlatformInfoTable) IPV4InfoAddLru(orgId uint16, info *Info, key uint64) {
	if info != nil {
		t.epcIDIPV4Lru[orgId].Add(key, info)
		atomic.AddUint64(info.HitCount, 1)
		return
	}
	var missCount uint64 = 1
	t.epcIDIPV4Lru[orgId].Add(key, &missCount)
	log.Debugf("can't find IPV4Info from epcID (%d) ip (%s)", key>>32, utils.IpFromUint32(uint32(key)).String())
	t.counter.IP4MissCount++
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

func (t *PlatformInfoTable) queryIPV4Infos(orgId uint16, epcID int32, ipv4 uint32) (info *Info) {
	if t.epcIDIPV4Lru[orgId] == nil {
		t.epcIDIPV4Lru[orgId] = lru.NewU64LRU(ckdb.OrgDatabasePrefix(orgId)+"epcIDIPV4_"+t.moduleName, LruSlotSize, LruCap)
	}
	var ok bool
	var lruValue interface{}
	t.counter.IP4TotalCount++
	key := uint64(epcID)<<32 | uint64(ipv4)
	if lruValue, ok = t.epcIDIPV4Lru[orgId].Get(key, false); !ok {
		if info, ok = t.epcIDIPV4Infos[orgId][key]; !ok {
			info = t.queryIPV4Cidr(orgId, epcID, ipv4)
		}
		t.IPV4InfoAddLru(orgId, info, key)
	} else {
		t.counter.IP4HitCount++
		t.IPV4InfoStat(lruValue)
		info, _ = lruValue.(*Info)
	}
	return
}

func (t *PlatformInfoTable) InfoMissStat(orgId uint16, mac uint64) {
	if missCountAddr, exist := t.macMissCount[orgId][mac]; exist {
		atomic.AddUint64(missCountAddr, 1)
	} else {
		var missCount uint64 = 1
		t.macMissCount[orgId][mac] = &missCount
		log.Debugf("can't find info from mac (%x)", mac)
		t.counter.MacMissCount++
	}
}

// 只有当l3_epc_id为正数时，才能查到info
func (t *PlatformInfoTable) queryMacInfo(orgId uint16, mac uint64) *Info {
	info, ok := t.macInfos[orgId][mac]
	if !ok {
		t.InfoMissStat(orgId, mac)
	} else if info.DupCount > 0 {
		return nil
	} else {
		atomic.AddUint64(info.HitCount, 1)
	}
	return info
}

func (t *PlatformInfoTable) queryMacInfosPair(orgId uint16, mac0, mac1 uint64) (info0 *Info, info1 *Info) {
	var ok0, ok1 bool
	if info0, ok0 = t.macInfos[orgId][mac0]; ok0 {
		if info0.DupCount > 0 {
			info0 = nil
		} else {
			atomic.AddUint64(info0.HitCount, 1)
		}
	}
	if info1, ok1 = t.macInfos[orgId][mac1]; ok1 {
		if info1.DupCount > 0 {
			info1 = nil
		} else {
			atomic.AddUint64(info1.HitCount, 1)
		}
	}

	if !ok0 {
		t.InfoMissStat(orgId, mac0)
	}

	if !ok1 {
		t.InfoMissStat(orgId, mac1)
	}

	return
}

func (t *PlatformInfoTable) baseInfoMissStat(orgId uint16, epcID int32) {
	if missCountAddr, exist := t.epcIDBaseMissCount[orgId][epcID]; exist {
		atomic.AddUint64(missCountAddr, 1)
	} else {
		var missCount uint64 = 1
		t.epcIDBaseMissCount[orgId][epcID] = &missCount
		log.Debug("can't find baseInfo from epcID (%d)", epcID)
		t.counter.EpcMissCount++
	}
}

func (t *PlatformInfoTable) queryEpcIDBaseInfo(orgId uint16, epcID int32) *BaseInfo {
	// when the IP belongs to the 10/8、172.16/12、192.168/16、169.254/16 network segment,
	// EPC_ID may be EPC_UNKNOWN, and the RegionID should be the RegionID to which the Organization belongs
	if epcID == datatype.EPC_UNKNOWN {
		return &BaseInfo{
			RegionID: t.QueryRegionID(orgId),
		}
	}
	baseInfo, ok := t.epcIDBaseInfos[orgId][epcID]
	if !ok {
		t.baseInfoMissStat(orgId, epcID)
	} else {
		atomic.AddUint64(&baseInfo.HitCount, 1)
	}
	return baseInfo
}

func (t *PlatformInfoTable) queryEpcIDBaseInfosPair(orgId uint16, epcID0, epcID1 int32) (baseInfo0 *BaseInfo, baseInfo1 *BaseInfo) {
	var ok0, ok1 bool
	if baseInfo0, ok0 = t.epcIDBaseInfos[orgId][epcID0]; ok0 {
		atomic.AddUint64(&baseInfo0.HitCount, 1)
	}
	if baseInfo1, ok1 = t.epcIDBaseInfos[orgId][epcID1]; ok1 {
		atomic.AddUint64(&baseInfo1.HitCount, 1)
	}

	if !ok0 {
		t.baseInfoMissStat(orgId, epcID0)
	}

	if !ok1 {
		t.baseInfoMissStat(orgId, epcID1)
	}

	return
}

// 需要一起查询, 防止查询时，平台信息更新
func (t *PlatformInfoTable) queryIPV4InfosPair(orgId uint16, epcID0 int32, ipv40 uint32, epcID1 int32, ipv41 uint32) (info0 *Info, info1 *Info) {
	if t.epcIDIPV4Lru[orgId] == nil {
		t.epcIDIPV4Lru[orgId] = lru.NewU64LRU(ckdb.OrgDatabasePrefix(orgId)+"epcIDIPV4_"+t.moduleName, LruSlotSize, LruCap)
	}
	var ok0, ok1 bool
	var lruValue0, lruValue1 interface{}
	key0 := uint64(epcID0)<<32 | uint64(ipv40)
	key1 := uint64(epcID1)<<32 | uint64(ipv41)
	t.counter.IP4TotalCount += 2
	if lruValue0, ok0 = t.epcIDIPV4Lru[orgId].Get(key0, false); !ok0 {
		if info0, ok0 = t.epcIDIPV4Infos[orgId][key0]; !ok0 {
			info0 = t.queryIPV4Cidr(orgId, epcID0, ipv40)
		}
	} else {
		t.counter.IP4HitCount++
		t.IPV4InfoStat(lruValue0)
		info0, _ = lruValue0.(*Info)
	}
	if lruValue1, ok1 = t.epcIDIPV4Lru[orgId].Get(key1, false); !ok1 {
		if info1, ok1 = t.epcIDIPV4Infos[orgId][key1]; !ok1 {
			info1 = t.queryIPV4Cidr(orgId, epcID1, ipv41)
		}
	} else {
		t.counter.IP4HitCount++
		t.IPV4InfoStat(lruValue1)
		info1, _ = lruValue1.(*Info)
	}

	if !ok0 {
		t.IPV4InfoAddLru(orgId, info0, key0)
	}
	if !ok1 {
		t.IPV4InfoAddLru(orgId, info1, key1)
	}

	return
}

func (t *PlatformInfoTable) IPV6InfoAddLru(orgId uint16, info *Info, key []byte) {
	if info != nil {
		t.epcIDIPV6Lru[orgId].Add(key, info)
		atomic.AddUint64(info.HitCount, 1)
		return
	}
	var missCount uint64 = 1
	t.epcIDIPV6Lru[orgId].Add(key, &missCount)
	log.Debugf("can't find IPV6Info from epcID (%d) ip (%s)", int32(binary.LittleEndian.Uint16(key[:4])), net.IP(key[4:]).String())
	t.counter.IP6MissCount++
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

func (t *PlatformInfoTable) queryIPV6Infos(orgId uint16, epcID int32, ipv6 net.IP) (info *Info) {
	var ok bool
	var lruValue interface{}
	var key [EpcIDIPV6_LEN]byte
	binary.LittleEndian.PutUint32(key[:], uint32(epcID))
	copy(key[4:], ipv6)

	if t.epcIDIPV6Lru[orgId] == nil {
		t.epcIDIPV6Lru[orgId] = lru.NewU160LRU(ckdb.OrgDatabasePrefix(orgId)+"epcIDIPV6_"+t.moduleName, LruSlotSize, LruCap)
	}
	t.counter.IP6TotalCount++
	if lruValue, ok = t.epcIDIPV6Lru[orgId].Get(key[:], false); !ok {
		if info, ok = t.epcIDIPV6Infos[orgId][key]; !ok {
			info = t.queryIPV6Cidr(orgId, epcID, ipv6)
		}
		t.IPV6InfoAddLru(orgId, info, key[:])
	} else {
		t.counter.IP6HitCount++
		t.IPV6InfoStat(lruValue)
		info, _ = lruValue.(*Info)
	}
	return
}

func (t *PlatformInfoTable) queryIPV6InfosPair(orgId uint16, epcID0 int32, ipv60 net.IP, epcID1 int32, ipv61 net.IP) (info0 *Info, info1 *Info) {
	var key0, key1 [EpcIDIPV6_LEN]byte
	binary.LittleEndian.PutUint32(key0[:], uint32(epcID0))
	copy(key0[4:], ipv60)
	binary.LittleEndian.PutUint32(key1[:], uint32(epcID1))
	copy(key1[4:], ipv61)

	if t.epcIDIPV6Lru[orgId] == nil {
		t.epcIDIPV6Lru[orgId] = lru.NewU160LRU(ckdb.OrgDatabasePrefix(orgId)+"epcIDIPV6_"+t.moduleName, LruSlotSize, LruCap)
	}
	t.counter.IP6TotalCount += 2
	var ok0, ok1 bool
	var lruValue0, lruValue1 interface{}
	if lruValue0, ok0 = t.epcIDIPV6Lru[orgId].Get(key0[:], false); !ok0 {
		if info0, ok0 = t.epcIDIPV6Infos[orgId][key0]; !ok0 {
			info0 = t.queryIPV6Cidr(orgId, epcID0, ipv60)
		}
	} else {
		t.counter.IP6HitCount++
		t.IPV6InfoStat(lruValue0)
		info0, _ = lruValue0.(*Info)
	}

	if lruValue1, ok1 = t.epcIDIPV6Lru[orgId].Get(key1[:], false); !ok1 {
		if info1, ok1 = t.epcIDIPV6Infos[orgId][key1]; !ok1 {
			info1 = t.queryIPV6Cidr(orgId, epcID1, ipv61)
		}
	} else {
		t.counter.IP6HitCount++
		t.IPV6InfoStat(lruValue1)
		info1, _ = lruValue1.(*Info)
	}

	if !ok0 {
		// 加入到map中，下次查该ip，无需遍历cidr
		t.IPV6InfoAddLru(orgId, info0, key0[:])
	}
	if !ok1 {
		t.IPV6InfoAddLru(orgId, info1, key1[:])
	}
	return
}

// 查询Cidr之前，需要先查询过epcip表, 否则会覆盖epcip表的内容
func (t *PlatformInfoTable) queryIPV4Cidr(orgId uint16, epcID int32, ipv4 uint32) *Info {
	var info *Info
	if cidrInfos, exist := t.epcIDIPV4CidrInfos[orgId][int32(epcID)]; exist {
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
func (t *PlatformInfoTable) queryIPV6Cidr(orgId uint16, epcID int32, ipv6 net.IP) *Info {
	var info *Info
	if cidrInfos, exist := t.epcIDIPV6CidrInfos[orgId][epcID]; exist {
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
	return t.OrgString(ckdb.DEFAULT_ORG_ID)
}

func (t *PlatformInfoTable) OrgString(orgId uint16) string {
	sb := &strings.Builder{}

	sb.WriteString(fmt.Sprintf("OrgID %d AnalyzerID %d RegionID:%d   Drop Other RegionID Data Count:%d\n", orgId, t.analyzerID, t.regionID[orgId], t.otherRegionCount[orgId]))
	sb.WriteString(fmt.Sprintf("moduleName:%s ctlIP:%s hostname:%s RegionID:%d\n",
		t.moduleName, t.ctlIP, t.hostname, t.regionID[orgId]))
	sb.WriteString(fmt.Sprintf("ARCH:%s OS:%s Kernel:%s CPUNum:%d MemorySize:%d\n", t.runtimeEnv.Arch, t.runtimeEnv.OS, t.runtimeEnv.KernelVersion, t.runtimeEnv.CpuNum, t.runtimeEnv.MemorySize))
	if len(t.epcIDIPV4Infos[orgId]) > 0 {
		sb.WriteString("\n1 *epcID  *ipv4           mac          host            hostID  regionID  deviceType  deviceID    subnetID  podNodeID podNSID podGroupID podGroupType podID podClusterID azID isVip isWan vtapId       hitCount (ipv4平台信息)\n")
		sb.WriteString("------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")
	}
	epcIP4s := make([]uint64, 0)
	for epcIP := range t.epcIDIPV4Infos[orgId] {
		epcIP4s = append(epcIP4s, epcIP)
	}
	sort.Slice(epcIP4s, func(i, j int) bool {
		return epcIP4s[i] < epcIP4s[j]
	})
	for _, epcIP := range epcIP4s {
		info := t.epcIDIPV4Infos[orgId][epcIP]
		if info == nil {
			continue
		}
		fmt.Fprintf(sb, "  %-6d  %-15s %-12x %-15s %-6d  %-7d   %-10d   %-7d    %-8d  %-9d %-7d %-10d %-12d %-5d %-12d %-4d %-5t %-5t %-6d    %d\n", epcIP>>32, utils.IpFromUint32(uint32(epcIP)).String(),
			info.Mac, info.HostStr, info.HostID, info.RegionID, info.DeviceType, info.DeviceID, info.SubnetID, info.PodNodeID, info.PodNSID, info.PodGroupID, info.PodGroupType, info.PodID, info.PodClusterID, info.AZID, info.IsVip, info.IsWan, info.VtapID, *info.HitCount)
	}

	if len(t.epcIDIPV6Infos[orgId]) > 0 {
		sb.WriteString("\n\n")
		sb.WriteString("2 *epcID  *ipv6                                        mac          host            hostID  regionID deviceType  deviceID subnetID  podNodeID podNSID podGroupID podGroupType podID podClusterID azID isVip isWan vtapId    hitCount (ipv6平台信息)\n")
		sb.WriteString("---------------------------------------------------------------------------------------------i--------------------------------------------------------------------------------------------------------------------------------------------------------------\n")
	}
	epcIP6s := make([][EpcIDIPV6_LEN]byte, 0)
	for epcIP := range t.epcIDIPV6Infos[orgId] {
		epcIP6s = append(epcIP6s, epcIP)
	}
	sort.Slice(epcIP6s, func(i, j int) bool {
		return bytes.Compare(epcIP6s[i][:4], epcIP6s[j][:4]) < 0
	})
	for _, epcIP := range epcIP6s {
		info := t.epcIDIPV6Infos[orgId][epcIP]
		if info == nil {
			continue
		}
		fmt.Fprintf(sb, "  %-6d  %-44s %-12x %-15s %-6d  %-7d  %-10d  %-7d  %-8d  %-9d %-7d %-10d %-12d %-5d %-12d %-4d %-5t %-5t %-6d %d\n", int32(binary.LittleEndian.Uint32(epcIP[:4])), net.IP(epcIP[4:]).String(),
			info.Mac, info.HostStr, info.HostID, info.RegionID, info.DeviceType, info.DeviceID, info.SubnetID, info.PodNodeID, info.PodNSID, info.PodGroupID, info.PodGroupType, info.PodID, info.PodClusterID, info.AZID, info.IsVip, info.IsWan, info.VtapID, *info.HitCount)
	}
	if len(t.epcIDIPV4CidrInfos[orgId]) > 0 || len(t.epcIDIPV6CidrInfos[orgId]) > 0 {
		sb.WriteString("\n3 *epcID  *cidr                                          regionID  subnetID   azID   isWan hitCount (cidr平台信息) \n")
		sb.WriteString("---------------------------------------------------------------------------------------------------------------------\n")
	}

	CidrInfos := make([]*CidrInfo, 0)

	for _, cidrInfo := range t.epcIDIPV4CidrInfos[orgId] {
		CidrInfos = append(CidrInfos, cidrInfo...)
	}
	for _, cidrInfo := range t.epcIDIPV6CidrInfos[orgId] {
		CidrInfos = append(CidrInfos, cidrInfo...)
	}

	sort.Slice(CidrInfos, func(i, j int) bool {
		return CidrInfos[i].EpcID < CidrInfos[j].EpcID
	})
	for _, cidrInfo := range CidrInfos {
		fmt.Fprintf(sb, "  %-6d  %-44s   %-7d   %-8d   %-5d  %-5t %d\n",
			cidrInfo.EpcID, cidrInfo.Cidr, cidrInfo.RegionID, cidrInfo.SubnetID, cidrInfo.AZID, cidrInfo.IsWan, *cidrInfo.HitCount)
	}

	sb.WriteString("\n4 *epcID  *ip                                          miss  (epcID和IP无法匹配到1,2,3表的统计)\n")
	sb.WriteString("---------------------------------------------------------------\n")
	epcIP4s = epcIP4s[:0]
	if t.epcIDIPV4Lru[orgId] != nil {
		t.epcIDIPV4Lru[orgId].Walk(func(key uint64, value interface{}) {
			if _, ok := value.(*uint64); ok {
				epcIP4s = append(epcIP4s, key)
			}
		})
		sort.Slice(epcIP4s, func(i, j int) bool {
			return epcIP4s[i] < epcIP4s[j]
		})
		for _, epcIP := range epcIP4s {
			info, _ := t.epcIDIPV4Lru[orgId].Get(epcIP, true)
			missCount, _ := info.(*uint64)
			fmt.Fprintf(sb, "  %-6d  %-44s %d\n", epcIP>>32, utils.IpFromUint32(uint32(epcIP)).String(), *missCount)
		}
	}

	if t.epcIDIPV6Lru[orgId] != nil {
		epcIP6s = make([][EpcIDIPV6_LEN]byte, 0)
		t.epcIDIPV6Lru[orgId].Walk(func(key [EpcIDIPV6_LEN]byte, value interface{}) bool {
			if _, ok := value.(*uint64); ok {
				epcIP6s = append(epcIP6s, key)
			}
			return false
		})

		sort.Slice(epcIP6s, func(i, j int) bool {
			return bytes.Compare(epcIP6s[i][:4], epcIP6s[j][:4]) < 0
		})
		for _, epcIP := range epcIP6s {
			info, _ := t.epcIDIPV6Lru[orgId].Get(epcIP[:], true)
			fmt.Fprintf(sb, "  %-6d  %-44s %d\n", int(binary.LittleEndian.Uint32(epcIP[:4])), net.IP(epcIP[4:]).String(), *(info.(*uint64)))
		}
	}

	if len(t.macInfos[orgId]) > 0 {
		sb.WriteString("\n5 *epcID *Mac        hit   dup (epcID和MAC匹配到平台信息的统计, 优先级最高)\n")
		sb.WriteString("-----------------------------\n")
	}
	for mac, hitCount := range t.macInfos[orgId] {
		fmt.Fprintf(sb, "  %-5d  %-12x  %-5d %d\n", mac>>48, mac&0xffffffffffff, *hitCount.HitCount, hitCount.DupCount)
	}

	if len(t.macMissCount[orgId]) > 0 {
		sb.WriteString("\n6 *epcID *Mac       miss  (epcID和MAC匹配不到平台信息的统计)\n")
		sb.WriteString("------------------------------\n")
	}
	for mac, missCount := range t.macMissCount[orgId] {
		fmt.Fprintf(sb, "  %-5d  %-12x  %d\n", mac>>48, mac&0xffffffffffff, *missCount)
	}

	if len(t.epcIDBaseInfos[orgId]) > 0 {
		sb.WriteString("\n7 *epcID           regionID  hitcount (若1,2,3都无法匹配到平台信息，则只使用epcID匹配到Region信息的统计)\n")
		sb.WriteString("---------------------------------------\n")
		epcIDs := make([]int32, 0, len(t.epcIDBaseInfos[orgId]))
		for epcID := range t.epcIDBaseInfos[orgId] {
			epcIDs = append(epcIDs, epcID)
		}
		sort.Slice(epcIDs, func(i, j int) bool {
			return epcIDs[i] < epcIDs[j]
		})
		for _, epcID := range epcIDs {
			fmt.Fprintf(sb, "  %-15d  %-8d  %-8d\n", epcID, t.epcIDBaseInfos[orgId][epcID].RegionID, t.epcIDBaseInfos[orgId][epcID].HitCount)
		}
	}

	if len(t.epcIDBaseMissCount[orgId]) > 0 {
		sb.WriteString("\n8 *epcID         miss  (只使用epcID也无法匹配到region信息的统计)\n")
		sb.WriteString("--------------------------\n")
	}
	for epcID, missCount := range t.epcIDBaseMissCount[orgId] {
		fmt.Fprintf(sb, "  %-15d  %d\n", epcID, *missCount)
	}

	if len(t.containerHitCount[orgId]) > 0 {
		sb.WriteString("\n9 *containerID         hitcount  (使用containerID匹配pod信息成功的统计)\n")
		sb.WriteString("--------------------------------\n")
	}

	for containerID, hitCount := range t.containerHitCount[orgId] {
		fmt.Fprintf(sb, "  %-20s  %d\n", containerID, *hitCount)
	}

	if len(t.containerMissCount[orgId]) > 0 {
		sb.WriteString("\n10 *containerID         miss  (使用containerID无法匹配到pod信息的统计)\n")
		sb.WriteString("--------------------------------\n")
	}

	for containerID, missCount := range t.containerMissCount[orgId] {
		fmt.Fprintf(sb, "  %-20s  %d\n", containerID, *missCount)
	}

	return sb.String()
}

func (t *PlatformInfoTable) HandleSimpleCommand(op uint16, arg string) string {
	orgId := debug.GetOrgId()
	switch arg {
	case "vtap":
		return t.vtapsString(orgId)
	case "pod":
		return t.podsString(orgId)
	case "peer_conn":
		return t.peerConnectionsString(orgId)
	case "comm_vtaps":
		return t.communicationVtapsString(orgId)
	case "service":
		return t.ServiceTable[orgId].String()
	case "gprocess":
		return t.gprocessInfosString(orgId)
	case "container":
		return t.containersString(orgId)
	}

	filter := arg
	all := t.OrgString(orgId)
	lines := strings.Split(all, "\n")
	if filter != "" { // 按arg过滤返回
		filterLines := make([]string, 0, 10)
		for _, line := range lines {
			if strings.Contains(line, filter) ||
				strings.Contains(line, "epcID") ||
				strings.Contains(line, "mac") ||
				strings.Contains(line, "Region") ||
				strings.Contains(line, "------") ||
				line == "" {
				filterLines = append(filterLines, line)
			}
		}
		return strings.Join(filterLines, "\n")
	}

	rePrintLineIndex := 0
	newLines := make([]string, 0, 200)
	for i, line := range lines {
		if strings.Contains(line, "-----") && i > 0 {
			rePrintLineIndex = i - 1
		}
		newLines = append(newLines, line)
		if i%20 == 0 && len(lines)-i > 10 && lines[i+1] != "" && !strings.Contains(lines[i+1], "-----") && i-rePrintLineIndex > 10 {
			newLines = append(newLines, lines[rePrintLineIndex])
		}
	}

	return strings.Join(newLines, "\n")
}

func (t *PlatformInfoTable) updateServices(orgId uint16, groupsData *trident.Groups) {
	t.ServiceTable[orgId] = NewServiceTable(groupsData.GetSvcs())
	t.counter.UpdateServicesCount += int64(len(groupsData.GetSvcs()))
}

func (t *PlatformInfoTable) updatePlatformData(orgId uint16, platformData *trident.PlatformData) {
	newEpcIDIPV4Infos := make(map[uint64]*Info)
	newEpcIDIPV6Infos := make(map[[EpcIDIPV6_LEN]byte]*Info)
	newMacInfos := make(map[uint64]*Info)
	newEpcIDBaseInfos := make(map[int32]*BaseInfo)
	newEpcIDIPV4CidrInfos := make(map[int32][]*CidrInfo)
	newEpcIDIPV6CidrInfos := make(map[int32][]*CidrInfo)
	newEpcIDPodInfos := make(map[uint32]*Info)

	newResourceInfos := make(map[uint64]*Info)
	newPodNodeInfos := make(map[uint32]*Info)
	newHostInfos := make(map[uint32]*Info)
	newVmInfos := make(map[uint32]*Info)

	for _, intf := range platformData.GetInterfaces() {
		updateInterfaceInfos(newEpcIDIPV4Infos, newEpcIDIPV6Infos,
			newMacInfos, newResourceInfos,
			newEpcIDBaseInfos,
			newEpcIDPodInfos, newPodNodeInfos, newHostInfos, newVmInfos,
			intf)
	}
	for _, cidr := range platformData.GetCidrs() {
		updateCidrInfos(newEpcIDIPV4CidrInfos, newEpcIDIPV6CidrInfos, newEpcIDBaseInfos, cidr)
	}
	t.updatePeerConnections(orgId, platformData.GetPeerConnections())
	t.updateGprocessInfos(orgId, platformData.GetGprocessInfos())

	t.epcIDIPV4Infos[orgId] = newEpcIDIPV4Infos
	t.epcIDIPV4CidrInfos[orgId] = newEpcIDIPV4CidrInfos
	if t.epcIDIPV4Lru[orgId] != nil {
		t.epcIDIPV4Lru[orgId].NoStats()
	}
	t.epcIDIPV4Lru[orgId] = nil

	t.epcIDIPV6Infos[orgId] = newEpcIDIPV6Infos
	t.epcIDIPV6CidrInfos[orgId] = newEpcIDIPV6CidrInfos
	if t.epcIDIPV6Lru[orgId] != nil {
		t.epcIDIPV6Lru[orgId].NoStats()
	}
	t.epcIDIPV6Lru[orgId] = nil

	t.macInfos[orgId] = newMacInfos
	t.macMissCount[orgId] = make(map[uint64]*uint64)

	t.epcIDBaseInfos[orgId] = newEpcIDBaseInfos
	t.epcIDBaseMissCount[orgId] = make(map[int32]*uint64)
	t.containerHitCount[orgId] = make(map[string]*uint64)
	t.containerMissCount[orgId] = make(map[string]*uint64)

	t.podIDInfosPlatformData[orgId] = newEpcIDPodInfos

	t.resourceInfos[orgId] = newResourceInfos
	t.podNodeInfos[orgId] = newPodNodeInfos
	t.hostInfos[orgId] = newHostInfos
	t.vmInfos[orgId] = newVmInfos
}

func (t *PlatformInfoTable) updateOthers(orgId uint16, response *trident.SyncResponse) {
	vtapIps := response.GetVtapIps()
	t.updateVtapIps(orgId, vtapIps)
	podIps := response.GetPodIps()
	if podIps != nil {
		t.updatePodIps(orgId, podIps)
	}

	if analyzerConfig := response.GetAnalyzerConfig(); analyzerConfig != nil {
		t.regionID[orgId] = analyzerConfig.GetRegionId()
		t.analyzerID = analyzerConfig.GetAnalyzerId()
	} else {
		log.Warning("get analyzer config failed")
	}
	if t.analyzerID == 0 {
		log.Error("get analyzerID from Controller is invalid")
	}
}

func (t *PlatformInfoTable) ReloadSlave(orgId uint16) error {
	if t.manager == nil || t.manager.masterTable == nil {
		return nil
	}

	masterTable := t.manager.masterTable

	newGroupsVersion := masterTable.versionGroups[orgId]
	if newGroupsVersion != t.versionGroups[orgId] {
		t.versionGroups[orgId], t.ServiceTable[orgId] = newGroupsVersion, masterTable.ServiceTable[orgId]
		log.Infof("update slave (%s) rpc groups version %d -> %d ", t.moduleName, t.versionGroups[orgId], newGroupsVersion, logger.NewORGPrefix(int(orgId)))
	}

	newVersion := masterTable.versionPlatformData[orgId]
	if newVersion != t.versionPlatformData[orgId] {
		log.Infof("update slave (%s) rpc platformdata version %d -> %d  regionID=%d", t.moduleName, t.versionPlatformData[orgId], newVersion, t.regionID[orgId], logger.NewORGPrefix(int(orgId)))
		t.peerConnections[orgId] = masterTable.peerConnections[orgId]
		t.gprocessInfos[orgId] = masterTable.gprocessInfos[orgId]
		t.vtapIDProcessInfos[orgId] = masterTable.vtapIDProcessInfos[orgId]
		t.podIDInfos[orgId] = masterTable.podIDInfos[orgId]

		t.epcIDIPV4Infos[orgId] = masterTable.epcIDIPV4Infos[orgId]
		t.epcIDIPV4CidrInfos[orgId] = masterTable.epcIDIPV4CidrInfos[orgId]
		if t.epcIDIPV4Lru[orgId] != nil {
			t.epcIDIPV4Lru[orgId].NoStats()
		}
		t.epcIDIPV4Lru[orgId] = lru.NewU64LRU(ckdb.OrgDatabasePrefix(orgId)+"epcIDIPV4_"+t.moduleName, LruSlotSize, LruCap)

		t.epcIDIPV6Infos[orgId] = masterTable.epcIDIPV6Infos[orgId]
		t.epcIDIPV6CidrInfos[orgId] = masterTable.epcIDIPV6CidrInfos[orgId]
		if t.epcIDIPV6Lru[orgId] != nil {
			t.epcIDIPV6Lru[orgId].NoStats()
		}
		t.epcIDIPV6Lru[orgId] = lru.NewU160LRU(ckdb.OrgDatabasePrefix(orgId)+"epcIDIPV6_"+t.moduleName, LruSlotSize, LruCap)

		t.macInfos[orgId] = masterTable.macInfos[orgId]
		t.macMissCount[orgId] = make(map[uint64]*uint64)

		t.epcIDBaseInfos[orgId] = masterTable.epcIDBaseInfos[orgId]
		t.epcIDBaseMissCount[orgId] = make(map[int32]*uint64)

		t.containerHitCount[orgId] = make(map[string]*uint64)
		t.containerMissCount[orgId] = make(map[string]*uint64)

		t.versionPlatformData[orgId] = newVersion
		t.otherRegionCount[orgId] = 0

		t.resourceInfos[orgId] = masterTable.resourceInfos[orgId]
		t.podNodeInfos[orgId] = masterTable.podNodeInfos[orgId]
		t.hostInfos[orgId] = masterTable.hostInfos[orgId]
		t.vmInfos[orgId] = masterTable.vmInfos[orgId]
	}
	t.vtapIdInfos[orgId] = masterTable.vtapIdInfos[orgId]
	t.orgIds = masterTable.orgIds
	t.orgIdExists = masterTable.orgIdExists
	t.orgIdsUpdateTime = masterTable.orgIdsUpdateTime
	t.podNameInfos[orgId] = masterTable.podNameInfos[orgId]
	t.regionID = masterTable.regionID
	t.analyzerID = masterTable.analyzerID
	t.containerInfos[orgId] = masterTable.containerInfos[orgId]

	return nil
}

func (t *PlatformInfoTable) ReloadMaster(orgId uint16) error {
	t.counter.UpdateCount++
	var response *trident.SyncResponse
	start := time.Now()
	err := t.Request(func(ctx context.Context, remote net.IP) error {
		var err error
		if t.ctlIP == "" {
			var local net.IP
			// 根据remote ip获取本端ip
			if local, err = Lookup(remote); err != nil {
				return err
			}
			t.ctlIP = local.String()
		}

		hostname, err := os.Hostname()
		if err != nil {
			log.Infof("get hostname failed. %s", err)
		}
		t.hostname = hostname

		request := trident.SyncRequest{
			BootTime:            proto.Uint32(t.bootTime),
			VersionPlatformData: proto.Uint64(t.versionPlatformData[orgId]),
			VersionGroups:       proto.Uint64(t.versionGroups[orgId]),
			CtrlIp:              proto.String(t.ctlIP),
			ProcessName:         proto.String(t.moduleName),
			Host:                proto.String(hostname),
			CommunicationVtaps:  t.getCommunicationVtaps(orgId),
			CpuNum:              proto.Uint32(t.runtimeEnv.CpuNum),
			MemorySize:          proto.Uint64(t.runtimeEnv.MemorySize),
			Arch:                proto.String(t.runtimeEnv.Arch),
			Os:                  proto.String(t.runtimeEnv.OS),
			KernelVersion:       proto.String(t.runtimeEnv.KernelVersion),
			OrgId:               proto.Uint32(uint32(orgId)),
		}
		client := trident.NewSynchronizerClient(t.GetClient())
		// 分析器请求消息接口，用于ingester
		response, err = client.AnalyzerSync(ctx, &request)
		return err
	})
	if err != nil {
		return err
	}
	grpcRequestTime := int64(time.Since(start))
	t.counter.GrpcRequestTime += grpcRequestTime

	if status := response.GetStatus(); status != trident.Status_SUCCESS {
		return fmt.Errorf("org %d grpc response failed. responseStatus is %v", orgId, status)
	}

	newGroupsVersion := response.GetVersionGroups()
	if newGroupsVersion != t.versionGroups[orgId] {
		log.Infof("update rpc groups version %d -> %d", t.versionGroups[orgId], newGroupsVersion, logger.NewORGPrefix(int(orgId)))
		groupsData := trident.Groups{}
		if compressed := response.GetGroups(); compressed != nil {
			if err := groupsData.Unmarshal(compressed); err != nil {
				log.Warningf("unmarshal grpc compressed groups failed as %v", err, logger.NewORGPrefix(int(orgId)))
			}
		}

		if len(groupsData.GetSvcs()) > 0 {
			t.updateServices(orgId, &groupsData)
			t.versionGroups[orgId] = newGroupsVersion
		}
	}
	serviceTime := int64(time.Since(start)) - grpcRequestTime
	t.counter.UpdateServiceTime += serviceTime

	newVersion := response.GetVersionPlatformData()
	isUnmarshalSuccess := false
	if newVersion != t.versionPlatformData[orgId] {
		platformData := trident.PlatformData{}
		if plarformCompressed := response.GetPlatformData(); plarformCompressed != nil {
			if err := platformData.Unmarshal(plarformCompressed); err != nil {
				log.Warningf("unmarshal grpc compressed platformData failed as %v", err, logger.NewORGPrefix(int(orgId)))
			} else {
				isUnmarshalSuccess = true
			}
		}

		if isUnmarshalSuccess {
			log.Infof("update rpc platformdata version %d -> %d  regionID=%d", t.versionPlatformData[orgId], newVersion, t.regionID[orgId], logger.NewORGPrefix(int(orgId)))
			t.updatePlatformData(orgId, &platformData)
			t.otherRegionCount[orgId] = 0
		}
	}
	platformTime := int64(time.Since(start)) - grpcRequestTime - serviceTime
	t.counter.UpdatePlatformTime += platformTime

	t.updateOthers(orgId, response)

	// the versionPlatformData needs to be updated at the end, otherwise the Slave may have updated the Master's map.
	//  at this time, updateOthers()->updatePodIps() of Master and QueryPodInfo() of Slave will cause concurrent map write and read panic.
	if isUnmarshalSuccess {
		t.versionPlatformData[orgId] = newVersion
	}

	return nil
}

func (t *PlatformInfoTable) requestOrgIds() []uint16 {
	var response *trident.OrgIDsResponse
	err := t.Request(func(ctx context.Context, remote net.IP) error {
		client := trident.NewSynchronizerClient(t.GetClient())
		var err error
		response, err = client.GetOrgIDs(ctx, &trident.OrgIDsRequest{})
		return err
	})
	if err != nil {
		log.Errorf("request org ids failed: %s", err)
		return t.orgIds
	}
	orgIdU32s := response.GetOrgIds()
	orgIdsUpdateTime := response.GetUpdateTime()
	orgIdU16s := make([]uint16, 0, len(orgIdU32s))
	for _, orgId := range orgIdU32s {
		if ckdb.IsValidOrgID(uint16(orgId)) {
			orgIdU16s = append(orgIdU16s, uint16(orgId))
		}
	}
	if len(orgIdU16s) == 0 {
		log.Errorf("request org ids is invalid: %+v", orgIdU32s)
		return t.orgIds
	}

	sort.Slice(orgIdU16s, func(i, j int) bool {
		return orgIdU16s[i] < orgIdU16s[j]
	})

	isChanged := len(t.orgIds) != len(orgIdU16s)
	if !isChanged {
		for i := range orgIdU16s {
			if t.orgIds[i] != orgIdU16s[i] {
				isChanged = true
				break
			}
		}
	}
	if isChanged {
		log.Infof("org ids changed from %+v to %+v", t.orgIds, orgIdU16s)
		t.orgIds = orgIdU16s
		var orgIdExists [MAX_ORG_COUNT]bool
		for _, v := range orgIdU16s {
			orgIdExists[v] = true
		}
		t.orgIdExists = orgIdExists
	}
	t.orgIdsUpdateTime = orgIdsUpdateTime
	return t.orgIds
}

func (t *PlatformInfoTable) Version(orgId uint16) uint64 {
	return t.versionPlatformData[orgId]
}

func (t *PlatformInfoTable) getCommunicationVtaps(orgId uint16) []*trident.CommunicationVtap {
	var communicationVtaps []*trident.CommunicationVtap
	if t.receiver != nil {
		status := t.receiver.GetTridentStatus(orgId)
		for _, s := range status {
			communicationVtaps = append(communicationVtaps, &trident.CommunicationVtap{
				VtapId:         proto.Uint32(uint32(s.VTAPID)),
				LastActiveTime: proto.Uint32(s.LastLocalTimestamp),
			})
		}
	}
	return communicationVtaps
}

func (t *PlatformInfoTable) communicationVtapsString(orgId uint16) string {
	sb := &strings.Builder{}
	sb.WriteString(fmt.Sprintf("orgId: %d\n", orgId))
	for _, comm := range t.getCommunicationVtaps(orgId) {
		sb.WriteString(fmt.Sprintf("Vtapid: %d  LastActiveTime: %d %s\n", *comm.VtapId, *comm.LastActiveTime, time.Unix(int64(*comm.LastActiveTime), 0)))
	}
	return sb.String()
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
		log.Warningf("parse cidr (%s) failed: %s", err)
		return
	}

	epcID := tridentCidr.GetEpcId()
	// 由于doc中epcID为-2，对应trisolaris的epcID为0.故在此统一将收到epcID为0的，修改为-2，便于doc数据查找
	if epcID == 0 {
		epcID = datatype.EPC_FROM_INTERNET
	}
	isWan := tridentCidr.GetType() == trident.CidrType_WAN
	cidrInfo := &CidrInfo{
		Cidr:     cidr,
		EpcID:    epcID,
		AZID:     tridentCidr.GetAzId(),
		RegionID: tridentCidr.GetRegionId(),
		SubnetID: tridentCidr.GetSubnetId(),
		IsWan:    isWan,
		HitCount: new(uint64),
	}
	if _, exist := epcIDBaseInfos[epcID]; !exist {
		epcIDBaseInfos[epcID] = &BaseInfo{
			RegionID: tridentCidr.GetRegionId(),
		}
	}
	if isIPV4(prefix) {
		if _, ok := IPV4CidrInfos[epcID]; !ok {
			IPV4CidrInfos[epcID] = make([]*CidrInfo, 0, 1)
		}
		IPV4CidrInfos[epcID] = append(IPV4CidrInfos[epcID], cidrInfo)
		if isWan {
			// 对于WAN数据，额外插入一条epcid为零的数据，方便忽略epc进行搜索
			if _, ok := IPV4CidrInfos[0]; !ok {
				IPV4CidrInfos[0] = make([]*CidrInfo, 0, 128)
			}
			IPV4CidrInfos[0] = append(IPV4CidrInfos[0], cidrInfo)
		}
	} else {
		if _, ok := IPV6CidrInfos[epcID]; !ok {
			IPV6CidrInfos[epcID] = make([]*CidrInfo, 0, 1)
		}
		IPV6CidrInfos[epcID] = append(IPV6CidrInfos[epcID], cidrInfo)
		if isWan {
			// 对于WAN数据，额外插入一条epcid为零的数据，方便忽略epc进行搜索
			if _, ok := IPV6CidrInfos[0]; !ok {
				IPV6CidrInfos[0] = make([]*CidrInfo, 0, 128)
			}
			IPV6CidrInfos[0] = append(IPV6CidrInfos[0], cidrInfo)
		}
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

func updateInterfaceInfos(epcIDIPV4Infos map[uint64]*Info, epcIDIPV6Infos map[[EpcIDIPV6_LEN]byte]*Info, macInfos, resourceInfos map[uint64]*Info, epcIDBaseInfos map[int32]*BaseInfo, podIDInfos, podNodeInfos, hostInfos, vmInfos map[uint32]*Info, intf *trident.Interface) {
	// intf.GetEpcId() in range (0,64000], when convert to int32, 0 need convert to datatype.EPC_FROM_INTERNET
	epcID := int32(intf.GetEpcId())
	// 由于doc中epcID为-2，对应trisolaris的epcID为0.故在此统一将收到epcID为0的，修改为-2，便于doc数据查找
	if epcID == 0 {
		epcID = datatype.EPC_FROM_INTERNET
	}

	deviceType := intf.GetDeviceType()
	deviceID := intf.GetDeviceId()
	podNodeID := intf.GetPodNodeId()
	podNSID := intf.GetPodNsId()
	podGroupID := intf.GetPodGroupId()
	podGroupType := uint8(intf.GetPodGroupType())
	podID := intf.GetPodId()
	podClusterID := intf.GetPodClusterId()
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
	vtapId := intf.GetVtapId()

	firstSubnetID := uint32(0)
	var epcIDIPV6 [EpcIDIPV6_LEN]byte
	isWan := intf.GetIfType() == datatype.IF_TYPE_WAN
	for _, ipRes := range intf.GetIpResources() {
		subnetID := ipRes.GetSubnetId()
		if firstSubnetID == 0 {
			firstSubnetID = subnetID
		}
		ipStr := ipRes.GetIp()
		if isIPV4(ipStr) {
			ipU32 := utils.IpToUint32(utils.ParserStringIpV4(ipStr))
			info := &Info{
				EpcID:        epcID,
				Host:         host,
				HostStr:      hostStr,
				HostID:       hostID,
				Mac:          mac,
				RegionID:     regionID,
				DeviceType:   deviceType,
				DeviceID:     deviceID,
				SubnetID:     subnetID,
				PodNodeID:    podNodeID,
				PodNSID:      podNSID,
				PodGroupID:   podGroupID,
				PodGroupType: podGroupType,
				PodID:        podID,
				PodClusterID: podClusterID,
				AZID:         azID,
				IsWan:        isWan,
				VtapID:       vtapId,
				IsIPv4:       true,
				IP4:          ipU32,
				HitCount:     new(uint64),
			}
			epcIDIPV4Infos[uint64(epcID)<<32|uint64(ipU32)] = info
			if podID > 0 {
				podIDInfos[podID] = info
			}
			if isWan {
				// 对于WAN数据，额外插入一条epcid为零的数据，方便忽略epc进行搜索
				epcIDIPV4Infos[uint64(ipU32)] = &Info{
					EpcID:    epcID,
					HitCount: new(uint64),
				}
			}
		} else {
			netIP := net.ParseIP(ipStr)
			if netIP == nil {
				log.Warningf("IP(%s) parse failed", ipStr)
				continue
			}
			binary.LittleEndian.PutUint32(epcIDIPV6[:4], uint32(epcID))
			copy(epcIDIPV6[4:], netIP)
			info := &Info{
				EpcID:        epcID,
				Host:         host,
				HostStr:      hostStr,
				HostID:       hostID,
				Mac:          mac,
				RegionID:     regionID,
				DeviceType:   deviceType,
				DeviceID:     deviceID,
				SubnetID:     subnetID,
				PodNodeID:    podNodeID,
				PodNSID:      podNSID,
				PodGroupID:   podGroupID,
				PodGroupType: podGroupType,
				PodID:        podID,
				PodClusterID: podClusterID,
				AZID:         azID,
				IsWan:        isWan,
				VtapID:       vtapId,
				HitCount:     new(uint64),
				IsIPv4:       false,
				IP6:          netIP,
			}

			epcIDIPV6Infos[epcIDIPV6] = info
			if podID > 0 {
				podIDInfos[podID] = info
			}
			if isWan {
				// 对于WAN数据，额外插入一条epcid为零的数据，方便忽略epc进行搜索
				binary.LittleEndian.PutUint32(epcIDIPV6[:4], 0)
				epcIDIPV6Infos[epcIDIPV6] = &Info{
					EpcID:    epcID,
					HitCount: new(uint64),
				}
			}
		}
	}
	if mac != 0 {
		l3EpcMac := mac | uint64(epcID)<<48 // 取l3EpcID的低16位和Mac组成新的Mac，防止mac跨AZ冲突
		if info, exist := macInfos[l3EpcMac]; exist {
			info.DupCount += 1
		} else {
			macInfos[l3EpcMac] = &Info{
				EpcID:        epcID,
				L2EpcID:      epcID,
				DeviceType:   deviceType,
				DeviceID:     deviceID,
				HostID:       hostID,
				Mac:          mac,
				RegionID:     regionID,
				SubnetID:     firstSubnetID,
				PodNodeID:    podNodeID,
				PodGroupID:   podGroupID,
				PodGroupType: podGroupType,
				PodID:        podID,
				PodClusterID: podClusterID,
				AZID:         azID,
				VtapID:       vtapId,
				HitCount:     new(uint64),
			}
		}
	}

	resourceInfo := &Info{
		EpcID:        epcID,
		HostID:       hostID,
		RegionID:     regionID,
		DeviceType:   deviceType,
		DeviceID:     deviceID,
		PodNodeID:    podNodeID,
		PodNSID:      podNSID,
		PodGroupID:   podGroupID,
		PodGroupType: podGroupType,
		PodID:        podID,
		PodClusterID: podClusterID,
		AZID:         azID,
	}
	resourceInfos[uint64(deviceType)<<32|uint64(deviceID)] = resourceInfo

	podNodeInfo := &Info{
		EpcID:      epcID,
		HostID:     hostID,
		RegionID:   regionID,
		DeviceType: deviceType,
		DeviceID:   deviceID,
		PodNodeID:  podNodeID,
		AZID:       azID,
	}
	podNodeInfos[podNodeID] = podNodeInfo

	hostInfo := &Info{
		EpcID:      epcID,
		HostID:     hostID,
		RegionID:   regionID,
		DeviceType: deviceType,
		DeviceID:   deviceID,
		AZID:       azID,
	}
	hostInfos[hostID] = hostInfo

	if deviceType == uint32(trident.DeviceType_DEVICE_TYPE_VM) {
		vmInfos[deviceID] = hostInfo
	}
}

func (t *PlatformInfoTable) QueryVtapEpc0(orgId, vtapId uint16) int32 {
	if vtapInfo, ok := t.vtapIdInfos[orgId][vtapId]; ok {
		return int32(vtapInfo.EpcId)
	}
	return datatype.EPC_FROM_INTERNET
}

func (t *PlatformInfoTable) QueryVtapInfo(orgId, vtapId uint16) *VtapInfo {
	if vtapInfo, ok := t.vtapIdInfos[orgId][vtapId]; ok {
		return vtapInfo
	}
	return nil
}

func (t *PlatformInfoTable) QueryVtapOrgAndTeamID(orgId, vtapId uint16) (uint16, uint16) {
	if vtapInfo, ok := t.vtapIdInfos[orgId][vtapId]; ok {
		return vtapInfo.OrgId, vtapInfo.TeamId
	}
	return ckdb.DEFAULT_ORG_ID, ckdb.INVALID_TEAM_ID
}

func (t *PlatformInfoTable) inPlatformData(orgId uint16, epcID int32, isIPv4 bool, ip4 uint32, ip6 net.IP) bool {
	if isIPv4 {
		if t.queryIPV4Infos(orgId, epcID, ip4) != nil {
			return true
		}
	} else {
		if t.queryIPV6Infos(orgId, epcID, ip6) != nil {
			return true
		}
	}

	return false
}

func (t *PlatformInfoTable) findEpcInWan(orgId uint16, isIPv4 bool, ip4 uint32, ip6 net.IP) int32 {
	if isIPv4 {
		// wan数据使用ecpip为0查找
		if info := t.queryIPV4Infos(orgId, 0, ip4); info != nil {
			return info.EpcID
		}
	} else {
		// wan数据使用ecpip为0查找
		if info := t.queryIPV6Infos(orgId, 0, ip6); info != nil {
			return info.EpcID
		}
	}

	return datatype.EPC_FROM_INTERNET
}

// epc1的计算
// 1. 本地路由优先, 先假设等于epc0: 验证epc0+ip1是否在cidr list中
// 2. 对等连接路由其次, 假设等于epc0的peer-connection的epc:
// 2.1 查询PeerConnection list, 确认epc0的对等连接的epc为: epc0_0, epc0_1...
// 2.2 假设等于epc_0_0: 验证epc0_0+ip1是否在cidr list中
// 2.3 假设等于epc_0_1: 验证epc0_0+ip1是否在cidr list中
// 2.4 ...
// 3. 如果还找不到, 直接使用ip1去查wan ip
func (t *PlatformInfoTable) QueryVtapEpc1(orgId, vtapId uint16, isIPv4 bool, ip41 uint32, ip61 net.IP) int32 {
	epc0 := t.QueryVtapEpc0(orgId, vtapId)
	if t.inPlatformData(orgId, epc0, isIPv4, ip41, ip61) {
		return epc0
	}

	for _, epc1 := range t.queryPeerConnections(orgId, epc0) {
		if t.inPlatformData(orgId, epc1, isIPv4, ip41, ip61) {
			return epc1
		}
	}

	return t.findEpcInWan(orgId, isIPv4, ip41, ip61)
}

func (t *PlatformInfoTable) updateVtapIps(orgId uint16, vtapIps []*trident.VtapIp) {
	vtapIdInfos := make(map[uint16]*VtapInfo)
	for _, vtapIp := range vtapIps {
		// vtapIp.GetEpcId() in range (0,64000], when convert to int32, 0 convert to datatype.EPC_FROM_INTERNET
		epcId := int32(vtapIp.GetEpcId())
		if epcId == 0 {
			epcId = datatype.EPC_FROM_INTERNET
		}

		info := &VtapInfo{
			VtapId:       uint16(vtapIp.GetVtapId()),
			EpcId:        epcId,
			Ip:           vtapIp.GetIp(),
			PodClusterId: vtapIp.GetPodClusterId(),
			OrgId:        uint16(vtapIp.GetOrgId()),
			TeamId:       uint16(vtapIp.GetTeamId()),
			IsIPv4:       true,
		}
		if ip := net.ParseIP(info.Ip); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				info.IP4 = utils.IpToUint32(ip4)
				info.IsIPv4 = true
			} else {
				info.IP6 = ip
				info.IsIPv4 = false
			}
		}

		vtapIdInfos[uint16(vtapIp.GetVtapId())] = info
	}
	t.vtapIdInfos[orgId] = vtapIdInfos
}

func (t *PlatformInfoTable) vtapsString(orgId uint16) string {
	sb := &strings.Builder{}
	sb.WriteString(fmt.Sprintf("orgId: %d\n", orgId))
	for k, v := range t.vtapIdInfos[orgId] {
		sb.WriteString(fmt.Sprintf("vtapid: %d  %+v\n", k, *v))
	}
	return sb.String()
}

func (t *PlatformInfoTable) QueryPodInfo(orgId, vtapId uint16, podName string) *PodInfo {
	if vtapInfo, ok := t.vtapIdInfos[orgId][vtapId]; ok {
		podClusterId := vtapInfo.PodClusterId
		for _, podInfo := range t.podNameInfos[orgId][podName] {
			if podInfo.PodClusterId == podClusterId {
				return podInfo
			}
		}
	}
	return nil
}

func (t *PlatformInfoTable) QueryPodContainerInfo(orgId, vtapID uint16, containerID string) *PodInfo {
	if vtapInfo, ok := t.vtapIdInfos[orgId][vtapID]; ok {
		podClusterId := vtapInfo.PodClusterId
		atomic.AddInt64(&t.counter.ContainerTotalCount, 1)
		// assume containerid will not repeat in one cluster
		if containerInfos, ok := t.containerInfos[orgId][containerID]; ok {
			for _, podInfo := range containerInfos {
				if podInfo.PodClusterId == podClusterId {
					hitCount, ok := t.containerHitCount[orgId][containerID]
					if !ok {
						hitCount = new(uint64)
						t.containerHitCount[orgId][containerID] = hitCount
					}
					atomic.AddUint64(hitCount, 1)
					atomic.AddInt64(&t.counter.ContainerHitCount, 1)

					return podInfo
				}
			}
		} else {
			log.Debugf("can't find PodInfo from containerID(%s) and vtapID(%d)", containerID, vtapID)
			missCount, ok := t.containerMissCount[orgId][containerID]
			if !ok {
				missCount = new(uint64)
				t.containerMissCount[orgId][containerID] = missCount
			}
			atomic.AddUint64(missCount, 1)
			atomic.AddInt64(&t.counter.ContainerMissCount, 1)
		}
	}
	return nil
}

func parseIP(ipStr string) (isIPv4 bool, ip4U32 uint32, ip6 net.IP) {
	isIPv4 = true
	ip := net.ParseIP(ipStr)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			ip4U32 = utils.IpToUint32(ip4)
		} else {
			isIPv4 = false
			ip6 = ip
		}
	}
	return
}

func (t *PlatformInfoTable) updatePodIps(orgId uint16, podIps []*trident.PodIp) {
	podNameInfos := make(map[string][]*PodInfo)
	containerInfos := make(map[string][]*PodInfo)

	podIDInfos := make(map[uint32]*Info)
	// deep copy podIDInfos from t.podIDInfosPlatformData, prevent map read/write panic
	for k, v := range t.podIDInfosPlatformData[orgId] {
		podIDInfos[k] = v
	}

	for _, podIp := range podIps {
		podName := podIp.GetPodName()
		// podIp.GetEpcId() in range [0,64000], convert to int32, 0 convert to datatype.EPC_FROM_INTERNET
		epcId := int32(podIp.GetEpcId())
		if epcId == 0 {
			epcId = datatype.EPC_FROM_INTERNET
		}
		podId := podIp.GetPodId()
		pIp := podIp.GetIp()
		podNodeIp := podIp.GetPodNodeIp()
		containerIds := podIp.GetContainerIds()
		podClusterId := podIp.GetPodClusterId()
		podNsId := podIp.GetPodNsId()
		podGroupId := podIp.GetPodGroupId()
		podGroupType := uint8(podIp.GetPodGroupType())
		podInfo := &PodInfo{
			PodId:        podId,
			PodName:      podIp.GetPodName(),
			EpcId:        epcId,
			Ip:           pIp,
			PodClusterId: podClusterId,
			ContainerIds: containerIds,
			PodNodeIp:    podNodeIp,
			PodNsId:      podNsId,
			PodGroupId:   podGroupId,
			PodGroupType: podGroupType,
		}
		if podInfos, ok := podNameInfos[podName]; ok {
			podNameInfos[podName] = append(podInfos, podInfo)
		} else {
			podNameInfos[podName] = []*PodInfo{podInfo}
		}
		for _, containerId := range containerIds {
			if podInfos, ok := containerInfos[containerId]; ok {
				containerInfos[containerId] = append(podInfos, podInfo)
			} else {
				containerInfos[containerId] = []*PodInfo{podInfo}
			}
		}
		if _, ok := podIDInfos[podId]; !ok {
			ip := pIp
			if ip == "" {
				ip = podNodeIp
			}
			info := Info{}
			if ip != "" {
				isIPv4, ip4, ip6 := parseIP(ip)
				var infoPtr *Info
				if isIPv4 {
					infoPtr = t.QueryIPV4Infos(orgId, epcId, ip4)
				} else {
					infoPtr = t.QueryIPV6Infos(orgId, epcId, ip6)
				}
				if infoPtr != nil {
					info = *infoPtr
				}
				info.IsIPv4, info.IP4, info.IP6 = isIPv4, ip4, ip6
			}
			info.HitCount = new(uint64)
			info.PodID = podId
			info.PodClusterID = podClusterId
			info.PodNSID = podNsId
			info.PodGroupID = podGroupId
			info.PodGroupType = podGroupType
			info.EpcID = epcId
			podIDInfos[podId] = &info
		}
	}
	t.podNameInfos[orgId] = podNameInfos
	t.containerInfos[orgId] = containerInfos
	t.podIDInfos[orgId] = podIDInfos
}

func (t *PlatformInfoTable) podsString(orgId uint16) string {
	sb := &strings.Builder{}
	sb.WriteString(fmt.Sprintf("orgId: %d\n", orgId))
	for podName, podInfos := range t.podNameInfos[orgId] {
		for _, podInfo := range podInfos {
			sb.WriteString(fmt.Sprintf("%s %+v\n", podName, *podInfo))
		}
	}
	return sb.String()
}

func (t *PlatformInfoTable) containersString(orgId uint16) string {
	sb := &strings.Builder{}
	sb.WriteString(fmt.Sprintf("orgId: %d\n", orgId))
	for containerId, podInfos := range t.containerInfos[orgId] {
		for _, podInfo := range podInfos {
			sb.WriteString(fmt.Sprintf("%s %+v\n", containerId, *podInfo))
		}
	}
	return sb.String()
}

func inSlice(s []int32, item int32) bool {
	for _, e := range s {
		if e == item {
			return true
		}
	}
	return false
}

func (t *PlatformInfoTable) updatePeerConnections(orgId uint16, connections []*trident.PeerConnection) {
	peerConnections := make(map[int32][]int32, 1024)

	for _, connection := range connections {
		localEpcId, remoteEpcId := int32(connection.GetLocalEpcId()), int32(connection.GetRemoteEpcId())
		if peers, ok := peerConnections[localEpcId]; ok {
			if !inSlice(peers, remoteEpcId) {
				peerConnections[localEpcId] = append(peers, remoteEpcId)
			}
		} else {
			peerConnections[localEpcId] = []int32{remoteEpcId}
		}

		if peers, ok := peerConnections[remoteEpcId]; ok {
			if !inSlice(peers, localEpcId) {
				peerConnections[remoteEpcId] = append(peers, localEpcId)
			}
		} else {
			peerConnections[remoteEpcId] = []int32{localEpcId}
		}
	}

	t.peerConnections[orgId] = peerConnections
}

func (t *PlatformInfoTable) peerConnectionsString(orgId uint16) string {
	return fmt.Sprintf("org %d: %+v", orgId, t.peerConnections[orgId])
}

func (t *PlatformInfoTable) queryPeerConnections(orgId uint16, epcId int32) []int32 {
	return t.peerConnections[orgId][epcId]
}

func (t *PlatformInfoTable) updateGprocessInfos(orgId uint16, infos []*trident.GProcessInfo) {
	gProcessInfos := make(map[uint32]uint64, 1024)
	vtapIDProcessInfos := make(map[uint64]uint32, 1024)

	for _, info := range infos {
		vtapId := info.GetVtapId()
		gProcessId := info.GetGprocessId()
		podId := info.GetPodId()
		pid := info.GetPid()
		if pid != 0 {
			vtapIDProcessInfos[uint64(vtapId)<<32|uint64(pid)] = gProcessId
		}
		if vtapId == 0 || gProcessId == 0 || podId == 0 {
			continue
		}
		gProcessInfos[gProcessId] = uint64(vtapId)<<32 | uint64(podId)
	}

	t.gprocessInfos[orgId] = gProcessInfos
	t.vtapIDProcessInfos[orgId] = vtapIDProcessInfos
}

func (t *PlatformInfoTable) gprocessInfosString(orgId uint16) string {
	sb := &strings.Builder{}
	sb.WriteString(fmt.Sprintf("orgId: %d\n", orgId))
	sb.WriteString("gprocessId         vtapId        podId\n")
	sb.WriteString("--------------------------------------\n")
	for gpid, vtapPodId := range t.gprocessInfos[orgId] {
		sb.WriteString(fmt.Sprintf("%-10d         %-6d       %d\n", gpid, vtapPodId>>32, vtapPodId<<32>>32))
	}
	sb.WriteString("\nvtapId         processId        gprocessId\n")
	sb.WriteString("----------------------------------------\n")
	for vtapIdPid, gprocessId := range t.vtapIDProcessInfos[orgId] {
		sb.WriteString(fmt.Sprintf("%-6d         %-9d       %d\n", vtapIdPid>>32, vtapIdPid<<32>>32, gprocessId))
	}
	return sb.String()
}

// return vtapID, podID
func (t *PlatformInfoTable) QueryGprocessInfo(orgId uint16, gprocessId uint32) (uint16, uint32) {
	if vtapPod, ok := t.gprocessInfos[orgId][gprocessId]; ok {
		return uint16(vtapPod >> 32), uint32(vtapPod << 32 >> 32)
	}
	return 0, 0
}

// return gProcessID
func (t *PlatformInfoTable) QueryProcessInfo(orgId, vtapId uint16, processId uint32) uint32 {
	return t.vtapIDProcessInfos[orgId][uint64(vtapId)<<32|uint64(processId)]
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
			table := NewPlatformInfoTable(ips, port, 0, 41943040, "test", "", nil, true, nil)
			table.ReloadMaster(ckdb.DEFAULT_ORG_ID)
			fmt.Println(table)
		},
	})

	return root
}
