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

package vtap

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/message/trident"
	. "github.com/deepflowio/deepflow/server/controller/common"
	models "github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/config"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/dbmgr"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
	"github.com/deepflowio/deepflow/server/libs/pool"
	libu "github.com/deepflowio/deepflow/server/libs/utils"
)

const (
	GPID0_MASK = 0xFFFF_FFFF_0000_0000
	GPID1_MASK = 0x0000_0000_FFFF_FFFF
	CACHE_SIZE = 65535

	TCP_PROTO_STR = "TCP"
	UDP_PROTO_STR = "UDP"
	LOOP_BACK_IP  = 0x7F000001
)

type PidPair struct {
	agentId0 uint32
	pid0     uint32
	agentId1 uint32
	pid1     uint32
}

var pidPairPool = pool.NewLockFreePool(func() interface{} {
	return &PidPair{}
})

func newPidPair() *PidPair {
	return pidPairPool.Get().(*PidPair)
}

func releasePidPair(pidPair *PidPair) {
	if pidPair == nil {
		return
	}

	*pidPair = PidPair{}
	pidPairPool.Put(pidPair)
}

func (g *PidPair) setPid0(pid0 uint32, agentId0 uint32) {
	if g == nil {
		return
	}
	g.agentId0 = agentId0
	g.pid0 = pid0
}

func (g *PidPair) setPid1(pid1 uint32, agentId1 uint32) {
	if g == nil {
		return
	}
	g.agentId1 = agentId1
	g.pid1 = pid1
}

func (g *PidPair) getPid0Data() (pid0, agentId0 uint32) {
	if g == nil {
		return
	}
	pid0 = g.pid0
	agentId0 = g.agentId0
	return
}

func (g *PidPair) getPid1Data() (pid1, agentId1 uint32) {
	if g == nil {
		return
	}
	pid1 = g.pid1
	agentId1 = g.agentId1
	return
}

func (g *PidPair) getData() (pid0, agentId0, pid1, agentId1 uint32) {
	if g == nil {
		return
	}
	pid0 = g.pid0
	agentId0 = g.agentId0
	pid1 = g.pid1
	agentId1 = g.agentId1
	return
}

// epcId(u16),port(u16),ip(u32)
func generateEPKey(epcId, port, ip uint32) uint64 {
	epcIDPort := epcId<<16 | port
	return uint64(epcIDPort)<<32 | uint64(ip)
}

func getEpcIdPortIP(value uint64) (epcId, port, ip uint32) {
	ip = uint32(value & 0xffffffff)
	epcIdPort := uint32(value >> 32)
	port = (epcIdPort & 0xffff)
	epcId = epcIdPort >> 16
	return
}

// agentId(u32),port(u16),netnsIndex(u16)
func generateLoopbackKey(agentId, port, netnsIndex uint32) uint64 {
	portNS := port<<16 | netnsIndex
	return uint64(agentId)<<32 | uint64(portNS)
}

func getAgentIdPortNetnsIndex(value uint64) (agentId, port, netnsIndex uint32) {
	agentId = uint32(value >> 32)
	portNS := uint32(value & 0xffffffff)
	netnsIndex = portNS & 0xffff
	port = portNS >> 16
	return
}

func convertProto(proto string) trident.ServiceProtocol {
	switch proto {
	case TCP_PROTO_STR:
		return trident.ServiceProtocol_TCP_SERVICE
	case UDP_PROTO_STR:
		return trident.ServiceProtocol_UDP_SERVICE
	}

	return 0
}

var serviceTypes = [MAX_SERVICE_TYPE]int{TCPService, UDPService}
var ipTypes = [MAX_IP_TYPE]int{NORMAL_IP, LOOP_IP}

const (
	NORMAL_IP = iota // normal_ip
	LOOP_IP          // 127.0.0.1/8
	MAX_IP_TYPE
)

const (
	TCPService = iota
	UDPService
	MAX_SERVICE_TYPE
)

type EntryData [MAX_SERVICE_TYPE][MAX_IP_TYPE]*utils.U128IDMap

func NewEntryData() EntryData {
	var entryData EntryData
	for index, _ := range entryData {
		entryData[index][NORMAL_IP] = utils.NewU128IDMapNoStats("trisolaris-global-gpid", CACHE_SIZE)
		entryData[index][LOOP_IP] = utils.NewU128IDMapNoStats("trisolaris-global-gpid", CACHE_SIZE)
	}

	return entryData
}

func isLoopbackIP(ip uint32) bool {
	if ip&0xFF000000 == 0x7F000000 {
		return true
	}

	return false
}

func (d EntryData) getAggregateMap(entry *trident.GPIDSyncEntry) *utils.U128IDMap {
	protocol := entry.GetProtocol()
	ip := entry.GetIpv4_1()
	serviceIndex := MAX_SERVICE_TYPE
	switch {
	case protocol == trident.ServiceProtocol_TCP_SERVICE:
		serviceIndex = TCPService
	case protocol == trident.ServiceProtocol_UDP_SERVICE:
		serviceIndex = UDPService
	}
	if serviceIndex == MAX_SERVICE_TYPE {
		return nil
	}

	ipIndex := NORMAL_IP
	if isLoopbackIP(ip) == true {
		ipIndex = LOOP_IP
	}

	return d[serviceIndex][ipIndex]
}

func (d EntryData) addData(agentId uint32, entry *trident.GPIDSyncEntry, p *ProcessInfo) {
	aggregateMap := d.getAggregateMap(entry)
	if aggregateMap == nil {
		return
	}
	pid0, pid1 := entry.GetPid_0(), entry.GetPid_1()
	if pid0 == 0 && pid1 == 0 {
		return
	}
	key0, key1 := p.getKey(agentId, entry)
	value := newPidPair()
	if pid0 > 0 {
		value.setPid0(pid0, agentId)
	}
	if pid1 > 0 {
		value.setPid1(pid1, agentId)
	}
	mapValue, add := aggregateMap.AddOrGet(key0, key1, value, false)
	if add == false {
		// add pid0/pid1 data
		entry := mapValue.(*PidPair)
		if pid0 > 0 {
			entry.setPid0(pid0, agentId)
		}
		if pid1 > 0 {
			entry.setPid1(pid1, agentId)
		}
		releasePidPair(value)
	}
}

func (d EntryData) getData(agentId uint32, entry *trident.GPIDSyncEntry, p *ProcessInfo) *PidPair {
	aggregateMap := d.getAggregateMap(entry)
	if aggregateMap == nil {
		return nil
	}
	key0, key1 := p.getKey(agentId, entry)
	value, _ := aggregateMap.Get(key0, key1)
	if value == nil {
		return nil
	}
	return value.(*PidPair)
}

func (e EntryData) getGPIDGlobalData(p *ProcessInfo) []*trident.GlobalGPIDEntry {

	allData := []*trident.GlobalGPIDEntry{}
	for _, serviceIndex := range serviceTypes {
		var protocol trident.ServiceProtocol
		switch serviceIndex {
		case TCPService:
			protocol = trident.ServiceProtocol_TCP_SERVICE
		case UDPService:
			protocol = trident.ServiceProtocol_UDP_SERVICE
		}
		if serviceIndex >= MAX_SERVICE_TYPE {
			break
		}
		for _, ipIndex := range ipTypes {
			if ipIndex >= MAX_IP_TYPE {
				break
			}
			for keyValue := range e[serviceIndex][ipIndex].Iter() {
				var epcId0, port0, ip0, epcId1, port1, ip1, netnsIndex uint32
				key0, key1, value := keyValue.GetData()
				if ipIndex == LOOP_IP {
					_, port0, netnsIndex = getAgentIdPortNetnsIndex(key0)
					_, port1, _ = getAgentIdPortNetnsIndex(key1)
					ip0 = LOOP_BACK_IP
					ip1 = LOOP_BACK_IP
				} else {
					epcId0, port0, ip0 = getEpcIdPortIP(key0)
					epcId1, port1, ip1 = getEpcIdPortIP(key1)
				}
				realValue, ok := value.(*PidPair)
				if ok == false {
					continue
				}
				pid0, agentId0, pid1, agentId1 := realValue.getData()
				gpid0 := p.agentIdAndPIDToGPID.getData(agentId0, pid0)
				gpid1 := p.agentIdAndPIDToGPID.getData(agentId1, pid1)
				entry := &trident.GlobalGPIDEntry{
					Protocol:  &protocol,
					AgentId_1: &agentId1,
					EpcId_1:   &epcId1,
					Ipv4_1:    &ip1,
					Port_1:    &port1,
					Pid_1:     &pid1,
					Gpid_1:    &gpid1,
					AgentId_0: &agentId0,
					EpcId_0:   &epcId0,
					Ipv4_0:    &ip0,
					Port_0:    &port0,
					Pid_0:     &pid0,
					Gpid_0:    &gpid0,
					NetnsIdx:  &netnsIndex,
				}
				allData = append(allData, entry)
			}
		}
	}

	return allData
}

type CacheReq struct {
	updateTime time.Time
	req        *trident.GPIDSyncRequest
}

func NewCacheReq(req *trident.GPIDSyncRequest) *CacheReq {
	return &CacheReq{
		updateTime: time.Now(),
		req:        req,
	}
}

func (c *CacheReq) getReq() *trident.GPIDSyncRequest {
	if c == nil {
		return nil
	}
	return c.req
}

func (c *CacheReq) getUpdateTime() int {
	if c == nil {
		return 0
	}
	return int(c.updateTime.Unix())
}

func (c *CacheReq) After(r *CacheReq) bool {
	if c == nil || r == nil {
		return false
	}
	return c.updateTime.After(r.updateTime)
}

type AgentIDToReq struct {
	sync.RWMutex
	idToReq map[uint32]*CacheReq
}

func (r *AgentIDToReq) getKeys() []uint32 {
	r.RLock()
	keys := make([]uint32, 0, len(r.idToReq))
	for key, _ := range r.idToReq {
		keys = append(keys, key)
	}
	r.RUnlock()
	return keys
}

func (r *AgentIDToReq) getSetIntKeys() mapset.Set {
	r.RLock()
	keys := mapset.NewSet()
	for key, _ := range r.idToReq {
		keys.Add(int(key))
	}
	r.RUnlock()
	return keys
}

func (r *AgentIDToReq) updateReq(req *trident.GPIDSyncRequest) {
	if req == nil {
		return
	}
	r.Lock()
	r.idToReq[req.GetVtapId()] = NewCacheReq(req)
	r.Unlock()
}

func (r *AgentIDToReq) updateCacheReq(cacheReq *CacheReq) {
	if cacheReq == nil || cacheReq.req == nil {
		return
	}

	r.Lock()
	r.idToReq[cacheReq.req.GetVtapId()] = cacheReq
	r.Unlock()
}

func (r *AgentIDToReq) getCacheReq(agentId uint32) *CacheReq {
	r.RLock()
	cacheReq := r.idToReq[agentId]
	r.RUnlock()
	return cacheReq
}

func (r *AgentIDToReq) getReq(agentId uint32) *trident.GPIDSyncRequest {
	r.RLock()
	cacheReq := r.idToReq[agentId]
	r.RUnlock()
	if cacheReq != nil {
		return cacheReq.getReq()
	}
	return nil
}

func (r *AgentIDToReq) getAllReqAndClear() map[uint32]*CacheReq {
	r.Lock()
	allData := r.idToReq
	r.idToReq = make(map[uint32]*CacheReq)
	r.Unlock()

	return allData
}

func (r *AgentIDToReq) deleteData(agentId uint32) {
	r.Lock()
	delete(r.idToReq, agentId)
	r.Unlock()
}

func NewAgentIDToReq() *AgentIDToReq {
	return &AgentIDToReq{
		idToReq: make(map[uint32]*CacheReq),
	}
}

// (vtap_id + pid): gpid
type IDToGPID map[uint64]uint32

func generateVPKey(agentId uint32, pid uint32) uint64 {
	return uint64(agentId)<<32 | uint64(pid)
}

func (p IDToGPID) getData(agentId uint32, pid uint32) uint32 {
	return p[generateVPKey(agentId, pid)]
}

func (p IDToGPID) addData(process *models.Process) {
	p[generateVPKey(uint32(process.VTapID), uint32(process.PID))] = uint32(process.ID)
}

type RealServerData struct {
	agentId   uint32
	epcIdReal uint32
	portReal  uint32
	ipv4Real  uint32
	pidReal   uint32
}

func (r RealServerData) getData() (uint32, uint32, uint32, uint32, uint32) {
	return r.agentId, r.epcIdReal, r.portReal, r.ipv4Real, r.pidReal
}

type RipToVipMap map[uint64]uint64

type RVData [MAX_SERVICE_TYPE]RipToVipMap

func NewRVData() RVData {
	var rvData RVData
	for index, _ := range rvData {
		rvData[index] = make(RipToVipMap)
	}

	return rvData
}

func (r RVData) getRVmap(protocol trident.ServiceProtocol) RipToVipMap {
	serviceIndex := MAX_SERVICE_TYPE
	switch {
	case protocol == trident.ServiceProtocol_TCP_SERVICE:
		serviceIndex = TCPService
	case protocol == trident.ServiceProtocol_UDP_SERVICE:
		serviceIndex = UDPService
	}
	if serviceIndex == MAX_SERVICE_TYPE {
		return nil
	}

	return r[serviceIndex]
}

func (r RVData) addData(epcId, rIp, rPort, vIp, vPort uint32, protocol trident.ServiceProtocol) {
	rvMap := r.getRVmap(protocol)
	if rvMap == nil {
		return
	}
	rvMap.addData(epcId, rIp, rPort, vIp, vPort)
}

func (r RVData) getvIp(rEpcId, rIp, rPort uint32, protocol trident.ServiceProtocol) (vIp, vport uint32) {
	rvMap := r.getRVmap(protocol)
	if rvMap == nil {
		return
	}
	vIp, vport = rvMap.getvIp(rEpcId, rIp, rPort)
	return
}

func (r RVData) getDebugData() []*trident.RipToVip {
	allData := []*trident.RipToVip{}
	for _, serviceIndex := range serviceTypes {
		var protocol trident.ServiceProtocol
		switch serviceIndex {
		case TCPService:
			protocol = trident.ServiceProtocol_TCP_SERVICE
		case UDPService:
			protocol = trident.ServiceProtocol_UDP_SERVICE
		}
		if serviceIndex >= MAX_SERVICE_TYPE {
			break
		}
		for key, value := range r[serviceIndex] {
			epcId, rport, rip := getEpcIdPortIP(key)
			_, vport, vIp := getEpcIdPortIP(value)
			entry := &trident.RipToVip{
				Protocol: &protocol,
				EpcId:    &epcId,
				RIpv4:    &rip,
				RPort:    &rport,
				VIpv4:    &vIp,
				VPort:    &vport,
			}
			allData = append(allData, entry)
		}
	}

	return allData

}

func (v RipToVipMap) addData(epcId, rip, rport, vIp, vport uint32) {
	// FIXME: fix epcid
	epcId = 0
	v[generateEPKey(epcId, rport, rip)] = generateEPKey(0, vport, vIp)
}

func (v RipToVipMap) getvIp(rEpcId, rIp, rPort uint32) (vIp, vport uint32) {
	// FIXME: fix epcid
	rEpcId = 0
	key, ok := v[generateEPKey(rEpcId, rPort, rIp)]
	if ok == false {
		return
	}
	_, vport, vIp = getEpcIdPortIP(key)
	return
}

type ProcessInfo struct {
	sendGPIDReq            *AgentIDToReq
	agentIdToLocalGPIDReq  *AgentIDToReq
	agentIdToShareGPIDReq  *AgentIDToReq
	agentIdAndPIDToGPID    IDToGPID
	rvData                 RVData
	globalLocalEntries     EntryData
	realClientToRealServer *utils.U128IDMap
	grpcConns              map[string]*grpc.ClientConn
	db                     *gorm.DB
	config                 *config.Config
}

func NewProcessInfo(db *gorm.DB, cfg *config.Config) *ProcessInfo {
	return &ProcessInfo{
		sendGPIDReq:            NewAgentIDToReq(),
		agentIdToLocalGPIDReq:  NewAgentIDToReq(),
		agentIdToShareGPIDReq:  NewAgentIDToReq(),
		agentIdAndPIDToGPID:    make(IDToGPID),
		rvData:                 NewRVData(),
		globalLocalEntries:     NewEntryData(),
		realClientToRealServer: utils.NewU128IDMapNoStats("trisolaris-real-pid", CACHE_SIZE),
		grpcConns:              make(map[string]*grpc.ClientConn),
		db:                     db,
		config:                 cfg,
	}
}

func (p *ProcessInfo) GetRealGlobalData() []*trident.RealClientToRealServer {
	data := make([]*trident.RealClientToRealServer, 0, p.realClientToRealServer.Size())

	for keyValue := range p.realClientToRealServer.Iter() {
		key0, key1, value := keyValue.GetData()
		epcId0, port0, ip0 := getEpcIdPortIP(key0)
		epcId1, port1, ip1 := getEpcIdPortIP(key1)
		realValue, ok := value.(*RealServerData)
		if ok == false {
			continue
		}
		agentIdReal, epcIdReal, portReal, ipReal, pidReal := realValue.getData()
		etnry := &trident.RealClientToRealServer{
			EpcId_1:     &epcId1,
			Ipv4_1:      &ip1,
			Port_1:      &port1,
			EpcId_0:     &epcId0,
			Ipv4_0:      &ip0,
			Port_0:      &port0,
			EpcIdReal:   &epcIdReal,
			Ipv4Real:    &ipReal,
			PortReal:    &portReal,
			PidReal:     &pidReal,
			AgentIdReal: &agentIdReal,
		}
		data = append(data, etnry)
	}

	return data
}

func (p *ProcessInfo) GetRVData() []*trident.RipToVip {
	return p.rvData.getDebugData()
}

func (p *ProcessInfo) getKey(agentId uint32, entry *trident.GPIDSyncEntry) (key0, key1 uint64) {
	if isLoopbackIP(entry.GetIpv4_1()) {
		netnsIndex := entry.GetNetnsIdx()
		key0 = generateLoopbackKey(agentId, entry.GetPort_0(), netnsIndex)
		key1 = generateLoopbackKey(agentId, entry.GetPort_1(), netnsIndex)
		return
	}
	// server
	// If there is a real client, use the real client ip/port instead of the client ip/port
	// Use the server ip/port to query the load balancing RIP>vIp mapping table on the controller and convert it to vIp/vport
	if entry.GetPid_1() > 0 && entry.GetIpv4Real() > 0 && entry.GetRoleReal() == trident.RoleType_ROLE_CLIENT {
		key0 = generateEPKey(entry.GetEpcIdReal(), entry.GetPortReal(), entry.GetIpv4Real())
		rEpcId, rPort, rIpv4 := entry.GetEpcId_1(), entry.GetPort_1(), entry.GetIpv4_1()
		vIpv4, vPort := p.rvData.getvIp(rEpcId, rIpv4, rPort, entry.GetProtocol())
		if vIpv4 > 0 && vPort > 0 {
			key1 = generateEPKey(rEpcId, vPort, vIpv4)
		} else {
			key1 = generateEPKey(rEpcId, rPort, rIpv4)
		}
	} else {
		key0 = generateEPKey(entry.GetEpcId_0(), entry.GetPort_0(), entry.GetIpv4_0())
		key1 = generateEPKey(entry.GetEpcId_1(), entry.GetPort_1(), entry.GetIpv4_1())
	}
	return
}

func (p *ProcessInfo) addRealData(agentId uint32, entry *trident.GPIDSyncEntry, toRS *utils.U128IDMap) {
	if entry.GetPid_1() > 0 && entry.GetIpv4Real() > 0 && entry.GetRoleReal() == trident.RoleType_ROLE_CLIENT {
		key0, key1 := p.getKey(agentId, entry)
		value := &RealServerData{
			epcIdReal: entry.GetEpcId_1(),
			portReal:  entry.GetPort_1(),
			ipv4Real:  entry.GetIpv4_1(),
			pidReal:   entry.GetPid_1(),
			agentId:   agentId,
		}
		toRS.AddOrGet(key0, key1, value, true)
	}
}

func (p *ProcessInfo) getRealData(agentId uint32, entry *trident.GPIDSyncEntry) *RealServerData {
	key0, key1 := p.getKey(agentId, entry)
	realData, ok := p.realClientToRealServer.Get(key0, key1)
	if ok {
		return realData.(*RealServerData)
	}

	return nil
}

func (p *ProcessInfo) UpdateAgentGPIDReq(req *trident.GPIDSyncRequest) {
	p.sendGPIDReq.updateReq(req)
}

func (p *ProcessInfo) GetAgentGPIDReq(agentId uint32) (*trident.GPIDSyncRequest, uint32) {
	cacheReq := p.sendGPIDReq.getCacheReq(agentId)
	if cacheReq == nil {
		localReq := p.agentIdToLocalGPIDReq.getCacheReq(agentId)
		shareReq := p.agentIdToShareGPIDReq.getCacheReq(agentId)
		if localReq != nil && shareReq != nil {
			if localReq.After(shareReq) {
				cacheReq = localReq
			} else {
				cacheReq = shareReq
			}
		} else {
			if localReq == nil {
				cacheReq = shareReq
			} else {
				cacheReq = localReq
			}
		}
	}

	return cacheReq.getReq(), uint32(cacheReq.getUpdateTime())
}

func (p *ProcessInfo) UpdateGPIDReqFromShare(shareReq *trident.ShareGPIDSyncRequests) {
	for _, req := range shareReq.GetSyncRequests() {
		p.agentIdToShareGPIDReq.updateReq(req)
	}
}

func (p *ProcessInfo) GetGPIDShareReqs() *trident.ShareGPIDSyncRequests {
	reqs := p.sendGPIDReq.getAllReqAndClear()
	shareSyncReqs := make([]*trident.GPIDSyncRequest, 0, len(reqs))
	for _, req := range reqs {
		p.agentIdToLocalGPIDReq.updateCacheReq(req)
		shareSyncReqs = append(shareSyncReqs, req.getReq())
	}
	if len(shareSyncReqs) > 0 {
		return &trident.ShareGPIDSyncRequests{
			ServerIp:     proto.String(p.config.NodeIP),
			SyncRequests: shareSyncReqs,
		}
	}
	return nil
}

func (p *ProcessInfo) updateGlobalLocalEntries(data EntryData) {
	p.globalLocalEntries = data
}

func (p *ProcessInfo) updateRealClientToRealServer(data *utils.U128IDMap) {
	p.realClientToRealServer = data
}

func (p *ProcessInfo) GetGlobalEntries() []*trident.GlobalGPIDEntry {
	return p.globalLocalEntries.getGPIDGlobalData(p)
}

func (p *ProcessInfo) generateGlobalLocalEntries() {
	globalLocalEntries := NewEntryData()
	realClientToRealServer := utils.NewU128IDMapNoStats("trisolaris-real-pid", CACHE_SIZE)
	agentIds := p.agentIdToLocalGPIDReq.getKeys()
	shareFilter := mapset.NewSet()
	for _, agentId := range agentIds {
		localCacheReq := p.agentIdToLocalGPIDReq.getCacheReq(agentId)
		if localCacheReq == nil {
			continue
		}
		shareCacheReq := p.agentIdToShareGPIDReq.getCacheReq(agentId)
		if shareCacheReq != nil {
			if shareCacheReq.After(localCacheReq) {
				continue
			} else {
				shareFilter.Add(agentId)
			}
		}

		req := localCacheReq.getReq()
		if req == nil || len(req.GetEntries()) == 0 {
			continue
		}
		for _, entry := range req.GetEntries() {
			globalLocalEntries.addData(agentId, entry, p)
			p.addRealData(agentId, entry, realClientToRealServer)
		}
	}

	agentIds = p.agentIdToShareGPIDReq.getKeys()
	for _, agentId := range agentIds {
		if shareFilter.Contains(agentId) {
			continue
		}
		req := p.agentIdToShareGPIDReq.getReq(agentId)
		if req == nil {
			continue
		}
		if len(req.GetEntries()) == 0 {
			continue
		}
		for _, entry := range req.GetEntries() {
			globalLocalEntries.addData(agentId, entry, p)
			p.addRealData(agentId, entry, realClientToRealServer)
		}
	}

	releaseData := p.globalLocalEntries
	p.updateGlobalLocalEntries(globalLocalEntries)
	p.updateRealClientToRealServer(realClientToRealServer)
	p.releaseGlobalLocalEntries(releaseData)
}

func (p *ProcessInfo) releaseGlobalLocalEntries(data EntryData) {
	for _, serviceIndex := range serviceTypes {
		if serviceIndex >= MAX_SERVICE_TYPE {
			break
		}
		for _, ipIndex := range ipTypes {
			if ipIndex >= MAX_IP_TYPE {
				break
			}
			for keyValue := range data[serviceIndex][ipIndex].Iter() {
				_, _, value := keyValue.GetData()
				if realValue, ok := value.(*PidPair); ok {
					releasePidPair(realValue)
				}
			}
		}
	}
}

func (p *ProcessInfo) getGPIDInfoFromDB() {
	processes, err := dbmgr.DBMgr[models.Process](p.db).GetFields([]string{"id", "vtap_id", "pid"})
	if err != nil {
		log.Error(err)
		return
	}
	newVtapIDAndPIDToGPID := make(IDToGPID)
	for _, process := range processes {
		newVtapIDAndPIDToGPID.addData(process)
	}
	p.agentIdAndPIDToGPID = newVtapIDAndPIDToGPID
}

func (p *ProcessInfo) getRIPToVIPFromDB() {
	rvData := NewRVData()
	idTolbListener := make(map[int]*models.LBListener)
	lbListeners, err := dbmgr.DBMgr[models.LBListener](p.db).Gets()
	if err != nil {
		log.Error(err)
		return
	}
	for _, lbListener := range lbListeners {
		idTolbListener[lbListener.ID] = lbListener
	}

	lbTargetServers, err := dbmgr.DBMgr[models.LBTargetServer](p.db).Gets()
	if err != nil {
		log.Error(err)
		return
	}
	for _, lbTargetServer := range lbTargetServers {
		if lbListener, ok := idTolbListener[lbTargetServer.LBListenerID]; ok {
			ripNet := libu.ParserStringIp(lbTargetServer.IP)
			if ripNet == nil {
				continue
			}
			vIps := strings.Split(lbListener.IPs, ",")
			for _, vIp := range vIps {
				vIpNet := libu.ParserStringIp(vIp)
				if vIpNet == nil {
					continue
				}
				epcId := uint32(lbTargetServer.VPCID)
				rip := libu.IpToUint32(ripNet)
				rPort := uint32(lbTargetServer.Port)
				vIp := libu.IpToUint32(vIpNet)
				vport := uint32(lbListener.Port)
				rvData.addData(epcId, rip, rPort, vIp, vport, convertProto(lbListener.Protocol))
			}
		}
	}
	p.rvData = rvData
}

func (p *ProcessInfo) GetGPIDResponseByVtapID(agentId uint32) *trident.GPIDSyncResponse {
	req, _ := p.GetAgentGPIDReq(agentId)
	return p.GetGPIDResponseByReq(req)
}

func (p *ProcessInfo) GetGPIDResponseByReq(req *trident.GPIDSyncRequest) *trident.GPIDSyncResponse {
	if req == nil {
		return &trident.GPIDSyncResponse{}
	}
	entries := req.GetEntries()
	if len(entries) == 0 {
		return &trident.GPIDSyncResponse{}
	}
	agentId := req.GetVtapId()
	responseEntries := make([]*trident.GPIDSyncEntry, 0, len(entries))
	for _, entry := range entries {
		netnsIndex := entry.GetNetnsIdx()
		roleReal := entry.GetRoleReal()
		protocol := entry.GetProtocol()
		responseEntry := &trident.GPIDSyncEntry{
			Protocol:  &protocol,
			RoleReal:  &roleReal,
			EpcId_1:   proto.Uint32(entry.GetEpcId_1()),
			Ipv4_1:    proto.Uint32(entry.GetIpv4_1()),
			Port_1:    proto.Uint32(entry.GetPort_1()),
			EpcId_0:   proto.Uint32(entry.GetEpcId_0()),
			Ipv4_0:    proto.Uint32(entry.GetIpv4_0()),
			Port_0:    proto.Uint32(entry.GetPort_0()),
			EpcIdReal: proto.Uint32(entry.GetEpcIdReal()),
			Ipv4Real:  proto.Uint32(entry.GetIpv4Real()),
			PortReal:  proto.Uint32(entry.GetPortReal()),
			NetnsIdx:  &netnsIndex,
		}
		var gpid0, gpid1, gpidReal uint32
		globalEntry := p.globalLocalEntries.getData(agentId, entry, p)
		if entry.GetPid_0() > 0 {
			gpid0 = p.agentIdAndPIDToGPID.getData(agentId, entry.GetPid_0())
		} else if globalEntry != nil {
			pid0, agentId0 := globalEntry.getPid0Data()
			if pid0 > 0 && agentId0 > 0 {
				gpid0 = p.agentIdAndPIDToGPID.getData(agentId0, pid0)
			}
		}
		if entry.GetPid_1() > 0 {
			gpid1 = p.agentIdAndPIDToGPID.getData(agentId, entry.GetPid_1())
		} else if globalEntry != nil {
			pid1, agentId1 := globalEntry.getPid1Data()
			if pid1 > 0 && agentId1 > 0 {
				gpid1 = p.agentIdAndPIDToGPID.getData(agentId1, pid1)
			}
		}

		if entry.GetPidReal() > 0 {
			gpid1 = p.agentIdAndPIDToGPID.getData(agentId, entry.GetPidReal())
		} else if entry.GetPidReal() == 0 && entry.GetIpv4Real() > 0 {
			if globalEntry != nil {
				pid, agentId := globalEntry.getPid0Data()
				if pid > 0 && agentId > 0 {
					gpidReal = p.agentIdAndPIDToGPID.getData(agentId, pid)
				}
			}
		}

		if entry.GetIpv4Real() == 0 {
			realServerData := p.getRealData(agentId, entry)
			if realServerData != nil {
				agentIdReal, epcIdReal, portReal, ipv4Real, pidReal := realServerData.getData()
				role := trident.RoleType_ROLE_SERVER
				responseEntry.EpcIdReal = &epcIdReal
				responseEntry.Ipv4Real = &ipv4Real
				responseEntry.PortReal = &portReal
				responseEntry.RoleReal = &role
				gpidReal = p.agentIdAndPIDToGPID.getData(agentIdReal, pidReal)
			}
		}

		responseEntry.Pid_0 = &gpid0
		responseEntry.Pid_1 = &gpid1
		responseEntry.PidReal = &gpidReal
		responseEntries = append(responseEntries, responseEntry)
	}
	return &trident.GPIDSyncResponse{Entries: responseEntries}
}

func (p *ProcessInfo) DeleteAgentExpiredData(dbAgentIDs mapset.Set) {
	cacheAgentIDs := p.agentIdToLocalGPIDReq.getSetIntKeys()
	delAgentIDs := cacheAgentIDs.Difference(dbAgentIDs)
	for val := range delAgentIDs.Iter() {
		agentId := val.(int)
		p.agentIdToLocalGPIDReq.deleteData(uint32(agentId))
	}

	cacheAgentIDs = p.agentIdToShareGPIDReq.getSetIntKeys()
	delAgentIDs = cacheAgentIDs.Difference(dbAgentIDs)
	for val := range delAgentIDs.Iter() {
		agentId := val.(int)
		p.agentIdToShareGPIDReq.deleteData(uint32(agentId))
	}
}

func (p *ProcessInfo) getLocalControllersConns() map[string]*grpc.ClientConn {
	controllerIPToRegion := make(map[string]string)
	localRegion := ""
	conns, err := dbmgr.DBMgr[models.AZControllerConnection](p.db).Gets()
	if err != nil {
		log.Errorf("get az_controller_conn failed, err:%s", err)
		return nil
	}
	for _, conn := range conns {
		controllerIPToRegion[conn.ControllerIP] = conn.Region
		if p.config.NodeIP == conn.ControllerIP {
			localRegion = conn.Region
		}
	}
	dbControllers, err := dbmgr.DBMgr[models.Controller](p.db).Gets()
	if err != nil {
		log.Errorf("get controller failed, err:%s", err)
		return nil
	}
	localControllers := map[string]struct{}{}
	for _, controller := range dbControllers {
		if controller.IP == p.config.NodeIP {
			continue
		}
		if controller.State != HOST_STATE_EXCEPTION {
			if controllerIPToRegion[controller.IP] == localRegion {
				serverIP := controller.PodIP
				if serverIP == "" {
					serverIP = controller.IP
				}
				localControllers[serverIP] = struct{}{}
				if _, ok := p.grpcConns[serverIP]; ok {
					continue
				}
				serverAddr := net.JoinHostPort(serverIP, strconv.Itoa(p.config.GetGrpcPort()))
				conn, err := grpc.Dial(serverAddr, grpc.WithInsecure(),
					grpc.WithMaxMsgSize(p.config.GetGrpcMaxMessageLength()))
				if err != nil {
					log.Error("failed to start gRPC connection(%s): %v", err)
					continue
				}
				p.grpcConns[serverIP] = conn
			}
		}
	}

	for serverIP, grpcConn := range p.grpcConns {
		if _, ok := localControllers[serverIP]; !ok {
			grpcConn.Close()
			delete(p.grpcConns, serverIP)
		}
	}

	return p.grpcConns
}

func (p *ProcessInfo) sendLocalShareEntryData() {
	grpcConns := p.getLocalControllersConns()
	if len(grpcConns) == 0 {
		for _, cacheReq := range p.sendGPIDReq.getAllReqAndClear() {
			p.agentIdToLocalGPIDReq.updateCacheReq(cacheReq)
		}

		return
	}
	shareReqs := p.GetGPIDShareReqs()
	if shareReqs == nil {
		return
	}
	for _, conn := range grpcConns {
		go func(conn *grpc.ClientConn) {
			log.Infof("server(%s) send local share req data to server(%s)", p.config.NodeIP, conn.Target())
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			client := trident.NewSynchronizerClient(conn)
			response, err := client.ShareGPIDLocalData(ctx, shareReqs)
			if err != nil {
				log.Error(err)
				return
			}
			if len(response.GetSyncRequests()) == 0 {
				return
			}
			log.Infof("receive gpid sync data from server(%s)", response.GetServerIp())
			for _, req := range response.GetSyncRequests() {
				p.agentIdToShareGPIDReq.updateReq(req)
			}
		}(conn)
	}
}

func (p *ProcessInfo) getDBData() {
	p.getGPIDInfoFromDB()
	p.getRIPToVIPFromDB()
}

func (p *ProcessInfo) generateData() {
	p.sendLocalShareEntryData()
	p.getDBData()
	p.generateGlobalLocalEntries()
}

func (p *ProcessInfo) TimedGenerateGPIDInfo() {
	p.getDBData()
	interval := time.Duration(p.config.GPIDRefreshInterval)
	ticker := time.NewTicker(interval * time.Second).C
	for {
		select {
		case <-ticker:
			log.Info("start generate gpid data from timed")
			p.generateData()
			log.Info("end generate gpid data from timed")
		}
	}
}
