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

	"github.com/deepflowio/deepflow/message/agent"
	. "github.com/deepflowio/deepflow/server/controller/common"
	models "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/config"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/dbmgr"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
	libu "github.com/deepflowio/deepflow/server/libs/utils"
)

func convertAgentProto(proto string) agent.ServiceProtocol {
	switch proto {
	case TCP_PROTO_STR:
		return agent.ServiceProtocol_TCP_SERVICE
	case UDP_PROTO_STR:
		return agent.ServiceProtocol_UDP_SERVICE
	}

	return 0
}

var agentServiceTypes = [MAX_SERVICE_TYPE]int{TCPService, UDPService}
var agentIpTypes = [MAX_IP_TYPE]int{NORMAL_IP, LOOP_IP}

type AgentEntryData [MAX_SERVICE_TYPE][MAX_IP_TYPE]*U128IDMap

func NewAgentEntryData() AgentEntryData {
	var entryData AgentEntryData
	for index, _ := range entryData {
		entryData[index][NORMAL_IP] = NewU128IDMapNoStats("trisolaris-global-gpid", CACHE_SIZE)
		entryData[index][LOOP_IP] = NewU128IDMapNoStats("trisolaris-global-gpid", CACHE_SIZE)
	}

	return entryData
}

func (d AgentEntryData) getAggregateMap(entry *agent.GPIDSyncEntry) *U128IDMap {
	protocol := entry.GetProtocol()
	ip := entry.GetIpv4_1()
	serviceIndex := MAX_SERVICE_TYPE
	switch {
	case protocol == agent.ServiceProtocol_TCP_SERVICE:
		serviceIndex = TCPService
	case protocol == agent.ServiceProtocol_UDP_SERVICE:
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

func (d AgentEntryData) addData(agentId uint32, entry *agent.GPIDSyncEntry, p *AgentProcessInfo) {
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

func (d AgentEntryData) getData(agentId uint32, entry *agent.GPIDSyncEntry, p *AgentProcessInfo) *PidPair {
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

func (e AgentEntryData) getGPIDGlobalData(p *AgentProcessInfo) []*agent.GlobalGPIDEntry {

	allData := []*agent.GlobalGPIDEntry{}
	for _, serviceIndex := range serviceTypes {
		var protocol agent.ServiceProtocol
		switch serviceIndex {
		case TCPService:
			protocol = agent.ServiceProtocol_TCP_SERVICE
		case UDPService:
			protocol = agent.ServiceProtocol_UDP_SERVICE
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
				gpid0 := p.agentIdAndPIDToGID.getData(agentId0, pid0)
				gpid1 := p.agentIdAndPIDToGID.getData(agentId1, pid1)
				entry := &agent.GlobalGPIDEntry{
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

type AgentCacheReq struct {
	updateTime time.Time
	req        *agent.GPIDSyncRequest
}

func NewAgentCacheReq(req *agent.GPIDSyncRequest) *AgentCacheReq {
	return &AgentCacheReq{
		updateTime: time.Now(),
		req:        req,
	}
}

func (c *AgentCacheReq) getReq() *agent.GPIDSyncRequest {
	if c == nil {
		return nil
	}
	return c.req
}

func (c *AgentCacheReq) getUpdateTime() int {
	if c == nil {
		return 0
	}
	return int(c.updateTime.Unix())
}

func (c *AgentCacheReq) After(r *AgentCacheReq) bool {
	if c == nil || r == nil {
		return false
	}
	return c.updateTime.After(r.updateTime)
}

type AIDToReq struct {
	sync.RWMutex
	idToReq map[uint32]*AgentCacheReq
}

func (r *AIDToReq) getKeys() []uint32 {
	r.RLock()
	keys := make([]uint32, 0, len(r.idToReq))
	for key, _ := range r.idToReq {
		keys = append(keys, key)
	}
	r.RUnlock()
	return keys
}

func (r *AIDToReq) getSetIntKeys() mapset.Set {
	r.RLock()
	keys := mapset.NewSet()
	for key, _ := range r.idToReq {
		keys.Add(int(key))
	}
	r.RUnlock()
	return keys
}

func (r *AIDToReq) updateReq(req *agent.GPIDSyncRequest) {
	if req == nil {
		return
	}
	r.Lock()
	r.idToReq[req.GetAgentId()] = NewAgentCacheReq(req)
	r.Unlock()
}

func (r *AIDToReq) updateAgentCacheReq(cacheReq *AgentCacheReq) {
	if cacheReq == nil || cacheReq.req == nil {
		return
	}

	r.Lock()
	r.idToReq[cacheReq.req.GetAgentId()] = cacheReq
	r.Unlock()
}

func (r *AIDToReq) getAgentCacheReq(agentId uint32) *AgentCacheReq {
	r.RLock()
	cacheReq := r.idToReq[agentId]
	r.RUnlock()
	return cacheReq
}

func (r *AIDToReq) getReq(agentId uint32) *agent.GPIDSyncRequest {
	r.RLock()
	cacheReq := r.idToReq[agentId]
	r.RUnlock()
	if cacheReq != nil {
		return cacheReq.getReq()
	}
	return nil
}

func (r *AIDToReq) getAllReqAndClear() map[uint32]*AgentCacheReq {
	r.Lock()
	allData := r.idToReq
	r.idToReq = make(map[uint32]*AgentCacheReq)
	r.Unlock()

	return allData
}

func (r *AIDToReq) deleteData(agentId uint32) {
	r.Lock()
	delete(r.idToReq, agentId)
	r.Unlock()
}

func NewAIDToReq() *AIDToReq {
	return &AIDToReq{
		idToReq: make(map[uint32]*AgentCacheReq),
	}
}

func (r RVData) getAgentRVmap(protocol agent.ServiceProtocol) RipToVipMap {
	serviceIndex := MAX_SERVICE_TYPE
	switch {
	case protocol == agent.ServiceProtocol_TCP_SERVICE:
		serviceIndex = TCPService
	case protocol == agent.ServiceProtocol_UDP_SERVICE:
		serviceIndex = UDPService
	}
	if serviceIndex == MAX_SERVICE_TYPE {
		return nil
	}

	return r[serviceIndex]
}

func (r RVData) addAgentData(epcId, rIp, rPort, vIp, vPort uint32, protocol agent.ServiceProtocol) {
	rvMap := r.getAgentRVmap(protocol)
	if rvMap == nil {
		return
	}
	rvMap.addData(epcId, rIp, rPort, vIp, vPort)
}

func (r RVData) getAgentVIp(rEpcId, rIp, rPort uint32, protocol agent.ServiceProtocol) (vIp, vport uint32) {
	rvMap := r.getAgentRVmap(protocol)
	if rvMap == nil {
		return
	}
	vIp, vport = rvMap.getvIp(rEpcId, rIp, rPort)
	return
}

func (r RVData) getAgentDebugData() []*agent.RipToVip {
	allData := []*agent.RipToVip{}
	for _, serviceIndex := range serviceTypes {
		var protocol agent.ServiceProtocol
		switch serviceIndex {
		case TCPService:
			protocol = agent.ServiceProtocol_TCP_SERVICE
		case UDPService:
			protocol = agent.ServiceProtocol_UDP_SERVICE
		}
		if serviceIndex >= MAX_SERVICE_TYPE {
			break
		}
		for key, value := range r[serviceIndex] {
			epcId, rport, rip := getEpcIdPortIP(key)
			_, vport, vIp := getEpcIdPortIP(value)
			entry := &agent.RipToVip{
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

type AgentProcessInfo struct {
	sendGPIDReq            *AIDToReq
	agentIdToLocalGPIDReq  *AIDToReq
	agentIdToShareGPIDReq  *AIDToReq
	agentIdAndPIDToGID     IDToGID
	rvData                 RVData
	globalLocalEntries     AgentEntryData
	realClientToRealServer *U128IDMap
	grpcConns              map[string]*grpc.ClientConn
	db                     *gorm.DB
	config                 *config.Config
	ORGID
}

func NewAgentProcessInfo(db *gorm.DB, cfg *config.Config, orgID int) *AgentProcessInfo {
	return &AgentProcessInfo{
		sendGPIDReq:            NewAIDToReq(),
		agentIdToLocalGPIDReq:  NewAIDToReq(),
		agentIdToShareGPIDReq:  NewAIDToReq(),
		agentIdAndPIDToGID:     make(IDToGID),
		rvData:                 NewRVData(),
		globalLocalEntries:     NewAgentEntryData(),
		realClientToRealServer: NewU128IDMapNoStats("trisolaris-real-pid", CACHE_SIZE),
		grpcConns:              make(map[string]*grpc.ClientConn),
		db:                     db,
		config:                 cfg,
		ORGID:                  ORGID(orgID),
	}
}

func (p *AgentProcessInfo) UpdateAgentIdAndPIDToGPID(data IDToGID) {
	p.agentIdAndPIDToGID = data
}

func (p *AgentProcessInfo) UpdateRVData(data RVData) {
	p.rvData = data
}

func (p *AgentProcessInfo) GetRealGlobalData() []*agent.RealClientToRealServer {
	data := make([]*agent.RealClientToRealServer, 0, p.realClientToRealServer.Size())

	for keyValue := range p.realClientToRealServer.Iter() {
		key0, key1, value := keyValue.GetData()
		epcId0, port0, ip0 := getEpcIdPortIP(key0)
		epcId1, port1, ip1 := getEpcIdPortIP(key1)
		realValue, ok := value.(*RealServerData)
		if ok == false {
			continue
		}
		agentIdReal, epcIdReal, portReal, ipReal, pidReal := realValue.getData()
		etnry := &agent.RealClientToRealServer{
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

func (p *AgentProcessInfo) GetAgentRVData() []*agent.RipToVip {
	return p.rvData.getAgentDebugData()
}

func (p *AgentProcessInfo) getKey(agentId uint32, entry *agent.GPIDSyncEntry) (key0, key1 uint64) {
	if isLoopbackIP(entry.GetIpv4_1()) {
		netnsIndex := entry.GetNetnsIdx()
		key0 = generateLoopbackKey(agentId, entry.GetPort_0(), netnsIndex)
		key1 = generateLoopbackKey(agentId, entry.GetPort_1(), netnsIndex)
		return
	}
	// server
	// If there is a real client, use the real client ip/port instead of the client ip/port
	// Use the server ip/port to query the load balancing RIP>vIp mapping table on the controller and convert it to vIp/vport
	if entry.GetPid_1() > 0 && entry.GetIpv4Real() > 0 && entry.GetRoleReal() == agent.RoleType_ROLE_CLIENT {
		key0 = generateEPKey(entry.GetEpcIdReal(), entry.GetPortReal(), entry.GetIpv4Real())
		rEpcId, rPort, rIpv4 := entry.GetEpcId_1(), entry.GetPort_1(), entry.GetIpv4_1()
		vIpv4, vPort := p.rvData.getAgentVIp(rEpcId, rIpv4, rPort, entry.GetProtocol())
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

func (p *AgentProcessInfo) addRealData(agentId uint32, entry *agent.GPIDSyncEntry, toRS *U128IDMap) {
	if entry.GetPid_1() > 0 && entry.GetIpv4Real() > 0 && entry.GetRoleReal() == agent.RoleType_ROLE_CLIENT {
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

func (p *AgentProcessInfo) getRealData(agentId uint32, entry *agent.GPIDSyncEntry) *RealServerData {
	key0, key1 := p.getKey(agentId, entry)
	realData, ok := p.realClientToRealServer.Get(key0, key1)
	if ok {
		return realData.(*RealServerData)
	}

	return nil
}

func (p *AgentProcessInfo) UpdateAgentGPIDReq(req *agent.GPIDSyncRequest) {
	p.sendGPIDReq.updateReq(req)
}

func (p *AgentProcessInfo) GetAgentGPIDReq(agentId uint32) (*agent.GPIDSyncRequest, uint32) {
	cacheReq := p.sendGPIDReq.getAgentCacheReq(agentId)
	if cacheReq == nil {
		localReq := p.agentIdToLocalGPIDReq.getAgentCacheReq(agentId)
		shareReq := p.agentIdToShareGPIDReq.getAgentCacheReq(agentId)
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

func (p *AgentProcessInfo) UpdateGPIDReqFromShare(shareReq *agent.ShareGPIDSyncRequests) {
	for _, req := range shareReq.GetSyncRequests() {
		p.agentIdToShareGPIDReq.updateReq(req)
	}
}

func (p *AgentProcessInfo) GetGPIDShareReqs() *agent.ShareGPIDSyncRequests {
	reqs := p.sendGPIDReq.getAllReqAndClear()
	shareSyncReqs := make([]*agent.GPIDSyncRequest, 0, len(reqs))
	for _, req := range reqs {
		p.agentIdToLocalGPIDReq.updateAgentCacheReq(req)
		shareSyncReqs = append(shareSyncReqs, req.getReq())
	}
	if len(shareSyncReqs) > 0 {
		return &agent.ShareGPIDSyncRequests{
			ServerIp:     proto.String(p.config.NodeIP),
			SyncRequests: shareSyncReqs,
			OrgId:        proto.Uint32(uint32(p.ORGID)),
		}
	}
	return nil
}

func (p *AgentProcessInfo) updateGlobalLocalEntries(data AgentEntryData) {
	p.globalLocalEntries = data
}

func (p *AgentProcessInfo) updateRealClientToRealServer(data *U128IDMap) {
	p.realClientToRealServer = data
}

func (p *AgentProcessInfo) GetGlobalEntries() []*agent.GlobalGPIDEntry {
	return p.globalLocalEntries.getGPIDGlobalData(p)
}

func (p *AgentProcessInfo) generateGlobalLocalEntries() {
	globalLocalEntries := NewAgentEntryData()
	realClientToRealServer := NewU128IDMapNoStats("trisolaris-real-pid", CACHE_SIZE)
	agentIds := p.agentIdToLocalGPIDReq.getKeys()
	shareFilter := mapset.NewSet()
	for _, agentId := range agentIds {
		localAgentCacheReq := p.agentIdToLocalGPIDReq.getAgentCacheReq(agentId)
		if localAgentCacheReq == nil {
			continue
		}
		shareAgentCacheReq := p.agentIdToShareGPIDReq.getAgentCacheReq(agentId)
		if shareAgentCacheReq != nil {
			if shareAgentCacheReq.After(localAgentCacheReq) {
				continue
			} else {
				shareFilter.Add(agentId)
			}
		}

		req := localAgentCacheReq.getReq()
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

func (p *AgentProcessInfo) releaseGlobalLocalEntries(data AgentEntryData) {
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

func (p *AgentProcessInfo) getGPIDInfoFromDB() {
	processes, err := dbmgr.DBMgr[models.Process](p.db).GetFields([]string{"id", "vtap_id", "pid"})
	if err != nil {
		log.Error(p.Log(err.Error()))
		return
	}
	newVtapIDAndPIDToGPID := make(IDToGID)
	for _, process := range processes {
		newVtapIDAndPIDToGPID.addData(process)
	}
	p.agentIdAndPIDToGID = newVtapIDAndPIDToGPID
}

func (p *AgentProcessInfo) getRIPToVIPFromDB() {
	rvData := NewRVData()
	idTolbListener := make(map[int]*models.LBListener)
	lbListeners, err := dbmgr.DBMgr[models.LBListener](p.db).Gets()
	if err != nil {
		log.Error(p.Log(err.Error()))
		return
	}
	for _, lbListener := range lbListeners {
		idTolbListener[lbListener.ID] = lbListener
	}

	lbTargetServers, err := dbmgr.DBMgr[models.LBTargetServer](p.db).Gets()
	if err != nil {
		log.Error(p.Log(err.Error()))
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
				rvData.addAgentData(epcId, rip, rPort, vIp, vport, convertAgentProto(lbListener.Protocol))
			}
		}
	}
	p.rvData = rvData
}

func (p *AgentProcessInfo) GetGPIDResponseByVtapID(agentId uint32) *agent.GPIDSyncResponse {
	req, _ := p.GetAgentGPIDReq(agentId)
	return p.GetGPIDResponseByReq(req)
}

func (p *AgentProcessInfo) GetGPIDResponseByReq(req *agent.GPIDSyncRequest) *agent.GPIDSyncResponse {
	if req == nil {
		return &agent.GPIDSyncResponse{}
	}
	entries := req.GetEntries()
	if len(entries) == 0 {
		return &agent.GPIDSyncResponse{}
	}
	agentId := req.GetAgentId()
	responseEntries := make([]*agent.GPIDSyncEntry, 0, len(entries))
	for _, entry := range entries {
		netnsIndex := entry.GetNetnsIdx()
		roleReal := entry.GetRoleReal()
		protocol := entry.GetProtocol()
		responseEntry := &agent.GPIDSyncEntry{
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
			gpid0 = p.agentIdAndPIDToGID.getData(agentId, entry.GetPid_0())
		} else if globalEntry != nil {
			pid0, agentId0 := globalEntry.getPid0Data()
			if pid0 > 0 && agentId0 > 0 {
				gpid0 = p.agentIdAndPIDToGID.getData(agentId0, pid0)
			}
		}
		if entry.GetPid_1() > 0 {
			gpid1 = p.agentIdAndPIDToGID.getData(agentId, entry.GetPid_1())
		} else if globalEntry != nil {
			pid1, agentId1 := globalEntry.getPid1Data()
			if pid1 > 0 && agentId1 > 0 {
				gpid1 = p.agentIdAndPIDToGID.getData(agentId1, pid1)
			}
		}

		if entry.GetPidReal() > 0 {
			gpid1 = p.agentIdAndPIDToGID.getData(agentId, entry.GetPidReal())
		} else if entry.GetPidReal() == 0 && entry.GetIpv4Real() > 0 {
			if globalEntry != nil {
				pid, agentId := globalEntry.getPid0Data()
				if pid > 0 && agentId > 0 {
					gpidReal = p.agentIdAndPIDToGID.getData(agentId, pid)
				}
			}
		}

		if entry.GetIpv4Real() == 0 {
			realServerData := p.getRealData(agentId, entry)
			if realServerData != nil {
				agentIdReal, epcIdReal, portReal, ipv4Real, pidReal := realServerData.getData()
				role := agent.RoleType_ROLE_SERVER
				responseEntry.EpcIdReal = &epcIdReal
				responseEntry.Ipv4Real = &ipv4Real
				responseEntry.PortReal = &portReal
				responseEntry.RoleReal = &role
				gpidReal = p.agentIdAndPIDToGID.getData(agentIdReal, pidReal)
			}
		}

		responseEntry.Pid_0 = &gpid0
		responseEntry.Pid_1 = &gpid1
		responseEntry.PidReal = &gpidReal
		responseEntries = append(responseEntries, responseEntry)
	}
	return &agent.GPIDSyncResponse{Entries: responseEntries}
}

func (p *AgentProcessInfo) DeleteAgentExpiredData(dbAgentIDs mapset.Set) {
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

func (p *AgentProcessInfo) getLocalControllersConns() map[string]*grpc.ClientConn {
	controllerIPToRegion := make(map[string]string)
	localRegion := ""
	conns, err := dbmgr.DBMgr[models.AZControllerConnection](p.db).Gets()
	if err != nil {
		log.Errorf(p.Logf("get az_controller_conn failed, err:%s", err))
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
		log.Errorf(p.Logf("get controller failed, err:%s", err))
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
					log.Error(p.Logf("failed to start gRPC connection(%s): %s", serverAddr, err))
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

func (p *AgentProcessInfo) UpdateGrpcConns(grpcConns map[string]*grpc.ClientConn) {
	p.grpcConns = grpcConns
}

func (p *AgentProcessInfo) sendLocalShareAgentEntryData(grpcConns map[string]*grpc.ClientConn) {
	if len(grpcConns) == 0 {
		for _, cacheReq := range p.sendGPIDReq.getAllReqAndClear() {
			p.agentIdToLocalGPIDReq.updateAgentCacheReq(cacheReq)
		}

		return
	}
	shareReqs := p.GetGPIDShareReqs()
	if shareReqs == nil {
		return
	}
	for _, conn := range grpcConns {
		go func(conn *grpc.ClientConn) {
			log.Infof(p.Logf("server(%s) send local share req data to server(%s)", p.config.NodeIP, conn.Target()))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			client := agent.NewSynchronizerClient(conn)
			response, err := client.ShareGPIDLocalData(ctx, shareReqs)
			if err != nil {
				log.Error(err)
				return
			}
			if len(response.GetSyncRequests()) == 0 {
				return
			}
			log.Infof(p.Logf("receive gpid sync data from server(%s)", response.GetServerIp()))
			for _, req := range response.GetSyncRequests() {
				p.agentIdToShareGPIDReq.updateReq(req)
			}
		}(conn)
	}
}

func (p *AgentProcessInfo) getDBData() {
	p.getGPIDInfoFromDB()
	p.getRIPToVIPFromDB()
}

func (p *AgentProcessInfo) generateData() {
	p.sendLocalShareAgentEntryData(p.grpcConns)
	p.generateGlobalLocalEntries()
}
