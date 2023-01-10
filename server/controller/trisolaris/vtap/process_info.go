/*
 * Copyright (c) 2022 Yunshan Networks
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
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
	"gorm.io/gorm"

	"github.com/deepflowys/deepflow/message/trident"
	. "github.com/deepflowys/deepflow/server/controller/common"
	models "github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/trisolaris/config"
	"github.com/deepflowys/deepflow/server/controller/trisolaris/dbmgr"
)

type GlobalEntry struct {
	vtapID uint32
	pid    uint32
}

func NewGlobalEntry(vtapID uint32, pid uint32) *GlobalEntry {
	return &GlobalEntry{
		vtapID: vtapID,
		pid:    pid,
	}
}

// epcId(u16),port(u16),ip(u32)
func generateEPKey(epcId, port, ip uint32) uint64 {
	epcIDPort := epcId<<16 | port
	return uint64(epcIDPort)<<32 | uint64(ip)
}

const (
	TCPServer = iota
	TCPClient
	UDPServer
	UDPClient
	MAX
)

// (protocol + role)->(epc_id + port + ip)
type EntryData [MAX]EpcIDPortIPMap

func NewEntryData() EntryData {
	var entryData EntryData
	for index, _ := range entryData {
		entryData[index] = make(EpcIDPortIPMap)
	}

	return entryData
}

func (e EntryData) getEpcIDPortIPMap(protocol trident.ServiceProtocol, role trident.RoleType) EpcIDPortIPMap {
	index := MAX
	switch {
	case protocol == trident.ServiceProtocol_TCP_SERVICE && role == trident.RoleType_ROLE_SERVER:
		index = TCPServer
	case protocol == trident.ServiceProtocol_TCP_SERVICE && role == trident.RoleType_ROLE_CLIENT:
		index = TCPClient
	case protocol == trident.ServiceProtocol_UDP_SERVICE && role == trident.RoleType_ROLE_SERVER:
		index = UDPServer
	case protocol == trident.ServiceProtocol_UDP_SERVICE && role == trident.RoleType_ROLE_CLIENT:
		index = UDPClient
	}
	if index == MAX {
		return nil
	}

	return e[index]
}

// (epc_id + port + ip): (vtap_id, pid)
type EpcIDPortIPMap map[uint64]*GlobalEntry

func (e EpcIDPortIPMap) addData(vtapID, epcID, port, pid, ip uint32) {
	e[generateEPKey(epcID, port, ip)] = NewGlobalEntry(vtapID, pid)
}

func (e EpcIDPortIPMap) getData(epcID uint32, port uint32, ip uint32) *GlobalEntry {
	return e[generateEPKey(epcID, port, ip)]
}

func (d EntryData) addData(vtapID uint32, entry *trident.GPIDSyncEntry) {
	if entry.GetPid_0() > 0 {
		epcIDPortIPMap := d.getEpcIDPortIPMap(entry.GetProtocol(), trident.RoleType_ROLE_CLIENT)
		if epcIDPortIPMap != nil {
			epcIDPortIPMap.addData(vtapID, entry.GetEpcId_0(), entry.GetPort_0(), entry.GetPid_0(), entry.GetIpv4_0())
		}
	}
	if entry.GetPid_1() > 0 {
		epcIDPortIPMap := d.getEpcIDPortIPMap(entry.GetProtocol(), trident.RoleType_ROLE_SERVER)
		if epcIDPortIPMap != nil {
			epcIDPortIPMap.addData(vtapID, entry.GetEpcId_1(), entry.GetPort_1(), entry.GetPid_1(), entry.GetIpv4_1())
		}
	}
	if entry.GetPidReal() > 0 {
		epcIDPortIPMap := d.getEpcIDPortIPMap(entry.GetProtocol(), entry.GetRoleReal())
		if epcIDPortIPMap != nil {
			epcIDPortIPMap.addData(vtapID, entry.GetEpcIdReal(), entry.GetPortReal(), entry.GetPidReal(), entry.GetIpv4Real())
		}
	}
}

func (d EntryData) getData(protocol trident.ServiceProtocol, role trident.RoleType, epcID, port, ip uint32) *GlobalEntry {
	epcIDPortIPMap := d.getEpcIDPortIPMap(protocol, role)
	if epcIDPortIPMap == nil {
		return nil
	}
	return epcIDPortIPMap.getData(epcID, port, ip)
}

func (e EntryData) getAllData() []*trident.GPIDSyncEntry {
	return nil
}

type VTapIDToReq struct {
	sync.RWMutex
	idToReq map[uint32]*trident.GPIDSyncRequest
}

func (r *VTapIDToReq) getKeys() []uint32 {
	r.RLock()
	keys := make([]uint32, 0, len(r.idToReq))
	for key, _ := range r.idToReq {
		keys = append(keys, key)
	}
	r.RUnlock()
	return keys
}

func (r *VTapIDToReq) getSetIntKeys() mapset.Set {
	r.RLock()
	keys := mapset.NewSet()
	for key, _ := range r.idToReq {
		keys.Add(int(key))
	}
	r.RUnlock()
	return keys
}

func (r *VTapIDToReq) updateReq(req *trident.GPIDSyncRequest) {
	r.Lock()
	r.idToReq[req.GetVtapId()] = req
	r.Unlock()
}

func (r *VTapIDToReq) getReq(vtapID uint32) *trident.GPIDSyncRequest {
	r.RLock()
	req := r.idToReq[vtapID]
	r.RUnlock()
	return req
}

func (r *VTapIDToReq) getAllReqAndClear() map[uint32]*trident.GPIDSyncRequest {
	r.Lock()
	allData := r.idToReq
	r.idToReq = make(map[uint32]*trident.GPIDSyncRequest)
	r.Unlock()

	return allData
}

func (r *VTapIDToReq) deleteData(vtapID uint32) {
	r.Lock()
	delete(r.idToReq, vtapID)
	r.Unlock()
}

func NewVTapIDToReq() *VTapIDToReq {
	return &VTapIDToReq{
		idToReq: make(map[uint32]*trident.GPIDSyncRequest),
	}
}

// (vtap_id + pid): gpid
type IDToGPID map[uint64]uint32

func generateVPKey(vtapID uint32, pid uint32) uint64 {
	return uint64(vtapID)<<32 | uint64(pid)
}

func (p IDToGPID) getData(vtapID uint32, pid uint32) uint32 {
	return p[generateVPKey(vtapID, pid)]
}

func (p IDToGPID) addData(process *models.Process) {
	p[generateVPKey(uint32(process.VTapID), uint32(process.PID))] = uint32(process.ID)
}

type ProcessInfo struct {
	sendGPIDReq          *VTapIDToReq
	vtapIDToLocalGPIDReq *VTapIDToReq
	vtapIDToShareGPIDReq *VTapIDToReq
	vtapIDAndPIDToGPID   IDToGPID
	globalLocalEntries   EntryData
	grpcConns            map[string]*grpc.ClientConn
	db                   *gorm.DB
	config               *config.Config
}

func NewProcessInfo(db *gorm.DB, cfg *config.Config) *ProcessInfo {
	return &ProcessInfo{
		sendGPIDReq:          NewVTapIDToReq(),
		vtapIDToLocalGPIDReq: NewVTapIDToReq(),
		vtapIDToShareGPIDReq: NewVTapIDToReq(),
		vtapIDAndPIDToGPID:   make(IDToGPID),
		globalLocalEntries:   NewEntryData(),
		grpcConns:            make(map[string]*grpc.ClientConn),
		db:                   db,
		config:               cfg,
	}
}

func (p *ProcessInfo) UpdateVTapGPIDReq(req *trident.GPIDSyncRequest) {
	p.sendGPIDReq.updateReq(req)
}

func (p *ProcessInfo) GetVTapGPIDReq(vtapID uint32) *trident.GPIDSyncRequest {
	req := p.sendGPIDReq.getReq(vtapID)
	if req == nil {
		req = p.vtapIDToLocalGPIDReq.getReq(vtapID)
		if req == nil {
			req = p.vtapIDToShareGPIDReq.getReq(vtapID)
		}
	}

	return req
}

func (p *ProcessInfo) UpdateGPIDReqFromShare(req *trident.GPIDSyncRequest) {
	p.vtapIDToShareGPIDReq.updateReq(req)
}

func (p *ProcessInfo) updateGlobalLocalEntries(data EntryData) {
	p.globalLocalEntries = data
}

func (p *ProcessInfo) GetGlobalLocalEntries() []*trident.GPIDSyncEntry {
	return p.globalLocalEntries.getAllData()
}

func (p *ProcessInfo) generateGlobalLocalEntries() {
	globalLocalEntries := NewEntryData()
	vtapIDs := p.vtapIDToLocalGPIDReq.getKeys()
	for _, vtapID := range vtapIDs {
		req := p.vtapIDToLocalGPIDReq.getReq(vtapID)
		if req == nil {
			continue
		}
		if len(req.GetEntries()) == 0 {
			continue
		}
		for _, entry := range req.GetEntries() {
			globalLocalEntries.addData(vtapID, entry)
		}
	}

	vtapIDs = p.vtapIDToShareGPIDReq.getKeys()
	for _, vtapID := range vtapIDs {
		req := p.vtapIDToShareGPIDReq.getReq(vtapID)
		if req == nil {
			continue
		}
		if len(req.GetEntries()) == 0 {
			continue
		}
		for _, entry := range req.GetEntries() {
			globalLocalEntries.addData(vtapID, entry)
		}
	}

	p.updateGlobalLocalEntries(globalLocalEntries)
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
	p.vtapIDAndPIDToGPID = newVtapIDAndPIDToGPID
}

func (p *ProcessInfo) GetGPIDResponseByVtapID(vtapID uint32) *trident.GPIDSyncResponse {
	return p.GetGPIDResponseByReq(p.GetVTapGPIDReq(vtapID))
}

func (p *ProcessInfo) GetGPIDResponseByReq(req *trident.GPIDSyncRequest) *trident.GPIDSyncResponse {
	if req == nil {
		return &trident.GPIDSyncResponse{}
	}
	entries := req.GetEntries()
	if len(entries) == 0 {
		return &trident.GPIDSyncResponse{}
	}
	vtapID := req.GetVtapId()
	responseEntries := make([]*trident.GPIDSyncEntry, 0, len(entries))
	for _, entry := range entries {
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
		}
		var gpid0, gpid1, gpidReal uint32
		if entry.GetPid_0() == 0 {
			global0 := p.globalLocalEntries.getData(protocol, trident.RoleType_ROLE_CLIENT,
				entry.GetEpcId_0(), entry.GetPort_0(), entry.GetIpv4_0())
			if global0 != nil {
				gpid0 = p.vtapIDAndPIDToGPID.getData(global0.vtapID, global0.pid)
			}
		} else {
			gpid0 = p.vtapIDAndPIDToGPID.getData(vtapID, entry.GetPid_0())
		}

		if entry.GetPid_1() == 0 {
			global1 := p.globalLocalEntries.getData(protocol, trident.RoleType_ROLE_SERVER,
				entry.GetEpcId_1(), entry.GetPort_1(), entry.GetIpv4_1())
			if global1 != nil {
				gpid1 = p.vtapIDAndPIDToGPID.getData(global1.vtapID, global1.pid)
			}
		} else {
			gpid1 = p.vtapIDAndPIDToGPID.getData(vtapID, entry.GetPid_1())
		}

		if entry.GetPidReal() == 0 {
			globalReal := p.globalLocalEntries.getData(protocol, roleReal,
				entry.GetEpcIdReal(), entry.GetPortReal(), entry.GetIpv4Real())
			if globalReal != nil {
				gpidReal = p.vtapIDAndPIDToGPID.getData(globalReal.vtapID, globalReal.pid)
			}
		} else {
			gpidReal = p.vtapIDAndPIDToGPID.getData(vtapID, entry.GetPidReal())
		}
		responseEntry.Pid_0 = &gpid0
		responseEntry.Pid_1 = &gpid1
		responseEntry.PidReal = &gpidReal
		responseEntries = append(responseEntries, responseEntry)
	}
	return &trident.GPIDSyncResponse{Entries: responseEntries}
}

func (p *ProcessInfo) DeleteVTapExpiredData(dbVTapIDs mapset.Set) {
	cacheVTapIDs := p.vtapIDToLocalGPIDReq.getSetIntKeys()
	delVTapIDs := cacheVTapIDs.Difference(dbVTapIDs)
	for val := range delVTapIDs.Iter() {
		vtapID := val.(int)
		p.vtapIDToLocalGPIDReq.deleteData(uint32(vtapID))
	}

	cacheVTapIDs = p.vtapIDToShareGPIDReq.getSetIntKeys()
	delVTapIDs = cacheVTapIDs.Difference(dbVTapIDs)
	for val := range delVTapIDs.Iter() {
		vtapID := val.(int)
		p.vtapIDToShareGPIDReq.deleteData(uint32(vtapID))
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
		for _, req := range p.sendGPIDReq.getAllReqAndClear() {
			p.vtapIDToLocalGPIDReq.updateReq(req)
		}

		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, req := range p.sendGPIDReq.getAllReqAndClear() {
		p.vtapIDToLocalGPIDReq.updateReq(req)
		sendReq := &trident.GPIDSyncRequest{
			CtrlIp:  proto.String(p.config.NodeIP),
			VtapId:  proto.Uint32(req.GetVtapId()),
			Entries: req.GetEntries(),
		}
		for _, conn := range grpcConns {
			client := trident.NewSynchronizerClient(conn)
			_, err := client.ShareGPIDLocalData(ctx, sendReq)
			if err != nil {
				log.Error(err)
			}
		}
	}
}

func (p *ProcessInfo) generateData() {
	p.sendLocalShareEntryData()
	p.getGPIDInfoFromDB()
	p.generateGlobalLocalEntries()
}

func (p *ProcessInfo) TimedGenerateGPIDInfo() {
	p.getGPIDInfoFromDB()
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
