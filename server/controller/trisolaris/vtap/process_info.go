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
	entry  *trident.GPIDSyncRequestLocalEntry
}

func NewGlobalEntry(vtapID uint32, entry *trident.GPIDSyncRequestLocalEntry) *GlobalEntry {
	return &GlobalEntry{
		vtapID: vtapID,
		entry:  entry,
	}
}

func generateKey(epcId uint32, protocol uint32) uint64 {
	return uint64(epcId)<<32 | uint64(protocol)
}

// (epc_id + protocol) -> ip
type EntryData map[uint64]map[string][]*GlobalEntry

func (e EntryData) addData(vtapID uint32, entry *trident.GPIDSyncRequestLocalEntry) {
	ip := entry.GetIp()
	key := generateKey(entry.GetEpcId(), uint32(entry.GetProtocol()))
	if _, ok := e[key]; ok {
		if _, ok := e[key][ip]; ok {
			e[key][ip] = append(e[key][ip], NewGlobalEntry(vtapID, entry))
		} else {
			e[key][ip] = []*GlobalEntry{NewGlobalEntry(vtapID, entry)}
		}

	} else {
		e[key] = make(map[string][]*GlobalEntry)
		e[key][ip] = []*GlobalEntry{NewGlobalEntry(vtapID, entry)}
	}
}

func (e EntryData) getData(epcID uint32, protocol uint32, ip string) []*GlobalEntry {
	key := generateKey(epcID, protocol)
	if _, ok := e[key]; ok {
		return e[key][ip]
	}

	return nil
}

func (e EntryData) getAllData() []*trident.GPIDSyncRequestLocalEntry {
	reqs := []*trident.GPIDSyncRequestLocalEntry{}
	for _, data := range e {
		for _, localEntries := range data {
			for _, localEntry := range localEntries {
				reqs = append(reqs, localEntry.entry)
			}
		}
	}

	return reqs
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

// vtap_id->pid: gpid
type IDToGPID map[int]map[int]uint64

func (p IDToGPID) getData(vtapID int, pid int) uint64 {
	if _, ok := p[vtapID]; ok {
		return p[vtapID][pid]
	}

	return 0
}

func (p IDToGPID) addData(process *models.Process) {
	if _, ok := p[process.VTapID]; ok {
		p[process.VTapID][process.PID] = uint64(process.ID)
	} else {
		p[process.VTapID] = make(map[int]uint64)
		p[process.VTapID][process.PID] = uint64(process.ID)
	}
}

type ProcessInfo struct {
	sendGPIDReq          *VTapIDToReq
	vtapIDToLocalGPIDReq *VTapIDToReq
	vtapIDToShareGPIDReq *VTapIDToReq
	globalLocalEntries   EntryData
	vtapIDAndPIDToGPID   IDToGPID
	vtapIDToGPIDResponse map[uint32]*trident.GPIDSyncResponse
	grpcConns            map[string]*grpc.ClientConn
	db                   *gorm.DB
	config               *config.Config
}

func NewProcessInfo(db *gorm.DB, cfg *config.Config) *ProcessInfo {
	return &ProcessInfo{
		sendGPIDReq:          NewVTapIDToReq(),
		vtapIDToLocalGPIDReq: NewVTapIDToReq(),
		vtapIDToShareGPIDReq: NewVTapIDToReq(),
		globalLocalEntries:   make(EntryData),
		vtapIDAndPIDToGPID:   make(IDToGPID),
		vtapIDToGPIDResponse: make(map[uint32]*trident.GPIDSyncResponse),
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

func (p *ProcessInfo) GetGlobalLocalEntries() []*trident.GPIDSyncRequestLocalEntry {
	return p.globalLocalEntries.getAllData()
}

func (p *ProcessInfo) generateGlobalLocalEntries() {
	globalLocalEntries := make(EntryData)
	vtapIDs := p.vtapIDToLocalGPIDReq.getKeys()
	for _, vtapID := range vtapIDs {
		req := p.vtapIDToLocalGPIDReq.getReq(vtapID)
		if req == nil {
			continue
		}
		if len(req.GetLocalEntries()) == 0 {
			continue
		}
		for _, entry := range req.GetLocalEntries() {
			globalLocalEntries.addData(vtapID, entry)
		}
	}

	vtapIDs = p.vtapIDToShareGPIDReq.getKeys()
	for _, vtapID := range vtapIDs {
		req := p.vtapIDToShareGPIDReq.getReq(vtapID)
		if req == nil {
			continue
		}
		if len(req.GetLocalEntries()) == 0 {
			continue
		}
		for _, entry := range req.GetLocalEntries() {
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
	vtapIDAndPIDToGPID := make(IDToGPID)
	for _, process := range processes {
		vtapIDAndPIDToGPID.addData(process)
	}
	p.vtapIDAndPIDToGPID = vtapIDAndPIDToGPID
}

func (p *ProcessInfo) GetGPIDResponseByReq(req *trident.GPIDSyncRequest) *trident.GPIDSyncResponse {
	localEntries := req.GetLocalEntries()
	peerEntries := req.GetPeerEntries()
	if len(localEntries) == 0 && len(peerEntries) == 0 {
		return &trident.GPIDSyncResponse{}
	}
	globalLocalEntries := p.globalLocalEntries
	vtapIDAndPIDToGPID := p.vtapIDAndPIDToGPID
	responseEntries := make([]*trident.GPIDSyncResponseEntry, 0, len(localEntries)+len(peerEntries))
	peerDataKey := make(map[uint64]map[string]bool)
	for _, entry := range peerEntries {
		data := globalLocalEntries.getData(entry.GetEpcId(), uint32(entry.GetProtocol()), entry.GetIp())
		if len(data) == 0 {
			continue
		}
		key := generateKey(entry.GetEpcId(), uint32(entry.GetProtocol()))
		if ipData, ok := peerDataKey[key]; ok {
			if _, ok := ipData[entry.GetIp()]; ok {
				continue
			} else {
				peerDataKey[key][entry.GetIp()] = true
			}
		} else {
			peerDataKey[key] = make(map[string]bool)
			peerDataKey[key][entry.GetIp()] = true
		}
		for _, globalEntry := range data {
			if globalEntry.entry == nil {
				continue
			}
			gpid := vtapIDAndPIDToGPID.getData(int(globalEntry.vtapID), int(globalEntry.entry.GetPid()))
			if gpid == 0 {
				continue
			}
			role := globalEntry.entry.GetRole()
			protocol := globalEntry.entry.GetProtocol()
			responseEntries = append(responseEntries, &trident.GPIDSyncResponseEntry{
				EpcId:    proto.Uint32(globalEntry.entry.GetEpcId()),
				Ip:       proto.String(globalEntry.entry.GetIp()),
				Port:     proto.Uint32(globalEntry.entry.GetPort()),
				Protocol: &protocol,
				Role:     &role,
				Gpid:     &gpid,
			})
		}
	}
	vtapID := int(req.GetVtapId())
	for _, entry := range localEntries {
		gpid := vtapIDAndPIDToGPID.getData(vtapID, int(entry.GetPid()))
		if gpid == 0 {
			continue
		}
		key := generateKey(entry.GetEpcId(), uint32(entry.GetProtocol()))
		if ipData, ok := peerDataKey[key]; ok {
			if _, ok := ipData[entry.GetIp()]; ok {
				continue
			}
		}
		role := entry.GetRole()
		protocol := entry.GetProtocol()
		responseEntries = append(responseEntries, &trident.GPIDSyncResponseEntry{
			EpcId:    proto.Uint32(entry.GetEpcId()),
			Ip:       proto.String(entry.GetIp()),
			Port:     proto.Uint32(entry.GetPort()),
			Protocol: &protocol,
			Role:     &role,
			Gpid:     &gpid,
		})
	}
	return &trident.GPIDSyncResponse{Entries: responseEntries}
}

func (p *ProcessInfo) GetGPIDResponseByVTapID(vtapID uint32) *trident.GPIDSyncResponse {
	var resp *trident.GPIDSyncResponse
	req := p.GetVTapGPIDReq(vtapID)
	if req != nil {
		resp = p.GetGPIDResponseByReq(req)
	} else {
		resp = &trident.GPIDSyncResponse{}
	}
	return resp
}

func (p *ProcessInfo) generateGPIDResponse() {
	vtapIDToGPIDResponse := make(map[uint32]*trident.GPIDSyncResponse)
	vtapIDs := p.vtapIDToLocalGPIDReq.getKeys()
	for _, vtapID := range vtapIDs {
		req := p.vtapIDToLocalGPIDReq.getReq(vtapID)
		if req == nil {
			continue
		}
		localEntries := req.GetLocalEntries()
		peerEntries := req.GetPeerEntries()
		if len(localEntries) == 0 && len(peerEntries) == 0 {
			continue
		}
		responseEntries := make([]*trident.GPIDSyncResponseEntry, 0, len(localEntries)+len(peerEntries))
		for _, entry := range localEntries {
			gpid := p.vtapIDAndPIDToGPID.getData(int(vtapID), int(entry.GetPid()))
			if gpid == 0 {
				continue
			}
			role := entry.GetRole()
			protocol := entry.GetProtocol()
			responseEntries = append(responseEntries, &trident.GPIDSyncResponseEntry{
				EpcId:    proto.Uint32(entry.GetEpcId()),
				Ip:       proto.String(entry.GetIp()),
				Port:     proto.Uint32(entry.GetPort()),
				Protocol: &protocol,
				Role:     &role,
				Gpid:     &gpid,
			})
		}

		for _, entry := range peerEntries {
			data := p.globalLocalEntries.getData(entry.GetEpcId(), uint32(entry.GetProtocol()), entry.GetIp())
			if len(data) == 0 {
				continue
			}
			for _, globalEntry := range data {
				if globalEntry.entry == nil {
					continue
				}
				gpid := p.vtapIDAndPIDToGPID.getData(int(globalEntry.vtapID), int(globalEntry.entry.GetPid()))
				if gpid == 0 {
					continue
				}
				role := globalEntry.entry.GetRole()
				protocol := globalEntry.entry.GetProtocol()
				responseEntries = append(responseEntries, &trident.GPIDSyncResponseEntry{
					EpcId:    proto.Uint32(globalEntry.entry.GetEpcId()),
					Ip:       proto.String(globalEntry.entry.GetIp()),
					Port:     proto.Uint32(globalEntry.entry.GetPort()),
					Protocol: &protocol,
					Role:     &role,
					Gpid:     &gpid,
				})
			}
		}
		vtapIDToGPIDResponse[vtapID] = &trident.GPIDSyncResponse{
			Entries: responseEntries,
		}
	}

	p.vtapIDToGPIDResponse = vtapIDToGPIDResponse
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
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, req := range p.sendGPIDReq.getAllReqAndClear() {
		p.vtapIDToLocalGPIDReq.updateReq(req)
		sendReq := &trident.GPIDSyncRequest{
			CtrlIp:       proto.String(p.config.NodeIP),
			LocalEntries: req.GetLocalEntries(),
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
	//p.generateGPIDResponse()
}

func (p *ProcessInfo) TimedGenerateGPIDInfo() {
	p.getGPIDInfoFromDB()
	ticker := time.NewTicker(60 * time.Second).C
	for {
		select {
		case <-ticker:
			log.Info("start generate gpid data from timed")
			p.generateData()
			log.Info("end generate gpid data from timed")
		}
	}
}
