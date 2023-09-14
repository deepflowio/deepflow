/*
 * Copyright (c) 2023 Yunshan Networks
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

package metadata

import (
	mapset "github.com/deckarep/golang-set"
	"github.com/golang/protobuf/proto"

	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/controller/common"
	models "github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type MacID struct {
	Mac  string
	VMac string
	ID   int
}

func newMacID(vif *models.VInterface) *MacID {
	return &MacID{
		Mac:  vif.Mac,
		ID:   vif.ID,
		VMac: vif.VMac,
	}
}

type NetworkMacs map[int][]*MacID

type IDToNetworkMacs map[int]NetworkMacs

type ServerToNetworkMacs map[string]NetworkMacs

func newNetworkMacs() NetworkMacs {
	return make(NetworkMacs)
}

func isMacNullOrDefault(mac string) bool {
	if mac == "" || mac == common.VIF_DEFAULT_MAC {
		return true
	}
	return false
}

func (n NetworkMacs) add(data interface{}) {
	vif := data.(*models.VInterface)
	if isMacNullOrDefault(vif.Mac) {
		return
	}
	macID := newMacID(vif)
	id := vif.NetworkID
	if _, ok := n[id]; ok {
		n[id] = append(n[id], macID)
	} else {
		n[id] = []*MacID{macID}
	}
}

func (n NetworkMacs) get(id int) []*MacID {
	return n[id]
}

func newIDToNetworkMacs() IDToNetworkMacs {
	return make(IDToNetworkMacs)
}

func newServerToNetworkMacs() ServerToNetworkMacs {
	return make(ServerToNetworkMacs)
}

func (t IDToNetworkMacs) add(id int, macs NetworkMacs) {
	t[id] = macs
}

func (t IDToNetworkMacs) getSegmentsByID(id int, s *Segment) []*trident.Segment {
	networkMacs, ok := t[id]
	if ok == false {
		return nil
	}
	segments := make([]*trident.Segment, 0, len(networkMacs))
	for networkID, macIDs := range networkMacs {
		macs := make([]string, 0, len(macIDs))
		vmacs := make([]string, 0, len(macIDs))
		vifIDs := make([]uint32, 0, len(macIDs))
		for _, macID := range macIDs {
			macs = append(macs, macID.Mac)
			vmacs = append(vmacs, macID.Mac)
			vifIDs = append(vifIDs, uint32(macID.ID))
			s.vtapUsedVInterfaceIDs.Add(macID.ID)
		}
		segment := &trident.Segment{
			Id:          proto.Uint32(uint32(networkID)),
			Mac:         macs,
			Vmac:        vmacs,
			InterfaceId: vifIDs,
		}
		segments = append(segments, segment)
	}

	return segments
}

func (t ServerToNetworkMacs) add(server string, macs NetworkMacs) {
	t[server] = macs
}

func (t ServerToNetworkMacs) getSegmentsByServer(server string, s *Segment) []*trident.Segment {
	networkMacs, ok := t[server]
	if ok == false {
		return nil
	}
	segments := make([]*trident.Segment, 0, len(networkMacs))
	for networkID, macIDs := range networkMacs {
		macs := make([]string, 0, len(macIDs))
		vmacs := make([]string, 0, len(macIDs))
		vifIDs := make([]uint32, 0, len(macIDs))
		for _, macID := range macIDs {
			macs = append(macs, macID.Mac)
			vmacs = append(vmacs, macID.Mac)
			vifIDs = append(vifIDs, uint32(macID.ID))
			s.vtapUsedVInterfaceIDs.Add(macID.ID)
		}
		segment := &trident.Segment{
			Id:          proto.Uint32(uint32(networkID)),
			Mac:         macs,
			Vmac:        vmacs,
			InterfaceId: vifIDs,
		}
		segments = append(segments, segment)
	}

	return segments
}

type IDToVifs map[int]mapset.Set

func newIDToVifs() IDToVifs {
	return make(IDToVifs)
}

func (v IDToVifs) add(id int, vifs mapset.Set) {
	if _, ok := v[id]; ok {
		for vif := range vifs.Iter() {
			v[id].Add(vif)
		}
	} else {
		v[id] = vifs.Clone()
	}
}

type Segment struct {
	launchServerToSegments  ServerToNetworkMacs
	hostIDToSegments        IDToNetworkMacs
	gatewayHostIDToSegments IDToNetworkMacs
	allGatewayHostSegments  []*trident.Segment
	vtapUsedVInterfaceIDs   mapset.Set
	notVtapUsedSegments     []*trident.Segment
	// vm所有vif的segment，包含vm上的pod pod_node
	vmIDToSegments IDToNetworkMacs
	// 专属采集器remote segment
	bmDedicatedRemoteSegments []*trident.Segment
	podNodeIDToSegments       IDToNetworkMacs

	vmIDToPodNodeAllVifs IDToVifs
	podNodeIDToAllVifs   IDToVifs

	vRouterLaunchServerToSegments ServerToNetworkMacs
}

func newSegment() *Segment {
	return &Segment{
		launchServerToSegments:        newServerToNetworkMacs(),
		hostIDToSegments:              newIDToNetworkMacs(),
		gatewayHostIDToSegments:       newIDToNetworkMacs(),
		allGatewayHostSegments:        []*trident.Segment{},
		vtapUsedVInterfaceIDs:         mapset.NewSet(),
		notVtapUsedSegments:           []*trident.Segment{},
		vmIDToSegments:                newIDToNetworkMacs(),
		bmDedicatedRemoteSegments:     []*trident.Segment{},
		podNodeIDToSegments:           newIDToNetworkMacs(),
		vmIDToPodNodeAllVifs:          newIDToVifs(),
		podNodeIDToAllVifs:            newIDToVifs(),
		vRouterLaunchServerToSegments: newServerToNetworkMacs(),
	}
}

func (s *Segment) GetAllGatewayHostSegments() []*trident.Segment {
	return s.allGatewayHostSegments
}

func (s *Segment) GetNotVtapUsedSegments() []*trident.Segment {
	return s.notVtapUsedSegments
}

func (s *Segment) ClearVTapUsedVInterfaceIDs() {
	s.vtapUsedVInterfaceIDs = mapset.NewSet()
}

func (s *Segment) convertDBInfo(rawData *PlatformRawData) {
	podNodeIDtoPodIDs := rawData.podNodeIDtoPodIDs
	podIDToVifs := rawData.podIDToVifs
	podNodeIDToVmID := rawData.podNodeIDToVmID
	podNodeIDToVifs := rawData.podNodeIDToVifs
	idToPodNode := rawData.idToPodNode

	vmIDToPodNodeAllVifs := newIDToVifs()
	podNodeIDToAllVifs := newIDToVifs()

	for _, podnode := range idToPodNode {
		podnodeID := podnode.ID
		if vifs, ok := podNodeIDToVifs[podnodeID]; ok {
			podNodeIDToAllVifs.add(podnodeID, vifs)
		}
		if podIDs, ok := podNodeIDtoPodIDs[podnodeID]; ok {
			for podID := range podIDs.Iter() {
				id := podID.(int)
				if vifs, ok := podIDToVifs[id]; ok {
					podNodeIDToAllVifs.add(podnodeID, vifs)
				}
			}
		}
	}
	for podnodeID, vmID := range podNodeIDToVmID {
		if allVifs, ok := podNodeIDToAllVifs[podnodeID]; ok {
			vmIDToPodNodeAllVifs.add(vmID, allVifs)
		}
	}
	s.podNodeIDToAllVifs = podNodeIDToAllVifs
	s.vmIDToPodNodeAllVifs = vmIDToPodNodeAllVifs
}

func (s *Segment) generateBaseSegmentsFromDB(rawData *PlatformRawData) {
	launchServerToSegments := newServerToNetworkMacs()
	hostIDToSegments := newIDToNetworkMacs()
	gatewayHostIDToSegments := newIDToNetworkMacs()
	vmIDToSegments := newIDToNetworkMacs()
	podNodeIDToSegments := newIDToNetworkMacs()
	vRouterLaunchServerToSegments := newServerToNetworkMacs()

	for server, vmids := range rawData.serverToVmIDs {
		netWorkMacs := newNetworkMacs()
		for vmid := range vmids.Iter() {
			id := vmid.(int)
			if vmVifs, ok := rawData.vmIDToVifs[id]; ok {
				for vmVif := range vmVifs.Iter() {
					netWorkMacs.add(vmVif)
				}
			}

			if allVifs, ok := s.vmIDToPodNodeAllVifs[id]; ok {
				for allVif := range allVifs.Iter() {
					netWorkMacs.add(allVif)
				}
			}
		}
		launchServerToSegments[server] = netWorkMacs
	}

	for hostID, vifs := range rawData.hostIDToVifs {
		netWorkMacs := newNetworkMacs()
		for hVif := range vifs.Iter() {
			netWorkMacs.add(hVif)
		}
		hostIDToSegments[hostID] = netWorkMacs
	}

	for hostID, vifs := range rawData.gatewayHostIDToVifs {
		netWorkMacs := newNetworkMacs()
		for gVif := range vifs.Iter() {
			netWorkMacs.add(gVif)
		}
		gatewayHostIDToSegments[hostID] = netWorkMacs
	}

	for vmID, vifs := range rawData.vmIDToVifs {
		netWorkMacs := newNetworkMacs()
		for vif := range vifs.Iter() {
			netWorkMacs.add(vif)
		}
		vmIDToSegments[vmID] = netWorkMacs
	}

	for vmID, podVifs := range s.vmIDToPodNodeAllVifs {
		netWorkMacs, ok := vmIDToSegments[vmID]
		if ok == false {
			netWorkMacs = newNetworkMacs()
		}
		for podVif := range podVifs.Iter() {
			netWorkMacs.add(podVif)
		}
		if ok == false {
			vmIDToSegments[vmID] = netWorkMacs
		}
	}

	for podNodeID, vifs := range s.podNodeIDToAllVifs {
		netWorkMacs := newNetworkMacs()
		for vif := range vifs.Iter() {
			netWorkMacs.add(vif)
		}
		podNodeIDToSegments[podNodeID] = netWorkMacs
	}

	for server, VRouterIDs := range rawData.launchServerToVRouterIDs {
		netWorkMacs := newNetworkMacs()
		for _, VRouterID := range VRouterIDs {
			if VRouterVifs, ok := rawData.vRouterIDToVifs[VRouterID]; ok {
				for vRouterVif := range VRouterVifs.Iter() {
					netWorkMacs.add(vRouterVif)
				}
			}
		}
		vRouterLaunchServerToSegments[server] = netWorkMacs
	}

	s.launchServerToSegments = launchServerToSegments
	s.hostIDToSegments = hostIDToSegments
	s.gatewayHostIDToSegments = gatewayHostIDToSegments
	s.vmIDToSegments = vmIDToSegments
	s.podNodeIDToSegments = podNodeIDToSegments
	s.vRouterLaunchServerToSegments = vRouterLaunchServerToSegments
}

func (s *Segment) generateGatewayHostSegments() {
	segments := make([]*trident.Segment, 0, 1)
	for _, hostSegments := range s.gatewayHostIDToSegments {
		for _, macIDs := range hostSegments {
			macs := make([]string, 0, len(macIDs))
			vmacs := make([]string, 0, len(macIDs))
			vifIDs := make([]uint32, 0, len(macIDs))
			for _, macID := range macIDs {
				if !isMacNullOrDefault(macID.Mac) {
					macs = append(macs, macID.Mac)
					vifIDs = append(vifIDs, uint32(macID.ID))
					if macID.VMac == "" {
						vmacs = append(vmacs, macID.Mac)
					} else {
						vmacs = append(vmacs, macID.VMac)
					}
				}
			}
			segment := &trident.Segment{
				Id:          proto.Uint32(uint32(1)),
				Mac:         macs,
				Vmac:        vmacs,
				InterfaceId: vifIDs,
			}
			segments = append(segments, segment)
		}
	}
	s.allGatewayHostSegments = segments
}

func (s *Segment) GenerateNoVTapUsedSegments(rawData *PlatformRawData) {
	macs := []string{}
	vmacs := []string{}
	vifIDs := []uint32{}
	segments := make([]*trident.Segment, 0, 1)
	for _, vif := range rawData.deviceVifs {
		if !s.vtapUsedVInterfaceIDs.Contains(vif.ID) {
			if !isMacNullOrDefault(vif.Mac) {
				macs = append(macs, vif.Mac)
				vmacs = append(vmacs, vif.Mac)
				vifIDs = append(vifIDs, uint32(vif.ID))
			}
		}
	}

	if len(macs) > 0 {
		segment := &trident.Segment{
			Id:          proto.Uint32(uint32(1)),
			Mac:         macs,
			Vmac:        vmacs,
			InterfaceId: vifIDs,
		}
		segments = append(segments, segment)
	}
	log.Infof("vtap about vifs used: %d  not used: %d",
		s.vtapUsedVInterfaceIDs.Cardinality(), len(macs))
	s.notVtapUsedSegments = segments
}

func (s *Segment) GetLaunchServerSegments(launchServer string) []*trident.Segment {
	segment1 := s.launchServerToSegments.getSegmentsByServer(launchServer, s)
	segment2 := s.vRouterLaunchServerToSegments.getSegmentsByServer(launchServer, s)

	return append(segment1, segment2...)
}

func (s *Segment) GetVMIDSegments(vmID int) []*trident.Segment {
	return s.vmIDToSegments.getSegmentsByID(vmID, s)
}

func (s *Segment) GetHostIDSegments(hostID int) []*trident.Segment {
	return s.hostIDToSegments.getSegmentsByID(hostID, s)
}

func (s *Segment) GetPodNodeSegments(podNodeID int) []*trident.Segment {
	return s.podNodeIDToSegments.getSegmentsByID(podNodeID, s)
}

func (s *Segment) GetTypeVMSegments(launchServer string, hostID int) []*trident.Segment {
	macs := []string{}
	vmacs := []string{}
	vifIDs := []uint32{}
	if networkMacs, ok := s.launchServerToSegments[launchServer]; ok {
		for _, macIDs := range networkMacs {
			for _, macID := range macIDs {
				macs = append(macs, macID.Mac)
				vmacs = append(vmacs, macID.Mac)
				vifIDs = append(vifIDs, uint32(macID.ID))
				s.vtapUsedVInterfaceIDs.Add(macID.ID)
			}
		}
	}
	if networkMacs, ok := s.vRouterLaunchServerToSegments[launchServer]; ok {
		for _, macIDs := range networkMacs {
			for _, macID := range macIDs {
				macs = append(macs, macID.Mac)
				vmacs = append(vmacs, macID.Mac)
				vifIDs = append(vifIDs, uint32(macID.ID))
				s.vtapUsedVInterfaceIDs.Add(macID.ID)
			}
		}
	}
	if networkMacs, ok := s.hostIDToSegments[hostID]; ok {
		for _, macIDs := range networkMacs {
			for _, macID := range macIDs {
				macs = append(macs, macID.Mac)
				vmacs = append(vmacs, macID.Mac)
				vifIDs = append(vifIDs, uint32(macID.ID))
				s.vtapUsedVInterfaceIDs.Add(macID.ID)
			}
		}
	}

	segment := &trident.Segment{
		Id:          proto.Uint32(uint32(1)),
		Mac:         macs,
		Vmac:        vmacs,
		InterfaceId: vifIDs,
	}
	return []*trident.Segment{segment}
}

func (s *Segment) generateBaseSegments(rawData *PlatformRawData) {
	s.convertDBInfo(rawData)
	s.generateBaseSegmentsFromDB(rawData)
	s.generateGatewayHostSegments()
}
