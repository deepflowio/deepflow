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

package metadata

import (
	"errors"
	"fmt"
	"strings"

	mapset "github.com/deckarep/golang-set"
	"github.com/golang/protobuf/proto"

	"github.com/deepflowio/deepflow/message/trident"
	. "github.com/deepflowio/deepflow/server/controller/common"
	models "github.com/deepflowio/deepflow/server/controller/db/mysql"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
)

var PodGroupTypeMap = map[int]uint32{
	POD_GROUP_DEPLOYMENT:            uint32(trident.AutoServiceType_AUTO_SERVICE_TYPE_POD_GROUP_DEPLOYMENT),
	POD_GROUP_STATEFULSET:           uint32(trident.AutoServiceType_AUTO_SERVICE_TYPE_POD_GROUP_STATEFULSET),
	POD_GROUP_RC:                    uint32(trident.AutoServiceType_AUTO_SERVICE_TYPE_POD_GROUP_RC),
	POD_GROUP_DAEMON_SET:            uint32(trident.AutoServiceType_AUTO_SERVICE_TYPE_POD_GROUP_DAEMON_SET),
	POD_GROUP_REPLICASET_CONTROLLER: uint32(trident.AutoServiceType_AUTO_SERVICE_TYPE_POD_GROUP_REPLICASET_CONTROLLER),
	POD_GROUP_CLONESET:              uint32(trident.AutoServiceType_AUTO_SERVICE_TYPE_POD_GROUP_CLONESET),
}

type TypeIDData struct {
	LaunchServer   string
	LaunchServerID int
	AZ             string
	VPCID          int
	PodID          int
	PodGroupID     int
	PodClusterID   int
	PodNodeID      int
	PodNamespaceID int
	Type           int
}

type IPData struct {
	IP     string
	VPCID  int
	Domain string
}

type DomainIPKey struct {
	Domain string
	IP     string
}

type TypeIDKey struct {
	Type int
	ID   int
}

type IpResourceData struct {
	ipResources       []*trident.IpResource
	simpleIpResources []*trident.IpResource
	isVipInterface    bool
}

type PlatformRawData struct {
	networkIDToSubnets     map[int][]*models.Subnet
	idToNetwork            map[int]*models.Network
	vInterfaceIDToIP       map[int][]*trident.IpResource
	vInterfaceIDToSimpleIP map[int][]*trident.IpResource
	noVInterfaceIDIPs      []*IPData
	typeIDToDevice         map[TypeIDKey]*TypeIDData
	vipDomainLcuuids       mapset.Set
	uuidToRegion           map[string]*models.Region
	uuidToAZ               map[string]*models.AZ
	podNodeIDToVmID        map[int]int
	vmIDToPodNodeID        map[int]int
	idToVPC                map[int]*models.VPC

	idToHost          map[int]*models.Host
	idToVM            map[int]*models.VM
	vmIDs             mapset.Set
	vRouterIDs        mapset.Set
	dhcpPortIDs       mapset.Set
	podIDs            mapset.Set
	vpcIDs            mapset.Set
	tunnelIDs         mapset.Set
	vifIDsOfLANIP     mapset.Set
	vifIDsOfWANIP     mapset.Set
	ipsOfLANIP        mapset.Set
	ipsOfWANIP        mapset.Set
	vmIDsOfFIP        mapset.Set
	regionUUIDs       mapset.Set
	azUUIDs           mapset.Set
	peerConnIDs       mapset.Set
	cenIDs            mapset.Set
	podServiceIDs     mapset.Set
	podGroupIDs       mapset.Set
	redisInstanceIDs  mapset.Set
	rdsInstanceIDs    mapset.Set
	podNodeIDs        mapset.Set
	lbIDs             mapset.Set
	natIDs            mapset.Set
	podServicePortIDs mapset.Set
	processIDs        mapset.Set
	vipIDs            mapset.Set

	vtapIdToVtap                  map[int]*models.VTap
	isVifofVip                    map[int]struct{}
	vipIDToNetwork                map[int]*models.Network
	subnetPrefix                  []string
	subnetMask                    []string
	serverToVmIDs                 map[string]mapset.Set
	floatingIPs                   map[int]*IPData
	podServiceIDToPodGroupPortIDs map[int]mapset.Set
	podServiceIDToPodGroupPorts   map[int][]*models.PodGroupPort

	vpcIDToDeviceIPs    map[int]map[TypeIDKey]mapset.Set
	podNodeIDtoPodIDs   map[int]mapset.Set
	VInterfaceIDToWANIP map[int][]*models.WANIP
	VInterfaceIDToLANIP map[int][]*models.LANIP
	vpcIDToVmidFips     map[int]map[int][]string
	domainIpToHostID    map[DomainIPKey]int
	podServiceIDToPorts map[int][]*models.PodServicePort
	idToPodNode         map[int]*models.PodNode
	idToPod             map[int]*models.Pod
	idToPodService      map[int]*models.PodService
	idToPodGroup        map[int]*models.PodGroup

	vmIDToVifs            map[int]mapset.Set
	vRouterIDToVifs       map[int]mapset.Set
	dhcpIDToVifs          map[int]mapset.Set
	podIDToVifs           map[int]mapset.Set
	podServiceIDToVifs    map[int]mapset.Set
	redisInstanceIDToVifs map[int]mapset.Set
	rdsInstanceIDToVifs   map[int]mapset.Set
	podNodeIDToVifs       map[int]mapset.Set
	lbIDToVifs            map[int]mapset.Set
	natIDToVifs           map[int]mapset.Set
	hostIDToVifs          map[int]mapset.Set
	gatewayHostIDToVifs   map[int]mapset.Set
	gatewayHostIDs        []int
	deviceVifs            []*models.VInterface

	deviceTypeAndIDToVInterfaceID map[TypeIDKey][]int

	launchServerToSkipInterface map[string][]*trident.SkipInterface

	vtapIDToContainer    map[int][]*trident.Container
	launchServerIDToVTap map[int]*models.VTap
	containerIdToPodId   map[string]int

	launchServerToVRouterIDs map[string][]int

	ORGID
}

func NewPlatformRawData(orgID ORGID) *PlatformRawData {
	return &PlatformRawData{
		idToHost:          make(map[int]*models.Host),
		idToVM:            make(map[int]*models.VM),
		vmIDs:             mapset.NewSet(),
		vRouterIDs:        mapset.NewSet(),
		dhcpPortIDs:       mapset.NewSet(),
		podIDs:            mapset.NewSet(),
		vpcIDs:            mapset.NewSet(),
		tunnelIDs:         mapset.NewSet(),
		vifIDsOfLANIP:     mapset.NewSet(),
		vifIDsOfWANIP:     mapset.NewSet(),
		ipsOfLANIP:        mapset.NewSet(),
		ipsOfWANIP:        mapset.NewSet(),
		vmIDsOfFIP:        mapset.NewSet(),
		regionUUIDs:       mapset.NewSet(),
		azUUIDs:           mapset.NewSet(),
		peerConnIDs:       mapset.NewSet(),
		cenIDs:            mapset.NewSet(),
		podServiceIDs:     mapset.NewSet(),
		podGroupIDs:       mapset.NewSet(),
		redisInstanceIDs:  mapset.NewSet(),
		rdsInstanceIDs:    mapset.NewSet(),
		podNodeIDs:        mapset.NewSet(),
		lbIDs:             mapset.NewSet(),
		natIDs:            mapset.NewSet(),
		podServicePortIDs: mapset.NewSet(),
		processIDs:        mapset.NewSet(),
		vipIDs:            mapset.NewSet(),

		vtapIdToVtap:                  make(map[int]*models.VTap),
		isVifofVip:                    make(map[int]struct{}),
		vipIDToNetwork:                make(map[int]*models.Network),
		serverToVmIDs:                 make(map[string]mapset.Set),
		floatingIPs:                   make(map[int]*IPData),
		podServiceIDToPodGroupPortIDs: make(map[int]mapset.Set),
		podServiceIDToPodGroupPorts:   make(map[int][]*models.PodGroupPort),
		subnetPrefix:                  []string{},
		subnetMask:                    []string{},

		idToNetwork:            make(map[int]*models.Network),
		networkIDToSubnets:     make(map[int][]*models.Subnet),
		vpcIDToDeviceIPs:       make(map[int]map[TypeIDKey]mapset.Set),
		podNodeIDtoPodIDs:      make(map[int]mapset.Set),
		idToVPC:                make(map[int]*models.VPC),
		VInterfaceIDToWANIP:    make(map[int][]*models.WANIP),
		VInterfaceIDToLANIP:    make(map[int][]*models.LANIP),
		vpcIDToVmidFips:        make(map[int]map[int][]string),
		uuidToRegion:           make(map[string]*models.Region),
		uuidToAZ:               make(map[string]*models.AZ),
		domainIpToHostID:       make(map[DomainIPKey]int),
		podServiceIDToPorts:    make(map[int][]*models.PodServicePort),
		vmIDToPodNodeID:        make(map[int]int),
		podNodeIDToVmID:        make(map[int]int),
		vipDomainLcuuids:       mapset.NewSet(),
		vInterfaceIDToIP:       make(map[int][]*trident.IpResource),
		vInterfaceIDToSimpleIP: make(map[int][]*trident.IpResource),
		idToPodNode:            make(map[int]*models.PodNode),
		idToPod:                make(map[int]*models.Pod),
		idToPodService:         make(map[int]*models.PodService),
		idToPodGroup:           make(map[int]*models.PodGroup),

		vmIDToVifs:                    make(map[int]mapset.Set),
		vRouterIDToVifs:               make(map[int]mapset.Set),
		dhcpIDToVifs:                  make(map[int]mapset.Set),
		podIDToVifs:                   make(map[int]mapset.Set),
		podServiceIDToVifs:            make(map[int]mapset.Set),
		redisInstanceIDToVifs:         make(map[int]mapset.Set),
		rdsInstanceIDToVifs:           make(map[int]mapset.Set),
		podNodeIDToVifs:               make(map[int]mapset.Set),
		lbIDToVifs:                    make(map[int]mapset.Set),
		natIDToVifs:                   make(map[int]mapset.Set),
		hostIDToVifs:                  make(map[int]mapset.Set),
		gatewayHostIDToVifs:           make(map[int]mapset.Set),
		gatewayHostIDs:                []int{},
		deviceVifs:                    []*models.VInterface{},
		deviceTypeAndIDToVInterfaceID: make(map[TypeIDKey][]int),
		typeIDToDevice:                make(map[TypeIDKey]*TypeIDData),
		launchServerToSkipInterface:   make(map[string][]*trident.SkipInterface),

		vtapIDToContainer:    make(map[int][]*trident.Container),
		launchServerIDToVTap: make(map[int]*models.VTap),
		containerIdToPodId:   make(map[string]int),

		launchServerToVRouterIDs: make(map[string][]int),

		ORGID: orgID,
	}
}

func (r *PlatformRawData) ConvertDBVInterface(dbDataCache *DBDataCache) {
	vinterfaces := dbDataCache.GetVInterfaces()
	if vinterfaces == nil {
		return
	}
	for _, vif := range vinterfaces {
		typeIDkey := TypeIDKey{
			Type: vif.DeviceType,
			ID:   vif.DeviceID,
		}
		if _, ok := r.deviceTypeAndIDToVInterfaceID[typeIDkey]; ok {
			r.deviceTypeAndIDToVInterfaceID[typeIDkey] = append(r.deviceTypeAndIDToVInterfaceID[typeIDkey], vif.ID)
		} else {
			r.deviceTypeAndIDToVInterfaceID[typeIDkey] = []int{vif.ID}
		}
		filter := true
		switch vif.DeviceType {
		case VIF_DEVICE_TYPE_VM:
			if vifs, ok := r.vmIDToVifs[vif.DeviceID]; ok {
				vifs.Add(vif)
			} else {
				r.vmIDToVifs[vif.DeviceID] = mapset.NewSet(vif)
			}
		case VIF_DEVICE_TYPE_VROUTER:
			if vifs, ok := r.vRouterIDToVifs[vif.DeviceID]; ok {
				vifs.Add(vif)
			} else {
				r.vRouterIDToVifs[vif.DeviceID] = mapset.NewSet(vif)
			}
		case VIF_DEVICE_TYPE_DHCP_PORT:
			if vifs, ok := r.dhcpIDToVifs[vif.DeviceID]; ok {
				vifs.Add(vif)
			} else {
				r.dhcpIDToVifs[vif.DeviceID] = mapset.NewSet(vif)
			}
		case VIF_DEVICE_TYPE_POD:
			if vifs, ok := r.podIDToVifs[vif.DeviceID]; ok {
				vifs.Add(vif)
			} else {
				r.podIDToVifs[vif.DeviceID] = mapset.NewSet(vif)
			}
		case VIF_DEVICE_TYPE_POD_SERVICE:
			if vifs, ok := r.podServiceIDToVifs[vif.DeviceID]; ok {
				vifs.Add(vif)
			} else {
				r.podServiceIDToVifs[vif.DeviceID] = mapset.NewSet(vif)
			}
		case VIF_DEVICE_TYPE_REDIS_INSTANCE:
			if vifs, ok := r.redisInstanceIDToVifs[vif.DeviceID]; ok {
				vifs.Add(vif)
			} else {
				r.redisInstanceIDToVifs[vif.DeviceID] = mapset.NewSet(vif)
			}
		case VIF_DEVICE_TYPE_RDS_INSTANCE:
			if vifs, ok := r.rdsInstanceIDToVifs[vif.DeviceID]; ok {
				vifs.Add(vif)
			} else {
				r.rdsInstanceIDToVifs[vif.DeviceID] = mapset.NewSet(vif)
			}
		case VIF_DEVICE_TYPE_POD_NODE:
			if vifs, ok := r.podNodeIDToVifs[vif.DeviceID]; ok {
				vifs.Add(vif)
			} else {
				r.podNodeIDToVifs[vif.DeviceID] = mapset.NewSet(vif)
			}
		case VIF_DEVICE_TYPE_LB:
			if vifs, ok := r.lbIDToVifs[vif.DeviceID]; ok {
				vifs.Add(vif)
			} else {
				r.lbIDToVifs[vif.DeviceID] = mapset.NewSet(vif)
			}
		case VIF_DEVICE_TYPE_NAT_GATEWAY:
			if vifs, ok := r.natIDToVifs[vif.DeviceID]; ok {
				vifs.Add(vif)
			} else {
				r.natIDToVifs[vif.DeviceID] = mapset.NewSet(vif)
			}
		case VIF_DEVICE_TYPE_HOST:
			if vifs, ok := r.hostIDToVifs[vif.DeviceID]; ok {
				vifs.Add(vif)
			} else {
				r.hostIDToVifs[vif.DeviceID] = mapset.NewSet(vif)
			}
			if Find[int](r.gatewayHostIDs, vif.DeviceID) {
				if vifs, ok := r.gatewayHostIDToVifs[vif.DeviceID]; ok {
					vifs.Add(vif)
				} else {
					r.gatewayHostIDToVifs[vif.DeviceID] = mapset.NewSet(vif)
				}
			}
		default:
			filter = false
		}
		if filter {
			r.deviceVifs = append(r.deviceVifs, vif)
		}
	}
}

func (r *PlatformRawData) ConvertDBVM(dbDataCache *DBDataCache) {
	vms := dbDataCache.GetVms()
	if vms == nil {
		return
	}
	for _, vm := range vms {
		r.idToVM[vm.ID] = vm
		r.vmIDs.Add(vm.ID)
		if vmIDs, ok := r.serverToVmIDs[vm.LaunchServer]; ok {
			vmIDs.Add(vm.ID)
		} else {
			r.serverToVmIDs[vm.LaunchServer] = mapset.NewSet(vm.ID)
		}
		typeIDKey := TypeIDKey{
			Type: VIF_DEVICE_TYPE_VM,
			ID:   vm.ID,
		}
		if deviceIPs, ok := r.vpcIDToDeviceIPs[vm.VPCID]; ok == false {
			r.vpcIDToDeviceIPs[vm.VPCID] = make(map[TypeIDKey]mapset.Set)
			r.vpcIDToDeviceIPs[vm.VPCID][typeIDKey] = mapset.NewSet()
		} else {
			deviceIPs[typeIDKey] = mapset.NewSet()
		}

		key := DomainIPKey{
			Domain: vm.Domain,
			IP:     vm.LaunchServer,
		}
		hostID, ok := r.domainIpToHostID[key]
		if ok == false {
			hostID = 0
		}
		r.typeIDToDevice[typeIDKey] = &TypeIDData{
			LaunchServer:   vm.LaunchServer,
			LaunchServerID: hostID,
			AZ:             vm.AZ,
			VPCID:          vm.VPCID,
			Type:           VIF_DEVICE_TYPE_VM,
		}
	}
}

func (r *PlatformRawData) ConvertDBVRouter(dbDataCache *DBDataCache) {
	vRouters := dbDataCache.GetVRouters()
	if vRouters == nil {
		return
	}
	for _, vRouter := range vRouters {
		r.vRouterIDs.Add(vRouter.ID)
		if _, ok := r.launchServerToVRouterIDs[vRouter.GWLaunchServer]; ok {
			r.launchServerToVRouterIDs[vRouter.GWLaunchServer] = append(
				r.launchServerToVRouterIDs[vRouter.GWLaunchServer], vRouter.ID)
		} else {
			r.launchServerToVRouterIDs[vRouter.GWLaunchServer] = []int{vRouter.ID}
		}
		typeIDKey := TypeIDKey{
			Type: VIF_DEVICE_TYPE_VROUTER,
			ID:   vRouter.ID,
		}
		if deviceIPs, ok := r.vpcIDToDeviceIPs[vRouter.VPCID]; ok == false {
			r.vpcIDToDeviceIPs[vRouter.VPCID] = make(map[TypeIDKey]mapset.Set)
			r.vpcIDToDeviceIPs[vRouter.VPCID][typeIDKey] = mapset.NewSet()
		} else {
			deviceIPs[typeIDKey] = mapset.NewSet()
		}

		key := DomainIPKey{
			Domain: vRouter.Domain,
			IP:     vRouter.GWLaunchServer,
		}
		hostID, ok := r.domainIpToHostID[key]
		if ok == false {
			hostID = 0
		}
		r.typeIDToDevice[typeIDKey] = &TypeIDData{
			LaunchServer:   vRouter.GWLaunchServer,
			LaunchServerID: hostID,
			AZ:             vRouter.AZ,
			VPCID:          vRouter.VPCID,
			Type:           VIF_DEVICE_TYPE_VROUTER,
		}
	}
}

func (r *PlatformRawData) ConvertDBDHCPPort(dbDataCache *DBDataCache) {
	dhcpPorts := dbDataCache.GetDhcpPorts()
	if dhcpPorts == nil {
		return
	}
	for _, dhcpPort := range dhcpPorts {
		r.dhcpPortIDs.Add(dhcpPort.ID)
		typeIDKey := TypeIDKey{
			Type: VIF_DEVICE_TYPE_DHCP_PORT,
			ID:   dhcpPort.ID,
		}
		if deviceIPs, ok := r.vpcIDToDeviceIPs[dhcpPort.VPCID]; ok == false {
			r.vpcIDToDeviceIPs[dhcpPort.VPCID] = make(map[TypeIDKey]mapset.Set)
			r.vpcIDToDeviceIPs[dhcpPort.VPCID][typeIDKey] = mapset.NewSet()
		} else {
			deviceIPs[typeIDKey] = mapset.NewSet()
		}

		az := ""
		if vpc, ok := r.idToVPC[dhcpPort.VPCID]; ok {
			az = vpc.AZ
		}
		r.typeIDToDevice[typeIDKey] = &TypeIDData{
			LaunchServer:   "",
			LaunchServerID: 0,
			AZ:             az,
			VPCID:          dhcpPort.VPCID,
			Type:           VIF_DEVICE_TYPE_DHCP_PORT,
		}
	}
}

func (r *PlatformRawData) GetContainers(vtapID int) []*trident.Container {
	return r.vtapIDToContainer[vtapID]
}

func (r *PlatformRawData) addContainers(pod *models.Pod) {
	if pod.ContainerIDs == "" {
		return
	}
	vtap, ok := r.launchServerIDToVTap[pod.PodNodeID]
	for _, cid := range strings.Split(pod.ContainerIDs, ", ") {
		r.containerIdToPodId[cid] = pod.ID
		if ok {
			container := &trident.Container{
				PodId:       proto.Uint32(uint32(pod.ID)),
				ContainerId: proto.String(cid),
			}
			r.vtapIDToContainer[vtap.ID] = append(r.vtapIDToContainer[vtap.ID], container)
		}
	}
}

func (r *PlatformRawData) ConvertDBPod(dbDataCache *DBDataCache) {
	pods := dbDataCache.GetPods()
	if pods == nil {
		return
	}
	for _, pod := range pods {
		r.addContainers(pod)
		r.idToPod[pod.ID] = pod
		r.podIDs.Add(pod.ID)
		podIDs, ok := r.podNodeIDtoPodIDs[pod.PodNodeID]
		if ok {
			podIDs.Add(pod.ID)
		} else {
			r.podNodeIDtoPodIDs[pod.PodNodeID] = mapset.NewSet(pod.ID)
		}
		typeIDKey := TypeIDKey{
			Type: VIF_DEVICE_TYPE_POD,
			ID:   pod.ID,
		}
		deviceIPs, ok := r.vpcIDToDeviceIPs[pod.VPCID]
		if ok == false {
			r.vpcIDToDeviceIPs[pod.VPCID] = make(map[TypeIDKey]mapset.Set)
			r.vpcIDToDeviceIPs[pod.VPCID][typeIDKey] = mapset.NewSet()
		} else {
			deviceIPs[typeIDKey] = mapset.NewSet()
		}

		r.typeIDToDevice[typeIDKey] = &TypeIDData{
			LaunchServerID: pod.PodNodeID,
			AZ:             pod.AZ,
			VPCID:          pod.VPCID,
			PodGroupID:     pod.PodGroupID,
			PodClusterID:   pod.PodClusterID,
			PodNodeID:      pod.PodNodeID,
			PodNamespaceID: pod.PodNamespaceID,
			PodID:          pod.ID,
			Type:           VIF_DEVICE_TYPE_POD,
		}
	}
}

func (r *PlatformRawData) ConvertDBVPC(dbDataCache *DBDataCache) {
	vpcs := dbDataCache.GetVPCs()
	if vpcs == nil {
		return
	}
	for _, vpc := range vpcs {
		r.idToVPC[vpc.ID] = vpc
		r.vpcIDs.Add(vpc.ID)
		r.tunnelIDs.Add(vpc.TunnelID)
	}
}

func (r *PlatformRawData) ConvertDBIPs(dbDataCache *DBDataCache) {
	wanIPs := dbDataCache.GetWANIPs()
	for _, wanIP := range wanIPs {
		r.vifIDsOfWANIP.Add(wanIP.VInterfaceID)
		r.ipsOfWANIP.Add(wanIP.IP)
		if _, ok := r.VInterfaceIDToWANIP[wanIP.VInterfaceID]; ok {
			r.VInterfaceIDToWANIP[wanIP.VInterfaceID] = append(r.VInterfaceIDToWANIP[wanIP.VInterfaceID], wanIP)
		} else {
			r.VInterfaceIDToWANIP[wanIP.VInterfaceID] = []*models.WANIP{wanIP}
		}

		if wanIP.VInterfaceID == 0 {
			r.noVInterfaceIDIPs = append(r.noVInterfaceIDIPs, &IPData{IP: wanIP.IP, Domain: wanIP.Domain})
		} else {

			ipReource := generateProtoIpResource(wanIP.IP, uint32(wanIP.Netmask), 0)
			if _, ok := r.vInterfaceIDToIP[wanIP.VInterfaceID]; ok {
				r.vInterfaceIDToIP[wanIP.VInterfaceID] = append(r.vInterfaceIDToIP[wanIP.VInterfaceID], ipReource)
			} else {
				r.vInterfaceIDToIP[wanIP.VInterfaceID] = []*trident.IpResource{ipReource}
			}
			sipReource := ipReource
			if _, ok := r.vInterfaceIDToSimpleIP[wanIP.VInterfaceID]; ok {
				r.vInterfaceIDToSimpleIP[wanIP.VInterfaceID] = append(r.vInterfaceIDToSimpleIP[wanIP.VInterfaceID], sipReource)
			} else {
				r.vInterfaceIDToSimpleIP[wanIP.VInterfaceID] = []*trident.IpResource{sipReource}
			}
		}
	}

	lanIPs := dbDataCache.GetLANIPs()
	for _, lanIP := range lanIPs {
		r.vifIDsOfLANIP.Add(lanIP.VInterfaceID)
		r.ipsOfLANIP.Add(lanIP.IP)
		if _, ok := r.VInterfaceIDToLANIP[lanIP.VInterfaceID]; ok {
			r.VInterfaceIDToLANIP[lanIP.VInterfaceID] = append(r.VInterfaceIDToLANIP[lanIP.VInterfaceID], lanIP)
		} else {
			r.VInterfaceIDToLANIP[lanIP.VInterfaceID] = []*models.LANIP{lanIP}
		}

		if lanIP.VInterfaceID == 0 {
			r.noVInterfaceIDIPs = append(r.noVInterfaceIDIPs, &IPData{IP: lanIP.IP, Domain: lanIP.Domain})
		} else {
			ipReource := generateProtoIpResource(lanIP.IP, 0, uint32(lanIP.NetworkID))
			if _, ok := r.vInterfaceIDToIP[lanIP.VInterfaceID]; ok {
				r.vInterfaceIDToIP[lanIP.VInterfaceID] = append(r.vInterfaceIDToIP[lanIP.VInterfaceID], ipReource)
			} else {
				r.vInterfaceIDToIP[lanIP.VInterfaceID] = []*trident.IpResource{ipReource}
			}

			sipReource := generateProtoIpResource(lanIP.IP, 0, 0)
			if _, ok := r.vInterfaceIDToSimpleIP[lanIP.VInterfaceID]; ok {
				r.vInterfaceIDToSimpleIP[lanIP.VInterfaceID] = append(r.vInterfaceIDToSimpleIP[lanIP.VInterfaceID], sipReource)
			} else {
				r.vInterfaceIDToSimpleIP[lanIP.VInterfaceID] = []*trident.IpResource{sipReource}
			}
		}
	}

	for _, device := range r.vpcIDToDeviceIPs {
		for key, value := range device {
			vInterfaceIDs, ok := r.deviceTypeAndIDToVInterfaceID[key]
			if ok {
				for _, vInterfaceID := range vInterfaceIDs {
					lanIPs, ok := r.VInterfaceIDToLANIP[vInterfaceID]
					if ok {
						for _, lanIP := range lanIPs {
							if strings.Contains(lanIP.IP, ":") {
								value.Add(lanIP.IP + "/128")
							} else {
								value.Add(lanIP.IP + "/32")
							}
						}
					}
					wanIPs, ok := r.VInterfaceIDToWANIP[vInterfaceID]
					if ok {
						for _, wanIP := range wanIPs {
							if strings.Contains(wanIP.IP, ":") {
								value.Add(wanIP.IP + "/128")
							} else {
								value.Add(wanIP.IP + "/32")
							}
						}
					}
				}
			}
		}
	}

	floatingIPs := dbDataCache.GetFloatingIPs()
	for _, fip := range floatingIPs {
		r.vmIDsOfFIP.Add(fip.VMID)
		r.floatingIPs[fip.ID] = &IPData{IP: fip.IP, VPCID: fip.VPCID, Domain: fip.Domain}
		vmidFips, ok := r.vpcIDToVmidFips[fip.VPCID]
		if ok == false {
			r.vpcIDToVmidFips[fip.VPCID] = make(map[int][]string)
			r.vpcIDToVmidFips[fip.VPCID][fip.VMID] = []string{fip.IP + "/32"}
		} else {
			if _, ok := vmidFips[fip.VMID]; ok {
				vmidFips[fip.VMID] = append(vmidFips[fip.VMID], fip.IP+"/32")
			} else {
				vmidFips[fip.VMID] = []string{fip.IP + "/32"}
			}
		}
	}
}

func (r *PlatformRawData) ConvertHost(dbDataCache *DBDataCache) {
	hosts := dbDataCache.GetHostDevices()
	if hosts == nil {
		return
	}
	for _, host := range hosts {
		r.idToHost[host.ID] = host
		key := DomainIPKey{
			Domain: host.Domain,
			IP:     host.IP,
		}
		r.domainIpToHostID[key] = host.ID

		typeIDKey := TypeIDKey{
			Type: VIF_DEVICE_TYPE_HOST,
			ID:   host.ID,
		}
		r.typeIDToDevice[typeIDKey] = &TypeIDData{
			LaunchServer:   host.IP,
			LaunchServerID: host.ID,
			AZ:             host.AZ,
			Type:           VIF_DEVICE_TYPE_HOST,
		}
		if host.HType == HOST_HTYPE_GATEWAY {
			r.gatewayHostIDs = append(r.gatewayHostIDs, host.ID)
		}
	}
}

func (r *PlatformRawData) ConvertDBNetwork(dbDataCache *DBDataCache) {
	networks := dbDataCache.GetNetworks()
	for _, network := range networks {
		r.idToNetwork[network.ID] = network
	}

	subnets := dbDataCache.GetSubnets()
	for _, subnet := range subnets {
		r.subnetPrefix = append(r.subnetPrefix, subnet.Prefix)
		r.subnetMask = append(r.subnetMask, subnet.Netmask)
		if _, ok := r.networkIDToSubnets[subnet.NetworkID]; ok {
			r.networkIDToSubnets[subnet.NetworkID] = append(r.networkIDToSubnets[subnet.NetworkID], subnet)
		} else {
			r.networkIDToSubnets[subnet.NetworkID] = []*models.Subnet{subnet}
		}
	}
}

func (r *PlatformRawData) ConvertDBRegion(dbDataCache *DBDataCache) {
	regions := dbDataCache.GetRegions()
	for _, region := range regions {
		r.uuidToRegion[region.Lcuuid] = region
		r.regionUUIDs.Add(region.Lcuuid)
	}
}

func (r *PlatformRawData) ConvertDBAZ(dbDataCache *DBDataCache) {
	azs := dbDataCache.GetAZs()
	if azs == nil {
		return
	}
	for _, az := range azs {
		r.uuidToAZ[az.Lcuuid] = az
		r.azUUIDs.Add(az.Lcuuid)
	}
}

func (r *PlatformRawData) ConvertDBPeerConnection(dbDataCache *DBDataCache) {
	peerConnections := dbDataCache.GetPeerConnections()
	if peerConnections == nil {
		return
	}
	for _, pc := range peerConnections {
		r.peerConnIDs.Add(pc.ID)
	}
}

func (r *PlatformRawData) ConvertDBCEN(dbDataCache *DBDataCache) {
	cens := dbDataCache.GetCENs()
	if cens == nil {
		return
	}
	for _, cen := range cens {
		r.cenIDs.Add(cen.ID)
	}
}

func (r *PlatformRawData) ConvertDBPodService(dbDataCache *DBDataCache) {
	podServices := dbDataCache.GetPodServices()
	if podServices == nil {
		return
	}
	for _, ps := range podServices {
		r.idToPodService[ps.ID] = ps
		r.podServiceIDs.Add(ps.ID)
		typeIDKey := TypeIDKey{
			Type: VIF_DEVICE_TYPE_POD_SERVICE,
			ID:   ps.ID,
		}
		r.typeIDToDevice[typeIDKey] = &TypeIDData{
			LaunchServer:   "",
			LaunchServerID: 0,
			VPCID:          ps.VPCID,
			AZ:             ps.AZ,
			PodClusterID:   ps.PodClusterID,
			PodNamespaceID: ps.PodNamespaceID,
			Type:           VIF_DEVICE_TYPE_POD_SERVICE,
		}
	}
}

func (r *PlatformRawData) ConvertDBPodGroup(dbDataCache *DBDataCache) {
	podGroups := dbDataCache.GetPodGroups()
	if podGroups == nil {
		return
	}
	for _, pg := range podGroups {
		r.idToPodGroup[pg.ID] = pg
		r.podGroupIDs.Add(pg.ID)
	}
}

func (r *PlatformRawData) ConvertDBPodServicePort(dbDataCache *DBDataCache) {
	podServicePorts := dbDataCache.GetPodServicePorts()
	if podServicePorts == nil {
		return
	}
	for _, psPort := range podServicePorts {
		r.podServicePortIDs.Add(psPort.ID)
		if _, ok := r.podServiceIDToPorts[psPort.PodServiceID]; ok {
			r.podServiceIDToPorts[psPort.PodServiceID] = append(
				r.podServiceIDToPorts[psPort.PodServiceID], psPort)
		} else {
			r.podServiceIDToPorts[psPort.PodServiceID] = []*models.PodServicePort{psPort}
		}
	}
}

func (r *PlatformRawData) ConvertDBRedisInstance(dbDataCache *DBDataCache) {
	redisInstances := dbDataCache.GetRedisInstances()
	if redisInstances == nil {
		return
	}
	for _, redisInstance := range redisInstances {
		r.redisInstanceIDs.Add(redisInstance.ID)
		typeIDKey := TypeIDKey{
			Type: VIF_DEVICE_TYPE_REDIS_INSTANCE,
			ID:   redisInstance.ID,
		}
		r.typeIDToDevice[typeIDKey] = &TypeIDData{
			LaunchServer:   "",
			LaunchServerID: 0,
			AZ:             redisInstance.AZ,
			VPCID:          redisInstance.VPCID,
			Type:           VIF_DEVICE_TYPE_REDIS_INSTANCE,
		}
	}
}

func (r *PlatformRawData) ConvertDBRdsInstance(dbDataCache *DBDataCache) {
	rdsInstances := dbDataCache.GetRdsInstances()
	if rdsInstances == nil {
		return
	}
	for _, rdsInstance := range rdsInstances {
		r.rdsInstanceIDs.Add(rdsInstance.ID)
		typeIDKey := TypeIDKey{
			Type: VIF_DEVICE_TYPE_RDS_INSTANCE,
			ID:   rdsInstance.ID,
		}
		r.typeIDToDevice[typeIDKey] = &TypeIDData{
			LaunchServer:   "",
			LaunchServerID: 0,
			AZ:             rdsInstance.AZ,
			VPCID:          rdsInstance.VPCID,
			Type:           VIF_DEVICE_TYPE_RDS_INSTANCE,
		}
	}
}

func (r *PlatformRawData) ConvertDBPodNode(dbDataCache *DBDataCache) {
	podNodes := dbDataCache.GetPodNodes()
	if podNodes == nil {
		return
	}
	for _, podNode := range podNodes {
		r.podNodeIDs.Add(podNode.ID)
		r.idToPodNode[podNode.ID] = podNode

		typeIDKey := TypeIDKey{
			Type: VIF_DEVICE_TYPE_POD_NODE,
			ID:   podNode.ID,
		}
		r.typeIDToDevice[typeIDKey] = &TypeIDData{
			LaunchServer:   "",
			LaunchServerID: podNode.ID,
			AZ:             podNode.AZ,
			VPCID:          podNode.VPCID,
			PodClusterID:   podNode.PodClusterID,
			PodNodeID:      podNode.ID,
			Type:           VIF_DEVICE_TYPE_POD_NODE,
		}
	}
}

func (r *PlatformRawData) ConvertDBPodGroupPort(dbDataCache *DBDataCache) {
	podGroupPorts := dbDataCache.GetPodGroupPorts()
	if podGroupPorts == nil {
		return
	}
	for _, podGroupPort := range podGroupPorts {
		portIDs, ok := r.podServiceIDToPodGroupPortIDs[podGroupPort.PodServiceID]
		if ok {
			portIDs.Add(podGroupPort.ID)
		} else {
			r.podServiceIDToPodGroupPortIDs[podGroupPort.PodServiceID] = mapset.NewSet(podGroupPort.ID)
		}

		_, ok = r.podServiceIDToPodGroupPorts[podGroupPort.PodServiceID]
		if ok {
			r.podServiceIDToPodGroupPorts[podGroupPort.PodServiceID] = append(
				r.podServiceIDToPodGroupPorts[podGroupPort.PodServiceID], podGroupPort)
			portIDs.Add(podGroupPort.ID)
		} else {
			r.podServiceIDToPodGroupPorts[podGroupPort.PodServiceID] = []*models.PodGroupPort{podGroupPort}
		}
	}
}

func (r *PlatformRawData) ConvertDBLB(dbDataCache *DBDataCache) {
	lbs := dbDataCache.GetLBs()
	if lbs == nil {
		return
	}
	for _, lb := range lbs {
		r.lbIDs.Add(lb.ID)
		typeIDKey := TypeIDKey{
			Type: VIF_DEVICE_TYPE_LB,
			ID:   lb.ID,
		}
		r.typeIDToDevice[typeIDKey] = &TypeIDData{
			LaunchServer:   "",
			LaunchServerID: 0,
			AZ:             "",
			VPCID:          lb.VPCID,
			Type:           VIF_DEVICE_TYPE_LB,
		}
	}
}

func (r *PlatformRawData) ConvertDBNat(dbDataCache *DBDataCache) {
	nats := dbDataCache.GetNats()
	if nats == nil {
		return
	}
	for _, nat := range nats {
		r.natIDs.Add(nat.ID)
		typeIDKey := TypeIDKey{
			Type: VIF_DEVICE_TYPE_NAT_GATEWAY,
			ID:   nat.ID,
		}
		r.typeIDToDevice[typeIDKey] = &TypeIDData{
			LaunchServer:   "",
			LaunchServerID: 0,
			AZ:             "",
			VPCID:          nat.VPCID,
			Type:           VIF_DEVICE_TYPE_NAT_GATEWAY,
		}
	}
}

func (r *PlatformRawData) GetPodNodeIDToVmID() map[int]int {
	return r.podNodeIDToVmID
}

func (r *PlatformRawData) ConvertDBVmPodNodeConn(dbDataCache *DBDataCache) {
	vmPodNodeConns := dbDataCache.GetVmPodNodeConns()
	if vmPodNodeConns == nil {
		return
	}
	for _, conn := range vmPodNodeConns {
		r.vmIDToPodNodeID[conn.VMID] = conn.PodNodeID
		r.podNodeIDToVmID[conn.PodNodeID] = conn.VMID
	}
}

func (r *PlatformRawData) ConvertDBVipDomain(dbDataCache *DBDataCache) {
	vipDomains := dbDataCache.GetVipDomains()
	if vipDomains == nil {
		return
	}
	for _, vipDomain := range vipDomains {
		r.vipDomainLcuuids.Add(vipDomain.Lcuuid)
	}
}

func (r *PlatformRawData) ConvertSkipVTapVIfIDs(dbDataCache *DBDataCache) {
	kvmLaunchServer := mapset.NewSet()
	vtapLaunchServer := make(map[string][]int)
	skipVTaps := dbDataCache.GetSkipVTaps()
	for _, vtap := range skipVTaps {
		switch vtap.Type {
		case VTAP_TYPE_KVM:
			kvmLaunchServer.Add(vtap.LaunchServer)
		case VTAP_TYPE_WORKLOAD_V:
			vm, ok := r.idToVM[vtap.LaunchServerID]
			if ok == false {
				break
			}
			if vm.LaunchServer != "" {
				if _, ok := vtapLaunchServer[vm.LaunchServer]; ok {
					vtapLaunchServer[vm.LaunchServer] = append(
						vtapLaunchServer[vm.LaunchServer], vm.ID)
				} else {
					vtapLaunchServer[vm.LaunchServer] = []int{vm.ID}
				}
			}
		case VTAP_TYPE_POD_VM:
			vmid, ok := r.podNodeIDToVmID[vtap.LaunchServerID]
			if ok == false {
				break
			}
			vm, ok := r.idToVM[vmid]
			if ok == false {
				break
			}
			if vm.LaunchServer != "" {
				if _, ok := vtapLaunchServer[vm.LaunchServer]; ok {
					vtapLaunchServer[vm.LaunchServer] = append(
						vtapLaunchServer[vm.LaunchServer], vm.ID)
				} else {
					vtapLaunchServer[vm.LaunchServer] = []int{vm.ID}
				}
			}
		}
	}

	skipLaunchServerToVMIDs := make(map[string][]int)
	skipVMIDs := []int{}
	for launchServer, vmIDs := range vtapLaunchServer {
		if kvmLaunchServer.Contains(launchServer) {
			if _, ok := skipLaunchServerToVMIDs[launchServer]; ok {
				skipLaunchServerToVMIDs[launchServer] = append(
					skipLaunchServerToVMIDs[launchServer], vmIDs...)
			} else {
				skipLaunchServerToVMIDs[launchServer] = vmIDs[:]
			}
			skipVMIDs = append(skipVMIDs, vmIDs...)
		}
	}

	skipPodNodeIDs := []int{}
	for _, vmID := range skipVMIDs {
		if podNodeID, ok := r.vmIDToPodNodeID[vmID]; ok {
			skipPodNodeIDs = append(skipPodNodeIDs, podNodeID)
		}
	}

	vmIDToPodNodeAllVifs := newIDToVifs()
	for _, podNodeID := range skipPodNodeIDs {
		podnode, ok := r.idToPodNode[podNodeID]
		if ok == false {
			continue
		}
		podnodeID := podnode.ID
		vmID, ok := r.podNodeIDToVmID[podnodeID]
		if ok == false {
			continue
		}
		if vifs, ok := r.podNodeIDToVifs[podnodeID]; ok {
			vmIDToPodNodeAllVifs.add(vmID, vifs)
		}
		if podIDs, ok := r.podNodeIDtoPodIDs[podnodeID]; ok {
			for podID := range podIDs.Iter() {
				id := podID.(int)
				if vifs, ok := r.podIDToVifs[id]; ok {
					vmIDToPodNodeAllVifs.add(vmID, vifs)
				}
			}
		}
	}

	launchServerToSkipVifMacs := make(map[string]mapset.Set)
	for launchServer, vmIDs := range skipLaunchServerToVMIDs {
		for _, vmID := range vmIDs {
			vmVifs, ok := r.vmIDToVifs[vmID]
			if ok == false {
				continue
			}
			for vmVif := range vmVifs.Iter() {
				vif := vmVif.(*models.VInterface)
				if vif.Mac == "00:00:00:00:00:00" {
					continue
				}
				macU64, err := MacStrToU64(vif.Mac)
				if err != nil {
					log.Error(r.Logf("%s %s", err, vif.Mac))
					continue
				}
				if skipVifMacs, ok := launchServerToSkipVifMacs[launchServer]; ok {
					skipVifMacs.Add(macU64)
				} else {
					launchServerToSkipVifMacs[launchServer] = mapset.NewSet(macU64)
				}
			}
			podVifs, ok := vmIDToPodNodeAllVifs[vmID]
			if ok == false {
				continue
			}
			for podVif := range podVifs.Iter() {
				vif := podVif.(*models.VInterface)
				if vif.Mac == "00:00:00:00:00:00" {
					continue
				}
				macU64, err := MacStrToU64(vif.Mac)
				if err != nil {
					log.Error(r.Logf("%s %s", err, vif.Mac))
					continue
				}
				if skipVifMacs, ok := launchServerToSkipVifMacs[launchServer]; ok {
					skipVifMacs.Add(macU64)
				} else {
					launchServerToSkipVifMacs[launchServer] = mapset.NewSet(macU64)
				}
			}
		}
	}

	launchServerToSkipInterface := make(map[string][]*trident.SkipInterface)
	for launchServer, skipVifMacs := range launchServerToSkipVifMacs {
		for mac := range skipVifMacs.Iter() {
			macU64 := mac.(uint64)
			skipInterface := &trident.SkipInterface{
				Mac: proto.Uint64(macU64),
			}
			launchServerToSkipInterface[launchServer] = append(
				launchServerToSkipInterface[launchServer], skipInterface)
		}
	}
	r.launchServerToSkipInterface = launchServerToSkipInterface
	log.Debug(r.Logf("%s", r.launchServerToSkipInterface))
}

func (r *PlatformRawData) ConvertDBProcesses(dbDataCache *DBDataCache) {
	processes := dbDataCache.GetProcesses()
	if processes == nil {
		return
	}
	for _, process := range processes {
		r.processIDs.Add(process.ID)
	}
}

func (r *PlatformRawData) ConvertDBVIPs(dbDataCache *DBDataCache) {
	vips := dbDataCache.GetVIPs()
	if vips == nil {
		return
	}
	for _, vip := range vips {
		r.vipIDs.Add(vip.ID)

		vtap := r.GetVTap(int(vip.VTapID))
		if vtap == nil {
			continue
		}
		vifs, ok := r.vmIDToVifs[vtap.LaunchServerID]
		if ok == false {
			continue
		}

		for vmVif := range vifs.Iter() {
			vif := vmVif.(*models.VInterface)
			r.isVifofVip[vif.ID] = struct{}{}
			if network, ok := r.idToNetwork[vif.NetworkID]; ok {
				r.vipIDToNetwork[vip.ID] = network
			}
		}
	}
}

func (r *PlatformRawData) ConvertDBVTaps(dbDataCache *DBDataCache) {
	for _, vtap := range dbDataCache.GetVTapsIDAndName() {
		if vtap.Type == VTAP_TYPE_POD_HOST || vtap.Type == VTAP_TYPE_POD_VM {
			r.launchServerIDToVTap[vtap.LaunchServerID] = vtap
		}
		r.vtapIdToVtap[vtap.ID] = vtap
	}
}

// 有依赖 需要按顺序convert
func (r *PlatformRawData) ConvertDBCache(dbDataCache *DBDataCache) {
	r.ConvertDBVTaps(dbDataCache)
	r.ConvertDBVIPs(dbDataCache)
	r.ConvertHost(dbDataCache)
	r.ConvertDBVPC(dbDataCache)
	r.ConvertDBVM(dbDataCache)
	r.ConvertDBVRouter(dbDataCache)
	r.ConvertDBDHCPPort(dbDataCache)
	r.ConvertDBPod(dbDataCache)
	r.ConvertDBVInterface(dbDataCache)
	r.ConvertDBIPs(dbDataCache)
	r.ConvertDBNetwork(dbDataCache)
	r.ConvertDBRegion(dbDataCache)
	r.ConvertDBAZ(dbDataCache)
	r.ConvertDBPeerConnection(dbDataCache)
	r.ConvertDBCEN(dbDataCache)
	r.ConvertDBPodService(dbDataCache)
	r.ConvertDBPodGroup(dbDataCache)
	r.ConvertDBPodServicePort(dbDataCache)
	r.ConvertDBRedisInstance(dbDataCache)
	r.ConvertDBRdsInstance(dbDataCache)
	r.ConvertDBPodNode(dbDataCache)
	r.ConvertDBPodGroupPort(dbDataCache)
	r.ConvertDBLB(dbDataCache)
	r.ConvertDBNat(dbDataCache)
	r.ConvertDBVmPodNodeConn(dbDataCache)
	r.ConvertDBVipDomain(dbDataCache)
	r.ConvertSkipVTapVIfIDs(dbDataCache)
	r.ConvertDBProcesses(dbDataCache)
}

func (r *PlatformRawData) checkVifIsVip(vif *models.VInterface) bool {
	_, ok := r.isVifofVip[vif.ID]
	return ok
}

func (r *PlatformRawData) checkIsVip(ip string, vif *models.VInterface, platformVips []string) bool {
	if Contains(platformVips, ip) == true {
		return true
	}

	if vif == nil {
		return false
	}
	if r.checkVifIsVip(vif) == true {
		return true
	}
	switch vif.DeviceType {
	case VIF_DEVICE_TYPE_LB, VIF_DEVICE_TYPE_NAT_GATEWAY:
		if r.vipDomainLcuuids.Contains(vif.Domain) {
			return true
		}

	default:
		return false
	}

	return false
}

func (r *PlatformRawData) vInterfaceToProto(
	vif *models.VInterface, device *TypeIDData, ipResourceData *IpResourceData) (*InterfaceProto, error) {

	regionID := 0
	if region, ok := r.uuidToRegion[vif.Region]; ok {
		regionID = region.ID
	}
	azID := 0
	if az, ok := r.uuidToAZ[device.AZ]; ok {
		azID = az.ID
	}
	vpcID := 0
	if vif.DeviceType != VIF_DEVICE_TYPE_HOST {
		vpcID = device.VPCID
	} else {
		if vl2, ok := r.idToNetwork[vif.NetworkID]; ok {
			vpcID = vl2.VPCID
		} else {
			errorInfo := fmt.Sprintf("VIF(id:%d, mac:%s) not found vl2(id:%d)", vif.ID, vif.Mac, vif.NetworkID)
			return nil, errors.New(errorInfo)
		}
	}
	macU64, err := MacStrToU64(vif.Mac)
	if err != nil {
		log.Error(r.Logf("%s %s", err, vif.Mac))
	}
	podGroupType := uint32(0)
	podGroup := r.idToPodGroup[device.PodGroupID]
	if podGroup != nil {
		podGroupType = PodGroupTypeMap[podGroup.Type]
	}
	aInterface := &trident.Interface{
		Id:             proto.Uint32(uint32(vif.ID)),
		Mac:            proto.Uint64(macU64),
		DeviceType:     proto.Uint32(uint32(vif.DeviceType)),
		DeviceId:       proto.Uint32(uint32(vif.DeviceID)),
		IfType:         proto.Uint32(uint32(vif.Type)),
		EpcId:          proto.Uint32(uint32(vpcID)),
		LaunchServer:   proto.String(device.LaunchServer),
		LaunchServerId: proto.Uint32(uint32(device.LaunchServerID)),
		IpResources:    ipResourceData.ipResources,
		RegionId:       proto.Uint32(uint32(regionID)),
		AzId:           proto.Uint32(uint32(azID)),
		PodGroupId:     proto.Uint32(uint32(device.PodGroupID)),
		PodNsId:        proto.Uint32(uint32(device.PodNamespaceID)),
		PodClusterId:   proto.Uint32(uint32(device.PodClusterID)),
		PodNodeId:      proto.Uint32(uint32(device.PodNodeID)),
		PodId:          proto.Uint32(uint32(device.PodID)),
		IsVipInterface: proto.Bool(ipResourceData.isVipInterface),
		NetnsId:        proto.Uint32(vif.NetnsID),
		VtapId:         proto.Uint32(vif.VtapID),
		PodGroupType:   proto.Uint32(podGroupType),
	}
	sInterface := &trident.Interface{
		Id:             proto.Uint32(uint32(vif.ID)),
		Mac:            proto.Uint64(macU64),
		DeviceType:     proto.Uint32(uint32(vif.DeviceType)),
		EpcId:          proto.Uint32(uint32(vpcID)),
		IfType:         proto.Uint32(uint32(vif.Type)),
		IpResources:    ipResourceData.simpleIpResources,
		RegionId:       proto.Uint32(uint32(regionID)),
		PodClusterId:   proto.Uint32(uint32(device.PodClusterID)),
		PodNodeId:      proto.Uint32(uint32(device.PodNodeID)),
		IsVipInterface: proto.Bool(ipResourceData.isVipInterface),
	}

	return &InterfaceProto{aInterface: aInterface, sInterface: sInterface}, nil
}

func (r *PlatformRawData) modifyInterfaceProto(
	vif *models.VInterface, interfaceProto *InterfaceProto, device *TypeIDData) error {

	aInterface := interfaceProto.aInterface
	sInterface := interfaceProto.sInterface
	switch vif.DeviceType {
	case VIF_DEVICE_TYPE_POD, VIF_DEVICE_TYPE_POD_NODE:
		if vmID, ok := r.podNodeIDToVmID[device.PodNodeID]; ok {
			aInterface.DeviceType = proto.Uint32(uint32(VIF_DEVICE_TYPE_VM))
			aInterface.DeviceId = proto.Uint32(uint32(vmID))
			typeIDKey := TypeIDKey{
				Type: VIF_DEVICE_TYPE_VM,
				ID:   vmID,
			}
			vmDevice, ok := r.typeIDToDevice[typeIDKey]
			if ok == false {
				errorInfo := fmt.Sprintf("VIF(%s %s) not found vm", vif.Lcuuid, vif.Mac)
				return errors.New(errorInfo)
			}
			aInterface.LaunchServer = proto.String(vmDevice.LaunchServer)
			aInterface.LaunchServerId = proto.Uint32(uint32(vmDevice.LaunchServerID))
		} else {
			aInterface.DeviceType = proto.Uint32(uint32(0))
			aInterface.DeviceId = proto.Uint32(uint32(0))
			aInterface.LaunchServer = proto.String("")
			aInterface.LaunchServerId = proto.Uint32(uint32(0))
		}
	case VIF_DEVICE_TYPE_VM:
		if PodNodeID, ok := r.vmIDToPodNodeID[vif.DeviceID]; ok {
			typeIDKey := TypeIDKey{
				Type: VIF_DEVICE_TYPE_POD_NODE,
				ID:   PodNodeID,
			}
			podNodeDeivce, ok := r.typeIDToDevice[typeIDKey]
			if ok == false {
				errorInfo := fmt.Sprintf("VIF (%s %s) not found pod_node", vif.Lcuuid, vif.Mac)
				return errors.New(errorInfo)
			}
			sInterface.PodNodeId = proto.Uint32(uint32(PodNodeID))
			sInterface.PodClusterId = proto.Uint32(uint32(podNodeDeivce.PodClusterID))
			aInterface.PodNodeId = proto.Uint32(uint32(PodNodeID))
			aInterface.PodClusterId = proto.Uint32(uint32(podNodeDeivce.PodClusterID))
		}
	}

	return nil
}

func (r *PlatformRawData) generateIpResoureceData(
	vif *models.VInterface, vifPubIps []string, platformVips []string) (*IpResourceData, []string) {

	ipResources := []*trident.IpResource{}
	simpleIpResources := []*trident.IpResource{}
	isVipInterface := false

	// 云私有云中虚拟机上用于容器的hostnic网卡也会返回IP，在此将其忽略避免一个IP对应两块网卡
	if vif.Name == "" || strings.HasPrefix(strings.ToLower(vif.Name), "hostnic") == false {
		if ips, ok := r.vInterfaceIDToIP[vif.ID]; ok {
			for _, ipResource := range ips {
				isVipInterface = r.checkIsVip(ipResource.GetIp(), vif, platformVips)
				if ipResource.GetSubnetId() == 0 {
					ipResource.SubnetId = proto.Uint32(uint32(vif.NetworkID))
				}
				ipResources = append(ipResources, ipResource)
				if vif.Type == VIF_TYPE_WAN {
					vifPubIps = append(vifPubIps, ipResource.GetIp())
				}
			}
		}
		if ips, ok := r.vInterfaceIDToSimpleIP[vif.ID]; ok {
			for _, ipResource := range ips {
				isVipInterface = r.checkIsVip(ipResource.GetIp(), vif, platformVips)
				simpleIpResources = append(simpleIpResources, ipResource)
			}
		}
	}

	ipResourceData := &IpResourceData{
		ipResources:       ipResources,
		simpleIpResources: simpleIpResources,
		isVipInterface:    isVipInterface,
	}

	return ipResourceData, vifPubIps
}

func (r *PlatformRawData) GetIDToNetwork() map[int]*models.Network {
	return r.idToNetwork
}

func (r *PlatformRawData) GetHostIDToVifs() map[int]mapset.Set {
	return r.hostIDToVifs
}

func (r *PlatformRawData) GetServerToVmIDs() map[string]mapset.Set {
	return r.serverToVmIDs
}

func (r *PlatformRawData) GetVMIDToPodNodeID() map[int]int {
	return r.vmIDToPodNodeID
}

func (r *PlatformRawData) GetPodNode(podNodeID int) *models.PodNode {
	return r.idToPodNode[podNodeID]
}

func (r *PlatformRawData) GetPodGroup(podGroupID int) *models.PodGroup {
	return r.idToPodGroup[podGroupID]
}

func (r *PlatformRawData) GetPod(podID int) *models.Pod {
	return r.idToPod[podID]
}

func (r *PlatformRawData) GetSkipInterface(server string) []*trident.SkipInterface {
	if result, ok := r.launchServerToSkipInterface[server]; ok {
		return result
	}

	return nil
}

func (r *PlatformRawData) GetVTap(vtapID int) *models.VTap {
	return r.vtapIdToVtap[vtapID]
}

func (r *PlatformRawData) equal(o *PlatformRawData) bool {
	if !r.vmIDs.Equal(o.vmIDs) {
		log.Info(r.Log("platform vm changed"))
		return false
	}

	if !r.vRouterIDs.Equal(o.vRouterIDs) {
		log.Info(r.Log("platform vrouter changed"))
		return false
	}

	if !r.dhcpPortIDs.Equal(o.dhcpPortIDs) {
		log.Info(r.Log("platform dhcp_port changed"))
		return false
	}
	if !r.podIDs.Equal(o.podIDs) {
		log.Info(r.Log("platform pod changed"))
		return false
	}

	if len(r.idToNetwork) != len(o.idToNetwork) {
		log.Info(r.Log("platform network changed"))
		return false
	} else {
		for id, rnetwork := range r.idToNetwork {
			if onetwork, ok := o.idToNetwork[id]; ok {
				if rnetwork.NetType != onetwork.NetType {
					log.Info(r.Log("platform network changed"))
					return false
				}
			} else {
				log.Info(r.Log("platform network changed"))
				return false
			}
		}
	}

	if !SliceEqual[string](r.subnetPrefix, o.subnetPrefix) {
		log.Info(r.Log("platform subnet changed"))
		return false
	}

	if !SliceEqual[string](r.subnetMask, o.subnetMask) {
		log.Info(r.Log("platform subnet changed"))
		return false
	}

	if !r.vpcIDs.Equal(o.vpcIDs) {
		log.Info(r.Log("platform vpc changed"))
		return false
	}

	if !r.tunnelIDs.Equal(o.tunnelIDs) {
		log.Info(r.Log("platform vpc tunnel_id changed"))
		return false
	}

	if !r.vifIDsOfLANIP.Equal(o.vifIDsOfLANIP) {
		log.Info(r.Log("platform lan vifs changed"))
		return false
	}

	if !r.vifIDsOfWANIP.Equal(o.vifIDsOfWANIP) {
		log.Info(r.Log("platform wan vifs changed"))
		return false
	}

	if !r.ipsOfLANIP.Equal(o.ipsOfLANIP) {
		log.Info(r.Log("platform lan ips changed"))
		return false
	}

	if !r.ipsOfWANIP.Equal(o.ipsOfWANIP) {
		log.Info(r.Log("platform wan ips changed"))
		return false
	}

	if !r.vmIDsOfFIP.Equal(o.vmIDsOfFIP) {
		log.Info(r.Log("platform floating ips changed"))
		return false
	}

	if !r.regionUUIDs.Equal(o.regionUUIDs) {
		log.Info(r.Log("platform region changed"))
		return false
	}

	if !r.azUUIDs.Equal(o.azUUIDs) {
		log.Info(r.Log("platform az changed"))
		return false
	}

	if !r.peerConnIDs.Equal(o.peerConnIDs) {
		log.Info(r.Log("platform peer_connections changed"))
		return false
	}

	if !r.cenIDs.Equal(o.cenIDs) {
		log.Info(r.Log("platform cens changed"))
		return false
	}

	if len(r.serverToVmIDs) != len(o.serverToVmIDs) {
		log.Info(r.Log("platform vms launch_server changed"))
		return false
	} else {
		for server, vmIDs := range r.serverToVmIDs {
			if ovmIDs, ok := o.serverToVmIDs[server]; ok {
				if !vmIDs.Equal(ovmIDs) {
					log.Info(r.Log("platform vms launch_server changed"))
					return false
				}
			} else {
				log.Info(r.Log("platform vms launch_server changed"))
				return false
			}
		}
	}

	if len(r.floatingIPs) != len(o.floatingIPs) {
		log.Info(r.Log("platform floating_ip changed"))
		return false
	} else {
		for fID, fIP := range r.floatingIPs {
			if ofIP, ok := o.floatingIPs[fID]; ok {
				if *fIP != *ofIP {
					log.Info(r.Log("platform floating_ip changed"))
					return false
				}
			} else {
				log.Info(r.Log("platform floating_ip changed"))
				return false
			}
		}
	}

	if !r.podServiceIDs.Equal(o.podServiceIDs) {
		log.Info(r.Log("platform pod service changed"))
		return false
	}

	if !r.podGroupIDs.Equal(o.podGroupIDs) {
		log.Info(r.Log("platform pod group changed"))
		return false
	}

	if !r.redisInstanceIDs.Equal(o.redisInstanceIDs) {
		log.Info(r.Log("platform redis instance changed"))
		return false
	}

	if !r.rdsInstanceIDs.Equal(o.rdsInstanceIDs) {
		log.Info(r.Log("platform rds instance changed"))
		return false
	}

	if !r.podNodeIDs.Equal(o.podNodeIDs) {
		log.Info(r.Log("platform pod node changed"))
		return false
	}

	if !r.lbIDs.Equal(o.lbIDs) {
		log.Info(r.Log("platform lb changed"))
		return false
	}

	if !r.natIDs.Equal(o.natIDs) {
		log.Info(r.Log("platform nat changed"))
		return false
	}

	if len(r.idToHost) != len(o.idToHost) {
		log.Info(r.Log("platform host_device changed"))
		return false
	} else {
		for id, rhost := range r.idToHost {
			if ohost, ok := o.idToHost[id]; ok {
				if rhost.HType != ohost.HType {
					log.Info(r.Log("platform host_device changed"))
					return false
				}
			} else {
				log.Info(r.Log("platform host_device changed"))
				return false
			}
		}
	}

	if !r.podServicePortIDs.Equal(o.podServicePortIDs) {
		log.Info(r.Log("platform pod service ports changed"))
		return false
	}

	if !r.processIDs.Equal(o.processIDs) {
		log.Info(r.Log("platform processes changed"))
		return false
	}

	if !r.vipIDs.Equal(o.vipIDs) {
		log.Info(r.Log("vip changed"))
		return false
	}

	if len(r.podServiceIDToPodGroupPortIDs) != len(o.podServiceIDToPodGroupPortIDs) {
		log.Info(r.Log("platform pod service pod group ports changed"))
		return false
	} else {
		for podServiceID, rpodGroupPortIDs := range r.podServiceIDToPodGroupPortIDs {
			if opodGroupPortIDs, ok := o.podServiceIDToPodGroupPortIDs[podServiceID]; ok {
				if !rpodGroupPortIDs.Equal(opodGroupPortIDs) {
					log.Info(r.Log("platform pod service pod group ports changed"))
					return false
				}
			} else {
				log.Info(r.Log("platform pod service pod group ports changed"))
				return false
			}
		}
	}

	if len(r.vmIDToPodNodeID) != len(o.vmIDToPodNodeID) {
		log.Info(r.Log("platform vm pod_node connection changed"))
		return false
	} else {
		for rvmID, rpodNodeID := range r.vmIDToPodNodeID {
			if opodNodeID, ok := o.vmIDToPodNodeID[rvmID]; ok {
				if rpodNodeID != opodNodeID {
					log.Info(r.Log("platform vm pod_node connection changed"))
					return false
				}
			} else {
				log.Info(r.Log("platform vm pod_node connection changed"))
				return false
			}
		}
	}

	if !r.vipDomainLcuuids.Equal(o.vipDomainLcuuids) {
		log.Info(r.Log("platform vip domains changed"))
		return false
	}

	if len(r.gatewayHostIDToVifs) != len(o.gatewayHostIDToVifs) {
		log.Info(r.Log("platform gateway host vinterface changed"))
		return false
	} else {
		for id, vif := range r.gatewayHostIDToVifs {
			if ovif, ok := o.gatewayHostIDToVifs[id]; ok {
				if !vif.Equal(ovif) {
					log.Info(r.Log("platform gateway host vinterface changed"))
					return false
				}
			} else {
				log.Info(r.Log("platform gateway host vinterface changed"))
				return false
			}
		}
	}

	return true
}
