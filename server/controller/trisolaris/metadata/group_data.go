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
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	mapset "github.com/deckarep/golang-set"
	"github.com/deepflowio/deepflow/message/trident"
	. "github.com/deepflowio/deepflow/server/controller/common"
	models "github.com/deepflowio/deepflow/server/controller/db/mysql"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/common"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
	"github.com/golang/protobuf/proto"
)

type GroupRawData struct {
	idToGroup              map[int]*models.ResourceGroup
	dropletGroups          []*models.ResourceGroup
	tridentGroups          []*models.ResourceGroup
	pgidToVifIDs           map[int][]int
	groupIDToIPs           map[int]*GroupIP
	groupIDToPodServiceIDs map[int][]int
}

func newGroupRawData() *GroupRawData {
	return &GroupRawData{
		idToGroup:              make(map[int]*models.ResourceGroup),
		dropletGroups:          make([]*models.ResourceGroup, 0),
		tridentGroups:          make([]*models.ResourceGroup, 0),
		pgidToVifIDs:           make(map[int][]int),
		groupIDToIPs:           make(map[int]*GroupIP),
		groupIDToPodServiceIDs: make(map[int][]int),
	}
}

type GroupProto struct {
	groupVersion uint64
	groups       *atomic.Value // []byte
	groupHash    uint64
	startTime    int64
}

func newGroupProto() *GroupProto {
	groups := &atomic.Value{}
	groups.Store([]byte{})
	return &GroupProto{
		groupVersion: 0,
		groups:       groups,
		groupHash:    0,
	}
}

func (g *GroupProto) String() string {
	return fmt.Sprintf("groupVersion: %d, groupHash: %d, dataLen: %d", g.groupVersion,
		g.groupHash, len(g.getGroups()))
}

func (g *GroupProto) checkVersion(groupHash uint64) {
	if g.groupHash != groupHash {
		g.groupHash = groupHash
		if g.groupVersion == 0 {
			g.groupVersion = uint64(g.startTime)
		} else {
			atomic.AddUint64(&g.groupVersion, 1)
		}
		log.Infof("group data changed to %s", g)
	}
}

func (g *GroupProto) getVersion() uint64 {
	return atomic.LoadUint64(&g.groupVersion)
}

func (g *GroupProto) getGroups() []byte {
	return g.groups.Load().([]byte)
}

func (g *GroupProto) updateGroups(groups []byte) {
	g.groups.Store(groups)
}

func (g *GroupProto) generateGroupProto(groupsProto []*trident.Group, svcs []*trident.ServiceInfo) {
	groups := &trident.Groups{
		Groups: groupsProto,
		Svcs:   svcs,
	}
	groupBytes, err := groups.Marshal()
	if err == nil {
		g.updateGroups(groupBytes)
		h64 := fnv.New64()
		h64.Write(groupBytes)
		g.checkVersion(h64.Sum64())
	} else {
		log.Error(err)
	}
}

type GroupDataOP struct {
	metaData          *MetaData
	serviceDataOP     *ServiceDataOP
	groupRawData      *GroupRawData
	tridentGroupProto *GroupProto
	dropletGroupProto *GroupProto
}

func newGroupDataOP(metaData *MetaData) *GroupDataOP {
	return &GroupDataOP{
		groupRawData:      newGroupRawData(),
		serviceDataOP:     newServiceDataOP(metaData),
		metaData:          metaData,
		tridentGroupProto: newGroupProto(),
		dropletGroupProto: newGroupProto(),
	}
}

var tridentGroup = []int{NPB_BUSINESS_ID, PCAP_BUSINESS_ID}

type GroupIP struct {
	cidrs    []string
	ipRanges []string
}

func (g *GroupDataOP) SetStartTime(startTime int64) {
	g.tridentGroupProto.startTime = startTime
	g.dropletGroupProto.startTime = startTime
}

func (g *GroupDataOP) GetIDToGroup() map[int]*models.ResourceGroup {
	return g.groupRawData.idToGroup
}

func (g *GroupDataOP) GetGroupIDToPodServiceIDs() map[int][]int {
	return g.groupRawData.groupIDToPodServiceIDs
}

func (g *GroupDataOP) getTridentGroups() []byte {
	return g.tridentGroupProto.getGroups()
}

func (g *GroupDataOP) getTridentGroupsVersion() uint64 {
	return g.tridentGroupProto.getVersion()
}

func (g *GroupDataOP) getDropletGroups() []byte {
	return g.dropletGroupProto.getGroups()
}

func (g *GroupDataOP) getDropletGroupsVersion() uint64 {
	return g.dropletGroupProto.getVersion()
}

// The data traversal must be kept in order to ensure
// that the calculation hash is consistent when the data is unchanged
func (g *GroupDataOP) generateGroupRawData() {
	dbDataCache := g.metaData.GetDBDataCache()

	podServiceIDToPodGroupIDs := make(map[int][]int)
	for _, podGroupPort := range dbDataCache.GetPodGroupPorts() {
		if _, ok := podServiceIDToPodGroupIDs[podGroupPort.PodServiceID]; ok {
			podServiceIDToPodGroupIDs[podGroupPort.PodServiceID] = append(
				podServiceIDToPodGroupIDs[podGroupPort.PodServiceID], podGroupPort.PodGroupID)
		} else {
			podServiceIDToPodGroupIDs[podGroupPort.PodServiceID] = []int{podGroupPort.PodGroupID}
		}
	}

	groupIDsUsedByNpbPcap := mapset.NewSet()
	for _, acl := range dbDataCache.GetACLs() {
		if Find[int](tridentGroup, acl.BusinessID) {
			if acl.SrcGroupIDs != "" {
				id, err := strconv.Atoi(acl.SrcGroupIDs)
				if err == nil {
					groupIDsUsedByNpbPcap.Add(id)
				} else {
					log.Error(err)
				}
			}
			if acl.DstGroupIDs != "" {
				id, err := strconv.Atoi(acl.DstGroupIDs)
				if err == nil {
					groupIDsUsedByNpbPcap.Add(id)
				} else {
					log.Error(err)
				}
			}
		}
	}

	idToExtraInfo := make(map[int]*models.ResourceGroupExtraInfo)
	resourceGroupExtraInfos := dbDataCache.GetResourceGroupExtraInfos()
	for _, resourceGroupExtraInfo := range resourceGroupExtraInfos {
		idToExtraInfo[resourceGroupExtraInfo.ID] = resourceGroupExtraInfo
	}

	podGroupIDs := mapset.NewSet()
	podIDs := mapset.NewSet()
	groupIDToPodGroupIDs := make(map[int][]int)
	groupIDToPodIDs := make(map[int][]int)
	groupIDToPodServiceIDs := make(map[int][]int)
	resourceGroups := dbDataCache.GetResourceGroups()
	tridentGroups := make([]*models.ResourceGroup, 0, len(resourceGroups))
	dropletGroups := make([]*models.ResourceGroup, 0, len(resourceGroups))
	idToGroup := make(map[int]*models.ResourceGroup)
	for _, resourceGroup := range resourceGroups {
		idToGroup[resourceGroup.ID] = resourceGroup
		if Find[int](tridentGroup, resourceGroup.BusinessID) && groupIDsUsedByNpbPcap.Contains(resourceGroup.ID) {
			tridentGroups = append(tridentGroups, resourceGroup)
		}
		dropletGroups = append(dropletGroups, resourceGroup)
		if resourceGroup.ExtraInfoIDs != "" {
			ids := strings.Split(resourceGroup.ExtraInfoIDs, ",")
			for _, id := range ids {
				idInt, err := strconv.Atoi(id)
				if err != nil {
					log.Error(err)
					continue
				}
				extraInfo, ok := idToExtraInfo[idInt]
				if ok == false {
					log.Errorf("resourceGroup(id=%d) did not find extra_info(id:%d)", resourceGroup.ID, idInt)
					continue
				}
				switch resourceGroup.Type {
				case RESOURCE_GROUP_TYPE_ANONYMOUS_POD_GROUP:
					podGroupIDs.Add(extraInfo.ResourceID)
					if _, ok := groupIDToPodGroupIDs[resourceGroup.ID]; ok {
						groupIDToPodGroupIDs[resourceGroup.ID] = append(
							groupIDToPodGroupIDs[resourceGroup.ID], extraInfo.ResourceID)
					} else {
						groupIDToPodGroupIDs[resourceGroup.ID] = []int{extraInfo.ResourceID}
					}
				case RESOURCE_GROUP_TYPE_ANONYMOUS_POD_SERVICE, RESOURCE_GROUP_TYPE_ANONYMOUS_POD_GROUP_AS_POD_SERVICE:
					if ids, ok := podServiceIDToPodGroupIDs[extraInfo.ResourceID]; ok {
						newPodGroupIDs := mapset.NewSet()
						for _, id := range ids {
							newPodGroupIDs.Add(id)
						}
						podGroupIDs = podGroupIDs.Union(newPodGroupIDs)
					}
					if _, ok := groupIDToPodServiceIDs[resourceGroup.ID]; ok {
						groupIDToPodServiceIDs[resourceGroup.ID] = append(
							groupIDToPodServiceIDs[resourceGroup.ID], extraInfo.ResourceID)
					} else {
						groupIDToPodServiceIDs[resourceGroup.ID] = []int{extraInfo.ResourceID}
					}
				case RESOURCE_GROUP_TYPE_ANONYMOUS_POD:
					podIDs.Add(extraInfo.ResourceID)
					if _, ok := groupIDToPodIDs[resourceGroup.ID]; ok {
						groupIDToPodIDs[resourceGroup.ID] = append(
							groupIDToPodIDs[resourceGroup.ID], extraInfo.ResourceID)
					} else {
						groupIDToPodIDs[resourceGroup.ID] = []int{extraInfo.ResourceID}
					}
				}
			}
		}
	}

	pgidToPids := make(map[int][]int)
	groupPodIDs := mapset.NewSet()
	for _, pod := range dbDataCache.GetPods() {
		if podGroupIDs.Contains(pod.PodGroupID) {
			groupPodIDs.Add(pod.ID)
			if _, ok := pgidToPids[pod.PodGroupID]; ok {
				pgidToPids[pod.PodGroupID] = append(
					pgidToPids[pod.PodGroupID], pod.ID)
			} else {
				pgidToPids[pod.PodGroupID] = []int{pod.ID}
			}
		}
	}

	allPodVifs := mapset.NewSet()
	podVifs := mapset.NewSet()
	pidToVifIDs := make(map[int][]int)
	for _, vif := range dbDataCache.GetVInterfaces() {
		if vif.DeviceType == VIF_DEVICE_TYPE_POD &&
			(groupPodIDs.Contains(vif.DeviceID) || podIDs.Contains(vif.DeviceID)) {
			podVifs.Add(vif.ID)
			if _, ok := pidToVifIDs[vif.DeviceID]; ok {
				pidToVifIDs[vif.DeviceID] = append(
					pidToVifIDs[vif.DeviceID], vif.ID)
			} else {
				pidToVifIDs[vif.DeviceID] = []int{vif.ID}
			}
		}
		if vif.DeviceType == VIF_DEVICE_TYPE_POD || vif.DeviceType == VIF_DEVICE_TYPE_POD_SERVICE {
			if vif.NetworkID != 0 && vif.Type == VIF_TYPE_LAN {
				allPodVifs.Add(vif.ID)
			}
		}
	}

	vifidToIPs := make(map[int][]string)
	for _, lanIP := range dbDataCache.GetLANIPs() {
		if allPodVifs.Contains(lanIP.VInterfaceID) {
			if _, ok := vifidToIPs[lanIP.VInterfaceID]; ok {
				vifidToIPs[lanIP.VInterfaceID] = append(
					vifidToIPs[lanIP.VInterfaceID], lanIP.IP)
			} else {
				vifidToIPs[lanIP.VInterfaceID] = []string{lanIP.IP}
			}
		}
	}

	pgidToVifIDs := make(map[int][]int)
	for pgid, pids := range pgidToPids {
		vifIDs := []int{}
		for _, pid := range pids {
			vifids := pidToVifIDs[pid]
			if len(vifids) > 0 {
				vifIDs = append(vifIDs, vifids...)
			}
		}
		pgidToVifIDs[pgid] = vifIDs
	}

	pgidToIPs := make(map[int][]string)
	for pgid, vifids := range pgidToVifIDs {
		ips := []string{}
		for _, vifid := range vifids {
			if tips, ok := vifidToIPs[vifid]; ok {
				ips = append(ips, tips...)
			}
		}
		pgidToIPs[pgid] = ips
	}

	podClusterIDToPodNodeIPs := make(map[int][]string)
	for _, podNode := range dbDataCache.GetPodNodes() {
		if podNode.IP != "" {
			if _, ok := podClusterIDToPodNodeIPs[podNode.PodClusterID]; ok {
				podClusterIDToPodNodeIPs[podNode.PodClusterID] = append(
					podClusterIDToPodNodeIPs[podNode.PodClusterID], podNode.IP)
			}
		}
	}

	rawData := g.metaData.GetPlatformDataOP().GetRawData()
	groupIDToIPs := make(map[int]*GroupIP)
	for _, resourceGroup := range dbDataCache.GetResourceGroups() {
		var ips, ipRange []string
		switch resourceGroup.Type {
		case RESOURCE_GROUP_TYPE_VM, RESOURCE_GROUP_TYPE_ANONYMOUS_VM:
			if resourceGroup.VMIDs != "" {
				vmIDs := strings.Split(resourceGroup.VMIDs, ",")
				for _, vmID := range vmIDs {
					id, err := strconv.Atoi(vmID)
					if err != nil {
						log.Error(err)
						continue
					}
					if vpcData, ok := rawData.vpcIDToDeviceIPs[resourceGroup.VPCID]; ok {
						typeIDKey := TypeIDKey{
							Type: VIF_DEVICE_TYPE_VM,
							ID:   id,
						}
						if vpcIPs, ok := vpcData[typeIDKey]; ok {
							for ip := range vpcIPs.Iter() {
								ips = append(ips, ip.(string))
							}
						}
						// Keep data in order
						sort.Strings(ips)
					}
					if vpcData, ok := rawData.vpcIDToVmidFips[resourceGroup.VPCID]; ok {
						if vpcIPs, ok := vpcData[id]; ok {
							for _, ip := range vpcIPs {
								ips = append(ips, ip)
							}
						}
					}
				}
			} else {
				ips = append(ips, "0.0.0.0/0")
				ips = append(ips, "::/0")
			}
		case RESOURCE_GROUP_TYPE_ANONYMOUS_POD:
			for _, podID := range groupIDToPodIDs[resourceGroup.ID] {
				if vifIDs, ok := pidToVifIDs[podID]; ok {
					for _, vifID := range vifIDs {
						if tips, ok := vifidToIPs[vifID]; ok {
							ips = append(ips, tips...)
						}
					}
				}
			}
		case RESOURCE_GROUP_TYPE_ANONYMOUS_POD_GROUP:
			for _, podGroupID := range groupIDToPodGroupIDs[resourceGroup.ID] {
				if tips, ok := pgidToIPs[podGroupID]; ok {
					ips = append(ips, tips...)
				}
			}
		case RESOURCE_GROUP_TYPE_ANONYMOUS_POD_SERVICE:
			for _, podServiceID := range groupIDToPodServiceIDs[resourceGroup.ID] {
				if podService, ok := rawData.idToPodService[podServiceID]; ok {
					if podService.ServiceClusterIP == "" {
						podGroupIDs := podServiceIDToPodGroupIDs[podService.ID]
						for _, podGroupID := range podGroupIDs {
							if tips, ok := pgidToIPs[podGroupID]; ok {
								ips = append(ips, tips...)
							}
						}
					} else {
						ips = append(ips, podService.ServiceClusterIP)
						if podService.Type == POD_SERVICE_TYPE_NODE_PORT {
							if nodeIPs, ok := podClusterIDToPodNodeIPs[podService.PodClusterID]; ok {
								ips = append(ips, nodeIPs...)
							}
						}
					}
				}
			}
		case RESOURCE_GROUP_TYPE_ANONYMOUS_POD_GROUP_AS_POD_SERVICE:
			for _, podServiceID := range groupIDToPodServiceIDs[resourceGroup.ID] {
				if podService, ok := rawData.idToPodService[podServiceID]; ok {
					for _, podGroupID := range podServiceIDToPodGroupIDs[podService.ID] {
						if tips, ok := pgidToIPs[podGroupID]; ok {
							ips = append(ips, tips...)
						}
					}
				}
			}
		case RESOURCE_GROUP_TYPE_ANONYMOUS_VL2:
			nets := []*models.Subnet{}
			if resourceGroup.NetworkIDs != "" {
				strNetworkIDs := strings.Split(resourceGroup.NetworkIDs, ",")
				for _, strNetworkID := range strNetworkIDs {
					id, err := strconv.Atoi(strNetworkID)
					if err != nil {
						log.Error(err)
						continue
					}
					if tnets, ok := rawData.networkIDToSubnets[id]; ok {
						nets = append(nets, tnets...)
					}
				}
				for _, net := range nets {
					netmask := netmask2masklen(net.Netmask)
					if judgeNet(net.Prefix, netmask) == true {
						ips = append(ips, fmt.Sprintf("%s/%d", net.Prefix, netmask))
					}
				}
			}

		default:
			if resourceGroup.IPs != "" {
				for _, ip := range strings.Split(resourceGroup.IPs, ",") {
					if strings.Contains(ip, "-") {
						ipRange = append(ipRange, ip)
					} else {
						ips = append(ips, ip)
					}
				}
			}
		}
		// convert ip. for example:
		// 10.10.10.10 -> 10.10.10.10/32
		ConvertToCIDR(ips)
		groupIDToIPs[resourceGroup.ID] = &GroupIP{
			cidrs:    ips,
			ipRanges: ipRange,
		}
	}
	groupRawData := newGroupRawData()
	groupRawData.groupIDToIPs = groupIDToIPs
	groupRawData.dropletGroups = dropletGroups
	groupRawData.tridentGroups = tridentGroups
	groupRawData.idToGroup = idToGroup
	groupRawData.groupIDToPodServiceIDs = groupIDToPodServiceIDs
	g.groupRawData = groupRawData
}

func (g *GroupDataOP) generateResourceGroupData(groups []*models.ResourceGroup) []*trident.Group {
	named := trident.GroupType_NAMED
	anonymous := trident.GroupType_ANONYMOUS
	defaultGroup := &trident.Group{
		Id:    proto.Uint32(INTERNET_RESOURCE_GROUP_ID_UINT32),
		Type:  &named,
		EpcId: proto.Uint32(INTERNET_EPC_ID_UINT32),
		Ips:   []string{"0.0.0.0/0", "::/0"},
	}
	resGroups := []*trident.Group{defaultGroup}
	groupIDToIPs := g.groupRawData.groupIDToIPs
	for _, group := range groups {
		groupType := named
		if group.Type == RESOURCE_GROUP_TYPE_NONE {
			continue
		}
		groupIP, ok := groupIDToIPs[group.ID]
		if ok == false {
			continue
		}
		switch group.Type {
		case RESOURCE_GROUP_TYPE_ANONYMOUS_VM, RESOURCE_GROUP_TYPE_ANONYMOUS_IP,
			RESOURCE_GROUP_TYPE_ANONYMOUS_VL2, RESOURCE_GROUP_TYPE_ANONYMOUS_POD_GROUP,
			RESOURCE_GROUP_TYPE_ANONYMOUS_POD_SERVICE,
			RESOURCE_GROUP_TYPE_ANONYMOUS_POD_GROUP_AS_POD_SERVICE:

			groupType = anonymous
		}
		rg := &trident.Group{
			Id:       proto.Uint32(uint32(group.ID)),
			EpcId:    proto.Uint32(uint32(group.VPCID)),
			Type:     &groupType,
			IpRanges: groupIP.ipRanges,
			Ips:      groupIP.cidrs,
		}
		resGroups = append(resGroups, rg)
	}

	return resGroups
}

func (g *GroupDataOP) generateTridentGroupProto() {
	g.tridentGroupProto.generateGroupProto(
		g.generateResourceGroupData(g.groupRawData.tridentGroups), nil)
}

func (g *GroupDataOP) generateDropletGroupProto() {
	g.dropletGroupProto.generateGroupProto(
		g.generateResourceGroupData(g.groupRawData.dropletGroups),
		g.serviceDataOP.GetServiceData())
}

func (g *GroupDataOP) generateGroupData() {
	g.serviceDataOP.GenerateServiceData()
	g.generateGroupRawData()
	g.generateTridentGroupProto()
	g.generateDropletGroupProto()
}
