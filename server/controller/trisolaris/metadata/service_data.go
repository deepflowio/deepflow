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
	"fmt"
	"slices"
	"strconv"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/golang/protobuf/proto"

	"github.com/deepflowio/deepflow/message/trident"
	. "github.com/deepflowio/deepflow/server/controller/common"
	models "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/dbcache"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
)

type ServiceRawData struct {
	podServiceIDToPodServicePorts map[int][]*models.PodServicePort
	podGroupIDToPodGroupPorts     map[int][]*models.PodGroupPort
	podGroupIDToPodServiceID      map[int]int
	podGroupIDToVPCID             map[int]int
	podGroupIDToNodeIPs           map[int][]string
	podServicePortToPodServiceIDs map[int][]int
	lbIDToVPCID                   map[int]int
	customServiceIDToIPPorts      map[int]mapset.Set[customServiceIPPortKey]
	customServiceIDToResourceIDs  map[int][]uint32
}

type customServiceIPPortKey struct {
	vpcID int
	ip    string
	port  uint32 // 0 表示无端口
}

func (k customServiceIPPortKey) ipKey() string {
	return fmt.Sprintf("%d:%s", k.vpcID, k.ip)
}

func newCustomServiceIPPortKey(vpcID int, ip string, port uint32) customServiceIPPortKey {
	return customServiceIPPortKey{
		vpcID: vpcID,
		ip:    ip,
		port:  port,
	}
}

func newCustomSvcRcsKey() *customServiceResourceKey {
	return &customServiceResourceKey{}
}

type customServiceResourceKey struct {
	name           string
	uid            string
	vpcID          int
	podNamespaceID int
}

func (k *customServiceResourceKey) value() customServiceResourceKey {
	return *k
}

func (k *customServiceResourceKey) copyObject() *customServiceResourceKey {
	return &customServiceResourceKey{
		name:           k.name,
		uid:            k.uid,
		vpcID:          k.vpcID,
		podNamespaceID: k.podNamespaceID,
	}
}

func (k *customServiceResourceKey) setName(name string) *customServiceResourceKey {
	k.name = name
	return k
}

func (k *customServiceResourceKey) setUID(uid string) *customServiceResourceKey {
	k.uid = uid
	return k
}

func (k *customServiceResourceKey) setVPCID(vpcID int) *customServiceResourceKey {
	k.vpcID = vpcID
	return k
}

func (k *customServiceResourceKey) setPodNamespaceID(podNamespaceID int) *customServiceResourceKey {
	k.podNamespaceID = podNamespaceID
	return k
}

func newServiceRawData() *ServiceRawData {
	return &ServiceRawData{
		podServiceIDToPodServicePorts: make(map[int][]*models.PodServicePort),
		podGroupIDToPodGroupPorts:     make(map[int][]*models.PodGroupPort),
		podGroupIDToPodServiceID:      make(map[int]int),
		podGroupIDToVPCID:             make(map[int]int),
		podGroupIDToNodeIPs:           make(map[int][]string),
		podServicePortToPodServiceIDs: make(map[int][]int),
		lbIDToVPCID:                   make(map[int]int),
		customServiceIDToIPPorts:      make(map[int]mapset.Set[customServiceIPPortKey]),
		customServiceIDToResourceIDs:  make(map[int][]uint32),
	}
}

type ServiceDataOP struct {
	serviceRawData *ServiceRawData
	metaData       *MetaData
	services       []*trident.ServiceInfo
	ORGID
}

func newServiceDataOP(metaData *MetaData) *ServiceDataOP {
	return &ServiceDataOP{
		serviceRawData: newServiceRawData(),
		metaData:       metaData,
		services:       []*trident.ServiceInfo{},
		ORGID:          metaData.ORGID,
	}
}

func (r *ServiceRawData) ConvertDBData(md *MetaData) {
	dbDataCache := md.GetDBDataCache()

	// generate pod group to node ip relation
	podNodeIDToIP := make(map[int]string)
	podNodeIDToVPCID := make(map[int]int)
	for _, podNode := range dbDataCache.GetPodNodes() {
		podNodeIDToIP[podNode.ID] = podNode.IP
		podNodeIDToVPCID[podNode.ID] = podNode.VPCID
	}
	for _, pod := range dbDataCache.GetPods() {
		// get pod_node IP
		podNodeIP, ok := podNodeIDToIP[pod.PodNodeID]
		if !ok {
			continue
		}
		// get pod_node VPCID
		vpcID, ok := podNodeIDToVPCID[pod.PodNodeID]
		if !ok {
			continue
		}
		r.podGroupIDToVPCID[pod.PodGroupID] = vpcID
		r.podGroupIDToNodeIPs[pod.PodGroupID] = append(
			r.podGroupIDToNodeIPs[pod.PodGroupID], podNodeIP,
		)
	}

	for _, psp := range dbDataCache.GetPodServicePorts() {
		if _, ok := r.podServiceIDToPodServicePorts[psp.PodServiceID]; ok {
			r.podServiceIDToPodServicePorts[psp.PodServiceID] = append(
				r.podServiceIDToPodServicePorts[psp.PodServiceID], psp)
		} else {
			r.podServiceIDToPodServicePorts[psp.PodServiceID] = []*models.PodServicePort{psp}
		}

		if serviceIDs, ok := r.podServicePortToPodServiceIDs[psp.NodePort]; ok {
			if slices.Contains(serviceIDs, psp.PodServiceID) {
				continue
			}
			r.podServicePortToPodServiceIDs[psp.NodePort] = append(
				r.podServicePortToPodServiceIDs[psp.NodePort], psp.PodServiceID)
		} else {
			r.podServicePortToPodServiceIDs[psp.NodePort] = []int{psp.PodServiceID}
		}
	}
	podGroupIDToPodServiceIDs := make(map[int][]int, len(dbDataCache.GetPodGroupPorts()))
	for _, pgp := range dbDataCache.GetPodGroupPorts() {
		if _, ok := r.podGroupIDToPodGroupPorts[pgp.PodGroupID]; ok {
			r.podGroupIDToPodGroupPorts[pgp.PodGroupID] = append(
				r.podGroupIDToPodGroupPorts[pgp.PodGroupID], pgp)
		} else {
			r.podGroupIDToPodGroupPorts[pgp.PodGroupID] = []*models.PodGroupPort{pgp}
		}
		if ids, ok := podGroupIDToPodServiceIDs[pgp.PodGroupID]; ok {
			podGroupIDToPodServiceIDs[pgp.PodGroupID] = append(
				podGroupIDToPodServiceIDs[pgp.PodGroupID], pgp.PodServiceID)
		} else {
			if Find[int](ids, pgp.PodServiceID) != true {
				podGroupIDToPodServiceIDs[pgp.PodGroupID] = []int{pgp.PodServiceID}
			}
		}
	}

	for _, lb := range dbDataCache.GetLBs() {
		r.lbIDToVPCID[lb.ID] = lb.VPCID
	}

	podServiceIDToName := make(map[int]string, len(dbDataCache.GetPodServices()))
	for _, podService := range dbDataCache.GetPodServices() {
		podServiceIDToName[podService.ID] = podService.Name
	}
	podGroupIDToPodServiceID := make(map[int]int, len(podGroupIDToPodServiceIDs))
	for groupId, podServiceIDs := range podGroupIDToPodServiceIDs {
		var (
			minName string
			minID   int
		)
		for _, serviceID := range podServiceIDs {
			name := podServiceIDToName[serviceID]
			if len(name) == 0 {
				continue
			}
			if minName == "" || minName > name {
				minName = name
				minID = serviceID
			}
		}
		podGroupIDToPodServiceID[groupId] = minID
	}
	r.podGroupIDToPodServiceID = podGroupIDToPodServiceID

	r.mergeCustomServices(md, dbDataCache)
}

// IP/PORT 类型 VPC 内去重规则：
// 1. 按照 ip-port 元素去重后，ip-port 绑定第一个遍历到的服务
// 2. 如果存在 ip-port 的 port 为空，则其他 ip-port 都丢弃，只保留这一个值
// mergeCustomServices merges custom services according to the following rules:
// 1. Deduplicate by ip-port, binding each ip-port to the first encountered service.
// 2. If any ip has an empty port, discard all other ports for that ip and keep only the empty-port entry.
func (r *ServiceRawData) mergeCustomServices(md *MetaData, dbDataCache *dbcache.DBDataCache) {
	vmUIDToIDs := make(map[customServiceResourceKey][]int)
	vmNameToIDs := make(map[customServiceResourceKey][]int)
	for _, vm := range dbDataCache.GetVms() {
		uidK := newCustomSvcRcsKey().setVPCID(vm.VPCID).setUID(vm.UID).value()
		nameK := newCustomSvcRcsKey().setVPCID(vm.VPCID).setName(vm.Name).value()
		vmUIDToIDs[uidK] = append(vmUIDToIDs[uidK], vm.ID)
		vmNameToIDs[nameK] = append(vmNameToIDs[nameK], vm.ID)
	}
	podServiceUIDToIDs := make(map[customServiceResourceKey][]int)
	podServiceNameToIDs := make(map[customServiceResourceKey][]int)
	for _, podService := range dbDataCache.GetPodServices() {
		uidK := newCustomSvcRcsKey().setPodNamespaceID(podService.PodNamespaceID).setUID(podService.UID).value()
		nameK := newCustomSvcRcsKey().setPodNamespaceID(podService.PodNamespaceID).setName(podService.Name).value()
		podServiceUIDToIDs[uidK] = append(podServiceUIDToIDs[uidK], podService.ID)
		podServiceNameToIDs[nameK] = append(podServiceNameToIDs[nameK], podService.ID)
	}
	podGroupUIDToIDs := make(map[customServiceResourceKey][]int)
	podGroupNameToIDs := make(map[customServiceResourceKey][]int)
	for _, podGroup := range dbDataCache.GetPodGroups() {
		uidK := newCustomSvcRcsKey().setPodNamespaceID(podGroup.PodNamespaceID).setUID(podGroup.UID).value()
		nameK := newCustomSvcRcsKey().setPodNamespaceID(podGroup.PodNamespaceID).setName(podGroup.Name).value()
		podGroupUIDToIDs[uidK] = append(podGroupUIDToIDs[uidK], podGroup.ID)
		podGroupNameToIDs[nameK] = append(podGroupNameToIDs[nameK], podGroup.ID)
	}
	podUIDToIDs := make(map[customServiceResourceKey][]int)
	podNameToIDs := make(map[customServiceResourceKey][]int)
	for _, pod := range dbDataCache.GetPods() {
		uidK := newCustomSvcRcsKey().setPodNamespaceID(pod.PodNamespaceID).setUID(pod.UID).value()
		nameK := newCustomSvcRcsKey().setPodNamespaceID(pod.PodNamespaceID).setName(pod.Name).value()
		podUIDToIDs[uidK] = append(podUIDToIDs[uidK], pod.ID)
		podNameToIDs[nameK] = append(podNameToIDs[nameK], pod.ID)
	}
	hostUIDToIDs := make(map[customServiceResourceKey][]int)
	hostNameToIDs := make(map[customServiceResourceKey][]int)
	for _, host := range dbDataCache.GetHostDevices() {
		uidK := newCustomSvcRcsKey().setUID(host.UID).value()
		nameK := newCustomSvcRcsKey().setName(host.Name).value()
		hostUIDToIDs[uidK] = append(hostUIDToIDs[uidK], host.ID)
		hostNameToIDs[nameK] = append(hostNameToIDs[nameK], host.ID)
	}
	customServices := dbDataCache.GetCustomServices()
	customServiceIDToIPPorts := make(map[int]mapset.Set[customServiceIPPortKey])
	customServiceIDToResourceIDs := make(map[int][]uint32)

	ipPortKeyToServiceID := make(map[customServiceIPPortKey]int) // 记录每个 ip-port 绑定的服务ID
	hasEmptyPortForIP := make(map[string]bool)                   // 记录每个 VPC 内的 IP 是否有空端口，key格式为 "vpcID:ip"

	for _, cs := range customServices {
		resources := strings.Split(cs.Resources, ",")
		if slices.Contains([]int{
			CUSTOM_SERVICE_TYPE_HOST,
			CUSTOM_SERVICE_TYPE_CHOST,
			CUSTOM_SERVICE_TYPE_POD_SERVICE,
			CUSTOM_SERVICE_TYPE_POD_GROUP,
			CUSTOM_SERVICE_TYPE_POD,
		}, cs.Type) {
			resourceIDs := make([]uint32, 0)
			var resourceIDsMap map[customServiceResourceKey][]int
			switch cs.Type {
			case CUSTOM_SERVICE_TYPE_HOST:
				if cs.MatchType == CUSTOM_SERVICE_MATCH_TYPE_UID {
					resourceIDsMap = hostUIDToIDs
				} else {
					resourceIDsMap = hostNameToIDs
				}
			case CUSTOM_SERVICE_TYPE_CHOST:
				if cs.MatchType == CUSTOM_SERVICE_MATCH_TYPE_UID {
					resourceIDsMap = vmUIDToIDs
				} else {
					resourceIDsMap = vmNameToIDs
				}
			case CUSTOM_SERVICE_TYPE_POD_SERVICE:
				if cs.MatchType == CUSTOM_SERVICE_MATCH_TYPE_UID {
					resourceIDsMap = podServiceUIDToIDs
				} else {
					resourceIDsMap = podServiceNameToIDs
				}
			case CUSTOM_SERVICE_TYPE_POD_GROUP:
				if cs.MatchType == CUSTOM_SERVICE_MATCH_TYPE_UID {
					resourceIDsMap = podGroupUIDToIDs
				} else {
					resourceIDsMap = podGroupNameToIDs
				}
			case CUSTOM_SERVICE_TYPE_POD:
				if cs.MatchType == CUSTOM_SERVICE_MATCH_TYPE_UID {
					resourceIDsMap = podUIDToIDs
				} else {
					resourceIDsMap = podNameToIDs
				}
			default:
				continue
			}

			rscKs := make([]*customServiceResourceKey, 0)
			switch cs.Type {
			case CUSTOM_SERVICE_TYPE_CHOST:
				for _, id := range cs.VPCIDs {
					rscKs = append(rscKs, newCustomSvcRcsKey().setVPCID(id))
				}
			case CUSTOM_SERVICE_TYPE_POD, CUSTOM_SERVICE_TYPE_POD_SERVICE, CUSTOM_SERVICE_TYPE_POD_GROUP:
				for _, id := range cs.PodNamespaceIDs {
					rscKs = append(rscKs, newCustomSvcRcsKey().setPodNamespaceID(id))
				}
			default:
				rscKs = append(rscKs, newCustomSvcRcsKey())
			}
			if len(rscKs) == 0 {
				rscKs = append(rscKs, newCustomSvcRcsKey())
			}

			for _, rscK := range rscKs {
				for _, resource := range resources {
					resource = strings.TrimSpace(resource)
					if resource == "" {
						continue
					}
					copiedRscK := rscK.copyObject()
					if cs.MatchType == CUSTOM_SERVICE_MATCH_TYPE_UID {
						copiedRscK = copiedRscK.setUID(resource)
					} else {
						copiedRscK = copiedRscK.setName(resource)
					}
					if ids, ok := resourceIDsMap[copiedRscK.value()]; ok {
						for _, id := range ids {
							resourceIDs = append(resourceIDs, uint32(id))
						}
					}
				}
			}
			customServiceIDToResourceIDs[cs.ID] = resourceIDs

			continue
		}

		var ipPorts []customServiceIPPortKey
		if len(cs.VPCIDs) != 1 {
			log.Warningf("multi vpcs not supported for ip/port type custom_service (id: %v)", cs.ID)
			continue
		}
		vpcID := cs.VPCIDs[0]
		if cs.Type == CUSTOM_SERVICE_TYPE_IP {
			ips := resources
			for _, ip := range ips {
				ip = strings.TrimSpace(ip)
				if ip == "" {
					continue
				}
				ipPortKey := newCustomServiceIPPortKey(vpcID, ip, 0)
				hasEmptyPortForIP[ipPortKey.ipKey()] = true
				ipPorts = append(ipPorts, ipPortKey)
			}
		} else {
			ipPortStrs := resources
			for _, ipPortStr := range ipPortStrs {
				ipPortStr = strings.TrimSpace(ipPortStr)
				if ipPortStr == "" {
					continue
				}
				separatorIndex := strings.LastIndex(ipPortStr, ":")
				if separatorIndex == -1 {
					log.Warningf("[ORG-%v] invalid ip port format: %s", md.ORGID, ipPortStr)
					continue
				}
				ip := ipPortStr[:separatorIndex]
				portStr := ipPortStr[separatorIndex+1:]
				port, err := strconv.Atoi(portStr)
				if err != nil {
					log.Warningf("[ORG-%v] invalid port format: %s", md.ORGID, portStr)
					continue
				}
				ipPorts = append(ipPorts, newCustomServiceIPPortKey(vpcID, ip, uint32(port)))
			}
		}

		for _, ipPort := range ipPorts {
			// 检查该 ip-port 是否已经被其他服务绑定
			if _, exists := ipPortKeyToServiceID[ipPort]; !exists {
				// 该 ip-port 不存在，绑定到当前服务
				ipPortKeyToServiceID[ipPort] = cs.ID
				if _, ok := customServiceIDToIPPorts[cs.ID]; ok {
					customServiceIDToIPPorts[cs.ID].Add(ipPort)
				} else {
					customServiceIDToIPPorts[cs.ID] = mapset.NewSet[customServiceIPPortKey](ipPort)
				}
			}
			// 如果已经存在，则跳过（按照规则1：绑定第一个遍历到的服务）
		}
	}

	// 按照规则2：如果某个 ip 存在空端口，则该 ip 的其他端口都丢弃，只保留空端口
	for serviceID, ipPorts := range customServiceIDToIPPorts {
		newIPPorts := mapset.NewSet[customServiceIPPortKey]()
		for ipPort := range ipPorts.Iter() {
			if hasEmptyPortForIP[ipPort.ipKey()] {
				// 该 ip 有空端口，只保留空端口的记录
				if ipPort.port == 0 {
					newIPPorts.Add(ipPort)
				}
			} else {
				// 该 ip 没有空端口，保留所有端口
				newIPPorts.Add(ipPort)
			}
		}
		customServiceIDToIPPorts[serviceID] = newIPPorts
	}

	r.customServiceIDToIPPorts = customServiceIDToIPPorts
	r.customServiceIDToResourceIDs = customServiceIDToResourceIDs
}

func (s *ServiceDataOP) updateServiceRawData(serviceRawData *ServiceRawData) {
	s.serviceRawData = serviceRawData
}

func ipToCidr(ip string) string {
	if strings.Contains(ip, "/") {
		return ip
	} else if strings.Contains(ip, ":") {
		return fmt.Sprintf("%s/128", ip)
	} else {
		return fmt.Sprintf("%s/32", ip)
	}

}

var protocol_string_to_int = map[string]trident.ServiceProtocol{
	"ALL":   trident.ServiceProtocol_ANY,
	"HTTP":  trident.ServiceProtocol_TCP_SERVICE,
	"HTTPS": trident.ServiceProtocol_TCP_SERVICE,
	"TCP":   trident.ServiceProtocol_TCP_SERVICE,
	"UDP":   trident.ServiceProtocol_UDP_SERVICE,
}

func getProtocol(protocol string) trident.ServiceProtocol {
	if protocol, ok := protocol_string_to_int[protocol]; ok {
		return protocol
	}
	return trident.ServiceProtocol_ANY
}

func serviceToProto(
	vpcID int, ips []string, protocol trident.ServiceProtocol, serverPorts []uint32,
	serviceType trident.ServiceType, serviceID int) *trident.ServiceInfo {

	return &trident.ServiceInfo{
		EpcId:       proto.Uint32(uint32(vpcID)),
		Ips:         ips,
		Protocol:    &protocol,
		ServerPorts: serverPorts,
		Type:        &serviceType,
		Id:          proto.Uint32(uint32(serviceID)),
	}
}

func podGroupToProto(
	podGroupId int, protocol trident.ServiceProtocol, serverPorts []uint32,
	serviceType trident.ServiceType, serviceID int) *trident.ServiceInfo {

	return &trident.ServiceInfo{
		PodGroupIds: []uint32{uint32(podGroupId)},
		Protocol:    &protocol,
		ServerPorts: serverPorts,
		Type:        &serviceType,
		Id:          proto.Uint32(uint32(serviceID)),
	}
}

func NodeToProto(
	podClusterId int, protocol trident.ServiceProtocol, serverPorts []uint32,
	serviceType trident.ServiceType, serviceID int) *trident.ServiceInfo {

	return &trident.ServiceInfo{
		PodClusterId: proto.Uint32(uint32(podClusterId)),
		Protocol:     &protocol,
		ServerPorts:  serverPorts,
		Type:         &serviceType,
		Id:           proto.Uint32(uint32(serviceID)),
	}
}

type GroupKey struct {
	protocol     trident.ServiceProtocol
	podServiceID int
}

type NodeKey struct {
	podClusterID int
	protocol     trident.ServiceProtocol
	podServiceID int
}

// All traversals are guaranteed to be in order
func (s *ServiceDataOP) generateService() {
	dbDataCache := s.metaData.GetDBDataCache()
	services := []*trident.ServiceInfo{}
	rData := s.serviceRawData
	groupKeys := []GroupKey{}
	for _, podGroup := range dbDataCache.GetPodGroups() {
		ports, ok := rData.podGroupIDToPodGroupPorts[podGroup.ID]
		if ok == false {
			continue
		}
		groupKeys = groupKeys[:0]
		podServiceID := rData.podGroupIDToPodServiceID[podGroup.ID]
		keyToPorts := make(map[GroupKey][]uint32)
		for _, port := range ports {
			key := GroupKey{
				protocol:     getProtocol(port.Protocol),
				podServiceID: podServiceID,
			}
			if ports, ok := keyToPorts[key]; ok {
				if Find[uint32](ports, uint32(port.Port)) != true {
					keyToPorts[key] = append(keyToPorts[key], uint32(port.Port))
				}
			} else {
				groupKeys = append(groupKeys, key)
				keyToPorts[key] = []uint32{uint32(port.Port)}
			}
		}

		for index := range groupKeys {
			if values, ok := keyToPorts[groupKeys[index]]; ok {
				service := podGroupToProto(
					podGroup.ID,
					groupKeys[index].protocol,
					values,
					trident.ServiceType_POD_SERVICE_POD_GROUP,
					groupKeys[index].podServiceID,
				)
				services = append(services, service)
			}
		}

		// if pod_group hostNetwork == true
		// add ServiceType_POD_SERVICE_IP service(vpc_id + node_ips)
		if podGroup.NetworkMode == POD_GROUP_HOST_NETWORK {
			vpcID, ok := rData.podGroupIDToVPCID[podGroup.ID]
			if !ok {
				continue
			}
			nodeIPs, ok := rData.podGroupIDToNodeIPs[podGroup.ID]
			if !ok {
				continue
			}
			for index := range groupKeys {
				if values, ok := keyToPorts[groupKeys[index]]; ok {
					service := serviceToProto(
						vpcID,
						nodeIPs,
						groupKeys[index].protocol,
						values,
						trident.ServiceType_POD_SERVICE_IP,
						podServiceID,
					)
					services = append(services, service)
				}
			}
		}
	}

	nodeKeys := []NodeKey{}
	nodeServiceInfo := make(map[NodeKey][]uint32)
	for _, podService := range dbDataCache.GetPodServices() {
		podServiceports, ok := rData.podServiceIDToPodServicePorts[podService.ID]
		if ok == false {
			continue
		}
		// PodNamespaceID = 0 represent manual exposed service
		if podService.ServiceClusterIP == "" && podService.PodNamespaceID != 0 {
			log.Debugf(s.Logf("pod service(id=%d) has no service_cluster_ip", podService.ID))
			continue
		}
		protocols := []trident.ServiceProtocol{}
		protocolToPorts := make(map[trident.ServiceProtocol][]uint32)
		for _, podServiceport := range podServiceports {
			protocol := getProtocol(podServiceport.Protocol)
			if _, ok := protocolToPorts[protocol]; ok {
				protocolToPorts[protocol] = append(protocolToPorts[protocol], uint32(podServiceport.Port))
			} else {
				protocols = append(protocols, protocol)
				protocolToPorts[protocol] = []uint32{uint32(podServiceport.Port)}
			}
			if podService.Type == POD_SERVICE_TYPE_NODEPORT || podService.Type == POD_SERVICE_TYPE_LOADBALANCER {
				// PodNamespaceID = 0 represent manual exposed service
				if podService.PodNamespaceID == 0 {
					// if port related to multi-service, should use k8S self service id
					serviceIDs, ok := rData.podServicePortToPodServiceIDs[podServiceport.NodePort]
					if ok && len(serviceIDs) > 1 {
						continue
					}
				}
				key := NodeKey{
					podClusterID: podService.PodClusterID,
					protocol:     protocol,
					podServiceID: podServiceport.PodServiceID,
				}
				if _, ok := nodeServiceInfo[key]; ok {
					nodeServiceInfo[key] = append(nodeServiceInfo[key], uint32(podServiceport.NodePort))
				} else {
					nodeKeys = append(nodeKeys, key)
					nodeServiceInfo[key] = []uint32{uint32(podServiceport.NodePort)}
				}
			}
		}

		// PodNamespaceID = 0 represent manual exposed service
		// if PodNamespaceID = 0, should not send clusterIP to ingester
		if podService.PodNamespaceID != 0 {
			ips := []string{podService.ServiceClusterIP}
			for index := range protocols {
				if ports, ok := protocolToPorts[protocols[index]]; ok {
					service := serviceToProto(
						podService.VPCID,
						ips,
						protocols[index],
						ports,
						trident.ServiceType_POD_SERVICE_IP,
						podService.ID,
					)
					services = append(services, service)
				}
			}
		}
	}
	for index := range nodeKeys {
		if values, ok := nodeServiceInfo[nodeKeys[index]]; ok {
			service := NodeToProto(
				nodeKeys[index].podClusterID,
				nodeKeys[index].protocol,
				values,
				trident.ServiceType_POD_SERVICE_NODE,
				nodeKeys[index].podServiceID,
			)
			services = append(services, service)
		}
	}

	for _, lbListener := range dbDataCache.GetLBListeners() {
		vpcID := rData.lbIDToVPCID[lbListener.LBID]
		var ips []string
		if lbListener.IPs != "" {
			ips = strings.Split(lbListener.IPs, ",")
		}
		service := serviceToProto(
			vpcID,
			ips,
			getProtocol(lbListener.Protocol),
			[]uint32{uint32(lbListener.Port)},
			trident.ServiceType_LB_SERVICE,
			lbListener.ID,
		)
		services = append(services, service)
	}

	for _, lbts := range dbDataCache.GetLBTargetServers() {
		vpcID := rData.lbIDToVPCID[lbts.LBID]
		var ips []string
		if lbts.IP == "" {
			log.Debugf(s.Logf("lb_target_server(id=%d) has no ips", lbts.ID))
			continue
		} else {
			ips = []string{lbts.IP}
		}

		service := serviceToProto(
			vpcID,
			ips,
			getProtocol(lbts.Protocol),
			[]uint32{uint32(lbts.Port)},
			trident.ServiceType_LB_SERVICE,
			lbts.LBListenerID,
		)
		services = append(services, service)
	}

	services = append(services, s.mergeCustomServices(dbDataCache)...)

	s.services = services
	log.Debugf(s.Logf("service have %d", len(s.services)))
}

func (s *ServiceDataOP) mergeCustomServices(dbDataCache *dbcache.DBDataCache) []*trident.ServiceInfo {
	var services []*trident.ServiceInfo
	serviceTypeCustomService := trident.ServiceType_CUSTOM_SERVICE

	for _, customService := range dbDataCache.GetCustomServices() {
		if slices.Contains([]int{
			CUSTOM_SERVICE_TYPE_HOST,
			CUSTOM_SERVICE_TYPE_CHOST,
			CUSTOM_SERVICE_TYPE_POD_SERVICE,
			CUSTOM_SERVICE_TYPE_POD_GROUP,
			CUSTOM_SERVICE_TYPE_POD,
		}, customService.Type) {

			service := &trident.ServiceInfo{
				Type: &serviceTypeCustomService,
				Id:   proto.Uint32(uint32(customService.ID)),
				// 已确认，ingester 在打 自定义服务 CUSTOM_SERVICE 标记时，如果给了 ChostIds PodServiceIds PodGroupIds，不需要以下两字段数据
				// EpcId:        proto.Uint32(uint32(customService.VPCID)),
				// PodClusterId: proto.Uint32(uint32(customService.PodClusterID)),
			}
			switch customService.Type {
			case CUSTOM_SERVICE_TYPE_HOST:
				service.HostIds = s.serviceRawData.customServiceIDToResourceIDs[customService.ID]
			case CUSTOM_SERVICE_TYPE_CHOST:
				service.ChostIds = s.serviceRawData.customServiceIDToResourceIDs[customService.ID]
			case CUSTOM_SERVICE_TYPE_POD_SERVICE:
				service.PodServiceIds = s.serviceRawData.customServiceIDToResourceIDs[customService.ID]
			case CUSTOM_SERVICE_TYPE_POD_GROUP:
				service.PodGroupIds = s.serviceRawData.customServiceIDToResourceIDs[customService.ID]
			case CUSTOM_SERVICE_TYPE_POD:
				service.PodIds = s.serviceRawData.customServiceIDToResourceIDs[customService.ID]
			}
			services = append(services, service)
			continue
		}

		ipPorts, ok := s.serviceRawData.customServiceIDToIPPorts[customService.ID]
		if !ok {
			continue
		}
		for ipPort := range ipPorts.Iter() {
			var serverPorts []uint32
			if ipPort.port != 0 {
				serverPorts = []uint32{ipPort.port}
			}
			service := &trident.ServiceInfo{
				Type:        &serviceTypeCustomService,
				Id:          proto.Uint32(uint32(customService.ID)),
				EpcId:       proto.Uint32(uint32(ipPort.vpcID)),
				Ips:         []string{ipPort.ip},
				ServerPorts: serverPorts,
			}
			services = append(services, service)
		}
	}

	return services
}

func (s *ServiceDataOP) GetServiceData() []*trident.ServiceInfo {
	return s.services
}

func (s *ServiceDataOP) generateRawData() {
	serviceRawData := newServiceRawData()
	serviceRawData.ConvertDBData(s.metaData)
	s.updateServiceRawData(serviceRawData)
}

func (s *ServiceDataOP) GenerateServiceData() {
	s.generateRawData()
	s.generateService()
}
