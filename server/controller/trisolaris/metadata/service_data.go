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
	lbIDToVPCID                   map[int]int
	customServiceIDToIPPorts      map[int]mapset.Set[customServiceIPPortKey]
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

func newServiceRawData() *ServiceRawData {
	return &ServiceRawData{
		podServiceIDToPodServicePorts: make(map[int][]*models.PodServicePort),
		podGroupIDToPodGroupPorts:     make(map[int][]*models.PodGroupPort),
		podGroupIDToPodServiceID:      make(map[int]int),
		lbIDToVPCID:                   make(map[int]int),
		customServiceIDToIPPorts:      make(map[int]mapset.Set[customServiceIPPortKey]),
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
	for _, psp := range dbDataCache.GetPodServicePorts() {
		if _, ok := r.podServiceIDToPodServicePorts[psp.PodServiceID]; ok {
			r.podServiceIDToPodServicePorts[psp.PodServiceID] = append(
				r.podServiceIDToPodServicePorts[psp.PodServiceID], psp)
		} else {
			r.podServiceIDToPodServicePorts[psp.PodServiceID] = []*models.PodServicePort{psp}
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

	r.customServiceIDToIPPorts = r.mergeCustomServices(md, dbDataCache.GetCustomServices())
}

// VPC 内去重规则：
// 1. 按照 ip-port 元素去重后，ip-port 绑定第一个遍历到的服务
// 2. 如果存在 ip-port 的 port 为空，则其他 ip-port 都丢弃，只保留这一个值
// mergeCustomServices merges custom services according to the following rules:
// 1. Deduplicate by ip-port, binding each ip-port to the first encountered service.
// 2. If any ip has an empty port, discard all other ports for that ip and keep only the empty-port entry.
func (r *ServiceRawData) mergeCustomServices(md *MetaData, customServices []*models.CustomService) map[int]mapset.Set[customServiceIPPortKey] {
	customServiceIDToIPPorts := make(map[int]mapset.Set[customServiceIPPortKey])
	ipPortKeyToServiceID := make(map[customServiceIPPortKey]int) // 记录每个 ip-port 绑定的服务ID
	hasEmptyPortForIP := make(map[string]bool)                   // 记录每个 VPC 内的 IP 是否有空端口，key格式为 "vpcID:ip"

	for _, cs := range customServices {
		var ipPorts []customServiceIPPortKey

		if cs.Type == CUSTOM_SERVICE_TYPE_IP {
			ips := strings.Split(cs.Resource, ",")
			for _, ip := range ips {
				ip = strings.TrimSpace(ip)
				if ip == "" {
					continue
				}
				ipPortKey := newCustomServiceIPPortKey(cs.VPCID, ip, 0)
				hasEmptyPortForIP[ipPortKey.ipKey()] = true
				ipPorts = append(ipPorts, ipPortKey)
			}
		} else {
			ipPortStrs := strings.Split(cs.Resource, ",")
			for _, ipPortStr := range ipPortStrs {
				ipPortStr = strings.TrimSpace(ipPortStr)
				if ipPortStr == "" {
					continue
				}
				separatorIndex := strings.LastIndex(ipPortStr, ":")
				if separatorIndex == -1 {
					log.Warningf("[ORG-%s] invalid ip port format: %s", md.ORGID, ipPortStr)
					continue
				}
				ip := ipPortStr[:separatorIndex]
				portStr := ipPortStr[separatorIndex+1:]
				port, err := strconv.Atoi(portStr)
				if err != nil {
					log.Warningf("[ORG-%s] invalid port format: %s", md.ORGID, portStr)
					continue
				}
				ipPorts = append(ipPorts, newCustomServiceIPPortKey(cs.VPCID, ip, uint32(port)))
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

	return customServiceIDToIPPorts
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
			if valuse, ok := keyToPorts[groupKeys[index]]; ok {
				service := podGroupToProto(
					podGroup.ID,
					groupKeys[index].protocol,
					valuse,
					trident.ServiceType_POD_SERVICE_POD_GROUP,
					groupKeys[index].podServiceID,
				)
				services = append(services, service)
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
		if podService.ServiceClusterIP == "" {
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
				EpcId:       proto.Uint32(uint32(customService.VPCID)),
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
