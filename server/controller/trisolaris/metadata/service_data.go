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

package metadata

import (
	"fmt"
	"strconv"
	"strings"

	mapset "github.com/deckarep/golang-set"
	"github.com/golang/protobuf/proto"

	"github.com/deepflowys/deepflow/message/trident"
	. "github.com/deepflowys/deepflow/server/controller/common"
	models "github.com/deepflowys/deepflow/server/controller/db/mysql"
	. "github.com/deepflowys/deepflow/server/controller/trisolaris/utils"
)

type ServiceRawData struct {
	podServiceIDToPodServicePorts map[int][]*models.PodServicePort
	podServiceIDToPodNodeIPs      map[int][]string
	podGroupIDToPodGroupPorts     map[int][]*models.PodGroupPort
	podGroupIDToPodIPs            map[int][]string
	podClusterIDToVPCID           map[int]int
	lbIDToVPCID                   map[int]int
}

func newServiceRawData() *ServiceRawData {
	return &ServiceRawData{
		podServiceIDToPodServicePorts: make(map[int][]*models.PodServicePort),
		podServiceIDToPodNodeIPs:      make(map[int][]string),
		podGroupIDToPodGroupPorts:     make(map[int][]*models.PodGroupPort),
		podGroupIDToPodIPs:            make(map[int][]string),
		podClusterIDToVPCID:           make(map[int]int),
		lbIDToVPCID:                   make(map[int]int),
	}
}

type ServiceDataOP struct {
	serviceRawData *ServiceRawData
	metaData       *MetaData
	services       []*trident.Service
}

func newServiceDataOP(metaData *MetaData) *ServiceDataOP {
	return &ServiceDataOP{
		serviceRawData: newServiceRawData(),
		metaData:       metaData,
		services:       []*trident.Service{},
	}
}

func (r *ServiceRawData) ConvertDBIP(dbDataCache *DBDataCache) map[int][]string {
	vinterfaces := dbDataCache.GetVInterfaces()
	podVIFIDs := mapset.NewSet()
	podVIFs := make([]*models.VInterface, 0, len(vinterfaces)/2)
	for _, vinterface := range vinterfaces {
		if vinterface.DeviceType == VIF_DEVICE_TYPE_POD {
			podVIFIDs.Add(vinterface.ID)
			podVIFs = append(podVIFs, vinterface)
		}
	}

	podVIFIDToIPs := make(map[int][]string)
	lanIPs := dbDataCache.GetLANIPs()
	for _, lanIP := range lanIPs {
		if podVIFIDs.Contains(lanIP.VInterfaceID) {
			if _, ok := podVIFIDToIPs[lanIP.VInterfaceID]; ok {
				podVIFIDToIPs[lanIP.VInterfaceID] = append(
					podVIFIDToIPs[lanIP.VInterfaceID], lanIP.IP)
			} else {
				podVIFIDToIPs[lanIP.VInterfaceID] = []string{lanIP.IP}
			}
		}
	}

	wanIPs := dbDataCache.GetWANIPs()
	for _, wanIP := range wanIPs {
		if podVIFIDs.Contains(wanIP.VInterfaceID) {
			if _, ok := podVIFIDToIPs[wanIP.VInterfaceID]; ok {
				podVIFIDToIPs[wanIP.VInterfaceID] = append(
					podVIFIDToIPs[wanIP.VInterfaceID], wanIP.IP)
			} else {
				podVIFIDToIPs[wanIP.VInterfaceID] = []string{wanIP.IP}
			}
		}
	}

	podIDToIPs := make(map[int][]string)
	for _, podVIF := range podVIFs {
		if ips, ok := podVIFIDToIPs[podVIF.ID]; ok {
			if _, ok := podIDToIPs[podVIF.DeviceID]; ok {
				podIDToIPs[podVIF.DeviceID] = append(
					podIDToIPs[podVIF.DeviceID], ips...)
			} else {
				podIDToIPs[podVIF.DeviceID] = ips[:]
			}
		}
	}

	return podIDToIPs
}

func (r *ServiceRawData) ConvertDBData(dbDataCache *DBDataCache) {
	idToPodNode := make(map[int]*models.PodNode)
	podClusterIDToPodNodes := make(map[int][]*models.PodNode)
	podIDToIPs := r.ConvertDBIP(dbDataCache)
	podNodes := dbDataCache.GetPodNodes()
	for _, podNode := range podNodes {
		idToPodNode[podNode.ID] = podNode
		if _, ok := podClusterIDToPodNodes[podNode.PodClusterID]; ok {
			podClusterIDToPodNodes[podNode.PodClusterID] = append(
				podClusterIDToPodNodes[podNode.PodClusterID], podNode)
		} else {
			podClusterIDToPodNodes[podNode.PodClusterID] = []*models.PodNode{podNode}
		}
	}

	podGroupIDToPods := make(map[int][]*models.Pod)
	pods := dbDataCache.GetPods()
	for _, pod := range pods {
		if _, ok := podGroupIDToPods[pod.PodGroupID]; ok {
			podGroupIDToPods[pod.PodGroupID] = append(
				podGroupIDToPods[pod.PodGroupID], pod)
		} else {
			podGroupIDToPods[pod.PodGroupID] = []*models.Pod{pod}
		}
		ips, ok := podIDToIPs[pod.ID]
		if ok == false {
			continue
		}
		if _, ok := r.podGroupIDToPodIPs[pod.PodGroupID]; ok {
			r.podGroupIDToPodIPs[pod.PodGroupID] = append(
				r.podGroupIDToPodIPs[pod.PodGroupID], ips...)
		} else {
			r.podGroupIDToPodIPs[pod.PodGroupID] = ips[:]
		}
	}

	podServicePorts := dbDataCache.GetPodServicePorts()
	for _, psp := range podServicePorts {
		if _, ok := r.podServiceIDToPodServicePorts[psp.PodServiceID]; ok {
			r.podServiceIDToPodServicePorts[psp.PodServiceID] = append(
				r.podServiceIDToPodServicePorts[psp.PodServiceID], psp)
		} else {
			r.podServiceIDToPodServicePorts[psp.PodServiceID] = []*models.PodServicePort{psp}
		}
	}

	podServiceIDToPodGroupIDs := make(map[int][]int)
	podGroupPorts := dbDataCache.GetPodGroupPorts()
	for _, pgp := range podGroupPorts {
		if _, ok := r.podGroupIDToPodGroupPorts[pgp.PodGroupID]; ok {
			r.podGroupIDToPodGroupPorts[pgp.PodGroupID] = append(
				r.podGroupIDToPodGroupPorts[pgp.PodGroupID], pgp)
		} else {
			r.podGroupIDToPodGroupPorts[pgp.PodGroupID] = []*models.PodGroupPort{pgp}
		}
		if _, ok := podServiceIDToPodGroupIDs[pgp.PodServiceID]; ok {
			podServiceIDToPodGroupIDs[pgp.PodServiceID] = append(
				podServiceIDToPodGroupIDs[pgp.PodServiceID], pgp.PodGroupID)
		} else {
			podServiceIDToPodGroupIDs[pgp.PodServiceID] = []int{pgp.PodGroupID}
		}
	}

	podClusters := dbDataCache.GetPodClusters()
	for _, pc := range podClusters {
		r.podClusterIDToVPCID[pc.ID] = pc.VPCID
	}

	podServices := dbDataCache.GetPodServices()
	for _, ps := range podServices {
		if ps.Type == POD_SERVICE_TYPE_NODEPORT {
			pns, ok := podClusterIDToPodNodes[ps.PodClusterID]
			if ok == false {
				continue
			}
			for _, pn := range pns {
				if pn.IP == "" {
					continue
				}
				if podNodeIPs, ok := r.podServiceIDToPodNodeIPs[ps.ID]; ok {
					if !Find[string](podNodeIPs, pn.IP) {
						r.podServiceIDToPodNodeIPs[ps.ID] = append(
							r.podServiceIDToPodNodeIPs[ps.ID], pn.IP)
					}
				} else {
					r.podServiceIDToPodNodeIPs[ps.ID] = []string{pn.IP}
				}
			}
		} else {
			pgIDs, ok := podServiceIDToPodGroupIDs[ps.ID]
			if ok == false {
				continue
			}
			for _, pgID := range pgIDs {
				pods, ok := podGroupIDToPods[pgID]
				if ok == false {
					continue
				}
				for _, pod := range pods {
					pn, ok := idToPodNode[pod.PodNodeID]
					if ok == false || pn.IP == "" {
						continue
					}
					if podNodeIPs, ok := r.podServiceIDToPodNodeIPs[ps.ID]; ok {
						if !Find[string](podNodeIPs, pn.IP) {
							r.podServiceIDToPodNodeIPs[ps.ID] = append(
								r.podServiceIDToPodNodeIPs[ps.ID], pn.IP)
						}
					} else {
						r.podServiceIDToPodNodeIPs[ps.ID] = []string{pn.IP}
					}
				}
			}
		}
	}

	lbs := dbDataCache.GetLBs()
	for _, lb := range lbs {
		r.lbIDToVPCID[lb.ID] = lb.VPCID
	}
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

var protocol_string_to_int = map[string]int{
	"ALL":   256,
	"HTTP":  6,
	"HTTPS": 6,
	"TCP":   6,
	"UDP":   17,
}

func getProtocol(protocol string) uint32 {
	if protocol, ok := protocol_string_to_int[protocol]; ok {
		return uint32(protocol)
	}
	return 256
}

func serviceToProto(
	vpcID int, ips []string, protocol string, serverPorts string,
	serviceType int, serviceID int) *trident.Service {

	if len(ips) == 0 {
		log.Debugf("service(id=%d, type=%d) no ips ", serviceID, serviceType)
		return nil
	}
	if serverPorts == "" {
		log.Debugf("service(id=%d, type=%d) no server_ports.", serviceID, serviceType)
		return nil
	}
	cidrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		cidrs = append(cidrs, ipToCidr(ip))
	}
	sType := trident.ServiceType(serviceType)
	return &trident.Service{
		EpcId:       proto.Uint32(uint32(vpcID)),
		Ips:         cidrs,
		Protocol:    proto.Uint32(getProtocol(protocol)),
		ServerPorts: proto.String(serverPorts),
		Type:        &sType,
		Id:          proto.Uint32(uint32(serviceID)),
	}
}

func (s *ServiceDataOP) generateService() {
	dbDataCache := s.metaData.GetDBDataCache()
	services := []*trident.Service{}
	rData := s.serviceRawData
	for _, podGroup := range dbDataCache.GetPodGroups() {
		vpcID := rData.podClusterIDToVPCID[podGroup.PodClusterID]
		ports, ok := rData.podGroupIDToPodGroupPorts[podGroup.ID]
		if ok == false {
			continue
		}
		podIPs, ok := rData.podGroupIDToPodIPs[podGroup.ID]
		if ok == false {
			log.Debugf("pod group(id=%d) no pod ips", podGroup.ID)
			continue
		}
		for _, port := range ports {
			service := serviceToProto(
				vpcID,
				podIPs,
				port.Protocol,
				strconv.Itoa(port.Port),
				int(trident.ServiceType_POD_SERVICE),
				port.PodServiceID,
			)
			if service != nil {
				services = append(services, service)
			}
		}
	}

	for _, podService := range dbDataCache.GetPodServices() {
		ports, ok := rData.podServiceIDToPodServicePorts[podService.ID]
		if ok == false {
			continue
		}
		if podService.ServiceClusterIP == "" {
			log.Debugf("pod service(id=%d) no ips", podService.ID)
			continue
		}
		nodeIPs, ok := rData.podServiceIDToPodNodeIPs[podService.ID]
		if ok == false {
			log.Debugf("pod service(id=%d) no node ips", podService.ID)
		}
		ips := []string{podService.ServiceClusterIP}
		for _, port := range ports {
			service := serviceToProto(podService.VPCID,
				ips,
				port.Protocol,
				strconv.Itoa(port.Port),
				int(trident.ServiceType_POD_SERVICE),
				port.PodServiceID,
			)
			if service != nil {
				services = append(services, service)
			}
			if podService.Type == POD_SERVICE_TYPE_NODEPORT && len(nodeIPs) > 0 {
				service := serviceToProto(podService.VPCID,
					nodeIPs,
					port.Protocol,
					strconv.Itoa(port.NodePort),
					int(trident.ServiceType_POD_SERVICE),
					port.PodServiceID,
				)
				if service != nil {
					services = append(services, service)
				}
			}
		}
	}

	for _, lbListener := range dbDataCache.GetLBListeners() {
		vpcID := rData.lbIDToVPCID[lbListener.LBID]
		var ips []string
		if lbListener.IPs != "" {
			ips = strings.Split(lbListener.IPs, ",")
		}
		service := serviceToProto(vpcID,
			ips,
			lbListener.Protocol,
			strconv.Itoa(lbListener.Port),
			int(trident.ServiceType_LB_SERVICE),
			lbListener.ID,
		)
		if service != nil {
			services = append(services, service)
		}
	}

	for _, lbts := range dbDataCache.GetLBTargetServers() {
		vpcID := rData.lbIDToVPCID[lbts.LBID]
		var ips []string
		if lbts.IP == "" {
			log.Debugf("lb target server(id=%d no ips)", lbts.ID)
			continue
		} else {
			ips = []string{lbts.IP}
		}

		service := serviceToProto(vpcID,
			ips,
			lbts.Protocol,
			strconv.Itoa(lbts.Port),
			int(trident.ServiceType_LB_SERVICE),
			lbts.LBListenerID,
		)
		if service != nil {
			services = append(services, service)
		}
	}
	s.services = services
	log.Debugf("service have %d", len(s.services))
}

func (s *ServiceDataOP) GetServiceData() []*trident.Service {
	return s.services
}

func (s *ServiceDataOP) generateRawData() {
	serviceRawData := newServiceRawData()
	serviceRawData.ConvertDBData(s.metaData.GetDBDataCache())
	s.updateServiceRawData(serviceRawData)
}

func (s *ServiceDataOP) GenerateServiceData() {
	s.generateRawData()
	s.generateService()
}
