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

package grpc

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/deepflowio/deepflow/message/trident"
	flow_metrics "github.com/deepflowio/deepflow/server/libs/flow-metrics"
	"github.com/deepflowio/deepflow/server/libs/utils"
	"github.com/google/gopacket/layers"
)

type ServiceTable struct {
	podServiceClusterIP4PortTable [trident.ServiceProtocol_UDP_SERVICE + 1]map[uint64]uint32
	podServiceClusterIP6PortTable map[EpcIDIP6PortKey]uint32
	podServiceClusterIDPortTable  map[uint64]uint32
	podServiceGroupIDPortTable    map[uint64]uint32

	customServiceClusterIP4PortTable [trident.ServiceProtocol_UDP_SERVICE + 1]map[uint64]uint32
	customServiceClusterIP6PortTable map[EpcIDIP6PortKey]uint32
	customServiceClusterIP4Table     map[uint64]uint32      // used to ignore port matching
	customServiceClusterIP6Table     map[EpcIDIP6Key]uint32 // used to ignore port matching

	customServiceClusterIDPortTable map[uint64]uint32
	customServiceClusterIDTable     map[uint64]uint32 // used to ignore port matching

	customServicePodService map[uint32]uint32
	customServicePodGroup   map[uint32]uint32
	customServicePod        map[uint32]uint32
	customServiceChost      map[uint32]uint32
	customServiceHost       map[uint32]uint32
}

type EpcIDIP6PortKey struct {
	IPv6     [net.IPv6len]byte
	epcID    int32
	port     uint16
	protocol uint8
}

type EpcIDIP6Key struct {
	IPv6     [net.IPv6len]byte
	epcID    int32
	protocol uint8
}

func genEpcIDIP4PortKey(epcID int32, ipv4 uint32, port uint16) uint64 {
	return uint64(epcID)<<48 | uint64(ipv4)<<16 | uint64(port)
}

func parseEpcIDIP4PortKey(key uint64) (int32, net.IP, uint16) {
	return int32(key >> 48), utils.IpFromUint32(uint32(key >> 16)), uint16(key)
}

func genEpcIDIP4Key(epcID int32, ipv4 uint32, protocol trident.ServiceProtocol) uint64 {
	return uint64(epcID)<<48 | uint64(ipv4)<<16 | uint64(protocol)
}

func parseEpcIDIP4Key(key uint64) (int32, net.IP, trident.ServiceProtocol) {
	return int32(key >> 48), utils.IpFromUint32(uint32(key >> 16)), trident.ServiceProtocol(uint16(key))
}

func genEpcIDIP6PortKey(epcID int32, ipv6 net.IP, protocol trident.ServiceProtocol, port uint16) EpcIDIP6PortKey {
	key := EpcIDIP6PortKey{
		epcID:    int32(epcID),
		port:     port,
		protocol: uint8(protocol),
	}
	copy(key.IPv6[:], ipv6)
	return key
}

func parseEpcIDIP6PortKey(key *EpcIDIP6PortKey) (int32, net.IP, trident.ServiceProtocol, uint16) {
	return key.epcID, net.IP(key.IPv6[:]), trident.ServiceProtocol(key.protocol), key.port
}

func genEpcIDIP6Key(epcID int32, ipv6 net.IP, protocol trident.ServiceProtocol) EpcIDIP6Key {
	key := EpcIDIP6Key{
		epcID:    int32(epcID),
		protocol: uint8(protocol),
	}
	copy(key.IPv6[:], ipv6)
	return key
}

func parseEpcIDIP6Key(key *EpcIDIP6PortKey) (int32, net.IP, trident.ServiceProtocol) {
	return key.epcID, net.IP(key.IPv6[:]), trident.ServiceProtocol(key.protocol)
}

// podGroupID/podClusterId key
func genPodXIDKey(id uint32, protocol trident.ServiceProtocol) uint64 {
	return uint64(id)<<32 | uint64(protocol)<<16
}

func parsePodXIDKey(key uint64) (uint32, trident.ServiceProtocol) {
	return uint32(key >> 32), trident.ServiceProtocol(uint8(key >> 16))
}

// podGroupID/podClusterId key
func genPodXIDPortKey(id uint32, protocol trident.ServiceProtocol, port uint16) uint64 {
	return uint64(id)<<32 | uint64(protocol)<<16 | uint64(port)
}

func parsePodXIDPortKey(key uint64) (uint32, trident.ServiceProtocol, uint16) {
	return uint32(key >> 32), trident.ServiceProtocol(uint8(key >> 16)), uint16(key)
}

func toServiceProtocol(protocol layers.IPProtocol) trident.ServiceProtocol {
	switch protocol {
	case layers.IPProtocolTCP:
		return trident.ServiceProtocol_TCP_SERVICE
	case layers.IPProtocolUDP:
		return trident.ServiceProtocol_UDP_SERVICE
	default:
		return trident.ServiceProtocol_ANY
	}
}

func (s *ServiceTable) QueryPodService(podID, podNodeID, podClusterID, podGroupID uint32, epcID int32, isIPv6 bool, ipv4 uint32, ipv6 net.IP, protocol layers.IPProtocol, serverPort uint16) uint32 {
	// If server port is 0, protocol is also ignored
	if serverPort == 0 {
		protocol = 0
	}
	serviceProtocol := toServiceProtocol(protocol)

	serviceID := uint32(0)
	// 数据中的 IP 地址是 Pod IP，或者是由 Hostnetwork Pod（自身没有 IP）使用的 Node IP
	// -------------------------------------------------------------------------------------------------------
	// The IP address in the data is a Pod IP, or a Node IP used by a HostNetwork Pod (which has no own Pod IP)
	if podID != 0 {
		serviceID = s.podServiceGroupIDPortTable[genPodXIDPortKey(podGroupID, serviceProtocol, serverPort)]

		// 数据中的 IP 地址是 Node IP，当然也包括由 Hostnetwork Pod（自身没有 IP）使用的 Node IP
		// ----------------------------------------------------------------------------------------------------------------
		// The IP address in the data is a Node IP, including the Node IP used by a HostNetwork Pod (which has no own Pod IP)
	} else if podNodeID != 0 && serverPort != 0 { // If serverPort is 0, the matched Service may not be accurate
		serviceID = s.podServiceClusterIDPortTable[genPodXIDPortKey(podClusterID, serviceProtocol, serverPort)]
	}

	if serviceID != 0 {
		return serviceID
	}
	// 注意：在 Hostnetwork 场景下，控制器会将 Hostnetwork Pod 的服务信息通过 ip + server_port 的形式下发下来。
	// 因此如果前两步没有查询到服务信息时，还需要继续查询。
	// ------------------------------------------------------------------------------------------------------
	// Note: In HostNetwork scenarios, the Controller distributes service information of HostNetwork Pods
	// in the form of (ip + server_port). Therefore, if the service information was not found in the above steps,
	// an additional lookup is still required.

	// for performance optimization, return directly. Since when epcID <= 0, there is no Service information.
	if epcID <= 0 {
		return 0
	}
	if isIPv6 {
		return s.podServiceClusterIP6PortTable[genEpcIDIP6PortKey(epcID, ipv6, serviceProtocol, serverPort)]
	}
	return s.podServiceClusterIP4PortTable[serviceProtocol][genEpcIDIP4PortKey(epcID, ipv4, serverPort)]
}

func (s *ServiceTable) QueryCustomService(epcID int32, isIPv6 bool, ip4 uint32, ip6 net.IP, serverPort uint16, podServiceId, podGroupId, l3DeviceId, podId, podClusterID uint32, l3DeviceType uint8, protocol layers.IPProtocol) uint32 {
	// for performance optimization, return directly. Since when epcID <= 0, there is no Service information.
	if epcID <= 0 {
		return 0
	}
	serviceProtocol := toServiceProtocol(protocol)
	var serviceId uint32

	// priority 1. pod service
	if podServiceId != 0 && len(s.customServicePodService) > 0 {
		serviceId := s.customServicePodService[podServiceId]
		if serviceId != 0 {
			return serviceId
		}
	}
	// priority 2. pod group
	if podGroupId != 0 && len(s.customServicePodGroup) > 0 {
		serviceId := s.customServicePodGroup[podGroupId]
		if serviceId != 0 {
			return serviceId
		}
	}

	// priority 3. pod
	if podId != 0 && len(s.customServicePod) > 0 {
		serviceId := s.customServicePod[podId]
		if serviceId != 0 {
			return serviceId
		}
	}

	// priority 4. pod cluster
	if podClusterID != 0 && serverPort != 0 {
		// firstly query with port
		if len(s.customServiceClusterIDPortTable) > 0 {
			serviceId = s.customServiceClusterIDPortTable[genPodXIDPortKey(podClusterID, serviceProtocol, serverPort)]
			if serviceId > 0 {
				return serviceId
			}
		}
		// secondary query without port
		if len(s.customServiceClusterIDTable) > 0 {
			serviceId = s.customServiceClusterIDTable[genPodXIDKey(podClusterID, serviceProtocol)]
			if serviceId > 0 {
				return serviceId
			}
		}
	}

	// priority 5. chost
	if l3DeviceId != 0 && l3DeviceType == uint8(flow_metrics.VMDevice) && len(s.customServiceChost) > 0 {
		serviceId := s.customServiceChost[l3DeviceId]
		if serviceId != 0 {
			return serviceId
		}
	}

	// priority 6. host
	if l3DeviceId != 0 && l3DeviceType == uint8(flow_metrics.HostDevice) && len(s.customServiceHost) > 0 {
		serviceId := s.customServiceHost[l3DeviceId]
		if serviceId != 0 {
			return serviceId
		}
	}

	// priority 7. port ip
	if isIPv6 {
		// firstly query with port
		if len(s.customServiceClusterIP6PortTable) != 0 {
			serviceId = s.customServiceClusterIP6PortTable[genEpcIDIP6PortKey(epcID, ip6, serviceProtocol, serverPort)]
			if serviceId > 0 {
				return serviceId
			}
		}
		// secondary query without port
		if len(s.customServiceClusterIP6Table) != 0 && serverPort != 0 {
			serviceId = s.customServiceClusterIP6Table[genEpcIDIP6Key(epcID, ip6, serviceProtocol)]
		}
		return serviceId
	}

	if len(s.customServiceClusterIP4PortTable[serviceProtocol]) > 0 {
		serviceId = s.customServiceClusterIP4PortTable[serviceProtocol][genEpcIDIP4PortKey(epcID, ip4, serverPort)]
		if serviceId > 0 {
			return serviceId
		}
	}

	if len(s.customServiceClusterIP4Table) > 0 && serverPort != 0 {
		serviceId = s.customServiceClusterIP4Table[genEpcIDIP4Key(epcID, ip4, serviceProtocol)]
	}

	return serviceId
}

func NewServiceTable(grpcServices []*trident.ServiceInfo) *ServiceTable {
	s := &ServiceTable{
		podServiceClusterIP6PortTable:    make(map[EpcIDIP6PortKey]uint32),
		podServiceClusterIDPortTable:     make(map[uint64]uint32),
		podServiceGroupIDPortTable:       make(map[uint64]uint32),
		customServiceClusterIP6PortTable: make(map[EpcIDIP6PortKey]uint32),
		customServiceClusterIP4Table:     make(map[uint64]uint32),
		customServiceClusterIP6Table:     make(map[EpcIDIP6Key]uint32),
		customServiceClusterIDPortTable:  make(map[uint64]uint32),
		customServiceClusterIDTable:      make(map[uint64]uint32),
		customServicePodService:          make(map[uint32]uint32),
		customServicePodGroup:            make(map[uint32]uint32),
		customServicePod:                 make(map[uint32]uint32),
		customServiceChost:               make(map[uint32]uint32),
		customServiceHost:                make(map[uint32]uint32),
	}
	for i := range s.podServiceClusterIP4PortTable {
		s.podServiceClusterIP4PortTable[i] = make(map[uint64]uint32)
	}
	for i := range s.customServiceClusterIP4PortTable {
		s.customServiceClusterIP4PortTable[i] = make(map[uint64]uint32)
	}

	for _, svc := range grpcServices {
		protocol := svc.GetProtocol()
		serviceId := svc.GetId()
		switch svc.GetType() {
		// Service from 'nodeip + port' generate 'pod_cluster_id + port' table.
		case trident.ServiceType_POD_SERVICE_NODE:
			podClusterId := svc.GetPodClusterId()
			for _, port := range svc.GetServerPorts() {
				s.podServiceClusterIDPortTable[genPodXIDPortKey(podClusterId, protocol, uint16(port))] = serviceId
				// add Protocol ANY
				s.podServiceClusterIDPortTable[genPodXIDPortKey(podClusterId, trident.ServiceProtocol_ANY, uint16(port))] = serviceId
			}
			// add port 0 for ANY
			s.podServiceClusterIDPortTable[genPodXIDPortKey(podClusterId, protocol, 0)] = serviceId
			s.podServiceClusterIDPortTable[genPodXIDPortKey(podClusterId, trident.ServiceProtocol_ANY, 0)] = serviceId
		// Service from 'pod + port' generate 'pod_group_id + port' table
		case trident.ServiceType_POD_SERVICE_POD_GROUP:
			podGroupIds := svc.GetPodGroupIds()
			if len(podGroupIds) == 0 {
				break
			}
			podGroupId := podGroupIds[0]
			for _, port := range svc.GetServerPorts() {
				s.podServiceGroupIDPortTable[genPodXIDPortKey(podGroupId, protocol, uint16(port))] = serviceId
				// add Protocol ANY
				s.podServiceGroupIDPortTable[genPodXIDPortKey(podGroupId, trident.ServiceProtocol_ANY, uint16(port))] = serviceId
			}
			// add port 0 for ANY
			s.podServiceGroupIDPortTable[genPodXIDPortKey(podGroupId, protocol, 0)] = svc.GetId()
			s.podServiceGroupIDPortTable[genPodXIDPortKey(podGroupId, trident.ServiceProtocol_ANY, 0)] = svc.GetId()
		// Service from 'clusterIp + port' generate 'epc + ip + port' table
		case trident.ServiceType_POD_SERVICE_IP:
			s.addPodServiceIp(svc)
		case trident.ServiceType_CUSTOM_SERVICE:
			s.addCustomService(svc)
		}
	}
	return s
}

func (s *ServiceTable) addPodServiceIp(svc *trident.ServiceInfo) {
	protocol := svc.GetProtocol()
	if protocol > trident.ServiceProtocol_UDP_SERVICE {
		return
	}
	epcId := int32(svc.GetEpcId())
	serviceId := svc.GetId()
	for _, ip := range svc.GetIps() {
		netIp := net.ParseIP(ip)
		if netIp == nil {
			continue
		}
		ipv4 := netIp.To4()
		if ipv4 != nil {
			ipv4U32 := utils.IpToUint32(ipv4)
			for _, port := range svc.GetServerPorts() {
				key := genEpcIDIP4PortKey(epcId, ipv4U32, uint16(port))
				s.podServiceClusterIP4PortTable[protocol][key] = serviceId
				// add Protocol ANY
				s.podServiceClusterIP4PortTable[trident.ServiceProtocol_ANY][key] = serviceId
			}
			// add port 0 for ANY
			key := genEpcIDIP4PortKey(epcId, ipv4U32, 0)
			s.podServiceClusterIP4PortTable[protocol][key] = serviceId
			s.podServiceClusterIP4PortTable[trident.ServiceProtocol_ANY][key] = serviceId
		} else {
			key := genEpcIDIP6PortKey(epcId, netIp, protocol, 0)
			for _, port := range svc.GetServerPorts() {
				key.protocol = uint8(protocol)
				key.port = uint16(port)
				s.podServiceClusterIP6PortTable[key] = serviceId
				// add Protocol ANY
				key.protocol = uint8(trident.ServiceProtocol_ANY)
				s.podServiceClusterIP6PortTable[key] = serviceId
			}

			// add port 0 for ANY
			key.protocol = uint8(protocol)
			key.port = 0
			s.podServiceClusterIP6PortTable[key] = serviceId
			// add Protocol ANY
			key.protocol = uint8(trident.ServiceProtocol_ANY)
			s.podServiceClusterIP6PortTable[key] = serviceId
		}
	}
}

func (s *ServiceTable) addCustomService(svc *trident.ServiceInfo) {
	epcId := int32(svc.GetEpcId())
	serviceId := svc.GetId()

	for _, podServiceId := range svc.GetPodServiceIds() {
		s.customServicePodService[podServiceId] = serviceId
	}

	for _, podGroupId := range svc.GetPodGroupIds() {
		s.customServicePodGroup[podGroupId] = serviceId
	}

	for _, podId := range svc.GetPodIds() {
		s.customServicePod[podId] = serviceId
	}

	for _, chostId := range svc.GetChostIds() {
		s.customServiceChost[chostId] = serviceId
	}

	for _, hostId := range svc.GetHostIds() {
		s.customServiceHost[hostId] = serviceId
	}

	podClusterId := svc.GetPodClusterId()
	if podClusterId != trident.Default_ServiceInfo_PodClusterId {
		ports := svc.GetServerPorts()
		protocol := svc.GetProtocol()
		if len(ports) == 0 {
			s.customServiceClusterIDTable[genPodXIDKey(podClusterId, protocol)] = serviceId
			s.customServiceClusterIDPortTable[genPodXIDPortKey(podClusterId, protocol, 0)] = serviceId

			// add protocol Any
			s.customServiceClusterIDTable[genPodXIDKey(podClusterId, trident.ServiceProtocol_ANY)] = serviceId
			s.customServiceClusterIDPortTable[genPodXIDPortKey(podClusterId, trident.ServiceProtocol_ANY, 0)] = serviceId
			return
		}

		// add port 0
		ports = append(ports, 0)
		for _, port := range ports {
			s.customServiceClusterIDPortTable[genPodXIDPortKey(podClusterId, protocol, uint16(port))] = serviceId
			s.customServiceClusterIDPortTable[genPodXIDPortKey(podClusterId, trident.ServiceProtocol_ANY, uint16(port))] = serviceId
		}
		return
	}

	ips := svc.GetIps()
	if len(ips) == 0 {
		return
	}
	netIp := net.ParseIP(ips[0])
	if netIp == nil {
		return
	}
	ipv4 := netIp.To4()
	var ipv4U32 uint32
	if ipv4 != nil {
		ipv4U32 = utils.IpToUint32(ipv4)
	}

	ports := svc.GetServerPorts()
	protocol := svc.GetProtocol()
	if len(ports) == 0 {
		if ipv4 != nil {
			s.customServiceClusterIP4Table[genEpcIDIP4Key(epcId, ipv4U32, protocol)] = serviceId
			s.customServiceClusterIP4Table[genEpcIDIP4Key(epcId, ipv4U32, trident.ServiceProtocol_ANY)] = serviceId

			// add port 0 to port table, so if the query carries the port number 0, you only need to look up the port table.
			s.customServiceClusterIP4PortTable[protocol][genEpcIDIP4PortKey(epcId, ipv4U32, 0)] = serviceId
			s.customServiceClusterIP4PortTable[trident.ServiceProtocol_ANY][genEpcIDIP4PortKey(epcId, ipv4U32, 0)] = serviceId

		} else {
			s.customServiceClusterIP6Table[genEpcIDIP6Key(epcId, netIp, protocol)] = serviceId
			s.customServiceClusterIP6Table[genEpcIDIP6Key(epcId, netIp, trident.ServiceProtocol_ANY)] = serviceId

			// add port 0 to port table, so if the query carries the port number 0, you only need to look up the port table.
			s.customServiceClusterIP6PortTable[genEpcIDIP6PortKey(epcId, netIp, protocol, 0)] = serviceId
			s.customServiceClusterIP6PortTable[genEpcIDIP6PortKey(epcId, netIp, trident.ServiceProtocol_ANY, 0)] = serviceId
		}
		return
	}

	// add port 0
	ports = append(ports, 0)
	for _, port := range ports {
		if ipv4 != nil {
			key := genEpcIDIP4PortKey(epcId, ipv4U32, uint16(port))
			s.customServiceClusterIP4PortTable[protocol][key] = serviceId
			// add Protocol ANY
			s.customServiceClusterIP4PortTable[trident.ServiceProtocol_ANY][key] = serviceId
		} else {
			key := genEpcIDIP6PortKey(epcId, netIp, protocol, uint16(port))
			s.customServiceClusterIP6PortTable[key] = serviceId
			key.protocol = uint8(trident.ServiceProtocol_ANY)
			s.customServiceClusterIP6PortTable[key] = serviceId
		}
	}

}

func (s *ServiceTable) addCustomServicePodGroup(svc *trident.ServiceInfo) {

}

func printClusterIP4PortTable(name string, sb *strings.Builder, clusterIP4PortTable *[trident.ServiceProtocol_UDP_SERVICE + 1]map[uint64]uint32) {
	sb.WriteString("\n")
	sb.WriteString(name)
	if len(clusterIP4PortTable) > 0 {
		sb.WriteString("\n1  epcID   ipv4            protocol          port            serviceID\n")
		sb.WriteString("------------------------------------------------------------------------\n")
	}
	epcIP4s := make([]uint64, 0)
	for i := range clusterIP4PortTable {
		for epcIP := range clusterIP4PortTable[i] {
			epcIP4s = append(epcIP4s, epcIP)
		}
		sort.Slice(epcIP4s, func(i, j int) bool {
			return epcIP4s[i] < epcIP4s[j]
		})
		for _, epcIP := range epcIP4s {
			id := clusterIP4PortTable[i][epcIP]
			epcID, ipv4, port := parseEpcIDIP4PortKey(epcIP)
			fmt.Fprintf(sb, "   %-6d  %-15s %-12s      %-15d %-6d \n", epcID, ipv4, trident.ServiceProtocol(i), port, id)
		}
	}
}

func printClusterIP4Table(name string, sb *strings.Builder, clusterIP4Table map[uint64]uint32) {
	sb.WriteString("\n")
	sb.WriteString(name)
	if len(clusterIP4Table) > 0 {
		sb.WriteString("\n11  epcID   ipv4            protocol          serviceID\n")
		sb.WriteString("---------------------------------------------------------\n")
	}
	epcIP4s := make([]uint64, 0)
	for epcIP := range clusterIP4Table {
		epcIP4s = append(epcIP4s, epcIP)
	}
	sort.Slice(epcIP4s, func(i, j int) bool {
		return epcIP4s[i] < epcIP4s[j]
	})
	for _, epcIP := range epcIP4s {
		id := clusterIP4Table[epcIP]
		epcID, ipv4, protocol := parseEpcIDIP4Key(epcIP)
		fmt.Fprintf(sb, "   %-6d  %-15s %-12s      %-6d \n", epcID, ipv4, trident.ServiceProtocol(protocol), id)
	}
}

func printClusterIDPortTable(name string, sb *strings.Builder, clusterIDPortTable map[uint64]uint32) {
	sb.WriteString("\n")
	sb.WriteString(name)
	if len(clusterIDPortTable) > 0 {
		sb.WriteString("\n3 podClusterID    protocol     port            serviceID\n")
		sb.WriteString("------------------------------------------------------------------------\n")
	}
	keys := make([]uint64, 0)
	for key := range clusterIDPortTable {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	for _, key := range keys {
		id := clusterIDPortTable[key]
		clusterID, protocol, port := parsePodXIDPortKey(key)
		fmt.Fprintf(sb, "  %-6d            %-12s %-15d %-6d \n", clusterID, protocol, port, id)
	}
}

func printClusterIDTable(name string, sb *strings.Builder, clusterIDTable map[uint64]uint32) {
	sb.WriteString("\n")
	sb.WriteString(name)
	if len(clusterIDTable) > 0 {
		sb.WriteString("\n3 podClusterID    protocol     serviceID\n")
		sb.WriteString("------------------------------------------\n")
	}
	keys := make([]uint64, 0)
	for key := range clusterIDTable {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	for _, key := range keys {
		id := clusterIDTable[key]
		clusterID, protocol := parsePodXIDKey(key)
		fmt.Fprintf(sb, "  %-6d            %-12s %-6d \n", clusterID, protocol, id)
	}
}

func (s *ServiceTable) String() string {
	sb := &strings.Builder{}
	keys := make([]uint64, 0)

	printClusterIP4PortTable("podServiceClusterIP4PortTable", sb, &s.podServiceClusterIP4PortTable)

	if len(s.podServiceClusterIP6PortTable) > 0 {
		sb.WriteString("\n2  epcID   ipv6            protocol          port            serviceID\n")
		sb.WriteString("------------------------------------------------------------------------\n")
	}
	epcIP6s := make([]EpcIDIP6PortKey, 0)
	for epcIP := range s.podServiceClusterIP6PortTable {
		epcIP6s = append(epcIP6s, epcIP)
	}
	sort.Slice(epcIP6s, func(i, j int) bool {
		if epcIP6s[i].epcID < epcIP6s[j].epcID {
			return true
		} else if epcIP6s[i].epcID == epcIP6s[j].epcID {
			return bytes.Compare(epcIP6s[i].IPv6[:], epcIP6s[j].IPv6[:]) <= 0
		}
		return false
	})
	for _, epcIP := range epcIP6s {
		id := s.podServiceClusterIP6PortTable[epcIP]
		epcID, ipv6, protocol, port := parseEpcIDIP6PortKey(&epcIP)
		fmt.Fprintf(sb, "  %-6d  %-15s %-12s %-15d %-6d \n", epcID, ipv6, protocol, port, id)
	}

	printClusterIDPortTable("podServiceClusterIDPortTable", sb, s.podServiceClusterIDPortTable)

	if len(s.podServiceGroupIDPortTable) > 0 {
		sb.WriteString("\n4 podGroupID        protocol     port            serviceID\n")
		sb.WriteString("------------------------------------------------------------------------\n")
	}
	keys = keys[:0]
	for key := range s.podServiceGroupIDPortTable {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	for _, key := range keys {
		id := s.podServiceGroupIDPortTable[key]
		groupID, protocol, port := parsePodXIDPortKey(key)
		fmt.Fprintf(sb, "  %-6d            %-12s %-15d %-6d \n", groupID, protocol, port, id)
	}
	printClusterIP4Table("customServiceClusterIP4Table", sb, s.customServiceClusterIP4Table)
	printClusterIP4PortTable("customServiceClusterIP4PortTable", sb, &s.customServiceClusterIP4PortTable)

	if len(s.customServiceClusterIP6PortTable) > 0 {
		sb.WriteString("\nipv6 custom service\n")
		sb.WriteString("\n6  epcID   ipv6            port            serviceID\n")
		sb.WriteString("------------------------------------------------------\n")
	}
	epcIP6s = epcIP6s[:0]
	for epcIP := range s.customServiceClusterIP6PortTable {
		epcIP6s = append(epcIP6s, epcIP)
	}
	sort.Slice(epcIP6s, func(i, j int) bool {
		if epcIP6s[i].epcID < epcIP6s[j].epcID {
			return true
		} else if epcIP6s[i].epcID == epcIP6s[j].epcID {
			return bytes.Compare(epcIP6s[i].IPv6[:], epcIP6s[j].IPv6[:]) <= 0
		}
		return false
	})
	for _, epcIP := range epcIP6s {
		id := s.customServiceClusterIP6PortTable[epcIP]
		epcID, ipv6, _, port := parseEpcIDIP6PortKey(&epcIP)
		fmt.Fprintf(sb, "  %-6d  %-15s %-15d %-6d \n", epcID, ipv6, port, id)
	}

	printClusterIDTable("customServiceClusterIDTable", sb, s.customServiceClusterIDTable)
	printClusterIDPortTable("customServiceClusterIDPortTable", sb, s.customServiceClusterIDPortTable)

	if len(s.customServicePodService) > 0 {
		sb.WriteString("\npodServiceId custom service\n")
		sb.WriteString("\n7  podServiceId            serviceID\n")
		sb.WriteString("------------------------------------------------------\n")
		for podServiceId, serviceId := range s.customServicePodService {
			fmt.Fprintf(sb, "  %-11d            %-15d \n", podServiceId, serviceId)
		}
	}

	if len(s.customServicePodGroup) > 0 {
		sb.WriteString("\npodGroupId custom service\n")
		sb.WriteString("\n8  podGrouopId            serviceID\n")
		sb.WriteString("------------------------------------------------------\n")
		for podGroupId, serviceId := range s.customServicePodGroup {
			fmt.Fprintf(sb, "  %-11d            %-15d \n", podGroupId, serviceId)
		}
	}

	if len(s.customServicePod) > 0 {
		sb.WriteString("\npodId custom service\n")
		sb.WriteString("\n9  podId            serviceID\n")
		sb.WriteString("------------------------------------------------------\n")
		for podId, serviceId := range s.customServicePod {
			fmt.Fprintf(sb, "  %-11d       %-15d \n", podId, serviceId)
		}
	}

	if len(s.customServiceChost) > 0 {
		sb.WriteString("\nchostId custom service\n")
		sb.WriteString("\n10   chostId            serviceID\n")
		sb.WriteString("------------------------------------------------------\n")
		for chostId, serviceId := range s.customServiceChost {
			fmt.Fprintf(sb, "  %-11d            %-15d \n", chostId, serviceId)
		}
	}

	if len(s.customServiceHost) > 0 {
		sb.WriteString("\nhostId custom service\n")
		sb.WriteString("\n11   hostId            serviceID\n")
		sb.WriteString("------------------------------------------------------\n")
		for hostId, serviceId := range s.customServiceHost {
			fmt.Fprintf(sb, "  %-11d            %-15d \n", hostId, serviceId)
		}
	}

	return sb.String()
}
