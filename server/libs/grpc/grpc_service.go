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
	epcIDIPv4Table          [trident.ServiceProtocol_UDP_SERVICE + 1]map[uint64]uint32
	epcIDIPv6Table          map[EpcIDIPv6Key]uint32
	podClusterIDTable       map[uint64]uint32
	podGroupIDTable         map[uint64]uint32
	customServiceIpv4Table  map[uint64]uint32
	customServiceIpv6Table  map[EpcIDIPv6Key]uint32
	customServicePodService map[uint32]uint32
	customServicePodGroup   map[uint32]uint32
	customServicePod        map[uint32]uint32
	customServiceChost      map[uint32]uint32
	customServiceHost       map[uint32]uint32
}

type EpcIDIPv6Key struct {
	epcID    int32
	protocol uint8
	port     uint16
	IPv6     [net.IPv6len]byte
}

func genEpcIDIPv4Key(epcID int32, ipv4 uint32, port uint16) uint64 {
	return uint64(epcID)<<48 | uint64(ipv4)<<16 | uint64(port)
}

func parseEpcIDIPv4Key(key uint64) (int32, net.IP, uint16) {
	return int32(key >> 48), utils.IpFromUint32(uint32(key >> 16)), uint16(key)
}

func genEpcIDIPv6Key(epcID int32, ipv6 net.IP, protocol trident.ServiceProtocol, port uint16) EpcIDIPv6Key {
	key := EpcIDIPv6Key{
		epcID:    int32(epcID),
		port:     port,
		protocol: uint8(protocol),
	}
	copy(key.IPv6[:], ipv6)
	return key
}

func parseEpcIDIPv6Key(key *EpcIDIPv6Key) (int32, net.IP, trident.ServiceProtocol, uint16) {
	return key.epcID, net.IP(key.IPv6[:]), trident.ServiceProtocol(key.protocol), key.port
}

// podGroupID/podClusterId key
func genPodXIDKey(id uint32, protocol trident.ServiceProtocol, port uint16) uint64 {
	return uint64(id)<<32 | uint64(protocol)<<16 | uint64(port)
}

func parsePodXIDKey(key uint64) (uint32, trident.ServiceProtocol, uint16) {
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
		serviceID = s.podGroupIDTable[genPodXIDKey(podGroupID, serviceProtocol, serverPort)]

		// 数据中的 IP 地址是 Node IP，当然也包括由 Hostnetwork Pod（自身没有 IP）使用的 Node IP
		// ----------------------------------------------------------------------------------------------------------------
		// The IP address in the data is a Node IP, including the Node IP used by a HostNetwork Pod (which has no own Pod IP)
	} else if podNodeID != 0 && serverPort != 0 { // If serverPort is 0, the matched Service may not be accurate
		serviceID = s.podClusterIDTable[genPodXIDKey(podClusterID, serviceProtocol, serverPort)]
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
		return s.epcIDIPv6Table[genEpcIDIPv6Key(epcID, ipv6, serviceProtocol, serverPort)]
	}
	return s.epcIDIPv4Table[serviceProtocol][genEpcIDIPv4Key(epcID, ipv4, serverPort)]
}

func (s *ServiceTable) QueryCustomService(epcID int32, isIPv6 bool, ipv4 uint32, ipv6 net.IP, serverPort uint16, podServiceId, podGroupId, l3DeviceId, podId uint32, l3DeviceType uint8) uint32 {
	// for performance optimization, return directly. Since when epcID <= 0, there is no Service information.
	if epcID <= 0 {
		return 0
	}

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

	// priority 4. chost
	if l3DeviceId != 0 && l3DeviceType == uint8(flow_metrics.VMDevice) && len(s.customServiceChost) > 0 {
		serviceId := s.customServiceChost[l3DeviceId]
		if serviceId != 0 {
			return serviceId
		}
	}

	// priority 5. host
	if l3DeviceId != 0 && l3DeviceType == uint8(flow_metrics.HostDevice) && len(s.customServiceHost) > 0 {
		serviceId := s.customServiceHost[l3DeviceId]
		if serviceId != 0 {
			return serviceId
		}
	}

	// priority 6. port ip
	if isIPv6 {
		if len(s.customServiceIpv6Table) == 0 {
			return 0
		}
		serviceID := s.customServiceIpv6Table[genEpcIDIPv6Key(epcID, ipv6, 0, serverPort)]
		if serviceID > 0 || serverPort == 0 {
			return serviceID
		}
		return s.customServiceIpv6Table[genEpcIDIPv6Key(epcID, ipv6, 0, 0)]
	}
	if len(s.customServiceIpv4Table) == 0 {
		return 0
	}
	serviceID := s.customServiceIpv4Table[genEpcIDIPv4Key(epcID, ipv4, serverPort)]
	if serviceID > 0 || serverPort == 0 {
		return serviceID
	}
	return s.customServiceIpv4Table[genEpcIDIPv4Key(epcID, ipv4, 0)]
}

func NewServiceTable(grpcServices []*trident.ServiceInfo) *ServiceTable {
	s := &ServiceTable{
		epcIDIPv6Table:          make(map[EpcIDIPv6Key]uint32),
		podClusterIDTable:       make(map[uint64]uint32),
		podGroupIDTable:         make(map[uint64]uint32),
		customServiceIpv4Table:  make(map[uint64]uint32),
		customServiceIpv6Table:  make(map[EpcIDIPv6Key]uint32),
		customServicePodService: make(map[uint32]uint32),
		customServicePodGroup:   make(map[uint32]uint32),
		customServicePod:        make(map[uint32]uint32),
		customServiceChost:      make(map[uint32]uint32),
		customServiceHost:       make(map[uint32]uint32),
	}
	for i := range s.epcIDIPv4Table {
		s.epcIDIPv4Table[i] = make(map[uint64]uint32)
	}

	for _, svc := range grpcServices {
		protocol := svc.GetProtocol()
		serviceId := svc.GetId()
		switch svc.GetType() {
		// Service from 'nodeip + port' generate 'pod_cluster_id + port' table.
		case trident.ServiceType_POD_SERVICE_NODE:
			podClusterId := svc.GetPodClusterId()
			for _, port := range svc.GetServerPorts() {
				s.podClusterIDTable[genPodXIDKey(podClusterId, protocol, uint16(port))] = serviceId
				// add Protocol ANY
				s.podClusterIDTable[genPodXIDKey(podClusterId, trident.ServiceProtocol_ANY, uint16(port))] = serviceId
			}
			// add port 0 for ANY
			s.podClusterIDTable[genPodXIDKey(podClusterId, protocol, 0)] = serviceId
			s.podClusterIDTable[genPodXIDKey(podClusterId, trident.ServiceProtocol_ANY, 0)] = serviceId
		// Service from 'pod + port' generate 'pod_group_id + port' table
		case trident.ServiceType_POD_SERVICE_POD_GROUP:
			podGroupIds := svc.GetPodGroupIds()
			if len(podGroupIds) == 0 {
				break
			}
			podGroupId := podGroupIds[0]
			for _, port := range svc.GetServerPorts() {
				s.podGroupIDTable[genPodXIDKey(podGroupId, protocol, uint16(port))] = serviceId
				// add Protocol ANY
				s.podGroupIDTable[genPodXIDKey(podGroupId, trident.ServiceProtocol_ANY, uint16(port))] = serviceId
			}
			// add port 0 for ANY
			s.podGroupIDTable[genPodXIDKey(podGroupId, protocol, 0)] = svc.GetId()
			s.podGroupIDTable[genPodXIDKey(podGroupId, trident.ServiceProtocol_ANY, 0)] = svc.GetId()
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
				key := genEpcIDIPv4Key(epcId, ipv4U32, uint16(port))
				s.epcIDIPv4Table[protocol][key] = serviceId
				// add Protocol ANY
				s.epcIDIPv4Table[trident.ServiceProtocol_ANY][key] = serviceId
			}
			// add port 0 for ANY
			key := genEpcIDIPv4Key(epcId, ipv4U32, 0)
			s.epcIDIPv4Table[protocol][key] = serviceId
			s.epcIDIPv4Table[trident.ServiceProtocol_ANY][key] = serviceId
		} else {
			key := genEpcIDIPv6Key(epcId, netIp, protocol, 0)
			for _, port := range svc.GetServerPorts() {
				key.protocol = uint8(protocol)
				key.port = uint16(port)
				s.epcIDIPv6Table[key] = serviceId
				// add Protocol ANY
				key.protocol = uint8(trident.ServiceProtocol_ANY)
				s.epcIDIPv6Table[key] = serviceId
			}

			// add port 0 for ANY
			key.protocol = uint8(protocol)
			key.port = 0
			s.epcIDIPv6Table[key] = serviceId
			// add Protocol ANY
			key.protocol = uint8(trident.ServiceProtocol_ANY)
			s.epcIDIPv6Table[key] = serviceId
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

	ips := svc.GetIps()
	if len(ips) == 0 {
		return
	}
	ports := svc.GetServerPorts()
	if len(ports) == 0 {
		ports = []uint32{0}
	}
	for _, port := range ports {
		netIp := net.ParseIP(ips[0])
		if netIp == nil {
			continue
		}
		ipv4 := netIp.To4()
		if ipv4 != nil {
			ipv4U32 := utils.IpToUint32(ipv4)
			key := genEpcIDIPv4Key(epcId, ipv4U32, uint16(port))
			s.customServiceIpv4Table[key] = serviceId
		} else {
			key := genEpcIDIPv6Key(epcId, netIp, 0, uint16(port))
			s.customServiceIpv6Table[key] = serviceId
		}
	}
}

func (s *ServiceTable) addCustomServicePodGroup(svc *trident.ServiceInfo) {

}

func (s *ServiceTable) String() string {
	sb := &strings.Builder{}

	if len(s.epcIDIPv4Table) > 0 {
		sb.WriteString("\n1  epcID   ipv4            protocol          port            serviceID\n")
		sb.WriteString("------------------------------------------------------------------------\n")
	}
	epcIP4s := make([]uint64, 0)
	for i := range s.epcIDIPv4Table {
		for epcIP := range s.epcIDIPv4Table[i] {
			epcIP4s = append(epcIP4s, epcIP)
		}
		sort.Slice(epcIP4s, func(i, j int) bool {
			return epcIP4s[i] < epcIP4s[j]
		})
		for _, epcIP := range epcIP4s {
			id := s.epcIDIPv4Table[i][epcIP]
			epcID, ipv4, port := parseEpcIDIPv4Key(epcIP)
			fmt.Fprintf(sb, "   %-6d  %-15s %-12s      %-15d %-6d \n", epcID, ipv4, trident.ServiceProtocol(i), port, id)
		}
	}

	if len(s.epcIDIPv6Table) > 0 {
		sb.WriteString("\n2  epcID   ipv6            protocol          port            serviceID\n")
		sb.WriteString("------------------------------------------------------------------------\n")
	}
	epcIP6s := make([]EpcIDIPv6Key, 0)
	for epcIP := range s.epcIDIPv6Table {
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
		id := s.epcIDIPv6Table[epcIP]
		epcID, ipv6, protocol, port := parseEpcIDIPv6Key(&epcIP)
		fmt.Fprintf(sb, "  %-6d  %-15s %-12s %-15d %-6d \n", epcID, ipv6, protocol, port, id)
	}

	if len(s.podClusterIDTable) > 0 {
		sb.WriteString("\n3 podClusterID    protocol     port            serviceID\n")
		sb.WriteString("------------------------------------------------------------------------\n")
	}
	keys := make([]uint64, 0)
	for key := range s.podClusterIDTable {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	for _, key := range keys {
		id := s.podClusterIDTable[key]
		clusterID, protocol, port := parsePodXIDKey(key)
		fmt.Fprintf(sb, "  %-6d            %-12s %-15d %-6d \n", clusterID, protocol, port, id)
	}

	if len(s.podGroupIDTable) > 0 {
		sb.WriteString("\n4 podGroupID        protocol     port            serviceID\n")
		sb.WriteString("------------------------------------------------------------------------\n")
	}
	keys = keys[:0]
	for key := range s.podGroupIDTable {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	for _, key := range keys {
		id := s.podGroupIDTable[key]
		groupID, protocol, port := parsePodXIDKey(key)
		fmt.Fprintf(sb, "  %-6d            %-12s %-15d %-6d \n", groupID, protocol, port, id)
	}

	if len(s.customServiceIpv4Table) > 0 {
		sb.WriteString("\nipv4 custom service\n")
		sb.WriteString("5  epcID   ipv4            port            serviceID\n")
		sb.WriteString("----------------------------------------------------\n")
	}
	epcIP4s = epcIP4s[:0]
	for epcIP, _ := range s.customServiceIpv4Table {
		epcIP4s = append(epcIP4s, epcIP)
	}
	sort.Slice(epcIP4s, func(i, j int) bool {
		return epcIP4s[i] < epcIP4s[j]
	})
	for _, epcIP := range epcIP4s {
		id := s.customServiceIpv4Table[epcIP]
		epcID, ipv4, port := parseEpcIDIPv4Key(epcIP)
		fmt.Fprintf(sb, "   %-6d  %-15s %-15d %-6d \n", epcID, ipv4, port, id)
	}

	if len(s.customServiceIpv6Table) > 0 {
		sb.WriteString("\nipv6 custom service\n")
		sb.WriteString("\n6  epcID   ipv6            port            serviceID\n")
		sb.WriteString("------------------------------------------------------\n")
	}
	epcIP6s = epcIP6s[:0]
	for epcIP := range s.customServiceIpv6Table {
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
		id := s.customServiceIpv6Table[epcIP]
		epcID, ipv6, _, port := parseEpcIDIPv6Key(&epcIP)
		fmt.Fprintf(sb, "  %-6d  %-15s %-15d %-6d \n", epcID, ipv6, port, id)
	}

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
