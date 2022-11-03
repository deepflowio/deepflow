package microsoft_acs

import (
	"encoding/json"
	"fmt"
	simplejson "github.com/bitly/go-simplejson"
	"github.com/deepflowys/deepflow/server/controller/cloud/model"
	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	logging "github.com/op/go-logging"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

var log = logging.MustGetLogger("cloud.microsoft_acs")

var VM_STATES = map[string]int{
	"Running": common.VM_STATE_RUNNING,
	"Stopped": common.VM_STATE_STOPPED,
}

type MicrosoftAcs struct {
	rm                     *MicrosoftAcsResourceMap
	name                   string
	uuidGenerate           string
	regionUuid             string
	FileDir                string
	hostManageNetworkCidrs []string
	lbWanNetworkCidr       string
	envNames               string
}

type MicrosoftAcsResourceMap struct {
	HostIdToRegion map[string]string
	HostIdToAZ     map[string]string
	HostNameToId   map[string]string
	HostIdToIps    map[string][]string
	HostIdToIp     map[string]string

	VpcIdToRegion       map[string]string
	VpcIdToAz           map[string]string
	VpcNameToId         map[string]string
	VpcIdToSubnets      map[string][][]string
	VpcIdToHostNetworks map[string]map[string][][]string

	VnetIdToRegion map[string]string
	VnetIdToVpc    map[string]string

	NetworkIdToSubnets      map[string][][]string
	NetworkNameToExternal   map[string]bool
	NetworkIdToNameExternal map[string][]interface{}

	LogicalNetworkNameToExternal map[string]bool
	LogicalNetworkIdToVpc        map[string]string

	SubnetNameToId map[string]string

	IPsForTypeGateway []string

	PortIdToVpcVmIP  map[string][]string
	PortIdToRegionVm map[string][]string

	VirtualSubnetToPortIds map[string][]string
}

func NewMicrosoftAcsResourceMap() *MicrosoftAcsResourceMap {
	return &MicrosoftAcsResourceMap{
		HostIdToRegion: map[string]string{},
		HostIdToAZ:     map[string]string{},
		HostNameToId:   map[string]string{},
		HostIdToIps:    map[string][]string{},
		HostIdToIp:     map[string]string{},

		VpcIdToRegion:       map[string]string{},
		VpcIdToAz:           map[string]string{},
		VpcNameToId:         map[string]string{},
		VpcIdToSubnets:      map[string][][]string{},
		VpcIdToHostNetworks: map[string]map[string][][]string{},

		VnetIdToRegion: map[string]string{},
		VnetIdToVpc:    map[string]string{},

		NetworkIdToSubnets:      map[string][][]string{},
		NetworkNameToExternal:   map[string]bool{},
		NetworkIdToNameExternal: map[string][]interface{}{},

		LogicalNetworkNameToExternal: map[string]bool{},
		LogicalNetworkIdToVpc:        map[string]string{},

		SubnetNameToId: map[string]string{},

		IPsForTypeGateway: []string{},

		PortIdToVpcVmIP:  map[string][]string{},
		PortIdToRegionVm: map[string][]string{},

		VirtualSubnetToPortIds: map[string][]string{},
	}
}

func NewMicrosoftAcs(domain mysql.Domain) (m *MicrosoftAcs, err error) {
	config, err := simplejson.NewJson([]byte(domain.Config))
	if err != nil {
		log.Error(err)
		return nil, err
	}
	fileDir, err := config.Get("file_dir").String()
	if err != nil {
		log.Error("file_dir must be specified")
		return nil, err
	}

	hostManageNetworkCidrs, err := config.Get("host_manage_network_cidrs").String()
	if err != nil {
		log.Error("host_manage_network_cidrs must be specified")
		return nil, err
	}

	lbWanNetworkCidr, err := config.Get("lb_wan_network_cidr").String()
	if err != nil {
		log.Error("lb_wan_network_cidr must be specified")
		return nil, err
	}

	envNames := config.Get("env_names").MustString()
	if envNames == "" {
		log.Warning("env_names must be specified")
	}
	m = &MicrosoftAcs{
		name:                   domain.Name,
		uuidGenerate:           domain.DisplayName,
		regionUuid:             config.Get("region_uuid").MustString(),
		FileDir:                fileDir,
		hostManageNetworkCidrs: strings.Split(hostManageNetworkCidrs, ","),
		lbWanNetworkCidr:       lbWanNetworkCidr,
		envNames:               envNames,
		rm:                     NewMicrosoftAcsResourceMap(),
	}
	return m, err
}

func (m *MicrosoftAcs) GetCloudData() (model.Resource, error) {
	var resource model.Resource
	var regions []model.Region
	var azs []model.AZ
	var hosts []model.Host
	var vpcs []model.VPC
	var networks []model.Network
	var subnets []model.Subnet
	var ports []model.VInterface
	var ips []model.IP
	var vms []model.VM
	var peerConnections []model.PeerConnection
	var sgs []model.SecurityGroup
	var sgRules []model.SecurityGroupRule
	var vmSGs []model.VMSecurityGroup
	var lbs []model.LB
	var lbListeners []model.LBListener
	var lbTargetServers []model.LBTargetServer
	var nats []model.NATGateway
	var natRules []model.NATRule
	var floatingIPs []model.FloatingIP

	regions, azs, hosts, vpcs, networks = m.getHosts()

	tmpVpcs, tmpNetworks, subnets := m.getVpcAndNetworks()
	vpcs = append(vpcs, tmpVpcs...)
	networks = append(networks, tmpNetworks...)

	tmpNetworks, tmpSubnets := m.getHostNetowrks()
	networks = append(networks, tmpNetworks...)
	subnets = append(subnets, tmpSubnets...)

	tmpSubnets, ports, ips = m.getHostPorts()
	subnets = append(subnets, tmpSubnets...)

	tmpSubnets, vms, vmPorts, vmIPs := m.getVMsPortsIPs()
	subnets = append(subnets, tmpSubnets...)
	ports = append(ports, vmPorts...)
	ips = append(ips, vmIPs...)

	for _, host := range hosts {
		hostIP, ok := m.rm.HostIdToIp[host.Lcuuid]
		if ok {
			host.IP = hostIP
			if findStrInArray(hostIP, m.rm.IPsForTypeGateway) {
				host.Type = common.HOST_TYPE_NSP
			}
		}
	}

	peerConnections = m.getPeerConnections()

	sgs, sgRules, vmSGs = m.getSecurityGroupsAndRules()

	lbs, lbListeners, lbTargetServers, nats, natRules, lbPorts, lbIPs, floatingIPs := m.getLbs()
	ports = append(ports, lbPorts...)
	ips = append(ips, lbIPs...)

	resource.Regions = regions
	resource.AZs = azs
	resource.VPCs = vpcs
	resource.Networks = networks
	resource.Subnets = subnets
	resource.Hosts = hosts
	resource.VInterfaces = ports
	resource.IPs = ips
	resource.VMs = vms
	resource.PeerConnections = peerConnections
	resource.SecurityGroups = sgs
	resource.SecurityGroupRules = sgRules
	resource.VMSecurityGroups = vmSGs
	resource.LBs = lbs
	resource.LBListeners = lbListeners
	resource.LBTargetServers = lbTargetServers
	resource.NATGateways = nats
	resource.NATRules = natRules
	resource.FloatingIPs = floatingIPs

	return resource, nil
}

func (m *MicrosoftAcs) getPublicIps() (publicIdToPortIp map[string][]string) {
	data, err := readConfig(m.FileDir, "PublicIP.txt")
	if err != nil {
		// TODO
		return publicIdToPortIp
	}
	publicIdToPortIp = map[string][]string{}
	for _, ipInfo := range data {
		properties := ipInfo["properties"]
		if properties == nil {
			continue
		}
		var port string
		ipConfiguration, ok := properties.(map[string]interface{})["ipConfiguration"]
		if ok {
			port = ipConfiguration.(map[string]interface{})["resourceRef"].(string)
		}
		ip := properties.(map[string]interface{})["ipAddress"].(string)
		publicIdToPortIp[ipInfo["resourceRef"].(string)] = []string{port, ip}
	}
	return publicIdToPortIp
}

func (m *MicrosoftAcs) getLbs() (lbs []model.LB, lbListeners []model.LBListener, lbTargetServers []model.LBTargetServer, nats []model.NATGateway, natRules []model.NATRule, ports []model.VInterface, ips []model.IP, floatingIPs []model.FloatingIP) {

	log.Debug("Get load_balances and nats starting")
	attrs := []string{"resourceId", "properties"}
	listenerAttrs := []string{"resourceId", "properties"}
	listenerAttrs2 := []string{"protocol", "frontendPort", "backendPort"}
	publicIdToPortIp := m.getPublicIps()
	data, err := readConfig(m.FileDir, "LB.txt")
	if err != nil {
		// TODO
		return lbs, lbListeners, lbTargetServers, nats, natRules, ports, ips, floatingIPs
	}
	for _, lb := range data {
		if ok := checkAttributes(lb, attrs); !ok {
			continue
		}
		tags := lb["tags"].(map[string]interface{})
		vpcUUID := tags["VMNetworkID"].(string)
		properties := lb["properties"].(map[string]interface{})
		ipConfigs, ok := properties["frontendIPConfigurations"]
		lbUUID := lb["resourceId"].(string)
		if !ok || ipConfigs == nil {
			log.Debug("LB (%s) vip not found", lbUUID)
			continue
		} else if _, ok := ipConfigs.([]interface{})[0].(map[string]interface{}); !ok {
			log.Debug("LB (%s) vip not found", lbUUID)
			continue
		}
		lbIPs := []string{}
		for _, ipConfig := range ipConfigs.([]interface{}) {
			properties := ipConfig.(map[string]interface{})["properties"]
			if privateIPAddress, ok := properties.(map[string]interface{})["privateIPAddress"]; ok {
				lbIPs = append(lbIPs, privateIPAddress.(string))
			} else if publicIPAddress, ok := properties.(map[string]interface{})["publicIPAddress"]; ok {
				publicId := publicIPAddress.(map[string]interface{})["resourceRef"].(string)
				lbIP, ok := publicIdToPortIp[publicId]
				if ok {
					lbIPs = append(lbIPs, lbIP[1])
					delete(publicIdToPortIp, publicId)
				}
			}
		}
		if len(lbIPs) == 0 {
			log.Debug("LB (%s) vip not found", lbUUID)
			continue
		}
		lbModel := common.LB_MODEL_INTERNAL
		if lbType, ok := tags["LBType"]; ok || tags["LBType"] != nil {
			if lbType.(string) == "Public" {
				lbModel = common.LB_MODEL_EXTERNAL
			}
		} else {
			for _, lbIP := range lbIPs {
				if isIpInCidr(lbIP, m.lbWanNetworkCidr) {
					lbModel = common.LB_MODEL_EXTERNAL
				}
			}
		}
		if len(lbUUID) != 36 {
			lbUUID = common.GenerateUUID(m.uuidGenerate + lbUUID)
		}
		lbName := lb["resourceMetadata"].(map[string]interface{})["resourceName"].(string)
		if lbName == "" {
			lbName = lbUUID
		}
		lbResource := model.LB{
			Lcuuid:    lbUUID,
			Name:      lbName,
			Label:     lbUUID,
			Model:     lbModel,
			VPCLcuuid: vpcUUID,
		}

		listeners := properties["loadBalancingRules"].([]interface{})
		backendAddressPoolToPorts := map[string][]string{}
		for _, backend := range properties["backendAddressPools"].([]interface{}) {
			backendName := backend.(map[string]interface{})["resourceRef"].(string)
			for _, port := range backend.(map[string]interface{})["properties"].(map[string]interface{})["backendIPConfigurations"].([]interface{}) {
				backendAddressPoolToPorts[backendName] = append(backendAddressPoolToPorts[backendName], port.(map[string]interface{})["resourceRef"].(string))
			}
		}
		tmpListeners := []model.LBListener{}
		tmpServers := []model.LBTargetServer{}
		for _, listener := range listeners {
			lbListener := listener.(map[string]interface{})
			lbListenerProperties := lbListener["properties"].(map[string]interface{})
			if ok := checkAttributes(lbListener, listenerAttrs); !ok {
				continue
			}
			if ok := checkAttributes(lbListener, listenerAttrs2); !ok {
				continue
			}
			lbListenerUUID := lbListener["resourceId"].(string)
			if len(lbListenerUUID) != 36 {
				lbListenerUUID = common.GenerateUUID(lbUUID + lbListenerUUID)
			}
			protocol := strings.ToUpper(lbListenerProperties["protocol"].(string))
			lbListenerName := lbListener["resourceMetadata"].(map[string]interface{})["resourceName"].(string)
			if lbListenerName == "" {
				lbListenerName = lbListenerUUID
			}
			tmpListeners = append(tmpListeners, model.LBListener{
				Lcuuid:   lbListenerUUID,
				LBLcuuid: lbUUID,
				IPs:      strings.Join(lbIPs, ","),
				Name:     lbListenerName,
				Port:     lbListenerProperties["frontendPort"].(int),
				Protocol: protocol,
			})
			ref := lbListenerProperties["backendAddressPool"].(map[string]interface{})["resourceRef"].(string)
			vmPorts, ok := backendAddressPoolToPorts[ref]
			if !ok {
				vmPorts = []string{}
			}
			for _, port := range vmPorts {
				portUUID := strings.Split(port, "/")[2]
				if _, ok := m.rm.PortIdToVpcVmIP[portUUID]; !ok {
					log.Debugf("LB server port id (%s) not found", portUUID)
					continue
				}
				vpcVMIP := m.rm.PortIdToVpcVmIP[portUUID]
				tmpServers = append(tmpServers, model.LBTargetServer{
					Lcuuid:           common.GenerateUUID(lbListenerUUID + vpcVMIP[2]),
					LBLcuuid:         lbUUID,
					LBListenerLcuuid: lbListenerUUID,
					Type:             common.LB_SERVER_TYPE_VM,
					VMLcuuid:         vpcVMIP[1],
					IP:               vpcVMIP[2],
					Port:             lbListenerProperties["backendPort"].(int),
					VPCLcuuid:        vpcUUID,
				})
			}
		}
		if vpcUUID == "" {
			log.Debugf("LB (%s) vpc not found", lbUUID)
			continue
		}
		regionUUID := m.rm.VpcIdToRegion[vpcUUID]
		azUUID := m.rm.VpcIdToAz[vpcUUID]
		if regionUUID == "" {
			log.Debugf("LB (%s) az not found", lbUUID)
			continue
		}
		lbResource.VPCLcuuid = vpcUUID
		lbResource.AZLcuuid = azUUID
		lbResource.RegionLcuuid = m.getRegionLcuuid(regionUUID)
		lbs = append(lbs, lbResource)
		lbListeners = append(lbListeners, tmpListeners...)
		lbTargetServers = append(lbTargetServers, tmpServers...)
		for _, lbIP := range lbIPs {
			portUUID := common.GenerateUUID(lbResource.Lcuuid + lbIP)
			portType := common.VIF_TYPE_WAN
			networkUUID := common.NETWORK_ISP_LCUUID
			subnetUUID := common.GenerateUUID(common.NETWORK_ISP_LCUUID)
			if lbModel == common.LB_MODEL_INTERNAL {
				portType = common.VIF_TYPE_LAN
				subnets := m.rm.VpcIdToSubnets[vpcUUID]
				isFindNetwork := false
				for _, subnet := range subnets {
					if isIpInCidr(lbIP, subnet[1]) {
						networkUUID = common.GenerateUUID(vpcUUID)
						isFindNetwork = true
						break
					}
				}
				if !isFindNetwork {
					log.Debugf("LB (%s) ip (%s) network not found", lbUUID, lbIP)
					continue
				}
			}
			ports = append(ports, model.VInterface{
				Lcuuid:        portUUID,
				Type:          portType,
				Mac:           common.VIF_DEFAULT_MAC,
				DeviceLcuuid:  lbUUID,
				DeviceType:    common.VIF_DEVICE_TYPE_LB,
				NetworkLcuuid: networkUUID,
				VPCLcuuid:     vpcUUID,
				RegionLcuuid:  m.getRegionLcuuid(regionUUID),
			})
			ips = append(ips, model.IP{
				Lcuuid:           common.GenerateUUID(portUUID + lbIP),
				VInterfaceLcuuid: portUUID,
				IP:               lbIP,
				SubnetLcuuid:     subnetUUID,
				RegionLcuuid:     m.getRegionLcuuid(regionUUID),
			})
		}
	}
	for _, portIP := range publicIdToPortIp {
		if portIP[0] == "" {
			log.Debugf("Floating ip (%s) vm not found", portIP[1])
			continue
		}
		portUUID := strings.Split(portIP[0], "/")[2]
		vpcVMIP := m.rm.PortIdToVpcVmIP[portUUID]
		vpcUUID := vpcVMIP[0]
		regionUUID := m.rm.VpcIdToRegion[vpcUUID]
		if regionUUID == "" {
			log.Debugf("Floating ip (%s) region not found", portIP[1])
			continue
		}
		floatingIPs = append(floatingIPs, model.FloatingIP{
			Lcuuid:        common.GenerateUUID(vpcVMIP[1] + portIP[1]),
			IP:            portIP[1],
			VMLcuuid:      vpcVMIP[1],
			NetworkLcuuid: common.NETWORK_ISP_LCUUID,
			VPCLcuuid:     vpcUUID,
			RegionLcuuid:  m.getRegionLcuuid(regionUUID),
		})
	}
	log.Debug("Get load_balances and nats complete")

	return lbs, lbListeners, lbTargetServers, nats, natRules, ports, ips, floatingIPs
}

func (m *MicrosoftAcs) getSecurityGroupsAndRules() (sgs []model.SecurityGroup, sgRules []model.SecurityGroupRule, vmSGs []model.VMSecurityGroup) {
	log.Debug("Get security_group_and_rules starting")

	vmSGUUIDs := []string{}
	vmIdToPriority := map[string]int{}

	sgAttrs := []string{"ResourceId", "Properties"}
	ruleAttrs := []string{
		"Protocol", "SourcePortRange", "DestinationPortRange", "Action",
		"SourceAddressPrefix", "DestinationAddressPrefix", "Priority", "Type",
	}
	data, err := readConfig(m.FileDir, "NetworkSecurityGroup.txt")
	if err != nil {
		// TODO
		return sgs, sgRules, vmSGs
	}
	for _, sg := range data {
		if ok := checkAttributes(sg, sgAttrs); !ok {
			continue
		}
		properties := sg["Properties"].(map[string]interface{})
		subnets := properties["Subnets"]
		sgUUID := sg["ResourceId"].(string)
		if subnets == nil || len(subnets.([]interface{})) == 0 {
			log.Debugf("NSG (%s) subnets not found", sgUUID)
			continue
		}
		regionUUID := ""
		if len(sgUUID) != 36 {
			sgUUID = common.GenerateUUID(m.uuidGenerate + sgUUID)
		}
		for _, s := range subnets.([]interface{}) {
			subnet := s.(map[string]interface{})
			portUUIDs := m.rm.VirtualSubnetToPortIds[subnet["ResourceRef"].(string)]
			for _, portUUID := range portUUIDs {
				portRegionVm, ok := m.rm.PortIdToRegionVm[portUUID]
				vmUUID := ""
				if ok {
					vmUUID = portRegionVm[1]
				}
				vmSGUUID := common.GenerateUUID(sgUUID + vmUUID)
				if vmUUID != "" && !findStrInArray(vmSGUUID, vmSGUUIDs) {
					vmSGs = append(vmSGs, model.VMSecurityGroup{
						Lcuuid:              vmSGUUID,
						SecurityGroupLcuuid: sgUUID,
						VMLcuuid:            vmUUID,
						Priority:            vmIdToPriority[vmUUID],
					})
					vmIdToPriority[vmUUID] += 1
				}
			}
		}
		if regionUUID == "" {
			log.Debugf("NSG (%s) region not found", sgUUID)
			continue
		}
		sgName := ""
		if sg["ResourceMetadata"] != nil {
			resourceName := sg["ResourceMetadata"].(map[string]interface{})["ResourceName"]
			if resourceName != nil {
				sgName = resourceName.(string)
			}
		}
		if sgName == "" {
			sgName = sgUUID
		}
		sgs = append(sgs, model.SecurityGroup{
			Lcuuid:       sgUUID,
			Name:         sgName,
			VPCLcuuid:    "",
			RegionLcuuid: m.getRegionLcuuid(regionUUID),
		})
		aclRules := properties["AclRules"].([]interface{})
		for _, aclRule := range aclRules {
			rule := aclRule.(map[string]interface{})
			ruleProperties := rule["Properties"].(map[string]interface{})
			if ok := checkAttributes(ruleProperties, ruleAttrs); !ok {
				continue
			}
			ruleUUID := rule["ResourceId"].(string)
			protocol := strings.ToUpper(ruleProperties["Protocol"].(string))
			direction := common.SECURITY_GROUP_RULE_EGRESS
			local := ruleProperties["SourceAddressPrefix"].(string)
			remote := ruleProperties["DestinationAddressPrefix"].(string)
			if ruleProperties["Type"].(string) == "Inbound" {
				direction = common.SECURITY_GROUP_RULE_INGRESS
				local = ruleProperties["DestinationAddressPrefix"].(string)
				remote = ruleProperties["SourceAddressPrefix"].(string)
			}
			if local == "*" {
				local = common.SECURITY_GROUP_RULE_IPV4_CIDR
			}
			if remote == "*" {
				remote = common.SECURITY_GROUP_RULE_IPV4_CIDR
			}
			localPortRange := ruleProperties["SourcePortRange"].(string)
			if localPortRange == "*" {
				localPortRange = "0-65535"
			}
			remotePortRange := ruleProperties["DestinationPortRange"].(string)
			if remotePortRange == "*" {
				remotePortRange = "0-65535"
			}
			action := common.SECURITY_GROUP_RULE_ACCEPT
			if ruleProperties["Action"].(string) == "Deby" {
				action = common.SECURITY_GROUP_RULE_DROP
			}
			priority, _ := strconv.Atoi(ruleProperties["Priority"].(string))
			sgRules = append(sgRules, model.SecurityGroupRule{
				Lcuuid:              common.GenerateUUID(sgUUID + ruleUUID),
				SecurityGroupLcuuid: sgUUID,
				Direction:           direction,
				EtherType:           common.SECURITY_GROUP_RULE_IPV4,
				Protocol:            protocol,
				LocalPortRange:      localPortRange,
				RemotePortRange:     remotePortRange,
				Local:               firstUpper(local),
				Remote:              firstUpper(remote),
				Priority:            priority,
				Action:              action,
			})
		}
		for _, direction := range []int{common.SECURITY_GROUP_RULE_INGRESS, common.SECURITY_GROUP_RULE_EGRESS} {
			for _, ethertype := range []int{common.SECURITY_GROUP_RULE_IPV4, common.SECURITY_GROUP_RULE_IPV6} {
				remote := common.SECURITY_GROUP_RULE_IPV6_CIDR
				if ethertype == common.SECURITY_GROUP_RULE_IPV4 {
					remote = common.SECURITY_GROUP_RULE_IPV4_CIDR
				}
				sgRules = append(sgRules, model.SecurityGroupRule{
					Lcuuid:              common.GenerateUUID(sgUUID + strconv.Itoa(direction) + remote),
					SecurityGroupLcuuid: sgUUID,
					Direction:           direction,
					EtherType:           ethertype,
					Protocol:            "ALL",
					LocalPortRange:      "0-65535",
					RemotePortRange:     "0-65535",
					Local:               remote,
					Remote:              remote,
					Priority:            100000,
					Action:              common.SECURITY_GROUP_RULE_DROP,
				})
			}
		}

	}

	log.Debug("Get security_group_and_rules complete")
	return sgs, sgRules, vmSGs
}

func (m *MicrosoftAcs) getPeerConnections() (peerConnections []model.PeerConnection) {
	log.Debug("Get peer-connections starting")
	peerUUIDs := []string{}
	attrs := []string{"ResourceId", "Properties"}
	data, err := readConfig(m.FileDir, "VirtualNetwork.txt")
	if err != nil {
		// TODO
		return peerConnections
	}
	for _, network := range data {
		if properties, ok := network["Properties"]; ok {
			if subnets, ok := properties.(map[string]interface{})["Subnets"]; ok && subnets != nil {
				for _, s := range subnets.([]interface{}) {
					subnet := s.(map[string]interface{})
					property := subnet["Properties"]
					if property == nil {
						continue
					}
					ipConfigurations := property.(map[string]interface{})["IpConfigurations"]
					if ipConfigurations == nil {
						continue
					}
					for _, port := range ipConfigurations.([]interface{}) {
						portUUID := strings.Split(port.(map[string]interface{})["ResourceRef"].(string), "/")[2]
						subnetResourceRef := subnet["ResourceRef"].(string)
						m.rm.VirtualSubnetToPortIds[subnetResourceRef] = append(m.rm.VirtualSubnetToPortIds[subnetResourceRef], portUUID)
					}
				}
			}
		}
		if ok := checkAttributes(network, attrs); !ok {
			continue
		}
		properties := network["Properties"].(map[string]interface{})
		remotePeers := properties["VirtualNetworkPeerings"]
		vnetUUID := ""
		if _, ok := network["ResourceId"]; ok && network["ResourceId"] != nil {
			vnetUUID = network["ResourceId"].(string)
		}
		if remotePeers == nil {
			continue
		}
		regionUUID := m.rm.VnetIdToRegion[vnetUUID]
		vpcUUID, vpcOk := m.rm.VnetIdToVpc[vnetUUID]
		if !vpcOk {
			log.Debugf("Peer (%s) vpc not found", vnetUUID)
			continue
		}
		for _, rp := range remotePeers.([]interface{}) {
			remotePeer := rp.(map[string]interface{})
			if ok := checkAttributes(remotePeer, attrs); !ok {
				continue
			}
			remoteVnet := "//"
			if remotePeer["Properties"] != nil && remotePeer["Properties"].(map[string]interface{})["RemoteVirtualNetwork"] != nil {
				remoteVnet = remotePeer["Properties"].(map[string]interface{})["RemoteVirtualNetwork"].(map[string]interface{})["ResourceRef"].(string)
			}
			remoteVnet = strings.Split(remoteVnet, "/")[2]
			remoteRegionUUID := m.rm.VnetIdToRegion[remoteVnet]
			remoteVpcUUID, vpcOk := m.rm.VnetIdToVpc[remoteVnet]
			if !vpcOk {
				log.Debugf("Peer remote vpc (%s) not found", remoteVnet)
				continue
			}
			peerUUID := common.GenerateUUID(vpcUUID + remoteVpcUUID)
			peerUUIDRever := common.GenerateUUID(remoteVpcUUID + vpcUUID)
			if findStrInArray(peerUUID, peerUUIDs) || findStrInArray(peerUUIDRever, peerUUIDs) {
				continue
			}
			peerConnections = append(peerConnections, model.PeerConnection{
				Lcuuid:             peerUUID,
				Name:               vnetUUID,
				Label:              vnetUUID,
				RemoteVPCLcuuid:    remoteVpcUUID,
				LocalVPCLcuuid:     vpcUUID,
				RemoteRegionLcuuid: m.getRegionLcuuid(remoteRegionUUID),
				LocalRegionLcuuid:  m.getRegionLcuuid(regionUUID),
			})
		}
	}
	log.Debug("Get peer-connections complete")
	return peerConnections
}

func (m *MicrosoftAcs) getVMsPortsIPs() (subnets []model.Subnet, vms []model.VM, ports []model.VInterface, ips []model.IP) {
	log.Debug("Get vms starting")
	attrs := []string{"VMId", "Name", "HostId", "VirtualNetworkAdapters"}
	portAttrs := []string{"ID", "MACAddress", "VMSubnet", "VMNetwork", "IPv4Addresses"}

	data, err := readConfig(m.FileDir, "VM.txt")
	if err != nil {
		// TODO
		return subnets, vms, ports, ips
	}
	for _, vm := range data {
		if ok := checkAttributes(vm, attrs); !ok {
			continue
		}
		hostUUID := vm["HostId"].(string)
		hostIP, ok := m.rm.HostIdToIp[hostUUID]
		vmName := vm["Name"].(string)
		vmUUID := vm["VMId"].(string)
		if !ok {
			log.Debugf("VM (%s) host not found", vmName)
			continue
		}
		regionUUID, ok := m.rm.HostIdToRegion[hostUUID]
		if !ok {
			log.Debugf("VM (%s) region not found", vmName)
			continue
		}
		azUUID := m.rm.HostIdToAZ[hostUUID]
		vmIdToVpcId := map[string]string{}
		htype := common.VM_HTYPE_VM_C
		vmPorts, ok := vm["VirtualNetworkAdapters"]
		if !ok {
			continue
		}
		for _, port := range vmPorts.([]map[string]interface{}) {
			if ok := checkAttributes(port, portAttrs); !ok {
				continue
			}
			mac := port["MACAddress"].(string)
			ip := port["IPv4Addresses"].(string)
			if ip == "" {
				log.Debugf("Port (%s) ip not found", mac)
				continue
			}
			portUUID := port["ID"].(string)
			vpcName := port["VMNetwork"].(string)
			subnetName := port["VMSubnet"].(string)
			vpcUUID, vpcOk := m.rm.VpcNameToId[vpcName]
			networkUUID := common.GenerateUUID(vpcUUID)
			subnetUUID, subnetOk := m.rm.SubnetNameToId[subnetName]
			logicalNetworkName := port["LogicalNetwork"].(string)
			external := m.rm.LogicalNetworkNameToExternal[logicalNetworkName]
			if !vpcOk || !subnetOk {
				find := false
				for _, networks := range m.rm.VpcIdToHostNetworks {
					for _, hostSubnets := range networks {
						for _, subnet := range hostSubnets {
							if isIpInCidr(ip, subnet[1]) {
								find = true
								break
							}
						}
						if find {
							break
						}
					}
					if find {
						break
					}
				}
				if !find {
					vpcUUID = ""
				}
			}
			if vpcUUID == "" || strings.Contains(vmName, "MUX") || strings.Contains(vmName, "GW") {
				if strings.Contains(vmName, "MUX") || strings.Contains(vmName, "GW") {
					htype = common.VM_HTYPE_VM_N
				}
				vpcUUID = common.GenerateUUID(regionUUID + "basic_vpc")
				networkUUID = common.GenerateUUID(regionUUID + "basic_network")
				networkSubnets, ok := m.rm.NetworkIdToSubnets[networkUUID]
				if ok {
					ipInSubnetsFlag := false
					for _, subnets := range networkSubnets {
						if isIpInCidr(ip, subnets[1]) {
							ipInSubnetsFlag = true
							break
						}
					}
					if !ipInSubnetsFlag {
						cidr := strings.Split(port["IPv4Subnets"].(string), " ")[0]
						if cidr == "" {
							log.Debugf("Port (%s-%s) cidr not found", mac, ip)
							continue
						}
						subnetUUID := common.GenerateUUID(networkUUID + cidr)
						subnets = append(subnets, model.Subnet{
							Lcuuid:        subnetUUID,
							Name:          cidr,
							CIDR:          cidr,
							NetworkLcuuid: networkUUID,
							VPCLcuuid:     vpcUUID,
						})
						m.rm.NetworkIdToSubnets[networkUUID] = append(m.rm.NetworkIdToSubnets[networkUUID], []string{subnetUUID, cidr})
					}
				}
			}
			if !external {
				if nameAndExternanl, ok := m.rm.NetworkIdToNameExternal[networkUUID]; ok {
					external = nameAndExternanl[1].(bool)
				}
			}
			vmIdToVpcId[vmUUID] = vpcUUID
			portType := common.VIF_TYPE_LAN
			if external {
				portType = common.VIF_TYPE_WAN
			}
			ports = append(ports, model.VInterface{
				Lcuuid:        portUUID,
				Type:          portType,
				Mac:           mac,
				DeviceLcuuid:  vmUUID,
				DeviceType:    common.VIF_DEVICE_TYPE_VM,
				NetworkLcuuid: networkUUID,
				VPCLcuuid:     vpcUUID,
				RegionLcuuid:  m.getRegionLcuuid(regionUUID),
			})
			ips = append(ips, model.IP{
				Lcuuid:           common.GenerateUUID(portUUID + ip),
				VInterfaceLcuuid: portUUID,
				IP:               ip,
				SubnetLcuuid:     subnetUUID,
				RegionLcuuid:     m.getRegionLcuuid(regionUUID),
			})
			m.rm.PortIdToVpcVmIP[portUUID] = []string{vpcUUID, vmUUID, ip}
			m.rm.PortIdToRegionVm[portUUID] = []string{regionUUID, vmUUID}
		}
		if _, ok := vmIdToVpcId[vmUUID]; !ok {
			log.Debugf("VM (%s) vpc not found", vmName)
			continue
		}
		createdTimestamp, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(vm["CreationTime"].(string), "/Date("), ")/"))
		createdStr := time.Unix(int64(createdTimestamp/1000), 0).Format(time.RFC3339)
		createdAt, _ := time.Parse(time.RFC3339, createdStr)
		vmStateStr := vm["StatusString"].(string)
		vmState, ok := VM_STATES[vmStateStr]
		if !ok {
			vmState = common.VM_STATE_EXCEPTION
		}
		vms = append(vms, model.VM{
			Lcuuid:       vmUUID,
			Name:         vmName,
			Label:        vmName,
			VPCLcuuid:    vmIdToVpcId[vmUUID],
			State:        vmState,
			HType:        htype,
			LaunchServer: hostIP,
			CreatedAt:    createdAt,
			AZLcuuid:     azUUID,
			RegionLcuuid: m.getRegionLcuuid(regionUUID),
		})
		if htype == common.VM_HTYPE_VM_N {
			m.rm.IPsForTypeGateway = append(m.rm.IPsForTypeGateway, hostIP)
		}
	}
	log.Debug("Get vms complete")
	return subnets, vms, ports, ips
}

func (m *MicrosoftAcs) getHostPorts() (subnets []model.Subnet, ports []model.VInterface, ips []model.IP) {
	log.Debug("Get host-ports starting")
	attrs := []string{"ID", "MACAddress", "IPv4Addresses"}

	data, err := readConfig(m.FileDir, "VMHost-Port.txt")
	if err != nil {
		// TODO
		return subnets, ports, ips
	}

	portUUIDs := []string{}
	var hostID string
	for _, port := range data {
		if _, ok := port["MACAddress"]; !ok {
			hostID = port["ID"].(string)
		} else {
			port["HostID"] = hostID
		}
	}
	for _, port := range data {
		if ok := checkAttributes(port, attrs); !ok {
			continue
		}
		if _, ok := port["MACAddress"]; !ok {
			continue
		}
		portIPs := port["IPv4Addresses"].([]interface{})
		for _, ip := range portIPs {
			for vpcUUID, hostNetworks := range m.rm.VpcIdToHostNetworks {
				regionUUID := m.rm.VpcIdToRegion[vpcUUID]
				regionUUID = m.getRegionLcuuid(regionUUID)
				for networkUUID, hostSubnets := range hostNetworks {
					// []interface{networkName, external}
					networkNameExternal := m.rm.NetworkIdToNameExternal[networkUUID]
					for _, hostSubnet := range hostSubnets {
						subnetUUID := hostSubnet[0]
						cidr := hostSubnet[1]
						if isIpInCidr(ip.(string), cidr) {
							macAddress := port["MACAddress"].(string)
							portUUID := m.getRegionLcuuid(subnetUUID + macAddress)
							portType := common.VIF_TYPE_LAN
							if networkNameExternal[1].(bool) {
								// external == true
								portType = common.VIF_TYPE_WAN
							}
							if !findStrInArray(portUUID, portUUIDs) {
								portUUIDs = append(portUUIDs, portUUID)
								ports = append(ports, model.VInterface{
									Lcuuid:        portUUID,
									Type:          portType,
									Mac:           macAddress,
									DeviceLcuuid:  port["HostID"].(string),
									DeviceType:    common.VIF_DEVICE_TYPE_HOST,
									NetworkLcuuid: networkUUID,
									VPCLcuuid:     vpcUUID,
									RegionLcuuid:  regionUUID,
								})
							}
							ips = append(ips, model.IP{
								Lcuuid:           common.GenerateUUID(portUUID),
								VInterfaceLcuuid: portUUID,
								IP:               ip.(string),
								SubnetLcuuid:     subnetUUID,
								RegionLcuuid:     regionUUID,
							})
						}
					}
				}
			}
		}
	}
	for hostUUID, hostIPS := range m.rm.HostIdToIps {
		if _, ok := m.rm.HostIdToIp[hostUUID]; !ok {
			hostToIpFlag := false
			for _, ip := range hostIPS {
				for _, networkCidr := range m.hostManageNetworkCidrs {
					if isIpInCidr(ip, networkCidr) {
						m.rm.HostIdToIp[hostUUID] = ip
						hostToIpFlag = true
						break
					}
				}
				if _, ok := m.rm.HostIdToIp[hostUUID]; !ok {
					hostToIpFlag = true
					break
				}
			}
			if !hostToIpFlag && len(hostIPS) > 0 {
				m.rm.HostIdToIp[hostUUID] = hostIPS[0]
			}
		}
	}

	attrs = []string{"Address", "MacAddress", "PrefixLength", "PSComputerName"}
	data, err = readConfig(m.FileDir, "VMHost-ProviderAddress.txt")
	if err != nil {
		// TODO
		return subnets, ports, ips
	}
	for _, port := range data {
		if ok := checkAttributes(port, attrs); !ok {
			continue
		}
		portMacAddress := port["MacAddress"].(string)
		hostName := port["PSComputerName"].(string)
		hostUUID, ok := m.rm.HostNameToId[hostName]
		if !ok {
			log.Debugf("Port (%s) host not found", portMacAddress)
			continue
		}
		regionUUID := generateRegionUUID(m.uuidGenerate, hostName)
		vpcUUID := common.GenerateUUID(regionUUID + "basic_vpc")
		networkUUID := common.GenerateUUID(regionUUID + "basic_network")
		if _, ok := m.rm.NetworkIdToSubnets[networkUUID]; !ok {
			m.rm.NetworkIdToSubnets[networkUUID] = [][]string{}
		}
		portAddress := port["Address"].(string)
		portMask := strconv.Itoa(int(port["PrefixLength"].(float64)))
		ipInSubnetsFlag := false
		for _, subnet := range m.rm.NetworkIdToSubnets[networkUUID] {
			cidr := subnet[1]
			if isIpInCidr(portAddress, cidr) {
				ipInSubnetsFlag = true
			}
		}
		if !ipInSubnetsFlag {
			_, ipNet, err := net.ParseCIDR(portAddress + "/" + portMask)
			if err != nil {
				log.Errorf("portAddress(%s), portPrefixLength(%s) parse cidr error", portAddress, portMask)
				continue
			}
			cidr := ipNet.String()
			subnetLcuuid := common.GenerateUUID(networkUUID + cidr)
			subnets = append(subnets, model.Subnet{
				Lcuuid:        subnetLcuuid,
				Name:          cidr,
				CIDR:          cidr,
				NetworkLcuuid: networkUUID,
				VPCLcuuid:     vpcUUID,
			})
			m.rm.NetworkIdToSubnets[networkUUID] = append(m.rm.NetworkIdToSubnets[networkUUID], []string{subnetLcuuid, cidr})
		}
		mac := strings.ReplaceAll(portMacAddress, "-", ":")
		portUUID := common.GenerateUUID(hostUUID + mac)
		ports = append(ports, model.VInterface{
			Lcuuid:        portUUID,
			Type:          common.VIF_TYPE_LAN,
			Mac:           mac,
			DeviceLcuuid:  hostUUID,
			DeviceType:    common.VIF_DEVICE_TYPE_HOST,
			NetworkLcuuid: networkUUID,
			VPCLcuuid:     vpcUUID,
			RegionLcuuid:  m.getRegionLcuuid(regionUUID),
		})
	}
	log.Debug("Get host-ports complete")
	return subnets, ports, ips
}

func (m *MicrosoftAcs) getHostNetowrks() (networks []model.Network, subnets []model.Subnet) {
	log.Debug("Get host-networks starting")
	data, err := readConfig(m.FileDir, "VMHost-Network.txt")
	if err != nil {
		// TODO
		return networks, subnets
	}
	networkUUIDS := []string{}
	attrs := []string{"ID", "Name", "LogicalNetwork", "ServerConnection", "SubnetVLans"}
	for _, network := range data {
		if ok := checkAttributes(network, attrs); !ok {
			continue
		}
		regionName := strings.ToLower(network["ServerConnection"].(map[string]interface{})["FQDN"].(string))
		regionUUID := generateRegionUUID(m.uuidGenerate, regionName)
		azUUID := common.GenerateUUID(regionUUID)
		logicalNetwork := network["LogicalNetwork"].(map[string]interface{})
		networkUUID := logicalNetwork["ID"].(string)
		networkName := logicalNetwork["Name"].(string)
		external := false
		if isExternal, ok := m.rm.LogicalNetworkNameToExternal[networkName]; ok {
			external = isExternal
		}
		var vpcUUID string
		if uuid, ok := m.rm.LogicalNetworkIdToVpc[networkUUID]; !ok {
			log.Debugf("Host network (%s) vpc not found", networkName)
			continue
		} else {
			vpcUUID = uuid
		}
		if !findStrInArray(networkUUID, networkUUIDS) {
			networkUUIDS = append(networkUUIDS, networkUUID)
			networkNetType := common.NETWORK_TYPE_LAN
			if external {
				networkNetType = common.NETWORK_TYPE_WAN
			}
			networks = append(networks, model.Network{
				Lcuuid:         networkUUID,
				Name:           networkName,
				SegmentationID: 1,
				VPCLcuuid:      vpcUUID,
				Shared:         false,
				External:       false,
				NetType:        networkNetType,
				AZLcuuid:       azUUID,
				RegionLcuuid:   m.getRegionLcuuid(regionUUID),
			})
		}
		if _, ok := m.rm.VpcIdToHostNetworks[vpcUUID]; !ok {
			m.rm.VpcIdToHostNetworks[vpcUUID] = map[string][][]string{}
			m.rm.VpcIdToHostNetworks[vpcUUID][networkUUID] = [][]string{}
		}
		if _, ok := m.rm.VpcIdToRegion[vpcUUID]; !ok {
			m.rm.VpcIdToRegion[vpcUUID] = regionUUID
		}
		if _, ok := m.rm.VpcIdToAz[vpcUUID]; !ok {
			m.rm.VpcIdToAz[vpcUUID] = azUUID
		}
		m.rm.NetworkIdToNameExternal[networkUUID] = []interface{}{networkName, external}

		var cidrs []interface{}
		if subnetVLans, ok := network["SubnetVLans"]; ok {
			cidrs = subnetVLans.([]interface{})
		}
		for _, cidr := range cidrs {
			cidrStr := strings.Split(cidr.(string), "-")[0]
			subnetUUID := common.GenerateUUID(networkUUID + cidrStr)
			subnets = append(subnets, model.Subnet{
				Lcuuid:        subnetUUID,
				Name:          networkName,
				CIDR:          cidrStr,
				NetworkLcuuid: networkUUID,
				VPCLcuuid:     vpcUUID,
			})
			m.rm.VpcIdToHostNetworks[vpcUUID][networkUUID] = append(m.rm.VpcIdToHostNetworks[vpcUUID][networkUUID], []string{subnetUUID, cidrStr})
		}
	}
	log.Debug("Get host-networks complete")

	return networks, subnets
}

func (m *MicrosoftAcs) getVpcAndNetworks() (vpcs []model.VPC, networks []model.Network, subnets []model.Subnet) {
	data, err := readConfig(m.FileDir, "VMNetwork.txt")
	if err != nil {
		// TODO
		return nil, nil, nil
	}
	attrs := []string{"ID", "Name", "LogicalNetwork", "ServerConnection", "VMSubnet"}
	subnetAttrs := []string{"ID", "Name", "SubnetVLans"}
	for _, vpc := range data {
		if ok := checkAttributes(vpc, attrs); !ok {
			continue
		}
		regionName := strings.ToLower(vpc["ServerConnection"].(map[string]interface{})["FQDN"].(string))
		regionUUID := generateRegionUUID(m.uuidGenerate, regionName)
		azUUID := common.GenerateUUID(regionUUID)
		vpcUUID := vpc["ID"].(string)
		vpcName := vpc["Name"].(string)
		vpcs = append(vpcs, model.VPC{
			Lcuuid:       vpcUUID,
			Name:         vpcName,
			AZLcuuid:     azUUID,
			RegionLcuuid: m.getRegionLcuuid(regionUUID),
		})
		vpcExternalId := ""
		if _, ok := vpc["ExternalId"]; ok && vpc["ExternalId"] != nil {
			vpcExternalId = vpc["ExternalId"].(string)
		}
		m.rm.VnetIdToRegion[vpcExternalId] = regionUUID
		m.rm.VnetIdToVpc[vpcExternalId] = vpcUUID
		m.rm.VpcIdToRegion[vpcUUID] = regionUUID
		m.rm.VpcIdToAz[vpcUUID] = azUUID
		m.rm.VpcNameToId[vpcName] = vpcUUID
		networkUUID := common.GenerateUUID(vpcUUID)
		localNetwork := vpc["LogicalNetwork"].(map[string]interface{})
		external := localNetwork["IsPublicIPNetwork"].(bool)
		m.rm.LogicalNetworkNameToExternal[localNetwork["Name"].(string)] = external
		m.rm.LogicalNetworkIdToVpc[localNetwork["ID"].(string)] = vpcUUID

		networkNetType := common.NETWORK_TYPE_LAN
		if external {
			networkNetType = common.NETWORK_TYPE_WAN
		}
		networks = append(networks, model.Network{
			Lcuuid:         networkUUID,
			Name:           vpcName,
			SegmentationID: 1,
			VPCLcuuid:      vpcUUID,
			Shared:         false,
			External:       false,
			NetType:        networkNetType,
			AZLcuuid:       azUUID,
			RegionLcuuid:   m.getRegionLcuuid(regionUUID),
		})
		m.rm.VpcIdToSubnets[vpcUUID] = [][]string{}
		var vmSubnets []interface{}
		if vpcVmSubnet, ok := vpc["VMSubnet"]; ok {
			vmSubnets = vpcVmSubnet.([]interface{})
		}
		for _, vmSubnet := range vmSubnets {
			subnet, ok := vmSubnet.(map[string]interface{})
			if !ok {
				continue
			}
			if ok := checkAttributes(subnet, subnetAttrs); !ok {
				continue
			}
			cidr := strings.Split(subnet["SubnetVLans"].(string), "-")[0]
			subnetUUID := subnet["ID"].(string)
			subnetName := subnet["Name"].(string)
			subnets = append(subnets, model.Subnet{
				Lcuuid:        subnetUUID,
				Name:          subnetName,
				CIDR:          cidr,
				NetworkLcuuid: networkUUID,
				VPCLcuuid:     vpcUUID,
			})
			m.rm.SubnetNameToId[subnetName] = subnetUUID
			m.rm.VpcIdToSubnets[vpcUUID] = append(m.rm.VpcIdToSubnets[vpcUUID], []string{
				subnetUUID, cidr,
			})
		}
	}
	log.Debug("Get vpcs,networks complete")
	return vpcs, networks, subnets
}

func (m *MicrosoftAcs) getHosts() (regions []model.Region, azs []model.AZ, hosts []model.Host, vpcs []model.VPC, networks []model.Network) {
	data, err := readConfig(m.FileDir, "VMHost.txt")
	if err != nil {
		// TODO
		return nil, nil, nil, nil, nil
	}
	attrs := []string{"ID", "Name", "DomainName"}
	regionNames := []string{}
	for _, host := range data {
		if ok := checkAttributes(host, attrs); !ok {
			continue
		}
		regionUUID := common.GenerateUUID(m.uuidGenerate + host["DomainName"].(string))
		azUUID := common.GenerateUUID(regionUUID)
		regionName := strings.ToLower(host["DomainName"].(string))
		if !findStrInArray(regionName, regionNames) {
			regionNames = append(regionNames, regionName)
			regions = append(regions, model.Region{
				Lcuuid: regionUUID,
				Name:   regionName,
			})
			azs = append(azs, model.AZ{
				Lcuuid:       azUUID,
				Name:         regionName,
				RegionLcuuid: m.getRegionLcuuid(regionUUID),
			})
			vpcName := m.name + "_" + regionName + "_基础VPC"
			vpcUUID := common.GenerateUUID(regionUUID + "basic_vpc")
			vpcs = append(vpcs, model.VPC{
				Lcuuid:       vpcUUID,
				Name:         vpcName,
				AZLcuuid:     azUUID,
				RegionLcuuid: m.getRegionLcuuid(regionUUID),
			})
			networks = append(networks, model.Network{
				Lcuuid:         common.GenerateUUID(regionUUID + "basic_network"),
				Name:           vpcName + "_PA_NET",
				SegmentationID: 1,
				VPCLcuuid:      vpcUUID,
				Shared:         false,
				External:       false,
				NetType:        common.NETWORK_TYPE_LAN,
				AZLcuuid:       azUUID,
				RegionLcuuid:   m.getRegionLcuuid(regionUUID),
			})
		}
		hostCpuCount := 0
		if cpuCount, ok := host["LogicalCPUCount"]; ok && cpuCount.(float64) > 0 {
			hostCpuCount = int(cpuCount.(float64))
		}
		hostMemoryMb := 0
		if totalMemory, ok := host["TotalMemory"]; ok && totalMemory.(float64) > 0 {
			hostMemoryMb = int(totalMemory.(float64))
		}
		hostUUID := host["ID"].(string)
		hostName := host["Name"].(string)
		hosts = append(hosts, model.Host{
			Lcuuid:       hostUUID,
			Name:         hostName,
			HType:        common.HOST_HTYPE_HYPER_V,
			VCPUNum:      hostCpuCount,
			MemTotal:     hostMemoryMb,
			Type:         common.HOST_TYPE_VM,
			AZLcuuid:     azUUID,
			RegionLcuuid: m.getRegionLcuuid(regionUUID),
		})
		m.rm.HostNameToId[hostName] = hostUUID
		m.rm.HostIdToRegion[hostUUID] = regionUUID
		m.rm.HostIdToAZ[hostUUID] = azUUID

		if hostIPS, ok := host["MigrationSubnet"]; ok {
			for _, hostIP := range hostIPS.([]interface{}) {
				if i := strings.Index(hostIP.(string), ","); i >= 0 {
					m.rm.HostIdToIps[hostUUID] = append(m.rm.HostIdToIps[hostUUID], strings.Split(hostIP.(string), "/")[0])
				}
			}
		}
	}
	log.Debug("Get regions,azs,hosts complete")
	return regions, azs, hosts, vpcs, networks
}

func (m *MicrosoftAcs) getRegionLcuuid(lcuuid string) string {
	if m.regionUuid != "" {
		return m.regionUuid
	} else {
		return lcuuid
	}
}

func findStrInArray(name string, nameArray []string) bool {
	for _, n := range nameArray {
		if n == name {
			return true
		}
	}
	return false
}

func checkAttributes(data map[string]interface{}, attrs []string) bool {
	for _, attr := range attrs {
		if obj, ok := data[attr]; !ok {
			log.Infof("Attribute (%s) not in %v", attr, obj)
			return false
		}
	}
	return true
}

func readConfig(fileDir, fileName string) ([]map[string]interface{}, error) {
	filePath := fmt.Sprintf("%s%s", fileDir, fileName)
	_, err := os.Stat(filePath)
	if err != nil {
		if !os.IsExist(err) {
			return nil, fmt.Errorf("%s NOT EXIST", filePath)
		}
	}
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	charset, err := GetCharset(string(content))
	if err != nil {
		return nil, err
	}
	databyte := ConvertToByte(string(content), charset, "utf-8")
	if fileName == "PublicIP.txt" || fileName == "LB.txt" {
		data := map[string]interface{}{}
		err = json.Unmarshal(databyte, &data)
		if err != nil {
			return nil, err
		}
		if data != nil && data["values"] != nil {
			values := data["values"].([]map[string]interface{})
			return values, nil
		}
	} else {
		data := []map[string]interface{}{}
		err = json.Unmarshal(databyte, &data)
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	return nil, nil
}

func generateRegionUUID(generator, regionName string) string {
	regionName = strings.Join(strings.Split(regionName, ".")[1:], ".")
	return common.GenerateUUID(generator + regionName)
}

func isIpInCidr(ip, cidr string) bool {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Errorf("CIDR(%s) Parse Error", cidr)
		return false
	}
	if ipNet.Contains(net.ParseIP(ip)) {
		return true
	}
	return false
}

func firstUpper(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
