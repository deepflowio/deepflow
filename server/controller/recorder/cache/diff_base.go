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

package cache

import (
	"time"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	. "github.com/deepflowio/deepflow/server/controller/recorder/common"
)

// 所有资源的主要信息，用于与cloud数据比较差异，根据差异更新资源
// 应保持字段定义与cloud字段定义一致，用于在比较资源时可以抽象方法
type DiffBaseDataSet struct {
	Regions                map[string]*Region
	AZs                    map[string]*AZ
	SubDomains             map[string]*SubDomain
	Hosts                  map[string]*Host
	VMs                    map[string]*VM
	VPCs                   map[string]*VPC
	Networks               map[string]*Network
	Subnets                map[string]*Subnet
	VRouters               map[string]*VRouter
	RoutingTables          map[string]*RoutingTable
	DHCPPorts              map[string]*DHCPPort
	VInterfaces            map[string]*VInterface
	WANIPs                 map[string]*WANIP
	LANIPs                 map[string]*LANIP
	FloatingIPs            map[string]*FloatingIP
	SecurityGroups         map[string]*SecurityGroup
	SecurityGroupRules     map[string]*SecurityGroupRule
	VMSecurityGroups       map[string]*VMSecurityGroup
	NATGateways            map[string]*NATGateway
	NATVMConnections       map[string]*NATVMConnection
	NATRules               map[string]*NATRule
	LBs                    map[string]*LB
	LBVMConnections        map[string]*LBVMConnection
	LBListeners            map[string]*LBListener
	LBTargetServers        map[string]*LBTargetServer
	PeerConnections        map[string]*PeerConnection
	CENs                   map[string]*CEN
	RDSInstances           map[string]*RDSInstance
	RedisInstances         map[string]*RedisInstance
	PodClusters            map[string]*PodCluster
	PodNodes               map[string]*PodNode
	VMPodNodeConnections   map[string]*VMPodNodeConnection
	PodNamespaces          map[string]*PodNamespace
	PodIngresses           map[string]*PodIngress
	PodIngressRules        map[string]*PodIngressRule
	PodIngressRuleBackends map[string]*PodIngressRuleBackend
	PodServices            map[string]*PodService
	PodServicePorts        map[string]*PodServicePort
	PodGroups              map[string]*PodGroup
	PodGroupPorts          map[string]*PodGroupPort
	PodReplicaSets         map[string]*PodReplicaSet
	Pods                   map[string]*Pod
}

func NewDiffBaseDataSet() DiffBaseDataSet {
	return DiffBaseDataSet{
		Regions:                make(map[string]*Region),
		AZs:                    make(map[string]*AZ),
		SubDomains:             make(map[string]*SubDomain),
		Hosts:                  make(map[string]*Host),
		VMs:                    make(map[string]*VM),
		VPCs:                   make(map[string]*VPC),
		Networks:               make(map[string]*Network),
		Subnets:                make(map[string]*Subnet),
		VRouters:               make(map[string]*VRouter),
		RoutingTables:          make(map[string]*RoutingTable),
		DHCPPorts:              make(map[string]*DHCPPort),
		VInterfaces:            make(map[string]*VInterface),
		WANIPs:                 make(map[string]*WANIP),
		LANIPs:                 make(map[string]*LANIP),
		FloatingIPs:            make(map[string]*FloatingIP),
		SecurityGroups:         make(map[string]*SecurityGroup),
		SecurityGroupRules:     make(map[string]*SecurityGroupRule),
		VMSecurityGroups:       make(map[string]*VMSecurityGroup),
		NATGateways:            make(map[string]*NATGateway),
		NATVMConnections:       make(map[string]*NATVMConnection),
		NATRules:               make(map[string]*NATRule),
		LBs:                    make(map[string]*LB),
		LBVMConnections:        make(map[string]*LBVMConnection),
		LBListeners:            make(map[string]*LBListener),
		LBTargetServers:        make(map[string]*LBTargetServer),
		PeerConnections:        make(map[string]*PeerConnection),
		CENs:                   make(map[string]*CEN),
		RDSInstances:           make(map[string]*RDSInstance),
		RedisInstances:         make(map[string]*RedisInstance),
		PodClusters:            make(map[string]*PodCluster),
		PodNodes:               make(map[string]*PodNode),
		VMPodNodeConnections:   make(map[string]*VMPodNodeConnection),
		PodNamespaces:          make(map[string]*PodNamespace),
		PodIngresses:           make(map[string]*PodIngress),
		PodIngressRules:        make(map[string]*PodIngressRule),
		PodIngressRuleBackends: make(map[string]*PodIngressRuleBackend),
		PodServices:            make(map[string]*PodService),
		PodServicePorts:        make(map[string]*PodServicePort),
		PodGroups:              make(map[string]*PodGroup),
		PodGroupPorts:          make(map[string]*PodGroupPort),
		PodReplicaSets:         make(map[string]*PodReplicaSet),
		Pods:                   make(map[string]*Pod),
	}
}

func (b *DiffBaseDataSet) addRegion(dbItem *mysql.Region, seq int) {
	b.Regions[dbItem.Lcuuid] = &Region{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:  dbItem.Name,
		Label: dbItem.Label,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_REGION_EN, b.Regions[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteRegion(lcuuid string) {
	delete(b.Regions, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_REGION_EN, lcuuid))
}

func (b *DiffBaseDataSet) addAZ(dbItem *mysql.AZ, seq int) {
	b.AZs[dbItem.Lcuuid] = &AZ{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:         dbItem.Name,
		Label:        dbItem.Label,
		RegionLcuuid: dbItem.Region,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_AZ_EN, b.AZs[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteAZ(lcuuid string) {
	delete(b.AZs, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_AZ_EN, lcuuid))
}

func (b *DiffBaseDataSet) addSubDomain(dbItem *mysql.SubDomain, seq int) {
	b.SubDomains[dbItem.Lcuuid] = &SubDomain{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
	}
	log.Info(addDiffBase(RESOURCE_TYPE_SUB_DOMAIN_EN, b.SubDomains[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteSubDomain(lcuuid string) {
	delete(b.SubDomains, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_SUB_DOMAIN_EN, lcuuid))
}

func (b *DiffBaseDataSet) addHost(dbItem *mysql.Host, seq int) {
	b.Hosts[dbItem.Lcuuid] = &Host{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:         dbItem.Name,
		RegionLcuuid: dbItem.Region,
		AZLcuuid:     dbItem.AZ,
		IP:           dbItem.IP,
		HType:        dbItem.HType,
		VCPUNum:      dbItem.VCPUNum,
		MemTotal:     dbItem.MemTotal,
		ExtraInfo:    dbItem.ExtraInfo,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_HOST_EN, b.Hosts[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteHost(lcuuid string) {
	delete(b.Hosts, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_HOST_EN, lcuuid))
}

func (b *DiffBaseDataSet) addVM(dbItem *mysql.VM, seq int, toolDataSet *ToolDataSet) {
	vpcLcuuid, _ := toolDataSet.GetVPCLcuuidByID(dbItem.VPCID)
	newItem := &VM{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:         dbItem.Name,
		Label:        dbItem.Label,
		VPCLcuuid:    vpcLcuuid,
		State:        dbItem.State,
		HType:        dbItem.HType,
		LaunchServer: dbItem.LaunchServer,
		RegionLcuuid: dbItem.Region,
		AZLcuuid:     dbItem.AZ,
	}
	b.VMs[dbItem.Lcuuid] = newItem
	log.Info(addDiffBase(RESOURCE_TYPE_VM_EN, b.VMs[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteVM(lcuuid string) {
	delete(b.VMs, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_VM_EN, lcuuid))
}

func (b *DiffBaseDataSet) addVPC(dbItem *mysql.VPC, seq int) {
	b.VPCs[dbItem.Lcuuid] = &VPC{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:         dbItem.Name,
		Label:        dbItem.Label,
		TunnelID:     dbItem.TunnelID,
		CIDR:         dbItem.CIDR,
		RegionLcuuid: dbItem.Region,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_VPC_EN, b.VPCs[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteVPC(lcuuid string) {
	delete(b.VPCs, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_VPC_EN, lcuuid))
}

func (b *DiffBaseDataSet) addNetwork(dbItem *mysql.Network, seq int, toolDataSet *ToolDataSet) {
	vpcLcuuid, _ := toolDataSet.GetVPCLcuuidByID(dbItem.VPCID)
	b.Networks[dbItem.Lcuuid] = &Network{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:            dbItem.Name,
		Label:           dbItem.Label,
		TunnelID:        dbItem.TunnelID,
		NetType:         dbItem.NetType,
		SegmentationID:  dbItem.SegmentationID,
		VPCLcuuid:       vpcLcuuid,
		RegionLcuuid:    dbItem.Region,
		AZLcuuid:        dbItem.AZ,
		SubDomainLcuuid: dbItem.SubDomain,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_NETWORK_EN, b.Networks[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteNetwork(lcuuid string) {
	delete(b.Networks, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_NETWORK_EN, lcuuid))
}

func (b *DiffBaseDataSet) addSubnet(dbItem *mysql.Subnet, seq int) {
	b.Subnets[dbItem.Lcuuid] = &Subnet{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:            dbItem.Name,
		Label:           dbItem.Label,
		SubDomainLcuuid: dbItem.SubDomain,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_SUBNET_EN, b.Subnets[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteSubnet(lcuuid string) {
	delete(b.Subnets, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_SUBNET_EN, lcuuid))
}

func (b *DiffBaseDataSet) addVRouter(dbItem *mysql.VRouter, seq int, toolDataSet *ToolDataSet) {
	vpcLcuuid, _ := toolDataSet.GetVPCLcuuidByID(dbItem.VPCID)
	b.VRouters[dbItem.Lcuuid] = &VRouter{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:         dbItem.Name,
		Label:        dbItem.Label,
		VPCLcuuid:    vpcLcuuid,
		RegionLcuuid: dbItem.Region,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_VROUTER_EN, b.VRouters[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteVRouter(lcuuid string) {
	delete(b.VRouters, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_VROUTER_EN, lcuuid))
}

func (b *DiffBaseDataSet) addRoutingTable(dbItem *mysql.RoutingTable, seq int) {
	b.RoutingTables[dbItem.Lcuuid] = &RoutingTable{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Destination: dbItem.Destination,
		Nexthop:     dbItem.Nexthop,
		NexthopType: dbItem.NexthopType,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_ROUTING_TABLE_EN, b.RoutingTables[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteRoutingTable(lcuuid string) {
	delete(b.RoutingTables, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_ROUTING_TABLE_EN, lcuuid))
}

func (b *DiffBaseDataSet) addDHCPPort(dbItem *mysql.DHCPPort, seq int, toolDataSet *ToolDataSet) {
	vpcLcuuid, _ := toolDataSet.GetVPCLcuuidByID(dbItem.VPCID)
	b.DHCPPorts[dbItem.Lcuuid] = &DHCPPort{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:         dbItem.Name,
		RegionLcuuid: dbItem.Region,
		AZLcuuid:     dbItem.AZ,
		VPCLcuuid:    vpcLcuuid,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_DHCP_PORT_EN, b.DHCPPorts[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteDHCPPort(lcuuid string) {
	delete(b.DHCPPorts, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_DHCP_PORT_EN, lcuuid))
}

func (b *DiffBaseDataSet) addVInterface(dbItem *mysql.VInterface, seq int, toolDataSet *ToolDataSet) {
	var networkLcuuid string
	if dbItem.NetworkID != 0 {
		networkLcuuid, _ = toolDataSet.GetNetworkLcuuidByID(dbItem.NetworkID)
	}
	b.VInterfaces[dbItem.Lcuuid] = &VInterface{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:            dbItem.Name,
		Type:            dbItem.Type,
		TapMac:          dbItem.TapMac,
		NetworkLcuuid:   networkLcuuid,
		RegionLcuuid:    dbItem.Region,
		SubDomainLcuuid: dbItem.SubDomain,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_VINTERFACE_EN, b.VInterfaces[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteVInterface(lcuuid string) {
	delete(b.VInterfaces, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_VINTERFACE_EN, lcuuid))
}

func (b *DiffBaseDataSet) addWANIP(dbItem *mysql.WANIP, seq int, toolDataSet *ToolDataSet) {
	var subnetLcuuid string
	if dbItem.SubnetID != 0 {
		subnetLcuuid, _ = toolDataSet.GetSubnetLcuuidByID(dbItem.SubnetID)
	}
	b.WANIPs[dbItem.Lcuuid] = &WANIP{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		RegionLcuuid:    dbItem.Region,
		SubDomainLcuuid: dbItem.SubDomain,
		SubnetLcuuid:    subnetLcuuid,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_WAN_IP_EN, b.WANIPs[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteWANIP(lcuuid string) {
	delete(b.WANIPs, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_WAN_IP_EN, lcuuid))
}

func (b *DiffBaseDataSet) addLANIP(dbItem *mysql.LANIP, seq int, toolDataSet *ToolDataSet) {
	subnetLcuuid, _ := toolDataSet.GetSubnetLcuuidByID(dbItem.SubnetID)
	b.LANIPs[dbItem.Lcuuid] = &LANIP{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		SubDomainLcuuid: dbItem.SubDomain,
		SubnetLcuuid:    subnetLcuuid,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_LAN_IP_EN, b.LANIPs[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteLANIP(lcuuid string) {
	delete(b.LANIPs, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_LAN_IP_EN, lcuuid))
}

func (b *DiffBaseDataSet) addFloatingIP(dbItem *mysql.FloatingIP, seq int, toolDataSet *ToolDataSet) {
	vpcLcuuid, _ := toolDataSet.GetVPCLcuuidByID(dbItem.VPCID)
	b.FloatingIPs[dbItem.Lcuuid] = &FloatingIP{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		RegionLcuuid: dbItem.Region,
		VPCLcuuid:    vpcLcuuid,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_FLOATING_IP_EN, b.FloatingIPs[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteFloatingIP(lcuuid string) {
	delete(b.FloatingIPs, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_FLOATING_IP_EN, lcuuid))
}

func (b *DiffBaseDataSet) addSecurityGroup(dbItem *mysql.SecurityGroup, seq int) {
	b.SecurityGroups[dbItem.Lcuuid] = &SecurityGroup{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:         dbItem.Name,
		Label:        dbItem.Label,
		RegionLcuuid: dbItem.Region,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_SECURITY_GROUP_EN, b.SecurityGroups[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteSecurityGroup(lcuuid string) {
	delete(b.SecurityGroups, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_SECURITY_GROUP_EN, lcuuid))
}

func (b *DiffBaseDataSet) addSecurityGroupRule(dbItem *mysql.SecurityGroupRule, seq int) {
	b.SecurityGroupRules[dbItem.Lcuuid] = &SecurityGroupRule{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Priority:        dbItem.Priority,
		EtherType:       dbItem.EtherType,
		Local:           dbItem.Local,
		Remote:          dbItem.Remote,
		RemotePortRange: dbItem.RemotePortRange,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_SECURITY_GROUP_RULE_EN, b.SecurityGroupRules[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteSecurityGroupRule(lcuuid string) {
	delete(b.SecurityGroupRules, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_SECURITY_GROUP_RULE_EN, lcuuid))
}

func (b *DiffBaseDataSet) addVMSecurityGroup(dbItem *mysql.VMSecurityGroup, seq int) {
	b.VMSecurityGroups[dbItem.Lcuuid] = &VMSecurityGroup{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Priority: dbItem.Priority,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_VM_SECURITY_GROUP_EN, b.VMSecurityGroups[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteVMSecurityGroup(lcuuid string) {
	delete(b.VMSecurityGroups, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_VM_SECURITY_GROUP_EN, lcuuid))
}

func (b *DiffBaseDataSet) addNATGateway(dbItem *mysql.NATGateway, seq int) {
	b.NATGateways[dbItem.Lcuuid] = &NATGateway{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:         dbItem.Name,
		FloatingIPs:  dbItem.FloatingIPs,
		RegionLcuuid: dbItem.Region,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_NAT_GATEWAY_EN, b.NATGateways[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteNATGateway(lcuuid string) {
	delete(b.NATGateways, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_NAT_GATEWAY_EN, lcuuid))
}

func (b *DiffBaseDataSet) addNATVMConnection(dbItem *mysql.NATVMConnection, seq int) {
	b.NATVMConnections[dbItem.Lcuuid] = &NATVMConnection{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
	}
	log.Info(addDiffBase(RESOURCE_TYPE_NAT_VM_CONNECTION_EN, b.NATVMConnections[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteNATVMConnection(lcuuid string) {
	delete(b.NATVMConnections, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_NAT_VM_CONNECTION_EN, lcuuid))
}

func (b *DiffBaseDataSet) addNATRule(dbItem *mysql.NATRule, seq int) {
	b.NATRules[dbItem.Lcuuid] = &NATRule{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
	}
	log.Info(addDiffBase(RESOURCE_TYPE_NAT_RULE_EN, b.NATRules[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteNATRule(lcuuid string) {
	delete(b.NATRules, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_NAT_RULE_EN, lcuuid))
}

func (b *DiffBaseDataSet) addLB(dbItem *mysql.LB, seq int) {
	b.LBs[dbItem.Lcuuid] = &LB{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:         dbItem.Name,
		Model:        dbItem.Model,
		VIP:          dbItem.VIP,
		RegionLcuuid: dbItem.Region,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_LB_EN, b.LBs[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteLB(lcuuid string) {
	delete(b.LBs, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_LB_EN, lcuuid))
}

func (b *DiffBaseDataSet) addLBVMConnection(dbItem *mysql.LBVMConnection, seq int) {
	b.LBVMConnections[dbItem.Lcuuid] = &LBVMConnection{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
	}
	log.Info(addDiffBase(RESOURCE_TYPE_LB_VM_CONNECTION_EN, b.LBVMConnections[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteLBVMConnection(lcuuid string) {
	delete(b.LBVMConnections, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_LB_VM_CONNECTION_EN, lcuuid))
}

func (b *DiffBaseDataSet) addLBListener(dbItem *mysql.LBListener, seq int) {
	b.LBListeners[dbItem.Lcuuid] = &LBListener{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:     dbItem.Name,
		IPs:      dbItem.IPs,
		SNATIPs:  dbItem.SNATIPs,
		Port:     dbItem.Port,
		Protocol: dbItem.Protocol,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_LB_LISTENER_EN, b.LBListeners[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteLBListener(lcuuid string) {
	delete(b.LBListeners, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_LB_LISTENER_EN, lcuuid))
}

func (b *DiffBaseDataSet) addLBTargetServer(dbItem *mysql.LBTargetServer, seq int) {
	b.LBTargetServers[dbItem.Lcuuid] = &LBTargetServer{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		IP:       dbItem.IP,
		Port:     dbItem.Port,
		Protocol: dbItem.Protocol,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_LB_TARGET_SERVER_EN, b.LBTargetServers[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteLBTargetServer(lcuuid string) {
	delete(b.LBTargetServers, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_LB_TARGET_SERVER_EN, lcuuid))
}

func (b *DiffBaseDataSet) addPeerConnection(dbItem *mysql.PeerConnection, seq int, toolDataSet *ToolDataSet) {
	remoteRegionLcuuid, _ := toolDataSet.GetRegionLcuuidByID(dbItem.RemoteRegionID)
	localRegionLcuuid, _ := toolDataSet.GetRegionLcuuidByID(dbItem.LocalRegionID)
	b.PeerConnections[dbItem.Lcuuid] = &PeerConnection{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:               dbItem.Name,
		RemoteRegionLcuuid: remoteRegionLcuuid,
		LocalRegionLcuuid:  localRegionLcuuid,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_PEER_CONNECTION_EN, b.PeerConnections[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deletePeerConnection(lcuuid string) {
	delete(b.PeerConnections, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_PEER_CONNECTION_EN, lcuuid))
}

func (b *DiffBaseDataSet) addCEN(dbItem *mysql.CEN, seq int, toolDataSet *ToolDataSet) {
	vpcLcuuids := []string{}
	for _, vpcID := range StringToIntArray(dbItem.VPCIDs) {
		vpcLcuuid, exists := toolDataSet.GetVPCLcuuidByID(vpcID)
		if exists {
			vpcLcuuids = append(vpcLcuuids, vpcLcuuid)
		}
	}
	b.CENs[dbItem.Lcuuid] = &CEN{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:       dbItem.Name,
		VPCLcuuids: vpcLcuuids,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_CEN_EN, b.CENs[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteCEN(lcuuid string) {
	delete(b.CENs, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_CEN_EN, lcuuid))
}

func (b *DiffBaseDataSet) addRDSInstance(dbItem *mysql.RDSInstance, seq int) {
	b.RDSInstances[dbItem.Lcuuid] = &RDSInstance{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:         dbItem.Name,
		State:        dbItem.State,
		Series:       dbItem.Series,
		Model:        dbItem.Model,
		RegionLcuuid: dbItem.Region,
		AZLcuuid:     dbItem.AZ,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_RDS_INSTANCE_EN, b.RDSInstances[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteRDSInstance(lcuuid string) {
	delete(b.RDSInstances, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_RDS_INSTANCE_EN, lcuuid))
}

func (b *DiffBaseDataSet) addRedisInstance(dbItem *mysql.RedisInstance, seq int) {
	b.RedisInstances[dbItem.Lcuuid] = &RedisInstance{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:         dbItem.Name,
		State:        dbItem.State,
		PublicHost:   dbItem.PublicHost,
		RegionLcuuid: dbItem.Region,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_REDIS_INSTANCE_EN, b.RedisInstances[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteRedisInstance(lcuuid string) {
	delete(b.RedisInstances, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_REDIS_INSTANCE_EN, lcuuid))
}

func (b *DiffBaseDataSet) addPodCluster(dbItem *mysql.PodCluster, seq int) {
	b.PodClusters[dbItem.Lcuuid] = &PodCluster{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:            dbItem.Name,
		ClusterName:     dbItem.ClusterName,
		RegionLcuuid:    dbItem.Region,
		AZLcuuid:        dbItem.AZ,
		SubDomainLcuuid: dbItem.SubDomain,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_POD_CLUSTER_EN, b.PodClusters[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deletePodCluster(lcuuid string) {
	delete(b.PodClusters, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_POD_CLUSTER_EN, lcuuid))
}

func (b *DiffBaseDataSet) addPodNode(dbItem *mysql.PodNode, seq int) {
	b.PodNodes[dbItem.Lcuuid] = &PodNode{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		State:           dbItem.State,
		VCPUNum:         dbItem.VCPUNum,
		MemTotal:        dbItem.MemTotal,
		RegionLcuuid:    dbItem.Region,
		AZLcuuid:        dbItem.AZ,
		SubDomainLcuuid: dbItem.SubDomain,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_POD_NODE_EN, b.PodNodes[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deletePodNode(lcuuid string) {
	delete(b.PodNodes, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_POD_NODE_EN, lcuuid))
}

func (b *DiffBaseDataSet) addPodNamespace(dbItem *mysql.PodNamespace, seq int) {
	b.PodNamespaces[dbItem.Lcuuid] = &PodNamespace{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		RegionLcuuid:    dbItem.Region,
		AZLcuuid:        dbItem.AZ,
		SubDomainLcuuid: dbItem.SubDomain,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_POD_NAMESPACE_EN, b.PodNamespaces[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deletePodNamespace(lcuuid string) {
	delete(b.PodNamespaces, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_POD_NAMESPACE_EN, lcuuid))
}

func (b *DiffBaseDataSet) addPodIngress(dbItem *mysql.PodIngress, seq int) {
	b.PodIngresses[dbItem.Lcuuid] = &PodIngress{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:            dbItem.Name,
		RegionLcuuid:    dbItem.Region,
		AZLcuuid:        dbItem.AZ,
		SubDomainLcuuid: dbItem.SubDomain,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_POD_INGRESS_EN, b.PodIngresses[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deletePodIngress(lcuuid string) {
	delete(b.PodIngresses, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_POD_INGRESS_EN, lcuuid))
}

func (b *DiffBaseDataSet) addPodIngressRule(dbItem *mysql.PodIngressRule, seq int) {
	b.PodIngressRules[dbItem.Lcuuid] = &PodIngressRule{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		SubDomainLcuuid: dbItem.SubDomain,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_POD_INGRESS_RULE_EN, b.PodIngressRules[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deletePodIngressRule(lcuuid string) {
	delete(b.PodIngressRules, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_POD_INGRESS_RULE_EN, lcuuid))
}

func (b *DiffBaseDataSet) addPodIngressRuleBackend(dbItem *mysql.PodIngressRuleBackend, seq int) {
	b.PodIngressRuleBackends[dbItem.Lcuuid] = &PodIngressRuleBackend{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		SubDomainLcuuid: dbItem.SubDomain,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN, b.PodIngressRuleBackends[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deletePodIngressRuleBackend(lcuuid string) {
	delete(b.PodIngressRuleBackends, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN, lcuuid))
}

func (b *DiffBaseDataSet) addPodService(dbItem *mysql.PodService, seq int, toolDataSet *ToolDataSet) {
	var podIngressLcuuid string
	if dbItem.PodIngressID != 0 {
		podIngressLcuuid, _ = toolDataSet.GetPodIngressLcuuidByID(dbItem.PodIngressID)
	}
	b.PodServices[dbItem.Lcuuid] = &PodService{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:             dbItem.Name,
		Label:            dbItem.Label,
		Selector:         dbItem.Selector,
		ServiceClusterIP: dbItem.ServiceClusterIP,
		PodIngressLcuuid: podIngressLcuuid,
		RegionLcuuid:     dbItem.Region,
		AZLcuuid:         dbItem.AZ,
		SubDomainLcuuid:  dbItem.SubDomain,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_POD_SERVICE_EN, b.PodServices[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deletePodService(lcuuid string) {
	delete(b.PodServices, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_POD_SERVICE_EN, lcuuid))
}

func (b *DiffBaseDataSet) addPodServicePort(dbItem *mysql.PodServicePort, seq int) {
	b.PodServicePorts[dbItem.Lcuuid] = &PodServicePort{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:            dbItem.Name,
		SubDomainLcuuid: dbItem.SubDomain,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_POD_SERVICE_PORT_EN, b.PodServicePorts[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deletePodServicePort(lcuuid string) {
	delete(b.PodServicePorts, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_POD_SERVICE_PORT_EN, lcuuid))
}

func (b *DiffBaseDataSet) addPodGroup(dbItem *mysql.PodGroup, seq int) {
	b.PodGroups[dbItem.Lcuuid] = &PodGroup{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:            dbItem.Name,
		Label:           dbItem.Label,
		PodNum:          dbItem.PodNum,
		Type:            dbItem.Type,
		RegionLcuuid:    dbItem.Region,
		AZLcuuid:        dbItem.AZ,
		SubDomainLcuuid: dbItem.SubDomain,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_POD_GROUP_EN, b.PodGroups[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deletePodGroup(lcuuid string) {
	delete(b.PodGroups, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_POD_GROUP_EN, lcuuid))
}

func (b *DiffBaseDataSet) addPodGroupPort(dbItem *mysql.PodGroupPort, seq int) {
	b.PodGroupPorts[dbItem.Lcuuid] = &PodGroupPort{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:            dbItem.Name,
		SubDomainLcuuid: dbItem.SubDomain,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_POD_GROUP_PORT_EN, b.PodGroupPorts[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deletePodGroupPort(lcuuid string) {
	delete(b.PodGroupPorts, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_POD_GROUP_PORT_EN, lcuuid))
}

func (b *DiffBaseDataSet) addPodReplicaSet(dbItem *mysql.PodReplicaSet, seq int) {
	b.PodReplicaSets[dbItem.Lcuuid] = &PodReplicaSet{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:            dbItem.Name,
		PodNum:          dbItem.PodNum,
		RegionLcuuid:    dbItem.Region,
		AZLcuuid:        dbItem.AZ,
		SubDomainLcuuid: dbItem.SubDomain,
		Label:           dbItem.Label,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_POD_REPLICA_SET_EN, b.PodReplicaSets[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deletePodReplicaSet(lcuuid string) {
	delete(b.PodReplicaSets, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_POD_REPLICA_SET_EN, lcuuid))
}

func (b *DiffBaseDataSet) addPod(dbItem *mysql.Pod, seq int, toolDataSet *ToolDataSet) {
	podNodeLcuuid, _ := toolDataSet.GetPodNodeLcuuidByID(dbItem.PodNodeID)
	var podReplicaSetLcuuid string
	if dbItem.PodReplicaSetID != 0 {
		podReplicaSetLcuuid, _ = toolDataSet.GetPodReplicaSetLcuuidByID(dbItem.PodReplicaSetID)
	}
	var podGroupLcuuid string
	if dbItem.PodGroupID != 0 {
		podGroupLcuuid, _ = toolDataSet.GetPodGroupLcuuidByID(dbItem.PodGroupID)
	}
	vpcLcuuid, _ := toolDataSet.GetVPCLcuuidByID(dbItem.VPCID)
	b.Pods[dbItem.Lcuuid] = &Pod{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:                dbItem.Name,
		Label:               dbItem.Label,
		State:               dbItem.State,
		CreatedAt:           dbItem.CreatedAt,
		PodNodeLcuuid:       podNodeLcuuid,
		PodReplicaSetLcuuid: podReplicaSetLcuuid,
		PodGroupLcuuid:      podGroupLcuuid,
		VPCLcuuid:           vpcLcuuid,
		RegionLcuuid:        dbItem.Region,
		AZLcuuid:            dbItem.AZ,
		SubDomainLcuuid:     dbItem.SubDomain,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_POD_EN, b.Pods[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deletePod(lcuuid string) {
	delete(b.Pods, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_POD_EN, lcuuid))
}

func (b *DiffBaseDataSet) addVMPodNodeConnection(dbItem *mysql.VMPodNodeConnection, seq int) {
	b.VMPodNodeConnections[dbItem.Lcuuid] = &VMPodNodeConnection{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		SubDomainLcuuid: dbItem.SubDomain,
	}
	log.Info(addDiffBase(RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, b.VMPodNodeConnections[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteVMPodNodeConnection(lcuuid string) {
	delete(b.VMPodNodeConnections, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, lcuuid))
}

type DiffBase struct {
	Sequence int    `json:"sequence"`
	Lcuuid   string `json:"lcuuid"`
}

func (d *DiffBase) GetSequence() int {
	return d.Sequence
}

func (d *DiffBase) SetSequence(sequence int) {
	d.Sequence = sequence
}

func (d *DiffBase) GetLcuuid() string {
	return d.Lcuuid
}

type Region struct {
	DiffBase
	Name  string `json:"name"`
	Label string `json:"label"`
}

func (r *Region) Update(cloudItem *cloudmodel.Region) {
	r.Name = cloudItem.Name
	r.Label = cloudItem.Label
	log.Info(updateDiffBase(RESOURCE_TYPE_REGION_EN, r))
}

type AZ struct {
	DiffBase
	Name         string `json:"name"`
	Label        string `json:"label"`
	RegionLcuuid string `json:"region_lcuuid"`
}

func (a *AZ) Update(cloudItem *cloudmodel.AZ) {
	a.Name = cloudItem.Name
	a.Label = cloudItem.Label
	a.RegionLcuuid = cloudItem.RegionLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_AZ_EN, a))
}

type SubDomain struct {
	DiffBase
}

type Host struct {
	DiffBase
	Name         string `json:"name"`
	IP           string `json:"ip"`
	HType        int    `json:"htype"`
	VCPUNum      int    `json:"vcpu_num"`
	MemTotal     int    `json:"mem_total"`
	ExtraInfo    string `json:"extra_info"`
	RegionLcuuid string `json:"region_lcuuid"`
	AZLcuuid     string `json:"az_lcuuid"`
}

func (h *Host) Update(cloudItem *cloudmodel.Host) {
	h.Name = cloudItem.Name
	h.IP = cloudItem.IP
	h.HType = cloudItem.HType
	h.VCPUNum = cloudItem.VCPUNum
	h.MemTotal = cloudItem.MemTotal
	h.ExtraInfo = cloudItem.ExtraInfo
	h.RegionLcuuid = cloudItem.RegionLcuuid
	h.AZLcuuid = cloudItem.AZLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_HOST_EN, h))
}

type VM struct {
	DiffBase
	Name         string `json:"name"`
	Label        string `json:"label"`
	State        int    `json:"state"`
	HType        int    `json:"htype"`
	LaunchServer string `json:"launch_server"`
	VPCLcuuid    string `json:"vpc_lcuuid"`
	RegionLcuuid string `json:"region_lcuuid"`
	AZLcuuid     string `json:"az_lcuuid"`
}

func (v *VM) Update(cloudItem *cloudmodel.VM) {
	v.Name = cloudItem.Name
	v.Label = cloudItem.Label
	v.State = cloudItem.State
	v.HType = cloudItem.HType
	v.LaunchServer = cloudItem.LaunchServer
	v.VPCLcuuid = cloudItem.VPCLcuuid
	v.RegionLcuuid = cloudItem.RegionLcuuid
	v.AZLcuuid = cloudItem.AZLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_VM_EN, v))
}

type VPC struct {
	DiffBase
	Name         string `json:"name"`
	Label        string `json:"label"`
	TunnelID     int    `json:"tunnel_id"`
	CIDR         string `json:"cidr"`
	RegionLcuuid string `json:"region_lcuuid"`
}

func (v *VPC) Update(cloudItem *cloudmodel.VPC) {
	v.Name = cloudItem.Name
	v.Label = cloudItem.Label
	v.TunnelID = cloudItem.TunnelID
	v.CIDR = cloudItem.CIDR
	v.RegionLcuuid = cloudItem.RegionLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_VPC_EN, v))
}

type Network struct {
	DiffBase
	Name            string `json:"name"`
	Label           string `json:"label"`
	TunnelID        int    `json:"tunnel_id"`
	NetType         int    `json:"net_type"`
	SegmentationID  int    `json:"segmentation_id"`
	VPCLcuuid       string `json:"vpc_lcuuid"`
	RegionLcuuid    string `json:"region_lcuuid"`
	AZLcuuid        string `json:"az_lcuuid"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}

func (n *Network) Update(cloudItem *cloudmodel.Network) {
	n.Name = cloudItem.Name
	n.Label = cloudItem.Label
	n.TunnelID = cloudItem.TunnelID
	n.NetType = cloudItem.NetType
	n.SegmentationID = cloudItem.SegmentationID
	n.VPCLcuuid = cloudItem.VPCLcuuid
	n.RegionLcuuid = cloudItem.RegionLcuuid
	n.AZLcuuid = cloudItem.AZLcuuid
	n.SubDomainLcuuid = cloudItem.SubDomainLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_NETWORK_EN, n))
}

type Subnet struct {
	DiffBase
	Name            string `json:"name"`
	Label           string `json:"label"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}

func (s *Subnet) Update(cloudItem *cloudmodel.Subnet) {
	s.Name = cloudItem.Name
	s.Label = cloudItem.Label
	s.SubDomainLcuuid = cloudItem.SubDomainLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_SUBNET_EN, s))
}

type VRouter struct {
	DiffBase
	Name         string `json:"name"`
	Label        string `json:"label"`
	VPCLcuuid    string `json:"vpc_lcuuid"`
	RegionLcuuid string `json:"region_lcuuid"`
}

func (v *VRouter) Update(cloudItem *cloudmodel.VRouter) {
	v.Name = cloudItem.Name
	v.Label = cloudItem.Label
	v.VPCLcuuid = cloudItem.VPCLcuuid
	v.RegionLcuuid = cloudItem.RegionLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_VROUTER_EN, v))
}

type RoutingTable struct {
	DiffBase
	Destination string `json:"destination"`
	Nexthop     string `json:"nexthop"`
	NexthopType string `json:"nexthop_type"`
}

func (r *RoutingTable) Update(cloudItem *cloudmodel.RoutingTable) {
	r.Destination = cloudItem.Destination
	r.Nexthop = cloudItem.Nexthop
	r.NexthopType = cloudItem.NexthopType
	log.Info(updateDiffBase(RESOURCE_TYPE_ROUTING_TABLE_EN, r))
}

type DHCPPort struct {
	DiffBase
	Name         string `json:"name"`
	RegionLcuuid string `json:"region_lcuuid"`
	AZLcuuid     string `json:"az_lcuuid"`
	VPCLcuuid    string `json:"vpc_lcuuid"`
}

func (d *DHCPPort) Update(cloudItem *cloudmodel.DHCPPort) {
	d.Name = cloudItem.Name
	d.RegionLcuuid = cloudItem.RegionLcuuid
	d.AZLcuuid = cloudItem.AZLcuuid
	d.VPCLcuuid = cloudItem.VPCLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_DHCP_PORT_EN, d))
}

type VInterface struct {
	DiffBase
	Name            string `json:"name"`
	Type            int    `json:"type"`
	TapMac          string `json:"tap_mac"`
	NetworkLcuuid   string `json:"network_lcuuid"`
	RegionLcuuid    string `json:"region_lcuuid"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}

func (v *VInterface) Update(cloudItem *cloudmodel.VInterface) {
	v.Name = cloudItem.Name
	v.Type = cloudItem.Type
	v.TapMac = cloudItem.TapMac
	v.NetworkLcuuid = cloudItem.NetworkLcuuid
	v.RegionLcuuid = cloudItem.RegionLcuuid
	v.SubDomainLcuuid = cloudItem.SubDomainLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_VINTERFACE_EN, v))
}

type WANIP struct {
	DiffBase
	RegionLcuuid    string `json:"region_lcuuid"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
	SubnetLcuuid    string `json:"subnet_lcuuid"`
}

func (w *WANIP) Update(cloudItem *cloudmodel.IP) {
	w.RegionLcuuid = cloudItem.RegionLcuuid
	w.SubDomainLcuuid = cloudItem.SubDomainLcuuid
	w.SubnetLcuuid = cloudItem.SubnetLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_WAN_IP_EN, w))
}

type LANIP struct {
	DiffBase
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
	SubnetLcuuid    string `json:"subnet_lcuuid"`
}

func (l *LANIP) Update(cloudItem *cloudmodel.IP) {
	l.SubDomainLcuuid = cloudItem.SubDomainLcuuid
	l.SubnetLcuuid = cloudItem.SubnetLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_LAN_IP_EN, l))
}

type FloatingIP struct {
	DiffBase
	RegionLcuuid string `json:"region_lcuuid"`
	VPCLcuuid    string `json:"vpc_lcuuid"`
}

func (f *FloatingIP) Update(cloudItem *cloudmodel.FloatingIP) {
	f.RegionLcuuid = cloudItem.RegionLcuuid
	f.VPCLcuuid = cloudItem.VPCLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_FLOATING_IP_EN, f))
}

type SecurityGroup struct {
	DiffBase
	Name         string `json:"name"`
	Label        string `json:"label"`
	RegionLcuuid string `json:"region_lcuuid"`
}

func (s *SecurityGroup) Update(cloudItem *cloudmodel.SecurityGroup) {
	s.Name = cloudItem.Name
	s.Label = cloudItem.Label
	s.RegionLcuuid = cloudItem.RegionLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_SECURITY_GROUP_EN, s))
}

type SecurityGroupRule struct {
	DiffBase
	Priority        int    `json:"priority"`
	EtherType       int    `json:"ether_type"`
	Local           string `json:"local"`
	Remote          string `json:"remote"`
	RemotePortRange string `json:"remote_port_range"`
}

func (s *SecurityGroupRule) Update(cloudItem *cloudmodel.SecurityGroupRule) {
	s.Priority = cloudItem.Priority
	s.EtherType = cloudItem.EtherType
	s.Local = cloudItem.Local
	s.Remote = cloudItem.Remote
	s.RemotePortRange = cloudItem.RemotePortRange
	log.Info(updateDiffBase(RESOURCE_TYPE_SECURITY_GROUP_RULE_EN, s))
}

type VMSecurityGroup struct {
	DiffBase
	Priority int `json:"priority"`
}

func (s *VMSecurityGroup) Update(cloudItem *cloudmodel.VMSecurityGroup) {
	s.Priority = cloudItem.Priority
	log.Info(updateDiffBase(RESOURCE_TYPE_VM_SECURITY_GROUP_EN, s))
}

type NATGateway struct {
	DiffBase
	Name         string `json:"name"`
	FloatingIPs  string `json:"floating_ips"`
	RegionLcuuid string `json:"region_lcuuid"`
}

func (n *NATGateway) Update(cloudItem *cloudmodel.NATGateway) {
	n.Name = cloudItem.Name
	n.FloatingIPs = cloudItem.FloatingIPs
	n.RegionLcuuid = cloudItem.RegionLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_NAT_GATEWAY_EN, n))
}

type NATRule struct {
	DiffBase
}

type LB struct {
	DiffBase
	Name         string `json:"name"`
	Model        int    `json:"model"`
	VIP          string `json:"vip"`
	VPCLcuuid    string `json:"vpc_lcuuid"`
	RegionLcuuid string `json:"region_lcuuid"`
}

func (l *LB) Update(cloudItem *cloudmodel.LB) {
	l.Name = cloudItem.Name
	l.Model = cloudItem.Model
	l.VIP = cloudItem.VIP
	l.VPCLcuuid = cloudItem.VPCLcuuid
	l.RegionLcuuid = cloudItem.RegionLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_LB_EN, l))
}

type LBListener struct {
	DiffBase
	Name     string `json:"name"`
	IPs      string `json:"ips"`
	SNATIPs  string `json:"snat_ips"`
	Port     int    `json:"port"`
	Protocol string `json:"protocal"`
}

func (l *LBListener) Update(cloudItem *cloudmodel.LBListener) {
	l.Name = cloudItem.Name
	l.IPs = cloudItem.IPs
	l.SNATIPs = cloudItem.SNATIPs
	l.Port = cloudItem.Port
	l.Protocol = cloudItem.Protocol
	log.Info(updateDiffBase(RESOURCE_TYPE_LB_LISTENER_EN, l))
}

type LBTargetServer struct {
	DiffBase
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocal"`
}

func (l *LBTargetServer) Update(cloudItem *cloudmodel.LBTargetServer) {
	l.IP = cloudItem.IP
	l.Port = cloudItem.Port
	l.Protocol = cloudItem.Protocol
	log.Info(updateDiffBase(RESOURCE_TYPE_LB_TARGET_SERVER_EN, l))
}

type PeerConnection struct {
	DiffBase
	Name               string `json:"name"`
	RemoteRegionLcuuid string `json:"remote_region_lcuuid"`
	LocalRegionLcuuid  string `json:"local_region_lcuuid"`
}

func (p *PeerConnection) Update(cloudItem *cloudmodel.PeerConnection) {
	p.Name = cloudItem.Name
	p.RemoteRegionLcuuid = cloudItem.RemoteRegionLcuuid
	p.LocalRegionLcuuid = cloudItem.LocalRegionLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_PEER_CONNECTION_EN, p))
}

type CEN struct {
	DiffBase
	Name       string   `json:"name"`
	VPCLcuuids []string `json:"vpc_lcuuids"`
}

func (c *CEN) Update(cloudItem *cloudmodel.CEN) {
	c.Name = cloudItem.Name
	c.VPCLcuuids = cloudItem.VPCLcuuids
	log.Info(updateDiffBase(RESOURCE_TYPE_CEN_EN, c))
}

type RDSInstance struct {
	DiffBase
	Name         string `json:"name"`
	State        int    `json:"state"`
	Series       int    `json:"series"`
	Model        int    `json:"model"`
	VPCLcuuid    string `json:"vpc_lcuuid"`
	RegionLcuuid string `json:"region_lcuuid"`
	AZLcuuid     string `json:"az_lcuuid"`
}

func (r *RDSInstance) Update(cloudItem *cloudmodel.RDSInstance) {
	r.Name = cloudItem.Name
	r.State = cloudItem.State
	r.Series = cloudItem.Series
	r.Model = cloudItem.Model
	r.VPCLcuuid = cloudItem.VPCLcuuid
	r.RegionLcuuid = cloudItem.RegionLcuuid
	r.AZLcuuid = cloudItem.AZLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_RDS_INSTANCE_EN, r))
}

type RedisInstance struct {
	DiffBase
	Name         string `json:"name"`
	State        int    `json:"state"`
	PublicHost   string `json:"public_host"`
	RegionLcuuid string `json:"region_lcuuid"`
	AZLcuuid     string `json:"az_lcuuid"`
}

func (r *RedisInstance) Update(cloudItem *cloudmodel.RedisInstance) {
	r.Name = cloudItem.Name
	r.State = cloudItem.State
	r.PublicHost = cloudItem.PublicHost
	r.RegionLcuuid = cloudItem.RegionLcuuid
	r.AZLcuuid = cloudItem.AZLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_REDIS_INSTANCE_EN, r))
}

type PodCluster struct {
	DiffBase
	Name            string `json:"name"`
	ClusterName     string `json:"cluster_name"`
	RegionLcuuid    string `json:"region_lcuuid"`
	AZLcuuid        string `json:"az_lcuuid"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}

func (p *PodCluster) Update(cloudItem *cloudmodel.PodCluster) {
	p.Name = cloudItem.Name
	p.ClusterName = cloudItem.ClusterName
	p.RegionLcuuid = cloudItem.RegionLcuuid
	p.AZLcuuid = cloudItem.AZLcuuid
	p.SubDomainLcuuid = cloudItem.SubDomainLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_POD_CLUSTER_EN, p))
}

type PodNode struct {
	DiffBase
	State           int    `json:"state"`
	VCPUNum         int    `json:"vcpu_num"`
	MemTotal        int    `json:"mem_total"`
	RegionLcuuid    string `json:"region_lcuuid"`
	AZLcuuid        string `json:"az_lcuuid"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}

func (p *PodNode) Update(cloudItem *cloudmodel.PodNode) {
	p.State = cloudItem.State
	p.VCPUNum = cloudItem.VCPUNum
	p.MemTotal = cloudItem.MemTotal
	p.RegionLcuuid = cloudItem.RegionLcuuid
	p.AZLcuuid = cloudItem.AZLcuuid
	p.SubDomainLcuuid = cloudItem.SubDomainLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_POD_NODE_EN, p))
}

type PodNamespace struct {
	DiffBase
	RegionLcuuid    string `json:"region_lcuuid"`
	AZLcuuid        string `json:"az_lcuuid"`
	SubDomainLcuuid string `json:"sub_domain_lcuu"`
}

func (p *PodNamespace) Update(cloudItem *cloudmodel.PodNamespace) {
	p.RegionLcuuid = cloudItem.RegionLcuuid
	p.AZLcuuid = cloudItem.AZLcuuid
	p.SubDomainLcuuid = cloudItem.SubDomainLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_POD_NAMESPACE_EN, p))
}

type PodIngress struct {
	DiffBase
	Name            string `json:"name"`
	RegionLcuuid    string `json:"region_lcuuid"`
	AZLcuuid        string `json:"az_lcuuid"`
	SubDomainLcuuid string `json:"sub_domain_lcuu"`
}

func (p *PodIngress) Update(cloudItem *cloudmodel.PodIngress) {
	p.Name = cloudItem.Name
	p.RegionLcuuid = cloudItem.RegionLcuuid
	p.AZLcuuid = cloudItem.AZLcuuid
	p.SubDomainLcuuid = cloudItem.SubDomainLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_POD_INGRESS_EN, p))
}

type PodIngressRule struct {
	DiffBase
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}

func (p *PodIngressRule) Update(cloudItem *cloudmodel.PodIngressRule) {
	p.SubDomainLcuuid = cloudItem.SubDomainLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_POD_INGRESS_RULE_EN, p))
}

type PodIngressRuleBackend struct {
	DiffBase
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}

func (p *PodIngressRuleBackend) Update(cloudItem *cloudmodel.PodIngressRuleBackend) {
	p.SubDomainLcuuid = cloudItem.SubDomainLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN, p))
}

type PodService struct {
	DiffBase
	Name             string `json:"name"`
	Label            string `json:"label"`
	Selector         string `json:"selector"`
	ServiceClusterIP string `json:"service_cluster_ip"`
	PodIngressLcuuid string `json:"pod_ingress_lcuuid"`
	RegionLcuuid     string `json:"region_lcuuid"`
	AZLcuuid         string `json:"az_lcuuid"`
	SubDomainLcuuid  string `json:"sub_domain_lcuuid"`
}

func (p *PodService) Update(cloudItem *cloudmodel.PodService) {
	p.Name = cloudItem.Name
	p.Label = cloudItem.Label
	p.Selector = cloudItem.Selector
	p.ServiceClusterIP = cloudItem.ServiceClusterIP
	p.PodIngressLcuuid = cloudItem.PodIngressLcuuid
	p.RegionLcuuid = cloudItem.RegionLcuuid
	p.AZLcuuid = cloudItem.AZLcuuid
	p.SubDomainLcuuid = cloudItem.SubDomainLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_POD_SERVICE_EN, p))
}

type PodServicePort struct {
	DiffBase
	Name            string `json:"name"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}

func (p *PodServicePort) Update(cloudItem *cloudmodel.PodServicePort) {
	p.Name = cloudItem.Name
	p.SubDomainLcuuid = cloudItem.SubDomainLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_POD_SERVICE_PORT_EN, p))
}

type PodGroup struct {
	DiffBase
	Name            string `json:"name"`
	Label           string `json:"label"`
	PodNum          int    `json:"pod_num"`
	Type            int    `json:"type"`
	RegionLcuuid    string `json:"region_lcuuid"`
	AZLcuuid        string `json:"az_lcuuid"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}

func (p *PodGroup) Update(cloudItem *cloudmodel.PodGroup) {
	p.Name = cloudItem.Name
	p.Label = cloudItem.Label
	p.PodNum = cloudItem.PodNum
	p.Type = cloudItem.Type
	p.RegionLcuuid = cloudItem.RegionLcuuid
	p.AZLcuuid = cloudItem.AZLcuuid
	p.SubDomainLcuuid = cloudItem.SubDomainLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_POD_GROUP_EN, p))
}

type PodGroupPort struct {
	DiffBase
	Name            string `json:"name"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}

func (p *PodGroupPort) Update(cloudItem *cloudmodel.PodGroupPort) {
	p.Name = cloudItem.Name
	p.SubDomainLcuuid = cloudItem.SubDomainLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_POD_GROUP_PORT_EN, p))
}

type PodReplicaSet struct {
	DiffBase
	Name            string `json:"name"`
	Label           string `json:"label"`
	PodNum          int    `json:"pod_num"`
	RegionLcuuid    string `json:"region_lcuuid"`
	AZLcuuid        string `json:"az_lcuuid"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}

func (p *PodReplicaSet) Update(cloudItem *cloudmodel.PodReplicaSet) {
	p.Name = cloudItem.Name
	p.Label = cloudItem.Label
	p.PodNum = cloudItem.PodNum
	p.RegionLcuuid = cloudItem.RegionLcuuid
	p.AZLcuuid = cloudItem.AZLcuuid
	p.SubDomainLcuuid = cloudItem.SubDomainLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_POD_REPLICA_SET_EN, p))
}

type Pod struct {
	DiffBase
	Name                string    `json:"name"`
	Label               string    `json:"label"`
	State               int       `json:"state"`
	CreatedAt           time.Time `json:"created_at"`
	PodNodeLcuuid       string    `json:"pod_node_lcuuid"`
	PodReplicaSetLcuuid string    `json:"pod_replica_set_lcuuid"`
	PodGroupLcuuid      string    `json:"pod_group_lcuuid"`
	VPCLcuuid           string    `json:"vpc_lcuuid"`
	RegionLcuuid        string    `json:"region_lcuuid"`
	AZLcuuid            string    `json:"az_lcuuid"`
	SubDomainLcuuid     string    `json:"sub_domain_lcuuid"`
}

func (p *Pod) Update(cloudItem *cloudmodel.Pod) {
	p.Name = cloudItem.Name
	p.Label = cloudItem.Label
	p.State = cloudItem.State
	p.CreatedAt = cloudItem.CreatedAt
	p.PodNodeLcuuid = cloudItem.PodNodeLcuuid
	p.PodReplicaSetLcuuid = cloudItem.PodReplicaSetLcuuid
	p.PodGroupLcuuid = cloudItem.PodGroupLcuuid
	p.VPCLcuuid = cloudItem.VPCLcuuid
	p.RegionLcuuid = cloudItem.RegionLcuuid
	p.AZLcuuid = cloudItem.AZLcuuid
	p.SubDomainLcuuid = cloudItem.SubDomainLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_POD_EN, p))
}

type VMPodNodeConnection struct {
	DiffBase
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}

func (p *VMPodNodeConnection) Update(cloudItem *cloudmodel.VMPodNodeConnection) {
	p.SubDomainLcuuid = cloudItem.SubDomainLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, p))
}

type NATVMConnection struct {
	DiffBase
}

type LBVMConnection struct {
	DiffBase
}
