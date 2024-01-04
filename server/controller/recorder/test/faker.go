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

package test

import (
	"math/rand"
	"time"

	"github.com/bxcodec/faker/v3"
	"github.com/google/uuid"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	rcommon "github.com/deepflowio/deepflow/server/controller/recorder/common"
)

func RandID() int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(999)
}

func FormatLcuuid(lcuuid string) string {
	if lcuuid == "" {
		return uuid.NewString()
	}
	return lcuuid
}

func RandName() string {
	return uuid.NewString()[:7]
}

func NewCloudRegion() cloudmodel.Region {
	return cloudmodel.Region{
		Lcuuid: uuid.NewString(),
		Name:   faker.Name(),
		Label:  faker.Name(),
	}
}

func NewCloudAZ(regionLcuuid string) cloudmodel.AZ {
	return cloudmodel.AZ{
		Lcuuid:       uuid.NewString(),
		Name:         faker.Name(),
		Label:        faker.Name(),
		RegionLcuuid: FormatLcuuid(regionLcuuid),
	}
}

func NewCloudSubDomain() cloudmodel.SubDomain {
	return cloudmodel.SubDomain{
		Lcuuid: uuid.NewString(),
		Name:   faker.Name(),
	}
}

func NewCloudHost(regionLcuuid, azLcuuid string) cloudmodel.Host {
	return cloudmodel.Host{
		Lcuuid:       uuid.NewString(),
		Name:         faker.Name(),
		VCPUNum:      rand.Intn(10),
		AZLcuuid:     FormatLcuuid(azLcuuid),
		RegionLcuuid: FormatLcuuid(regionLcuuid),
	}
}

func NewCloudVM(regionLcuuid, azLcuuid, vpcLcuuid string) cloudmodel.VM {
	return cloudmodel.VM{
		Lcuuid:       uuid.NewString(),
		Name:         faker.Name(),
		Label:        faker.Name(),
		HType:        1,
		State:        4,
		LaunchServer: "10.1.1.10",
		VPCLcuuid:    FormatLcuuid(vpcLcuuid),
		AZLcuuid:     FormatLcuuid(azLcuuid),
		RegionLcuuid: FormatLcuuid(regionLcuuid),
	}
}

func NewCloudVPC(regionLcuuid string) cloudmodel.VPC {
	return cloudmodel.VPC{
		Lcuuid:       uuid.NewString(),
		Name:         faker.Name(),
		CIDR:         "1.1.1.0/24",
		TunnelID:     rand.Intn(100),
		RegionLcuuid: FormatLcuuid(regionLcuuid),
	}
}

func NewCloudNetwork(regionLcuuid, azLcuuid, subDomainLcuuid, vpcLcuuid string) cloudmodel.Network {
	return cloudmodel.Network{
		Lcuuid:          uuid.NewString(),
		Name:            faker.Name(),
		SegmentationID:  RandID(),
		SubDomainLcuuid: FormatLcuuid(subDomainLcuuid),
		VPCLcuuid:       FormatLcuuid(vpcLcuuid),
		AZLcuuid:        FormatLcuuid(azLcuuid),
		RegionLcuuid:    FormatLcuuid(regionLcuuid),
	}
}

func NewCloudSubnet(subDomainLcuuid, vpcLcuuid, networkLcuuid string) cloudmodel.Subnet {
	return cloudmodel.Subnet{
		Lcuuid:          uuid.NewString(),
		Name:            faker.Name(),
		CIDR:            "10.10.1.0/15",
		NetworkLcuuid:   FormatLcuuid(networkLcuuid),
		SubDomainLcuuid: FormatLcuuid(subDomainLcuuid),
		VPCLcuuid:       FormatLcuuid(vpcLcuuid),
	}
}

func NewCloudVRouter(regionLcuuid, vpcLcuuid string) cloudmodel.VRouter {
	return cloudmodel.VRouter{
		Lcuuid:       uuid.NewString(),
		Name:         faker.Name(),
		VPCLcuuid:    FormatLcuuid(vpcLcuuid),
		RegionLcuuid: FormatLcuuid(regionLcuuid),
	}
}

func NewCloudRoutingTable(vrouterLcuuid string) cloudmodel.RoutingTable {
	return cloudmodel.RoutingTable{
		Lcuuid:        uuid.NewString(),
		Destination:   uuid.NewString(),
		VRouterLcuuid: FormatLcuuid(vrouterLcuuid),
	}
}

func NewCloudDHCPPort(regionLcuuid, azLcuuid, vpcLcuuid string) cloudmodel.DHCPPort {
	return cloudmodel.DHCPPort{
		Lcuuid:       uuid.NewString(),
		Name:         faker.Name(),
		VPCLcuuid:    FormatLcuuid(vpcLcuuid),
		AZLcuuid:     FormatLcuuid(azLcuuid),
		RegionLcuuid: FormatLcuuid(regionLcuuid),
	}
}

func NewCloudVInterface(regionLcuuid, subDomainLcuuid, vpcLcuuid, networkLcuuid, deviceLcuuid string, deviceType, vifType int) cloudmodel.VInterface {
	return cloudmodel.VInterface{
		Lcuuid:          uuid.NewString(),
		Name:            faker.Name(),
		Mac:             faker.MacAddress(),
		Type:            vifType,
		DeviceType:      deviceType,
		VPCLcuuid:       FormatLcuuid(vpcLcuuid),
		SubDomainLcuuid: FormatLcuuid(subDomainLcuuid),
		RegionLcuuid:    FormatLcuuid(regionLcuuid),
		DeviceLcuuid:    FormatLcuuid(deviceLcuuid),
		NetworkLcuuid:   FormatLcuuid(networkLcuuid),
	}
}

func NewCloudIP(regionLcuuid, subDomainLcuuid, SubnetLcuuid, vinterfaceLcuuid string) cloudmodel.IP {
	return cloudmodel.IP{
		Lcuuid:           uuid.NewString(),
		IP:               faker.IPv4(),
		SubnetLcuuid:     FormatLcuuid(SubnetLcuuid),
		SubDomainLcuuid:  FormatLcuuid(subDomainLcuuid),
		RegionLcuuid:     FormatLcuuid(regionLcuuid),
		VInterfaceLcuuid: FormatLcuuid(vinterfaceLcuuid),
	}
}

func NewCloudFloatingIP(regionLcuuid, vpcLcuuid, networkLcuuid, vmLcuuid string) cloudmodel.FloatingIP {
	return cloudmodel.FloatingIP{
		Lcuuid:        uuid.NewString(),
		IP:            faker.IPv6(),
		VPCLcuuid:     FormatLcuuid(vpcLcuuid),
		RegionLcuuid:  FormatLcuuid(regionLcuuid),
		NetworkLcuuid: FormatLcuuid(networkLcuuid),
		VMLcuuid:      FormatLcuuid(vmLcuuid),
	}
}

func NewCloudSecurityGroup(regionLcuuid, vpcLcuuid string) cloudmodel.SecurityGroup {
	return cloudmodel.SecurityGroup{
		Lcuuid:       uuid.NewString(),
		Name:         faker.Name(),
		Label:        faker.Name(),
		VPCLcuuid:    FormatLcuuid(vpcLcuuid),
		RegionLcuuid: FormatLcuuid(regionLcuuid),
	}
}

func NewCloudSecurityGroupRule(securityGroupLcuuid string) cloudmodel.SecurityGroupRule {
	return cloudmodel.SecurityGroupRule{
		Lcuuid:              uuid.NewString(),
		Protocol:            "TCP",
		Action:              1,
		Priority:            RandID(),
		Direction:           1,
		EtherType:           2,
		LocalPortRange:      "0-65535",
		RemotePortRange:     "0-65535",
		Local:               "0.0.0.0/0",
		Remote:              "0.0.0.0/0",
		SecurityGroupLcuuid: FormatLcuuid(securityGroupLcuuid),
	}
}

func NewCloudVMSecurityGroup(vmLcuuid, securityGroupLcuuid string) cloudmodel.VMSecurityGroup {
	return cloudmodel.VMSecurityGroup{
		Lcuuid:              uuid.NewString(),
		VMLcuuid:            FormatLcuuid(vmLcuuid),
		SecurityGroupLcuuid: FormatLcuuid(securityGroupLcuuid),
		Priority:            RandID(),
	}
}

func NewCloudNATGateway(regionLcuuid, vpcLcuuid string) cloudmodel.NATGateway {
	return cloudmodel.NATGateway{
		Lcuuid:       uuid.NewString(),
		Name:         faker.Name(),
		Label:        faker.Name(),
		FloatingIPs:  faker.IPv4(),
		VPCLcuuid:    FormatLcuuid(vpcLcuuid),
		RegionLcuuid: FormatLcuuid(regionLcuuid),
	}
}

func NewCloudNATRule(natGatewayLcuuid string) cloudmodel.NATRule {
	return cloudmodel.NATRule{
		Lcuuid:           uuid.NewString(),
		Type:             "SNAT",
		Protocol:         "TCP",
		FloatingIP:       faker.IPv4(),
		FloatingIPPort:   22,
		FixedIP:          faker.IPv4(),
		FixedIPPort:      80,
		NATGatewayLcuuid: FormatLcuuid(natGatewayLcuuid),
	}
}

func NewCloudLB(regionLcuuid, vpcLcuuid string) cloudmodel.LB {
	return cloudmodel.LB{
		Lcuuid:       uuid.NewString(),
		Name:         faker.Name(),
		Label:        faker.Name(),
		Model:        1,
		VIP:          faker.IPv4(),
		VPCLcuuid:    FormatLcuuid(vpcLcuuid),
		RegionLcuuid: FormatLcuuid(regionLcuuid),
	}
}

func NewCloudLBListener(lbLcuuid string) cloudmodel.LBListener {
	return cloudmodel.LBListener{
		Lcuuid:   uuid.NewString(),
		Name:     faker.Name(),
		Label:    faker.Name(),
		IPs:      faker.IPv4(),
		Protocol: "TCP",
		Port:     RandID(),
		LBLcuuid: FormatLcuuid(lbLcuuid),
	}
}

func NewCloudLBTargetServer(lbLcuuid, lbListenerLcuuid, VPCLcuuid, vmLcuuid string) cloudmodel.LBTargetServer {
	return cloudmodel.LBTargetServer{
		Lcuuid:           uuid.NewString(),
		IP:               faker.IPv4(),
		Protocol:         "TCP",
		Port:             RandID(),
		VMLcuuid:         FormatLcuuid(vmLcuuid),
		LBLcuuid:         FormatLcuuid(lbLcuuid),
		LBListenerLcuuid: FormatLcuuid(lbListenerLcuuid),
		VPCLcuuid:        FormatLcuuid(VPCLcuuid),
	}
}

func NewCloudLBVMConnection(lbLcuuid, vmLcuuid string) cloudmodel.LBVMConnection {
	return cloudmodel.LBVMConnection{
		Lcuuid:   uuid.NewString(),
		VMLcuuid: FormatLcuuid(vmLcuuid),
		LBLcuuid: FormatLcuuid(lbLcuuid),
	}
}

func NewCloudPeerConnection(localVPCLcuuid, remoteVPCLcuuid, localRegionLcuuid, remoteRegionLcuuid string) cloudmodel.PeerConnection {
	return cloudmodel.PeerConnection{
		Lcuuid:             uuid.NewString(),
		LocalVPCLcuuid:     FormatLcuuid(localVPCLcuuid),
		RemoteVPCLcuuid:    FormatLcuuid(remoteVPCLcuuid),
		LocalRegionLcuuid:  FormatLcuuid(localRegionLcuuid),
		RemoteRegionLcuuid: FormatLcuuid(remoteRegionLcuuid),
	}
}

func NewCloudCEN(vpcLcuuids []string) cloudmodel.CEN {
	return cloudmodel.CEN{
		Lcuuid:     uuid.NewString(),
		Name:       faker.Name(),
		VPCLcuuids: vpcLcuuids,
	}
}

func NewCloudRDSInstance(regionLcuuid, azLcuuid, vpcLcuuid string) cloudmodel.RDSInstance {
	return cloudmodel.RDSInstance{
		Lcuuid:       uuid.NewString(),
		Name:         faker.Name(),
		Label:        faker.Name(),
		State:        1,
		Version:      faker.Word(),
		Series:       3,
		Model:        2,
		Type:         1,
		VPCLcuuid:    FormatLcuuid(vpcLcuuid),
		RegionLcuuid: FormatLcuuid(regionLcuuid),
		AZLcuuid:     FormatLcuuid(azLcuuid),
	}
}

func NewCloudRedisInstance(regionLcuuid, azLcuuid, vpcLcuuid string) cloudmodel.RedisInstance {
	return cloudmodel.RedisInstance{
		Lcuuid:       uuid.NewString(),
		Name:         faker.Name(),
		Label:        faker.Name(),
		State:        1,
		Version:      faker.Word(),
		PublicHost:   faker.DomainName(),
		VPCLcuuid:    FormatLcuuid(vpcLcuuid),
		RegionLcuuid: FormatLcuuid(regionLcuuid),
		AZLcuuid:     FormatLcuuid(azLcuuid),
	}
}

func NewCloudPodCluster(regionLcuuid, azLcuuid, subDomainLcuuid, vpcLcuuid string) cloudmodel.PodCluster {
	return cloudmodel.PodCluster{
		Lcuuid:          uuid.NewString(),
		Name:            faker.Name(),
		Version:         faker.Word(),
		VPCLcuuid:       FormatLcuuid(vpcLcuuid),
		RegionLcuuid:    FormatLcuuid(regionLcuuid),
		AZLcuuid:        FormatLcuuid(azLcuuid),
		SubDomainLcuuid: FormatLcuuid(subDomainLcuuid),
	}
}

func NewCloudPodNode(regionLcuuid, azLcuuid, subDomainLcuuid, vpcLcuuid, podClusterLcuuid string) cloudmodel.PodNode {
	return cloudmodel.PodNode{
		Lcuuid:           uuid.NewString(),
		Name:             faker.Name(),
		IP:               faker.IPv4(),
		Type:             1,
		VCPUNum:          RandID(),
		MemTotal:         RandID(),
		VPCLcuuid:        FormatLcuuid(vpcLcuuid),
		PodClusterLcuuid: FormatLcuuid(podClusterLcuuid),
		RegionLcuuid:     FormatLcuuid(regionLcuuid),
		AZLcuuid:         FormatLcuuid(azLcuuid),
		SubDomainLcuuid:  FormatLcuuid(subDomainLcuuid),
	}
}

func NewCloudVMPodNodeConnection(subDomainLcuuid, vmLcuuid, PodNodeLcuuid string) cloudmodel.VMPodNodeConnection {
	return cloudmodel.VMPodNodeConnection{
		Lcuuid:          uuid.NewString(),
		VMLcuuid:        FormatLcuuid(vmLcuuid),
		PodNodeLcuuid:   FormatLcuuid(PodNodeLcuuid),
		SubDomainLcuuid: FormatLcuuid(subDomainLcuuid),
	}
}

func NewCloudPodNamespace(regionLcuuid, azLcuuid, subDomainLcuuid, podClusterLcuuid string) cloudmodel.PodNamespace {
	return cloudmodel.PodNamespace{
		Lcuuid:           uuid.NewString(),
		Name:             faker.Name(),
		PodClusterLcuuid: FormatLcuuid(podClusterLcuuid),
		RegionLcuuid:     FormatLcuuid(regionLcuuid),
		AZLcuuid:         FormatLcuuid(azLcuuid),
		SubDomainLcuuid:  FormatLcuuid(subDomainLcuuid),
	}
}

func NewCloudPodIngress(regionLcuuid, azLcuuid, subDomainLcuuid, podClusterLcuuid, podNamespaceLcuuid string) cloudmodel.PodIngress {
	return cloudmodel.PodIngress{
		Lcuuid:             uuid.NewString(),
		Name:               faker.Name(),
		PodClusterLcuuid:   FormatLcuuid(podClusterLcuuid),
		RegionLcuuid:       FormatLcuuid(regionLcuuid),
		AZLcuuid:           FormatLcuuid(azLcuuid),
		SubDomainLcuuid:    FormatLcuuid(subDomainLcuuid),
		PodNamespaceLcuuid: FormatLcuuid(podNamespaceLcuuid),
	}
}

func NewCloudPodIngressRule(subDomainLcuuid, PodIngressLcuuid string) cloudmodel.PodIngressRule {
	return cloudmodel.PodIngressRule{
		Lcuuid:           uuid.NewString(),
		Name:             faker.Name(),
		Protocol:         "UDP",
		PodIngressLcuuid: FormatLcuuid(PodIngressLcuuid),
		SubDomainLcuuid:  FormatLcuuid(subDomainLcuuid),
	}
}

func NewCloudPodIngressRuleBackend(subDomainLcuuid, podIngressLcuuid, podIngressRuleLcuuid, podServiceLcuuid string) cloudmodel.PodIngressRuleBackend {
	return cloudmodel.PodIngressRuleBackend{
		Lcuuid:               uuid.NewString(),
		Port:                 RandID(),
		PodIngressLcuuid:     FormatLcuuid(podIngressLcuuid),
		PodIngressRuleLcuuid: FormatLcuuid(podIngressRuleLcuuid),
		PodServiceLcuuid:     FormatLcuuid(podServiceLcuuid),
		SubDomainLcuuid:      FormatLcuuid(subDomainLcuuid),
	}
}

func NewCloudPodService(regionLcuuid, azLcuuid, subDomainLcuuid, vpcLcuuid, podClusterLcuuid, podNamespaceLcuuid, podIngressLcuuid string) cloudmodel.PodService {
	return cloudmodel.PodService{
		Lcuuid:             uuid.NewString(),
		Name:               faker.Name(),
		ServiceClusterIP:   faker.IPv4(),
		PodClusterLcuuid:   FormatLcuuid(podClusterLcuuid),
		RegionLcuuid:       FormatLcuuid(regionLcuuid),
		AZLcuuid:           FormatLcuuid(azLcuuid),
		SubDomainLcuuid:    FormatLcuuid(subDomainLcuuid),
		PodNamespaceLcuuid: FormatLcuuid(podNamespaceLcuuid),
		PodIngressLcuuid:   FormatLcuuid(podIngressLcuuid),
		VPCLcuuid:          FormatLcuuid(vpcLcuuid),
	}
}

func NewCloudPodServicePort(subDomainLcuuid, podServiceLcuuid string) cloudmodel.PodServicePort {
	return cloudmodel.PodServicePort{
		Lcuuid:           uuid.NewString(),
		Name:             faker.Name(),
		Port:             RandID(),
		TargetPort:       RandID(),
		Protocol:         "TCP",
		NodePort:         RandID(),
		SubDomainLcuuid:  FormatLcuuid(subDomainLcuuid),
		PodServiceLcuuid: FormatLcuuid(podServiceLcuuid),
	}
}

func NewCloudPodGroup(regionLcuuid, azLcuuid, subDomainLcuuid, podClusterLcuuid, podNamespaceLcuuid string) cloudmodel.PodGroup {
	return cloudmodel.PodGroup{
		Lcuuid:             uuid.NewString(),
		Name:               faker.Name(),
		Label:              faker.Name(),
		PodNum:             RandID(),
		PodClusterLcuuid:   FormatLcuuid(podClusterLcuuid),
		RegionLcuuid:       FormatLcuuid(regionLcuuid),
		AZLcuuid:           FormatLcuuid(azLcuuid),
		SubDomainLcuuid:    FormatLcuuid(subDomainLcuuid),
		PodNamespaceLcuuid: FormatLcuuid(podNamespaceLcuuid),
	}
}

func NewCloudPodGroupPort(subDomainLcuuid, podServiceLcuuid, podGroupLcuuid string) cloudmodel.PodGroupPort {
	return cloudmodel.PodGroupPort{
		Lcuuid:           uuid.NewString(),
		Name:             faker.Name(),
		Port:             RandID(),
		PodGroupLcuuid:   FormatLcuuid(podGroupLcuuid),
		PodServiceLcuuid: FormatLcuuid(podServiceLcuuid),
		SubDomainLcuuid:  FormatLcuuid(subDomainLcuuid),
	}
}

func NewCloudPodReplicaSet(regionLcuuid, azLcuuid, subDomainLcuuid, podClusterLcuuid, podNamespaceLcuuid, podGroupLcuuid string) cloudmodel.PodReplicaSet {
	return cloudmodel.PodReplicaSet{
		Lcuuid:             uuid.NewString(),
		Name:               faker.Name(),
		PodNum:             RandID(),
		PodClusterLcuuid:   FormatLcuuid(podClusterLcuuid),
		RegionLcuuid:       FormatLcuuid(regionLcuuid),
		AZLcuuid:           FormatLcuuid(azLcuuid),
		SubDomainLcuuid:    FormatLcuuid(subDomainLcuuid),
		PodNamespaceLcuuid: FormatLcuuid(podNamespaceLcuuid),
		PodGroupLcuuid:     FormatLcuuid(podGroupLcuuid),
	}
}

func NewCloudPod(regionLcuuid, azLcuuid, subDomainLcuuid, vpcLcuuid, podClusterLcuuid, podNodeLcuuid, podNamespaceLcuuid, podGroupLcuuid, podReplicaSetLcuuid string) cloudmodel.Pod {
	return cloudmodel.Pod{
		Lcuuid:              uuid.NewString(),
		Name:                faker.Name(),
		PodClusterLcuuid:    FormatLcuuid(podClusterLcuuid),
		RegionLcuuid:        FormatLcuuid(regionLcuuid),
		AZLcuuid:            FormatLcuuid(azLcuuid),
		SubDomainLcuuid:     FormatLcuuid(subDomainLcuuid),
		PodNamespaceLcuuid:  FormatLcuuid(podNamespaceLcuuid),
		PodGroupLcuuid:      FormatLcuuid(podGroupLcuuid),
		VPCLcuuid:           FormatLcuuid(vpcLcuuid),
		PodNodeLcuuid:       FormatLcuuid(podNodeLcuuid),
		PodReplicaSetLcuuid: FormatLcuuid(podReplicaSetLcuuid),
	}
}

// 构造cloud数据
// 参数：baseCount，指定一个数据基数，用于构造数据数量
func NewCloudResource(baseCount int) cloudmodel.Resource {
	resource := cloudmodel.Resource{}

	// baseCount
	// region、az、sub_domain
	for i := 0; i < baseCount; i++ {
		region := NewCloudRegion()
		resource.Regions = append(resource.Regions, region)
		az := NewCloudAZ(region.Lcuuid)
		resource.AZs = append(resource.AZs, az)
		subDomain := NewCloudSubDomain()
		resource.SubDomains = append(resource.SubDomains, subDomain)

		// baseCount * 5
		// vpc、host、pod_cluster
		// peer_connection、cen
		for j := 0; j < 5; j++ {
			vpc := NewCloudVPC(region.Lcuuid)
			resource.VPCs = append(resource.VPCs, vpc)

			host := NewCloudHost(region.Lcuuid, az.Lcuuid)
			resource.Hosts = append(resource.Hosts, host)

			podCluster := NewCloudPodCluster(region.Lcuuid, az.Lcuuid, subDomain.Lcuuid, vpc.Lcuuid)
			resource.PodClusters = append(resource.PodClusters, podCluster)

			resource.CENs = append(resource.CENs, NewCloudCEN([]string{vpc.Lcuuid}))
			resource.PeerConnections = append(
				resource.PeerConnections,
				NewCloudPeerConnection(vpc.Lcuuid, vpc.Lcuuid, region.Lcuuid, region.Lcuuid),
			)

			// baseCount * 5 * 5
			// network、vrouter、dhcp_port、
			// security_group、nat_gateway、lb
			// rds_instance、redis_instance
			for k := 0; k < 5; k++ {
				network := NewCloudNetwork(region.Lcuuid, az.Lcuuid, subDomain.Lcuuid, vpc.Lcuuid)
				resource.Networks = append(resource.Networks, network)

				// baseCount * 5 * 5 * 5
				// subnet
				for l := 0; l < 5; l++ {
					resource.Subnets = append(resource.Subnets, NewCloudSubnet(subDomain.Lcuuid, vpc.Lcuuid, network.Lcuuid))
				}

				// baseCount * 5 * 5 * 50
				// vm
				for l := 0; l < 50; l++ {
					vm := NewCloudVM(region.Lcuuid, az.Lcuuid, vpc.Lcuuid)
					resource.VMs = append(resource.VMs, vm)
					vmVinterface := NewCloudVInterface(
						region.Lcuuid, subDomain.Lcuuid, vpc.Lcuuid, network.Lcuuid, vm.Lcuuid, common.VIF_DEVICE_TYPE_VM, 3,
					)
					resource.VInterfaces = append(resource.VInterfaces, vmVinterface)
					resource.IPs = append(
						resource.IPs,
						NewCloudIP(region.Lcuuid, subDomain.Lcuuid, resource.Subnets[len(resource.Subnets)-1].Lcuuid, vmVinterface.Lcuuid),
					)
					resource.FloatingIPs = append(
						resource.FloatingIPs,
						NewCloudFloatingIP(region.Lcuuid, vpc.Lcuuid, network.Lcuuid, vm.Lcuuid),
					)
				}

				vrouter := NewCloudVRouter(region.Lcuuid, vpc.Lcuuid)
				resource.VRouters = append(resource.VRouters, vrouter)
				vrouterVinterface := NewCloudVInterface(
					region.Lcuuid, subDomain.Lcuuid, vpc.Lcuuid, network.Lcuuid, vrouter.Lcuuid, common.VIF_DEVICE_TYPE_VROUTER, 4,
				)
				resource.VInterfaces = append(resource.VInterfaces, vrouterVinterface)
				resource.IPs = append(
					resource.IPs,
					NewCloudIP(region.Lcuuid, subDomain.Lcuuid, resource.Subnets[len(resource.Subnets)-1].Lcuuid, vrouterVinterface.Lcuuid),
				)

				dhcpPort := NewCloudDHCPPort(region.Lcuuid, az.Lcuuid, vpc.Lcuuid)
				resource.DHCPPorts = append(resource.DHCPPorts, dhcpPort)
				dhcpPortVinterface := NewCloudVInterface(
					region.Lcuuid, subDomain.Lcuuid, vpc.Lcuuid, network.Lcuuid, dhcpPort.Lcuuid, common.VIF_DEVICE_TYPE_DHCP_PORT, 3,
				)
				if k == 0 {
					dhcpPortVinterface.NetworkLcuuid = rcommon.PUBLIC_NETWORK_LCUUID
				}
				resource.VInterfaces = append(resource.VInterfaces, dhcpPortVinterface)
				resource.IPs = append(
					resource.IPs,
					NewCloudIP(region.Lcuuid, subDomain.Lcuuid, resource.Subnets[len(resource.Subnets)-2].Lcuuid, dhcpPortVinterface.Lcuuid),
				)

				natGateway := NewCloudNATGateway(region.Lcuuid, vpc.Lcuuid)
				resource.NATGateways = append(resource.NATGateways, natGateway)
				natGatewayVinterface := NewCloudVInterface(
					region.Lcuuid, subDomain.Lcuuid, vpc.Lcuuid, network.Lcuuid, natGateway.Lcuuid, common.VIF_DEVICE_TYPE_NAT_GATEWAY, 4,
				)
				resource.VInterfaces = append(resource.VInterfaces, natGatewayVinterface)
				resource.IPs = append(
					resource.IPs,
					NewCloudIP(region.Lcuuid, subDomain.Lcuuid, resource.Subnets[len(resource.Subnets)-2].Lcuuid, natGatewayVinterface.Lcuuid),
				)

				lb := NewCloudLB(region.Lcuuid, vpc.Lcuuid)
				resource.LBs = append(resource.LBs, lb)
				lbVinterface := NewCloudVInterface(
					region.Lcuuid, subDomain.Lcuuid, vpc.Lcuuid, network.Lcuuid, lb.Lcuuid, common.VIF_DEVICE_TYPE_LB, 3,
				)
				resource.VInterfaces = append(resource.VInterfaces, lbVinterface)
				resource.IPs = append(
					resource.IPs,
					NewCloudIP(region.Lcuuid, subDomain.Lcuuid, resource.Subnets[len(resource.Subnets)-2].Lcuuid, lbVinterface.Lcuuid),
				)

				rdsInstance := NewCloudRDSInstance(region.Lcuuid, az.Lcuuid, vpc.Lcuuid)
				resource.RDSInstances = append(resource.RDSInstances, rdsInstance)
				rdsVinterface := NewCloudVInterface(
					region.Lcuuid, subDomain.Lcuuid, vpc.Lcuuid, network.Lcuuid, rdsInstance.Lcuuid, common.VIF_DEVICE_TYPE_RDS_INSTANCE, 4,
				)
				resource.VInterfaces = append(resource.VInterfaces, rdsVinterface)
				resource.IPs = append(
					resource.IPs,
					NewCloudIP(region.Lcuuid, subDomain.Lcuuid, resource.Subnets[len(resource.Subnets)-2].Lcuuid, rdsVinterface.Lcuuid),
				)

				redisInstance := NewCloudRedisInstance(region.Lcuuid, az.Lcuuid, vpc.Lcuuid)
				resource.RedisInstances = append(resource.RedisInstances, redisInstance)
				redisVinterface := NewCloudVInterface(
					region.Lcuuid, subDomain.Lcuuid, vpc.Lcuuid, network.Lcuuid, redisInstance.Lcuuid, common.VIF_DEVICE_TYPE_REDIS_INSTANCE, 3,
				)
				resource.VInterfaces = append(resource.VInterfaces, redisVinterface)
				resource.IPs = append(
					resource.IPs,
					NewCloudIP(region.Lcuuid, subDomain.Lcuuid, resource.Subnets[len(resource.Subnets)-1].Lcuuid, redisVinterface.Lcuuid),
				)

				// baseCount * 5 * 5 * 5
				// security_group、vm_security_group、routing_table、nat_rule、lb_listener、lb_target_server
				for l := 0; l < 5; l++ {
					resource.RoutingTables = append(resource.RoutingTables, NewCloudRoutingTable(vrouter.Lcuuid))
					securityGroup := NewCloudSecurityGroup(region.Lcuuid, vpc.Lcuuid)
					resource.SecurityGroups = append(resource.SecurityGroups, securityGroup)
					resource.VMSecurityGroups = append(
						resource.VMSecurityGroups, NewCloudVMSecurityGroup(resource.VMs[len(resource.VMs)-1].Lcuuid, securityGroup.Lcuuid),
					)
					// baseCount * 5 * 5 * 5 * 5
					// security_group_rule
					for m := 0; m < 5; m++ {
						resource.SecurityGroupRules = append(resource.SecurityGroupRules, NewCloudSecurityGroupRule(securityGroup.Lcuuid))
					}
					resource.NATRules = append(resource.NATRules, NewCloudNATRule(natGateway.Lcuuid))
					lbListener := NewCloudLBListener(lb.Lcuuid)
					resource.LBListeners = append(resource.LBListeners, lbListener)
					resource.LBTargetServers = append(
						resource.LBTargetServers, NewCloudLBTargetServer(lb.Lcuuid, lbListener.Lcuuid, vpc.Lcuuid, resource.VMs[len(resource.VMs)-1].Lcuuid),
					)
				}

				// baseCount * 5 * 5 * 50
				// pod_node
				for l := 0; l < 50; l++ {
					podNode := NewCloudPodNode(region.Lcuuid, az.Lcuuid, subDomain.Lcuuid, vpc.Lcuuid, podCluster.Lcuuid)
					resource.PodNodes = append(resource.PodNodes, podNode)
					podNodeVinterface := NewCloudVInterface(
						region.Lcuuid, subDomain.Lcuuid, vpc.Lcuuid, network.Lcuuid, podNode.Lcuuid, common.VIF_DEVICE_TYPE_POD_NODE, 4,
					)
					resource.VInterfaces = append(resource.VInterfaces, podNodeVinterface)
					resource.IPs = append(
						resource.IPs,
						NewCloudIP(region.Lcuuid, subDomain.Lcuuid, resource.Subnets[len(resource.Subnets)-1].Lcuuid, podNodeVinterface.Lcuuid),
					)
					// baseCount * 5 * 5 * 50 * 5
					// pod_namespace
					for m := 0; m < 5; m++ {
						podNamespace := NewCloudPodNamespace(region.Lcuuid, az.Lcuuid, subDomain.Lcuuid, podCluster.Lcuuid)
						resource.PodNamespaces = append(resource.PodNamespaces, podNamespace)
						// baseCount * 5 * 5 * 50 * 5 * 2
						// pod_ingress、pod_ingress_rule、pod_ingress_rule_backend、pod_service、pod_service_port
						// pod_group、pod_group_port、pod_replica_set
						for n := 0; n < 2; n++ {
							podIngress := NewCloudPodIngress(
								region.Lcuuid, az.Lcuuid, subDomain.Lcuuid, podCluster.Lcuuid, podNamespace.Lcuuid,
							)
							resource.PodIngresses = append(resource.PodIngresses, podIngress)
							podService := NewCloudPodService(
								region.Lcuuid, az.Lcuuid, subDomain.Lcuuid, vpc.Lcuuid, podCluster.Lcuuid,
								podNamespace.Lcuuid, podIngress.Lcuuid,
							)
							resource.PodServices = append(resource.PodServices, podService)
							podServiceVinterface := NewCloudVInterface(
								region.Lcuuid, subDomain.Lcuuid, vpc.Lcuuid, network.Lcuuid, podService.Lcuuid, common.VIF_DEVICE_TYPE_POD_SERVICE, 4,
							)
							resource.VInterfaces = append(resource.VInterfaces, podServiceVinterface)
							resource.IPs = append(
								resource.IPs,
								NewCloudIP(region.Lcuuid, subDomain.Lcuuid, resource.Subnets[len(resource.Subnets)-1].Lcuuid, podServiceVinterface.Lcuuid),
							)

							podIngressRule := NewCloudPodIngressRule(subDomain.Lcuuid, podIngress.Lcuuid)
							resource.PodIngressRules = append(resource.PodIngressRules, podIngressRule)
							resource.PodIngressRuleBackends = append(
								resource.PodIngressRuleBackends,
								NewCloudPodIngressRuleBackend(
									subDomain.Lcuuid, podIngress.Lcuuid, podIngressRule.Lcuuid, podService.Lcuuid,
								),
							)
							resource.PodServicePorts = append(
								resource.PodServicePorts,
								NewCloudPodServicePort(subDomain.Lcuuid, podService.Lcuuid),
							)
							podGroup := NewCloudPodGroup(
								region.Lcuuid, az.Lcuuid, subDomain.Lcuuid, podCluster.Lcuuid, podNamespace.Lcuuid,
							)
							resource.PodGroups = append(resource.PodGroups, podGroup)
							resource.PodGroupPorts = append(
								resource.PodGroupPorts, NewCloudPodGroupPort(subDomain.Lcuuid, podService.Lcuuid, podGroup.Lcuuid),
							)
							podReplicaSet := NewCloudPodReplicaSet(
								region.Lcuuid, az.Lcuuid, subDomain.Lcuuid, podCluster.Lcuuid,
								podNamespace.Lcuuid, podGroup.Lcuuid,
							)
							resource.PodReplicaSets = append(resource.PodReplicaSets, podReplicaSet)
							// baseCount * 5 * 5 * 50 * 5 * 2 * 2
							// pod
							for o := 0; o < 2; o++ {
								pod := NewCloudPod(
									region.Lcuuid, az.Lcuuid, subDomain.Lcuuid, vpc.Lcuuid,
									podCluster.Lcuuid, podNode.Lcuuid, podNamespace.Lcuuid,
									podGroup.Lcuuid, podReplicaSet.Lcuuid,
								)
								resource.Pods = append(resource.Pods, pod)
								podVinterface := NewCloudVInterface(
									region.Lcuuid, subDomain.Lcuuid, vpc.Lcuuid, network.Lcuuid, pod.Lcuuid, common.VIF_DEVICE_TYPE_POD, 3,
								)
								resource.VInterfaces = append(resource.VInterfaces, podVinterface)
								resource.IPs = append(
									resource.IPs,
									NewCloudIP(region.Lcuuid, subDomain.Lcuuid, resource.Subnets[len(resource.Subnets)-1].Lcuuid, podVinterface.Lcuuid),
								)
							}
						}
					}
				}
			}
		}
	}

	return resource
}
