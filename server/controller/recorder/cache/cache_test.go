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
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

const (
	DOMAIN_LCUUID = "8f0d07b5-0312-50cf-96ce-d5b54c24a118"
)

func TestAddRegion(t *testing.T) {
	mysqlItem := &mysql.Region{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.Regions), 0)
	cache.AddRegion(mysqlItem)
	assert.Equal(t, len(cache.Regions), 1)
	assert.Equal(t, cache.regionLcuuidToID[mysqlItem.Lcuuid], mysqlItem.ID)
}

func TestAddAZ(t *testing.T) {
	mysqlItem := &mysql.AZ{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.AZs), 0)
	cache.AddAZ(mysqlItem)
	assert.Equal(t, len(cache.AZs), 1)
}

func TestAddSubDomain(t *testing.T) {
	mysqlItem := &mysql.SubDomain{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.SubDomains), 0)
	cache.AddSubDomain(mysqlItem)
	assert.Equal(t, len(cache.SubDomains), 1)
}

func TestAddHost(t *testing.T) {
	mysqlItem := &mysql.Host{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.Hosts), 0)
	cache.AddHost(mysqlItem)
	assert.Equal(t, len(cache.Hosts), 1)
	assert.Equal(t, cache.hostLcuuidToID[mysqlItem.Lcuuid], mysqlItem.ID)
}

func TestAddVM(t *testing.T) {
	mysqlItem := &mysql.VM{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.VMs), 0)
	cache.vpcIDToLcuuid[mysqlItem.VPCID] = uuid.New().String()
	cache.AddVM(mysqlItem)
	assert.Equal(t, len(cache.VMs), 1)
	assert.Equal(t, cache.vmLcuuidToID[mysqlItem.Lcuuid], mysqlItem.ID)
}

func TestAddNetwork(t *testing.T) {
	mysqlItem := &mysql.Network{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	cache.vpcIDToLcuuid[mysqlItem.VPCID] = uuid.New().String()
	assert.Equal(t, len(cache.Networks), 0)
	cache.AddNetwork(mysqlItem)
	assert.Equal(t, len(cache.Networks), 1)
	assert.Equal(t, cache.networkLcuuidToID[mysqlItem.Lcuuid], mysqlItem.ID)
}

func TestAddSubnets(t *testing.T) {
	mysqlItem := &mysql.Subnet{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}, NetworkID: 9}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.Subnets), 0)
	cache.AddSubnets([]*mysql.Subnet{mysqlItem})
	assert.Equal(t, len(cache.Subnets), 1)
}

func TestAddVRouter(t *testing.T) {
	mysqlItem := &mysql.VRouter{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	cache.vpcIDToLcuuid[mysqlItem.VPCID] = uuid.New().String()
	assert.Equal(t, len(cache.VRouters), 0)
	cache.AddVRouter(mysqlItem)
	assert.Equal(t, len(cache.VRouters), 1)
	assert.Equal(t, cache.vrouterLcuuidToID[mysqlItem.Lcuuid], mysqlItem.ID)
}

func TestAddRoutingTables(t *testing.T) {
	mysqlItem := &mysql.RoutingTable{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.RoutingTables), 0)
	cache.AddRoutingTables([]*mysql.RoutingTable{mysqlItem})
	assert.Equal(t, len(cache.RoutingTables), 1)
}

func TestAddDHCPPorts(t *testing.T) {
	mysqlItem := &mysql.DHCPPort{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.DHCPPorts), 0)
	cache.AddDHCPPorts([]*mysql.DHCPPort{mysqlItem})
	assert.Equal(t, len(cache.DHCPPorts), 1)
	assert.Equal(t, cache.dhcpPortLcuuidToID[mysqlItem.Lcuuid], mysqlItem.ID)
}

func TestAddVInterfaces(t *testing.T) {
	mysqlItem := &mysql.VInterface{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}, NetworkID: 9}
	networkLcuuid := uuid.New().String()
	cache := NewCache(DOMAIN_LCUUID)
	cache.networkIDToLcuuid[mysqlItem.NetworkID] = networkLcuuid
	assert.Equal(t, len(cache.VInterfaces), 0)
	cache.AddVInterfaces([]*mysql.VInterface{mysqlItem})
	assert.Equal(t, len(cache.VInterfaces), 1)
	assert.Equal(t, cache.vinterfaceLcuuidToNetworkID[mysqlItem.Lcuuid], 9)
}

func TestAddWANIPs(t *testing.T) {
	mysqlItem := &mysql.WANIP{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.WANIPs), 0)
	cache.AddWANIPs([]*mysql.WANIP{mysqlItem})
	assert.Equal(t, len(cache.WANIPs), 1)
}

func TestAddLANIPs(t *testing.T) {
	mysqlItem := &mysql.LANIP{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.LANIPs), 0)
	cache.AddLANIPs([]*mysql.LANIP{mysqlItem})
	assert.Equal(t, len(cache.LANIPs), 1)
}

func TestAddFloatingIPs(t *testing.T) {
	mysqlItem := &mysql.FloatingIP{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.FloatingIPs), 0)
	cache.AddFloatingIPs([]*mysql.FloatingIP{mysqlItem})
	assert.Equal(t, len(cache.FloatingIPs), 1)
}

func TestAddSecurityGroup(t *testing.T) {
	mysqlItem := &mysql.SecurityGroup{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.SecurityGroups), 0)
	cache.AddSecurityGroup(mysqlItem)
	assert.Equal(t, len(cache.SecurityGroups), 1)
	assert.Equal(t, cache.securityGroupLcuuidToID[mysqlItem.Lcuuid], mysqlItem.ID)
}

func TestAddSecurityGroupRules(t *testing.T) {
	mysqlItem := &mysql.SecurityGroupRule{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.SecurityGroupRules), 0)
	cache.AddSecurityGroupRules([]*mysql.SecurityGroupRule{mysqlItem})
	assert.Equal(t, len(cache.SecurityGroupRules), 1)
}

func TestAddVMSecurityGroups(t *testing.T) {
	mysqlItem := &mysql.VMSecurityGroup{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.VMSecurityGroups), 0)
	cache.AddVMSecurityGroups([]*mysql.VMSecurityGroup{mysqlItem})
	assert.Equal(t, len(cache.VMSecurityGroups), 1)
}

func TestAddNATGateways(t *testing.T) {
	mysqlItem := &mysql.NATGateway{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.NATGateways), 0)
	cache.AddNATGateways([]*mysql.NATGateway{mysqlItem})
	assert.Equal(t, len(cache.NATGateways), 1)
	assert.Equal(t, cache.natGatewayLcuuidToID[mysqlItem.Lcuuid], mysqlItem.ID)
}

func TestAddNATRules(t *testing.T) {
	mysqlItem := &mysql.NATRule{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.NATRules), 0)
	cache.AddNATRules([]*mysql.NATRule{mysqlItem})
	assert.Equal(t, len(cache.NATRules), 1)
}

func TestAddNATVMConnections(t *testing.T) {
	mysqlItem := &mysql.NATVMConnection{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.NATVMConnections), 0)
	cache.AddNATVMConnections([]*mysql.NATVMConnection{mysqlItem})
	assert.Equal(t, len(cache.NATVMConnections), 1)
}

func TestAddLBs(t *testing.T) {
	mysqlItem := &mysql.LB{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.LBs), 0)
	cache.AddLBs([]*mysql.LB{mysqlItem})
	assert.Equal(t, len(cache.LBs), 1)
	assert.Equal(t, cache.lbLcuuidToID[mysqlItem.Lcuuid], mysqlItem.ID)
}

func TestAddLBListeners(t *testing.T) {
	mysqlItem := &mysql.LBListener{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.LBListeners), 0)
	cache.AddLBListeners([]*mysql.LBListener{mysqlItem})
	assert.Equal(t, len(cache.LBListeners), 1)
}

func TestAddLBTargetServers(t *testing.T) {
	mysqlItem := &mysql.LBTargetServer{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.LBTargetServers), 0)
	cache.AddLBTargetServers([]*mysql.LBTargetServer{mysqlItem})
	assert.Equal(t, len(cache.LBTargetServers), 1)
}

func TestAddLBVMConnections(t *testing.T) {
	mysqlItem := &mysql.LBVMConnection{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.LBVMConnections), 0)
	cache.AddLBVMConnections([]*mysql.LBVMConnection{mysqlItem})
	assert.Equal(t, len(cache.LBVMConnections), 1)
}

func TestAddPeerConnections(t *testing.T) {
	mysqlItem := &mysql.PeerConnection{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	cache.regionIDToLcuuid[mysqlItem.RemoteRegionID] = uuid.New().String()
	cache.regionIDToLcuuid[mysqlItem.LocalRegionID] = uuid.New().String()
	assert.Equal(t, len(cache.PeerConnections), 0)
	cache.AddPeerConnections([]*mysql.PeerConnection{mysqlItem})
	assert.Equal(t, len(cache.PeerConnections), 1)
}

func TestAddCENs(t *testing.T) {
	mysqlItem := &mysql.CEN{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.CENs), 0)
	cache.AddCENs([]*mysql.CEN{mysqlItem})
	assert.Equal(t, len(cache.CENs), 1)
}

func TestAddRDSInstances(t *testing.T) {
	mysqlItem := &mysql.RDSInstance{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.RDSInstances), 0)
	cache.AddRDSInstances([]*mysql.RDSInstance{mysqlItem})
	assert.Equal(t, len(cache.RDSInstances), 1)
	assert.Equal(t, cache.rdsInstanceLcuuidToID[mysqlItem.Lcuuid], mysqlItem.ID)
}

func TestAddRedisInstances(t *testing.T) {
	mysqlItem := &mysql.RedisInstance{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.RedisInstances), 0)
	cache.AddRedisInstances([]*mysql.RedisInstance{mysqlItem})
	assert.Equal(t, len(cache.RedisInstances), 1)
	assert.Equal(t, cache.redisInstanceLcuuidToID[mysqlItem.Lcuuid], mysqlItem.ID)
}

func TestAddPodClusters(t *testing.T) {
	mysqlItem := &mysql.PodCluster{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.PodClusters), 0)
	cache.AddPodClusters([]*mysql.PodCluster{mysqlItem})
	assert.Equal(t, len(cache.PodClusters), 1)
	assert.Equal(t, cache.podClusterLcuuidToID[mysqlItem.Lcuuid], mysqlItem.ID)
}

func TestAddPodNodes(t *testing.T) {
	mysqlItem := &mysql.PodNode{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.PodNodes), 0)
	cache.AddPodNodes([]*mysql.PodNode{mysqlItem})
	assert.Equal(t, len(cache.PodNodes), 1)
	assert.Equal(t, cache.podNodeIDToLcuuid[mysqlItem.ID], mysqlItem.Lcuuid)
}

func TestAddPodNamespaces(t *testing.T) {
	mysqlItem := &mysql.PodNamespace{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.PodNamespaces), 0)
	cache.AddPodNamespaces([]*mysql.PodNamespace{mysqlItem})
	assert.Equal(t, len(cache.PodNamespaces), 1)
}

func TestAddPodIngress(t *testing.T) {
	mysqlItem := &mysql.PodIngress{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.PodIngresses), 0)
	cache.AddPodIngress(mysqlItem)
	assert.Equal(t, len(cache.PodIngresses), 1)
}

func TestAddPodIngressRules(t *testing.T) {
	mysqlItem := &mysql.PodIngressRule{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.PodIngressRules), 0)
	cache.AddPodIngressRules([]*mysql.PodIngressRule{mysqlItem})
	assert.Equal(t, len(cache.PodIngressRules), 1)
	assert.Equal(t, cache.podIngressRuleLcuuidToID[mysqlItem.Lcuuid], mysqlItem.ID)
}

func TestAddPodIngressRuleBackends(t *testing.T) {
	mysqlItem := &mysql.PodIngressRuleBackend{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.PodIngressRuleBackends), 0)
	cache.AddPodIngressRuleBackends([]*mysql.PodIngressRuleBackend{mysqlItem})
	assert.Equal(t, len(cache.PodIngressRuleBackends), 1)
}

func TestAddPodService(t *testing.T) {
	mysqlItem := &mysql.PodService{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.PodServices), 0)
	cache.AddPodService(mysqlItem)
	assert.Equal(t, len(cache.PodServices), 1)
}

func TestAddPodServicePorts(t *testing.T) {
	mysqlItem := &mysql.PodServicePort{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.PodServicePorts), 0)
	cache.AddPodServicePorts([]*mysql.PodServicePort{mysqlItem})
	assert.Equal(t, len(cache.PodServicePorts), 1)
}

func TestAddPodGroups(t *testing.T) {
	mysqlItem := &mysql.PodGroup{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.PodGroups), 0)
	cache.AddPodGroups([]*mysql.PodGroup{mysqlItem})
	assert.Equal(t, len(cache.PodGroups), 1)
}

func TestAddPodGroupPorts(t *testing.T) {
	mysqlItem := &mysql.PodGroupPort{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.PodGroupPorts), 0)
	cache.AddPodGroupPorts([]*mysql.PodGroupPort{mysqlItem})
	assert.Equal(t, len(cache.PodGroupPorts), 1)
}

func TestAddPodReplicaSets(t *testing.T) {
	mysqlItem := &mysql.PodReplicaSet{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.PodReplicaSets), 0)
	cache.AddPodReplicaSets([]*mysql.PodReplicaSet{mysqlItem})
	assert.Equal(t, len(cache.PodReplicaSets), 1)
}

func TestAddPods(t *testing.T) {
	mysqlItem := &mysql.Pod{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	cache.vpcIDToLcuuid[mysqlItem.VPCID] = uuid.New().String()
	cache.podNodeIDToLcuuid[mysqlItem.PodNodeID] = uuid.New().String()
	cache.podReplicaSetIDToLcuuid[mysqlItem.PodReplicaSetID] = uuid.New().String()
	assert.Equal(t, len(cache.Pods), 0)
	cache.AddPods([]*mysql.Pod{mysqlItem})
	assert.Equal(t, len(cache.Pods), 1)
}

func TestAddVMPodNodeConnections(t *testing.T) {
	mysqlItem := &mysql.VMPodNodeConnection{Base: mysql.Base{ID: 1, Lcuuid: uuid.New().String()}}
	cache := NewCache(DOMAIN_LCUUID)
	assert.Equal(t, len(cache.VMPodNodeConnections), 0)
	cache.AddVMPodNodeConnections([]*mysql.VMPodNodeConnection{mysqlItem})
	assert.Equal(t, len(cache.VMPodNodeConnections), 1)
}

func (t *SuiteTest) TestRefreshRegions() {
	cache := NewCache(DOMAIN_LCUUID)
	cache.refreshRegions()
	assert.Equal(t.T(), len(cache.Regions), 0)
}

func (t *SuiteTest) TestRefreshAZs() {
	cache := NewCache(DOMAIN_LCUUID)
	cache.refreshAZs()
	assert.Equal(t.T(), len(cache.AZs), 7)
}

func (t *SuiteTest) TestRefreshSubDomains() {
	cache := NewCache(DOMAIN_LCUUID)
	cache.refreshSubDomains()
	assert.Equal(t.T(), len(cache.SubDomains), 0)
}

func (t *SuiteTest) TestRefreshHosts() {
	cache := NewCache(DOMAIN_LCUUID)
	cache.refreshHosts()
	assert.Equal(t.T(), len(cache.Hosts), 1)
}

func (t *SuiteTest) TestRefreshVMs() {
	cache := NewCache(DOMAIN_LCUUID)
	cache.vpcIDToLcuuid[2] = uuid.New().String()
	cache.refreshVMs()
	assert.Equal(t.T(), len(cache.VMs), 53)
}

func (t *SuiteTest) TestRefreshVPCs() {
	cache := NewCache(DOMAIN_LCUUID)
	cache.refreshVPCs()
	assert.Equal(t.T(), len(cache.VPCs), 8)
}

func (t *SuiteTest) TestRefreshNetworks() {
	cache := NewCache(DOMAIN_LCUUID)
	cache.refreshNetworks()
	assert.Equal(t.T(), len(cache.Networks), 30)
}

func (t *SuiteTest) TestRefreshSubnets() {
	cache := NewCache(DOMAIN_LCUUID)
	cache.refreshSubnets([]int{4100})
	assert.Equal(t.T(), len(cache.Subnets), 1)
}

func (t *SuiteTest) TestRefreshVRouters() {
	cache := NewCache(DOMAIN_LCUUID)
	cache.refreshVRouters()
	assert.Equal(t.T(), len(cache.VRouters), 8)
}

func (t *SuiteTest) TestRefreshRoutingTables() {
	cache := NewCache(DOMAIN_LCUUID)
	cache.refreshRoutingTables([]int{2})
	assert.Equal(t.T(), len(cache.RoutingTables), 4)
}

func (t *SuiteTest) TestRefreshDHCPPorts() {
	cache := NewCache(DOMAIN_LCUUID)
	cache.refreshDHCPPorts()
	assert.Equal(t.T(), len(cache.DHCPPorts), 0)
}
