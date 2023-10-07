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

package cache

import (
	"github.com/op/go-logging"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/query"
	rcommon "github.com/deepflowio/deepflow/server/controller/recorder/common"
)

// 为支持domain及其sub_domain的独立刷新，将缓存拆分成对应的独立Cache
type CacheManager struct {
	DomainCache       *Cache
	SubDomainCacheMap map[string]*Cache
}

func NewCacheManager(domainLcuuid string) *CacheManager {
	cacheManager := &CacheManager{
		DomainCache:       NewCache(domainLcuuid),
		SubDomainCacheMap: make(map[string]*Cache),
	}
	var subDomains []*mysql.SubDomain
	err := mysql.Db.Where("domain = ?", domainLcuuid).Find(&subDomains).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_SUB_DOMAIN_EN, err))
		return cacheManager
	}
	for _, subDomain := range subDomains {
		subDomainCache := NewCache(domainLcuuid)
		subDomainCache.SubDomainLcuuid = subDomain.Lcuuid
		cacheManager.SubDomainCacheMap[subDomain.Lcuuid] = subDomainCache
	}
	return cacheManager
}

func (m *CacheManager) Refresh() {
	log.Infof("refresh domain cache")
	m.DomainCache.Refresh()
	for _, subDomainCache := range m.SubDomainCacheMap {
		log.Infof("refresh sub_domain cache (lcuuid: %s)", subDomainCache.SubDomainLcuuid)
		subDomainCache.Refresh()
	}
}

// sequence随cache刷新次数递增
func (m *CacheManager) UpdateSequence() {
	seq := m.DomainCache.GetSequence() + 1
	m.DomainCache.SetSequence(seq)
	for _, subDomainCache := range m.SubDomainCacheMap {
		subDomainCache.SetSequence(seq)
	}
}

func (m *CacheManager) SetLogLevel(logLevel logging.Level) {
	m.DomainCache.SetLogLevel(logLevel)
	for _, subDomainCache := range m.SubDomainCacheMap {
		subDomainCache.SetLogLevel(logLevel)
	}
}

func (m *CacheManager) CreateSubDomainCacheIfNotExists(subDomainLcuuid string) *Cache {
	cache, exists := m.SubDomainCacheMap[subDomainLcuuid]
	if exists {
		return cache
	}
	log.Infof("subdomain cache (lcuuid: %s) not exists", subDomainLcuuid)
	cache = NewCache(m.DomainCache.DomainLcuuid)
	cache.SubDomainLcuuid = subDomainLcuuid
	m.SubDomainCacheMap[subDomainLcuuid] = cache
	return cache
}

type Cache struct {
	Sequence        int // 缓存的序列标识，根据刷新递增；为debug方便，设置为公有属性，需避免直接修改值，使用接口修改
	DomainLcuuid    string
	SubDomainLcuuid string
	DiffBaseDataSet
	ToolDataSet
}

func NewCache(domainLcuuid string) *Cache {
	return &Cache{
		DomainLcuuid:    domainLcuuid,
		DiffBaseDataSet: NewDiffBaseDataSet(), // 所有资源的主要信息，用于与cloud数据比较差异，根据差异更新资源
		ToolDataSet:     NewToolDataSet(),     // 各类资源的映射关系，用于按需进行数据转换
	}
}

func (c *Cache) GetSequence() int {
	return c.Sequence
}

func (c *Cache) SetSequence(sequence int) {
	c.Sequence = sequence
}

func (c *Cache) SetLogLevel(level logging.Level) {
	c.DiffBaseDataSet.LogController.SetLogLevel(level)
	c.ToolDataSet.LogController.SetLogLevel(level)
}

func (c *Cache) getConditonDomainCreateMethod() map[string]interface{} {
	return map[string]interface{}{
		"domain":        c.DomainLcuuid,
		"create_method": ctrlrcommon.CREATE_METHOD_LEARN,
	}
}

func (c *Cache) getConditionDomain() map[string]string {
	return map[string]string{
		"domain": c.DomainLcuuid,
	}
}

func (c *Cache) getConditionDomainSubDomain() map[string]interface{} {
	return map[string]interface{}{
		"domain":     c.DomainLcuuid,
		"sub_domain": c.SubDomainLcuuid,
	}
}

func (c *Cache) getConditonDomainSubDomainCreateMethod() map[string]interface{} {
	return map[string]interface{}{
		"domain":        c.DomainLcuuid,
		"sub_domain":    c.SubDomainLcuuid,
		"create_method": ctrlrcommon.CREATE_METHOD_LEARN,
	}
}

// 所有缓存的刷新入口
func (c *Cache) Refresh() {
	c.DiffBaseDataSet = NewDiffBaseDataSet()
	c.ToolDataSet = NewToolDataSet()

	// 分类刷新资源的相关缓存

	// sub domain需要使用vpc、vm的映射数据
	c.refreshVPCs()
	c.refreshVMs()

	// 仅domain缓存需要刷新的资源
	if c.SubDomainLcuuid == "" {
		c.refreshRegions()
		c.refreshAZs()
		c.refreshSubDomains()
		c.refreshHosts()
		vrouterIDs := c.refreshVRouters()
		c.refreshRoutingTables(vrouterIDs)
		c.refreshDHCPPorts()
		c.refreshFloatingIPs()
		securityGroupIDs := c.refreshSecurityGroups()
		c.refreshSecurityGroupRules(securityGroupIDs)
		c.refreshVMSecurityGroups(securityGroupIDs)
		c.refreshNATGateways()
		c.refreshNATRules()
		c.refreshNATVMConnections()
		c.refreshLBs()
		c.refreshLBListeners()
		c.refreshLBTargetServers()
		c.refreshLBVMConnections()
		c.refreshPeeConnections()
		c.refreshCENs()
		c.refreshRDSInstances()
		c.refreshRedisInstances()
		c.refreshVIP()
	}
	c.refreshPodClusters()
	c.refreshPodNodes()
	c.refreshVMPodNodeConnections()
	c.refreshPodNamespaces()
	podIngressIDs := c.refreshPodIngresses()
	c.refreshPodIngressRules(podIngressIDs)
	c.refreshPodIngresseRuleBackends(podIngressIDs)
	podServiceIDs := c.refreshPodServices()
	c.refreshPodServicePorts(podServiceIDs)
	c.refreshPodGroups()
	c.refreshPodGroupPorts(podServiceIDs)
	c.refreshPodReplicaSets()
	c.refreshPods()
	networkIDs := c.refreshNetworks()
	c.refreshSubnets(networkIDs)
	c.refreshVInterfaces()
	c.refreshWANIPs()
	c.refreshLANIPs()
	c.refreshProcesses()
	c.refreshPrometheusTarget()
}

func (c *Cache) AddRegion(item *mysql.Region) {
	c.DiffBaseDataSet.addRegion(item, c.Sequence)
	c.ToolDataSet.addRegion(item)
}

func (c *Cache) AddRegions(items []*mysql.Region) {
	for _, item := range items {
		c.AddRegion(item)
	}
}

func (c *Cache) DeleteRegion(lcuuid string) {
	c.DiffBaseDataSet.deleteRegion(lcuuid)
	c.ToolDataSet.deleteRegion(lcuuid)
}

func (c *Cache) DeleteRegions(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DeleteRegion(lcuuid)
	}
}

func (c *Cache) refreshRegions() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_REGION_EN))
	var regions []*mysql.Region

	// 使用az获取domain关联的region数据，排除“系统默认”region
	var azs []*mysql.AZ
	err := mysql.Db.Where(c.getConditonDomainCreateMethod()).Find(&azs).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_AZ_EN, err))
		return
	}
	var regionLcuuids []string
	for _, az := range azs {
		if az.Region != ctrlrcommon.DEFAULT_REGION {
			regionLcuuids = append(regionLcuuids, az.Region)
		}
	}
	err = mysql.Db.Where(
		"create_method = ? AND lcuuid IN ?", ctrlrcommon.CREATE_METHOD_LEARN, regionLcuuids,
	).Find(&regions).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_REGION_EN, err))
		return
	}

	c.AddRegions(regions)
}

func (c *Cache) AddAZ(item *mysql.AZ) {
	c.DiffBaseDataSet.addAZ(item, c.Sequence)
	c.ToolDataSet.addAZ(item)
}

func (c *Cache) AddAZs(items []*mysql.AZ) {
	for _, item := range items {
		c.AddAZ(item)
	}
}

func (c *Cache) DeleteAZ(lcuuid string) {
	c.DiffBaseDataSet.deleteAZ(lcuuid)
	c.ToolDataSet.deleteAZ(lcuuid)
}

func (c *Cache) DeleteAZs(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DeleteAZ(lcuuid)
	}
}

func (c *Cache) refreshAZs() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_AZ_EN))
	var azs []*mysql.AZ

	err := mysql.Db.Where(c.getConditonDomainCreateMethod()).Find(&azs).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_AZ_EN, err))
		return
	}

	c.AddAZs(azs)
}

func (c *Cache) AddSubDomain(item *mysql.SubDomain) {
	c.DiffBaseDataSet.addSubDomain(item, c.Sequence)
}

func (c *Cache) AddSubDomains(items []*mysql.SubDomain) {
	for _, item := range items {
		c.AddSubDomain(item)
	}
}

func (c *Cache) DeleteSubDomain(lcuuid string) {
	c.DiffBaseDataSet.deleteSubDomain(lcuuid)
}

func (c *Cache) DeleteSubDomains(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DeleteSubDomain(lcuuid)
	}
}

func (c *Cache) refreshSubDomains() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_SUB_DOMAIN_EN))
	var subDomains []*mysql.SubDomain

	err := mysql.Db.Where(c.getConditonDomainCreateMethod()).Find(&subDomains).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_SUB_DOMAIN_EN, err))
		return
	}

	c.AddSubDomains(subDomains)
}

func (c *Cache) AddHost(item *mysql.Host) {
	c.DiffBaseDataSet.addHost(item, c.Sequence)
	c.ToolDataSet.addHost(item)
}

func (c *Cache) AddHosts(items []*mysql.Host) {
	for _, item := range items {
		c.AddHost(item)
	}
}

func (c *Cache) DeleteHost(lcuuid string) {
	c.DiffBaseDataSet.deleteHost(lcuuid)
	c.ToolDataSet.deleteHost(lcuuid)
}

func (c *Cache) DeleteHosts(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DeleteHost(lcuuid)
	}
}

func (c *Cache) UpdateHost(cloudItem *cloudmodel.Host) {
	c.ToolDataSet.updateHost(cloudItem)
}

func (c *Cache) refreshHosts() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_HOST_EN))
	var hosts []*mysql.Host

	err := mysql.Db.Where(
		map[string]interface{}{
			"domain":        c.DomainLcuuid,
			"create_method": ctrlrcommon.CREATE_METHOD_LEARN,
		},
	).Not(
		map[string]interface{}{
			"type": ctrlrcommon.HOST_TYPE_DFI,
		},
	).Find(&hosts).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_HOST_EN, err))
		return
	}

	c.AddHosts(hosts)
}

func (c *Cache) AddVM(item *mysql.VM) {
	c.DiffBaseDataSet.addVM(item, c.Sequence, &c.ToolDataSet)
	c.ToolDataSet.addVM(item)
}

func (c *Cache) AddVMs(items []*mysql.VM) {
	for _, item := range items {
		c.AddVM(item)
	}
}

func (c *Cache) UpdateVM(cloudItem *cloudmodel.VM) {
	c.ToolDataSet.updateVM(cloudItem)
}

func (c *Cache) DeleteVM(lcuuid string) {
	c.DiffBaseDataSet.deleteVM(lcuuid)
	c.ToolDataSet.deleteVM(lcuuid)
}

func (c *Cache) DeleteVMs(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DeleteVM(lcuuid)
	}
}

func (c *Cache) refreshVMs() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_VM_EN))
	var vms []*mysql.VM

	err := mysql.Db.Where(c.getConditonDomainCreateMethod()).Find(&vms).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_VM_EN, err))
		return
	}

	c.AddVMs(vms)
}

func (c *Cache) AddVPCs(items []*mysql.VPC) {
	for _, item := range items {
		c.DiffBaseDataSet.addVPC(item, c.Sequence)
		c.ToolDataSet.addVPC(item)
	}
}

func (c *Cache) DeleteVPCs(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteVPC(lcuuid)
		c.ToolDataSet.deleteVPC(lcuuid)
	}
}

func (c *Cache) refreshVPCs() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_VPC_EN))
	var vpcs []*mysql.VPC

	err := mysql.Db.Where(c.getConditonDomainCreateMethod()).Find(&vpcs).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_VPC_EN, err))
		return
	}

	c.AddVPCs(vpcs)
}

func (c *Cache) AddNetwork(item *mysql.Network) {
	c.DiffBaseDataSet.addNetwork(item, c.Sequence, &c.ToolDataSet)
	c.ToolDataSet.addNetwork(item)
}

func (c *Cache) AddNetworks(items []*mysql.Network) {
	for _, item := range items {
		c.AddNetwork(item)
	}
}

func (c *Cache) UpdateNetwork(cloudItem *cloudmodel.Network) {
	c.ToolDataSet.updateNetwork(cloudItem)
}

func (c *Cache) DeleteNetworks(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteNetwork(lcuuid)
		c.ToolDataSet.deleteNetwork(lcuuid)
	}
}

func (c *Cache) refreshNetworks() []int {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_NETWORK_EN))
	var networks []*mysql.Network
	networkIDs := []int{}

	err := mysql.Db.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL) AND create_method = ?", c.DomainLcuuid, c.SubDomainLcuuid, ctrlrcommon.CREATE_METHOD_LEARN).Find(&networks).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, err))
		return networkIDs
	}

	for _, item := range networks {
		networkIDs = append(networkIDs, item.ID)
		c.AddNetwork(item)
	}

	var publicNetwork *mysql.Network
	err = mysql.Db.Where("lcuuid = ?", rcommon.PUBLIC_NETWORK_LCUUID).First(&publicNetwork).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, err))
		return networkIDs
	}
	c.ToolDataSet.publicNetworkID = publicNetwork.ID

	return networkIDs
}

func (c *Cache) AddSubnets(items []*mysql.Subnet) {
	for _, item := range items {
		c.DiffBaseDataSet.addSubnet(item, c.Sequence)
		c.ToolDataSet.addSubnet(item)
	}
}

func (c *Cache) DeleteSubnets(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteSubnet(lcuuid)
		c.ToolDataSet.deleteSubnet(lcuuid)
	}
}

func (c *Cache) refreshSubnets(networkIDs []int) {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_SUBNET_EN))
	var subnets []*mysql.Subnet

	err := mysql.Db.Where(map[string]interface{}{"vl2id": networkIDs}).Find(&subnets).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_SUBNET_EN, err))
		return
	}

	c.AddSubnets(subnets)
}

func (c *Cache) AddVRouter(item *mysql.VRouter) {
	c.DiffBaseDataSet.addVRouter(item, c.Sequence, &c.ToolDataSet)
	c.ToolDataSet.addVRouter(item)
}

func (c *Cache) AddVRouters(items []*mysql.VRouter) {
	for _, item := range items {
		c.AddVRouter(item)
	}
}

func (c *Cache) UpdateVRouter(cloudItem *cloudmodel.VRouter) {
	c.ToolDataSet.updateVRouter(cloudItem)
}

func (c *Cache) DeleteVRouters(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteVRouter(lcuuid)
		c.ToolDataSet.deleteVRouter(lcuuid)
	}
}

func (c *Cache) refreshVRouters() []int {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_VROUTER_EN))
	var vrouters []*mysql.VRouter
	vrouterIDs := []int{}

	err := mysql.Db.Where(c.getConditionDomain()).Find(&vrouters).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, err))
		return vrouterIDs
	}

	for _, item := range vrouters {
		vrouterIDs = append(vrouterIDs, item.ID)
		c.AddVRouter(item)
	}
	return vrouterIDs
}

func (c *Cache) AddRoutingTables(items []*mysql.RoutingTable) {
	for _, item := range items {
		c.DiffBaseDataSet.addRoutingTable(item, c.Sequence)
	}
}

func (c *Cache) DeleteRoutingTables(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteRoutingTable(lcuuid)
	}
}

func (c *Cache) refreshRoutingTables(vrouterIDs []int) {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_ROUTING_TABLE_EN))
	var routingTables []*mysql.RoutingTable

	err := mysql.Db.Where(map[string]interface{}{"vnet_id": vrouterIDs}).Find(&routingTables).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_ROUTING_TABLE_EN, err))
		return
	}

	c.AddRoutingTables(routingTables)
}

func (c *Cache) AddDHCPPorts(items []*mysql.DHCPPort) {
	for _, item := range items {
		c.DiffBaseDataSet.addDHCPPort(item, c.Sequence, &c.ToolDataSet)
		c.ToolDataSet.addDHCPPort(item)
	}
}

func (c *Cache) UpdateDHCPPort(cloudItem *cloudmodel.DHCPPort) {
	c.ToolDataSet.updateDHCPPort(cloudItem)
}

func (c *Cache) DeleteDHCPPorts(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteDHCPPort(lcuuid)
		c.ToolDataSet.deleteDHCPPort(lcuuid)
	}
}

func (c *Cache) refreshDHCPPorts() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN))
	var dhcpPorts []*mysql.DHCPPort

	err := mysql.Db.Where(c.getConditionDomain()).Find(&dhcpPorts).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN, err))
		return
	}

	c.AddDHCPPorts(dhcpPorts)
}

func (c *Cache) AddVInterfaces(items []*mysql.VInterface) {
	for _, item := range items {
		c.DiffBaseDataSet.addVInterface(item, c.Sequence, &c.ToolDataSet)
		c.ToolDataSet.addVInterface(item)
	}
}

func (c *Cache) UpdateVInterface(cloudItem *cloudmodel.VInterface) {
	c.ToolDataSet.updateVInterface(cloudItem)
}

func (c *Cache) DeleteVInterfaces(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteVInterface(lcuuid)
		c.ToolDataSet.deleteVInterface(lcuuid)
	}
}

func (c *Cache) refreshVInterfaces() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN))
	var vifs []*mysql.VInterface

	err := mysql.Db.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL) AND create_method = ?", c.DomainLcuuid, c.SubDomainLcuuid, ctrlrcommon.CREATE_METHOD_LEARN).Find(&vifs).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, err))
		return
	}

	c.AddVInterfaces(vifs)
}

func (c *Cache) AddWANIPs(items []*mysql.WANIP) {
	for _, item := range items {
		c.DiffBaseDataSet.addWANIP(item, c.Sequence, &c.ToolDataSet)
		c.ToolDataSet.addWANIP(item)
	}
}

func (c *Cache) DeleteWANIPs(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteWANIP(lcuuid)
		c.ToolDataSet.deleteWANIP(lcuuid)
	}
}

func (c *Cache) refreshWANIPs() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN))
	var wanIPs []*mysql.WANIP

	err := mysql.Db.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL)", c.DomainLcuuid, c.SubDomainLcuuid).Find(&wanIPs).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN, err))
		return
	}

	c.AddWANIPs(wanIPs)
}

func (c *Cache) AddLANIPs(items []*mysql.LANIP) {
	for _, item := range items {
		c.DiffBaseDataSet.addLANIP(item, c.Sequence, &c.ToolDataSet)
		c.ToolDataSet.addLANIP(item)
	}
}

func (c *Cache) DeleteLANIPs(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteLANIP(lcuuid)
		c.ToolDataSet.deleteLANIP(lcuuid)
	}
}

func (c *Cache) refreshLANIPs() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN))
	var lanIPs []*mysql.LANIP

	err := mysql.Db.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL)", c.DomainLcuuid, c.SubDomainLcuuid).Find(&lanIPs).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN, err))
		return
	}

	c.AddLANIPs(lanIPs)
}

func (c *Cache) AddFloatingIPs(items []*mysql.FloatingIP) {
	for _, item := range items {
		c.DiffBaseDataSet.addFloatingIP(item, c.Sequence, &c.ToolDataSet)
	}
}

func (c *Cache) DeleteFloatingIPs(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteFloatingIP(lcuuid)
	}
}

func (c *Cache) refreshFloatingIPs() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_FLOATING_IP_EN))
	var floatingIPs []*mysql.FloatingIP

	err := mysql.Db.Where(c.getConditionDomain()).Find(&floatingIPs).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_FLOATING_IP_EN, err))
		return
	}

	c.AddFloatingIPs(floatingIPs)
}

func (c *Cache) AddSecurityGroup(item *mysql.SecurityGroup) {
	c.DiffBaseDataSet.addSecurityGroup(item, c.Sequence)
	c.ToolDataSet.addSecurityGroup(item)
}

func (c *Cache) AddSecurityGroups(items []*mysql.SecurityGroup) {
	for _, item := range items {
		c.AddSecurityGroup(item)
	}
}

func (c *Cache) DeleteSecurityGroups(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteSecurityGroup(lcuuid)
		c.ToolDataSet.deleteSecurityGroup(lcuuid)
	}
}

func (c *Cache) refreshSecurityGroups() []int {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_SECURITY_GROUP_EN))
	var securityGroups []*mysql.SecurityGroup
	securityGroupIDs := []int{}

	err := mysql.Db.Where(c.getConditionDomain()).Find(&securityGroups).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_SECURITY_GROUP_EN, err))
		return securityGroupIDs
	}

	for _, item := range securityGroups {
		securityGroupIDs = append(securityGroupIDs, item.ID)
		c.AddSecurityGroup(item)
	}
	return securityGroupIDs
}

func (c *Cache) AddSecurityGroupRules(items []*mysql.SecurityGroupRule) {
	for _, item := range items {
		c.DiffBaseDataSet.addSecurityGroupRule(item, c.Sequence)
	}
}

func (c *Cache) DeleteSecurityGroupRules(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteSecurityGroupRule(lcuuid)
	}
}

func (c *Cache) refreshSecurityGroupRules(securityGroupIDs []int) {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_SECURITY_GROUP_RULE_EN))
	var securityGroupRules []*mysql.SecurityGroupRule

	err := mysql.Db.Where(map[string]interface{}{"sg_id": securityGroupIDs}).Find(&securityGroupRules).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_SECURITY_GROUP_RULE_EN, err))
		return
	}

	c.AddSecurityGroupRules(securityGroupRules)
}

func (c *Cache) AddVMSecurityGroups(items []*mysql.VMSecurityGroup) {
	for _, item := range items {
		c.DiffBaseDataSet.addVMSecurityGroup(item, c.Sequence)
	}
}

func (c *Cache) DeleteVMSecurityGroups(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteVMSecurityGroup(lcuuid)
	}
}

func (c *Cache) refreshVMSecurityGroups(securityGroupIDs []int) {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_VM_SECURITY_GROUP_EN))
	var vmsg []*mysql.VMSecurityGroup

	err := mysql.Db.Where(map[string]interface{}{"sg_id": securityGroupIDs}).Find(&vmsg).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_VM_SECURITY_GROUP_EN, err))
		return
	}

	c.AddVMSecurityGroups(vmsg)
}

func (c *Cache) AddNATGateways(items []*mysql.NATGateway) {
	for _, item := range items {
		c.DiffBaseDataSet.addNATGateway(item, c.Sequence)
		c.ToolDataSet.addNATGateway(item)
	}
}

func (c *Cache) UpdateNATGateway(cloudItem *cloudmodel.NATGateway) {
	c.ToolDataSet.updateNATGateway(cloudItem)
}

func (c *Cache) DeleteNATGateways(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteNATGateway(lcuuid)
		c.ToolDataSet.deleteNATGateway(lcuuid)
	}
}

func (c *Cache) refreshNATGateways() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN))
	var natGateways []*mysql.NATGateway

	err := mysql.Db.Where(c.getConditionDomain()).Find(&natGateways).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN, err))
		return
	}

	c.AddNATGateways(natGateways)
}

func (c *Cache) AddNATVMConnections(items []*mysql.NATVMConnection) {
	for _, item := range items {
		c.DiffBaseDataSet.addNATVMConnection(item, c.Sequence)
	}
}

func (c *Cache) DeleteNATVMConnections(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteNATVMConnection(lcuuid)
	}
}

func (c *Cache) refreshNATVMConnections() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_NAT_VM_CONNECTION_EN))
	var natVMConnections []*mysql.NATVMConnection

	err := mysql.Db.Where(c.getConditionDomain()).Find(&natVMConnections).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_NAT_VM_CONNECTION_EN, err))
		return
	}

	c.AddNATVMConnections(natVMConnections)
}

func (c *Cache) AddNATRules(items []*mysql.NATRule) {
	for _, item := range items {
		c.DiffBaseDataSet.addNATRule(item, c.Sequence)
	}
}

func (c *Cache) DeleteNATRules(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteNATRule(lcuuid)
	}
}

func (c *Cache) refreshNATRules() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_NAT_RULE_EN))
	var natRules []*mysql.NATRule

	err := mysql.Db.Where(c.getConditionDomain()).Find(&natRules).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_NAT_RULE_EN, err))
		return
	}

	c.AddNATRules(natRules)
}

func (c *Cache) AddLBs(items []*mysql.LB) {
	for _, item := range items {
		c.DiffBaseDataSet.addLB(item, c.Sequence)
		c.ToolDataSet.addLB(item)
	}
}

func (c *Cache) UpdateLB(cloudItem *cloudmodel.LB) {
	c.ToolDataSet.updateLB(cloudItem)
}

func (c *Cache) DeleteLBs(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteLB(lcuuid)
		c.ToolDataSet.deleteLB(lcuuid)
	}
}

func (c *Cache) refreshLBs() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_LB_EN))
	var lbs []*mysql.LB

	err := mysql.Db.Where(c.getConditionDomain()).Find(&lbs).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_LB_EN, err))
		return
	}

	c.AddLBs(lbs)
}

func (c *Cache) AddLBVMConnections(items []*mysql.LBVMConnection) {
	for _, item := range items {
		c.DiffBaseDataSet.addLBVMConnection(item, c.Sequence)
	}
}

func (c *Cache) DeleteLBVMConnections(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteLBVMConnection(lcuuid)
	}
}

func (c *Cache) refreshLBVMConnections() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_LB_VM_CONNECTION_EN))
	var lbVMConnections []*mysql.LBVMConnection

	err := mysql.Db.Where(c.getConditionDomain()).Find(&lbVMConnections).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_LB_VM_CONNECTION_EN, err))
		return
	}

	c.AddLBVMConnections(lbVMConnections)
}

func (c *Cache) AddLBListeners(items []*mysql.LBListener) {
	for _, item := range items {
		c.DiffBaseDataSet.addLBListener(item, c.Sequence)
		c.ToolDataSet.addLBListener(item)
	}
}

func (c *Cache) DeleteLBListeners(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteLBListener(lcuuid)
		c.ToolDataSet.deleteLBListener(lcuuid)
	}
}

func (c *Cache) refreshLBListeners() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_LB_LISTENER_EN))
	var listeners []*mysql.LBListener

	err := mysql.Db.Where(c.getConditionDomain()).Find(&listeners).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_LB_LISTENER_EN, err))
		return
	}

	c.AddLBListeners(listeners)
}

func (c *Cache) AddLBTargetServers(items []*mysql.LBTargetServer) {
	for _, item := range items {
		c.DiffBaseDataSet.addLBTargetServer(item, c.Sequence)
	}
}

func (c *Cache) DeleteLBTargetServers(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteLBTargetServer(lcuuid)
	}
}

func (c *Cache) refreshLBTargetServers() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_LB_TARGET_SERVER_EN))
	var servers []*mysql.LBTargetServer

	err := mysql.Db.Where(c.getConditionDomain()).Find(&servers).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_LB_TARGET_SERVER_EN, err))
		return
	}

	c.AddLBTargetServers(servers)
}

func (c *Cache) AddPeerConnections(items []*mysql.PeerConnection) {
	for _, item := range items {
		c.DiffBaseDataSet.addPeerConnection(item, c.Sequence, &c.ToolDataSet)
	}
}

func (c *Cache) DeletePeerConnections(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deletePeerConnection(lcuuid)
	}
}

func (c *Cache) refreshPeeConnections() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_PEER_CONNECTION_EN))
	var peerConnections []*mysql.PeerConnection

	err := mysql.Db.Where(c.getConditonDomainCreateMethod()).Find(&peerConnections).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_PEER_CONNECTION_EN, err))
		return
	}

	c.AddPeerConnections(peerConnections)
}

func (c *Cache) AddCENs(items []*mysql.CEN) {
	for _, item := range items {
		c.DiffBaseDataSet.addCEN(item, c.Sequence, &c.ToolDataSet)
	}
}

func (c *Cache) DeleteCENs(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteCEN(lcuuid)
	}
}

func (c *Cache) refreshCENs() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_CEN_EN))
	var cens []*mysql.CEN

	err := mysql.Db.Where(c.getConditionDomain()).Find(&cens).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_CEN_EN, err))
		return
	}

	c.AddCENs(cens)
}

func (c *Cache) AddRDSInstances(items []*mysql.RDSInstance) {
	for _, item := range items {
		c.DiffBaseDataSet.addRDSInstance(item, c.Sequence)
		c.ToolDataSet.addRDSInstance(item)
	}
}

func (c *Cache) UpdateRDSInstance(cloudItem *cloudmodel.RDSInstance) {
	c.ToolDataSet.updateRDSInstance(cloudItem)
}

func (c *Cache) DeleteRDSInstances(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteRDSInstance(lcuuid)
		c.ToolDataSet.deleteRDSInstance(lcuuid)
	}
}

func (c *Cache) refreshRDSInstances() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN))
	var instances []*mysql.RDSInstance

	err := mysql.Db.Where(c.getConditionDomain()).Find(&instances).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN, err))
		return
	}

	c.AddRDSInstances(instances)
}

func (c *Cache) AddRedisInstances(items []*mysql.RedisInstance) {
	for _, item := range items {
		c.DiffBaseDataSet.addRedisInstance(item, c.Sequence)
		c.ToolDataSet.addRedisInstance(item)
	}
}

func (c *Cache) UpdateRedisInstance(cloudItem *cloudmodel.RedisInstance) {
	c.ToolDataSet.updateRedisInstance(cloudItem)
}

func (c *Cache) DeleteRedisInstances(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteRedisInstance(lcuuid)
		c.ToolDataSet.deleteRedisInstance(lcuuid)
	}
}

func (c *Cache) refreshRedisInstances() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN))
	var instances []*mysql.RedisInstance

	err := mysql.Db.Where(c.getConditionDomain()).Find(&instances).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN, err))
		return
	}

	c.AddRedisInstances(instances)
}

func (c *Cache) AddPodClusters(items []*mysql.PodCluster) {
	for _, item := range items {
		c.DiffBaseDataSet.addPodCluster(item, c.Sequence)
		c.ToolDataSet.addPodCluster(item)
	}
}

func (c *Cache) DeletePodClusters(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deletePodCluster(lcuuid)
		c.ToolDataSet.deletePodCluster(lcuuid)
	}
}

func (c *Cache) refreshPodClusters() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN))
	var podClusters []*mysql.PodCluster

	err := mysql.Db.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL)", c.DomainLcuuid, c.SubDomainLcuuid).Find(&podClusters).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, err))
		return
	}

	c.AddPodClusters(podClusters)
}

func (c *Cache) AddPodNodes(items []*mysql.PodNode) {
	for _, item := range items {
		c.DiffBaseDataSet.addPodNode(item, c.Sequence)
		c.ToolDataSet.addPodNode(item)
	}
}

func (c *Cache) UpdatePodNode(cloudItem *cloudmodel.PodNode) {
	c.ToolDataSet.updatePodNode(cloudItem)
}

func (c *Cache) DeletePodNodes(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deletePodNode(lcuuid)
		c.ToolDataSet.deletePodNode(lcuuid)
	}
}

func (c *Cache) refreshPodNodes() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN))
	var podNodes []*mysql.PodNode

	err := mysql.Db.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL)", c.DomainLcuuid, c.SubDomainLcuuid).Find(&podNodes).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, err))
		return
	}

	c.AddPodNodes(podNodes)
}

func (c *Cache) AddVMPodNodeConnections(items []*mysql.VMPodNodeConnection) {
	for _, item := range items {
		c.DiffBaseDataSet.addVMPodNodeConnection(item, c.Sequence)
	}
}

func (c *Cache) DeleteVMPodNodeConnections(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteVMPodNodeConnection(lcuuid)
	}
}

func (c *Cache) refreshVMPodNodeConnections() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN))
	var connections []*mysql.VMPodNodeConnection

	err := mysql.Db.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL)", c.DomainLcuuid, c.SubDomainLcuuid).Find(&connections).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, err))
		return
	}

	c.AddVMPodNodeConnections(connections)
}

func (c *Cache) AddPodNamespaces(items []*mysql.PodNamespace) {
	for _, item := range items {
		c.DiffBaseDataSet.addPodNamespace(item, c.Sequence)
		c.ToolDataSet.addPodNamespace(item)
	}
}

func (c *Cache) DeletePodNamespaces(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deletePodNamespace(lcuuid)
		c.ToolDataSet.deletePodNamespace(lcuuid)
	}
}

func (c *Cache) refreshPodNamespaces() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN))
	var podNamespaces []*mysql.PodNamespace

	err := mysql.Db.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL)", c.DomainLcuuid, c.SubDomainLcuuid).Find(&podNamespaces).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, err))
		return
	}

	c.AddPodNamespaces(podNamespaces)
}

func (c *Cache) AddPodIngress(item *mysql.PodIngress) {
	c.DiffBaseDataSet.addPodIngress(item, c.Sequence)
	c.ToolDataSet.addPodIngress(item)
}

func (c *Cache) AddPodIngresses(items []*mysql.PodIngress) {
	for _, item := range items {
		c.AddPodIngress(item)
	}
}

func (c *Cache) DeletePodIngresses(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deletePodIngress(lcuuid)
		c.ToolDataSet.deletePodIngress(lcuuid)
	}
}

func (c *Cache) refreshPodIngresses() []int {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN))
	var podIngresses []*mysql.PodIngress
	podIngressIDs := []int{}

	err := mysql.Db.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL)", c.DomainLcuuid, c.SubDomainLcuuid).Find(&podIngresses).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, err))
		return podIngressIDs
	}

	for _, item := range podIngresses {
		podIngressIDs = append(podIngressIDs, item.ID)
		c.AddPodIngress(item)
	}
	return podIngressIDs
}

func (c *Cache) AddPodIngressRules(items []*mysql.PodIngressRule) {
	for _, item := range items {
		c.DiffBaseDataSet.addPodIngressRule(item, c.Sequence)
		c.ToolDataSet.addPodIngressRule(item)
	}
}

func (c *Cache) DeletePodIngressRules(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deletePodIngressRule(lcuuid)
		c.ToolDataSet.deletePodIngressRule(lcuuid)
	}
}

func (c *Cache) refreshPodIngressRules(podIngressIDs []int) {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN))
	if len(podIngressIDs) == 0 {
		return
	}
	var podIngressRules []*mysql.PodIngressRule

	err := mysql.Db.Where("pod_ingress_id IN ?", podIngressIDs).Find(&podIngressRules).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN, err))
		return
	}

	c.AddPodIngressRules(podIngressRules)
}

func (c *Cache) AddPodIngressRuleBackends(items []*mysql.PodIngressRuleBackend) {
	for _, item := range items {
		c.DiffBaseDataSet.addPodIngressRuleBackend(item, c.Sequence)
	}
}

func (c *Cache) DeletePodIngressRuleBackends(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deletePodIngressRuleBackend(lcuuid)
	}
}

func (c *Cache) refreshPodIngresseRuleBackends(podIngressIDs []int) {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN))
	if len(podIngressIDs) == 0 {
		return
	}
	var podIngressRuleBackends []*mysql.PodIngressRuleBackend

	err := mysql.Db.Where("pod_ingress_id IN ?", podIngressIDs).Find(&podIngressRuleBackends).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN, err))
		return
	}

	c.AddPodIngressRuleBackends(podIngressRuleBackends)
}

func (c *Cache) AddPodService(item *mysql.PodService) {
	c.DiffBaseDataSet.addPodService(item, c.Sequence, &c.ToolDataSet)
	c.ToolDataSet.addPodService(item)
}

func (c *Cache) AddPodServices(items []*mysql.PodService) {
	for _, item := range items {
		c.AddPodService(item)
	}
}

func (c *Cache) UpdatePodService(cloudItem *cloudmodel.PodService) {
	c.ToolDataSet.updatePodService(cloudItem)
}

func (c *Cache) DeletePodServices(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deletePodService(lcuuid)
		c.ToolDataSet.deletePodService(lcuuid)
	}
}

func (c *Cache) refreshPodServices() []int {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN))
	var podServices []*mysql.PodService
	podServiceIDs := []int{}

	err := mysql.Db.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL)", c.DomainLcuuid, c.SubDomainLcuuid).Find(&podServices).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, err))
		return podServiceIDs
	}

	for _, item := range podServices {
		podServiceIDs = append(podServiceIDs, item.ID)
		c.AddPodService(item)
	}
	return podServiceIDs
}

func (c *Cache) AddPodServicePorts(items []*mysql.PodServicePort) {
	for _, item := range items {
		c.DiffBaseDataSet.addPodServicePort(item, c.Sequence)
	}
}

func (c *Cache) DeletePodServicePorts(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deletePodServicePort(lcuuid)
	}
}

func (c *Cache) refreshPodServicePorts(podServiceIDs []int) {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_PORT_EN))
	if len(podServiceIDs) == 0 {
		return
	}
	var podServicePorts []*mysql.PodServicePort

	err := mysql.Db.Where("pod_service_id IN ?", podServiceIDs).Find(&podServicePorts).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_PORT_EN, err))
		return
	}

	c.AddPodServicePorts(podServicePorts)
}

func (c *Cache) AddPodGroups(items []*mysql.PodGroup) {
	for _, item := range items {
		c.DiffBaseDataSet.addPodGroup(item, c.Sequence)
		c.ToolDataSet.addPodGroup(item)
	}
}

func (c *Cache) DeletePodGroups(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deletePodGroup(lcuuid)
		c.ToolDataSet.deletePodGroup(lcuuid)
	}
}

func (c *Cache) refreshPodGroups() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN))
	var podGroups []*mysql.PodGroup

	err := mysql.Db.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL)", c.DomainLcuuid, c.SubDomainLcuuid).Find(&podGroups).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, err))
		return
	}

	c.AddPodGroups(podGroups)
}

func (c *Cache) AddPodGroupPorts(items []*mysql.PodGroupPort) {
	for _, item := range items {
		c.DiffBaseDataSet.addPodGroupPort(item, c.Sequence)
	}
}

func (c *Cache) DeletePodGroupPorts(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deletePodGroupPort(lcuuid)
	}
}

func (c *Cache) refreshPodGroupPorts(podServiceIDs []int) {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN))
	if len(podServiceIDs) == 0 {
		return
	}
	var podGroupPorts []*mysql.PodGroupPort

	err := mysql.Db.Where("pod_service_id IN ?", podServiceIDs).Find(&podGroupPorts).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN, err))
		return
	}

	c.AddPodGroupPorts(podGroupPorts)
}

func (c *Cache) AddPodReplicaSets(items []*mysql.PodReplicaSet) {
	for _, item := range items {
		c.DiffBaseDataSet.addPodReplicaSet(item, c.Sequence)
		c.ToolDataSet.addPodReplicaSet(item)
	}
}

func (c *Cache) DeletePodReplicaSets(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deletePodReplicaSet(lcuuid)
		c.ToolDataSet.deletePodReplicaSet(lcuuid)
	}
}

func (c *Cache) refreshPodReplicaSets() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN))
	var podReplicaSets []*mysql.PodReplicaSet

	err := mysql.Db.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL)", c.DomainLcuuid, c.SubDomainLcuuid).Find(&podReplicaSets).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, err))
		return
	}

	c.AddPodReplicaSets(podReplicaSets)
}

func (c *Cache) AddPods(items []*mysql.Pod) {
	for _, item := range items {
		c.DiffBaseDataSet.addPod(item, c.Sequence, &c.ToolDataSet)
		c.ToolDataSet.addPod(item)
	}
}

func (c *Cache) UpdatePod(cloudItem *cloudmodel.Pod) {
	c.ToolDataSet.updatePod(cloudItem)
}

func (c *Cache) DeletePods(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deletePod(lcuuid)
		c.ToolDataSet.deletePod(lcuuid)
	}
}

func (c *Cache) refreshPods() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_POD_EN))
	var pods []*mysql.Pod

	err := mysql.Db.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL)", c.DomainLcuuid, c.SubDomainLcuuid).Find(&pods).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_POD_EN, err))
		return
	}

	c.AddPods(pods)
}

func (c *Cache) AddProcesses(items []*mysql.Process) {
	for _, item := range items {
		c.DiffBaseDataSet.addProcess(item, c.Sequence)
		c.ToolDataSet.addProcess(item)
	}
}

func (c *Cache) DeleteProcesses(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteProcess(lcuuid)
		c.ToolDataSet.deleteProcess(lcuuid)
	}
}

func (c *Cache) refreshProcesses() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_PROCESS_EN))
	var processes []*mysql.Process
	processes, err := query.FindInBatches[mysql.Process](mysql.Db.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL)", c.DomainLcuuid, c.SubDomainLcuuid))
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_PROCESS_EN, err))
		return
	}

	c.AddProcesses(processes)
}

func (c *Cache) AddPrometheusTargets(items []*mysql.PrometheusTarget) {
	for _, item := range items {
		c.DiffBaseDataSet.addPrometheusTarget(item, c.Sequence)
	}
}

func (c *Cache) DeletePrometheusTargets(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deletePrometheusTarget(lcuuid)
	}
}

func (c *Cache) refreshPrometheusTarget() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_PROMETHEUS_TARGET_EN))
	var prometheusTargets []*mysql.PrometheusTarget
	if err := mysql.Db.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL) AND create_method = ?", c.DomainLcuuid, c.SubDomainLcuuid, ctrlrcommon.PROMETHEUS_TARGET_CREATE_METHOD_RECORDER).Find(&prometheusTargets).Error; err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_PROMETHEUS_TARGET_EN, err))
		return
	}

	c.AddPrometheusTargets(prometheusTargets)
}

func (c *Cache) AddVIPs(items []*mysql.VIP) {
	for _, item := range items {
		c.DiffBaseDataSet.addVIP(item, c.Sequence)
	}
}

func (c *Cache) DeleteVIPs(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.deleteVIP(lcuuid)
	}
}

func (c *Cache) refreshVIP() {
	log.Infof(refreshResource(ctrlrcommon.RESOURCE_TYPE_VIP_EN))
	var vips []*mysql.VIP
	if err := mysql.Db.Where("domain = ?", c.DomainLcuuid).Find(&vips).Error; err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_VIP_EN, err))
		return
	}

	c.AddVIPs(vips)
}
