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

package cache

import (
	"context"
	"time"

	"github.com/op/go-logging"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/query"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	rcommon "github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/config"
)

// 为支持domain及其sub_domain的独立刷新，将缓存拆分成对应的独立Cache
type CacheManager struct {
	ctx context.Context

	metadata *rcommon.Metadata

	cacheSetSelfHealInterval time.Duration
	DomainCache              *Cache
	SubDomainCacheMap        map[string]*Cache
}

func NewCacheManager(ctx context.Context, cfg config.RecorderConfig, md *rcommon.Metadata) *CacheManager {
	mng := &CacheManager{
		ctx: ctx,

		metadata: md,

		cacheSetSelfHealInterval: time.Minute * time.Duration(cfg.CacheRefreshInterval),
		SubDomainCacheMap:        make(map[string]*Cache),
	}
	mng.DomainCache = NewCache(ctx, md, mng.cacheSetSelfHealInterval)

	var subDomains []*mysqlmodel.SubDomain
	err := mng.metadata.DB.Where("domain = ?", mng.metadata.Domain.Lcuuid).Find(&subDomains).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_SUB_DOMAIN_EN, err), mng.metadata.LogPrefixes)
		return mng
	}
	for _, subDomain := range subDomains {
		smd := mng.metadata.Copy()
		smd.SetSubDomain(*subDomain)
		mng.SubDomainCacheMap[subDomain.Lcuuid] = mng.CreateSubDomainCacheIfNotExists(smd)
	}
	return mng
}

func (m *CacheManager) CreateSubDomainCacheIfNotExists(md *rcommon.Metadata) *Cache {
	if _, exists := m.SubDomainCacheMap[md.SubDomain.Lcuuid]; !exists {
		log.Infof("new subdomain cache (lcuuid: %s) because not exists", md.SubDomain.Lcuuid, m.metadata.LogPrefixes)
		m.SubDomainCacheMap[md.SubDomain.Lcuuid] = NewCache(m.ctx, md, m.cacheSetSelfHealInterval)
	}
	return m.SubDomainCacheMap[md.SubDomain.Lcuuid]
}

type Cache struct {
	ctx context.Context

	metadata *rcommon.Metadata

	SelfHealInterval time.Duration
	RefreshSignal    chan struct{} // 用于限制并发刷新
	Sequence         int           // 缓存的序列标识，根据刷新递增；为debug方便，设置为公有属性，需避免直接修改值，使用接口修改

	DiffBaseDataSet *diffbase.DataSet
	ToolDataSet     *tool.DataSet
}

func NewCache(ctx context.Context, md *rcommon.Metadata, selfHealInterval time.Duration) *Cache {
	c := &Cache{
		ctx: ctx,

		metadata: md,

		SelfHealInterval: selfHealInterval,
		RefreshSignal:    make(chan struct{}, 1),
		DiffBaseDataSet:  diffbase.NewDataSet(md), // 所有资源的主要信息，用于与cloud数据比较差异，根据差异更新资源
		ToolDataSet:      tool.NewDataSet(md),     // 各类资源的映射关系，用于按需进行数据转换
	}
	c.StartSelfHealing()
	return c
}

func (c *Cache) GetMetadata() *rcommon.Metadata {
	return c.metadata
}

func (c *Cache) GetSequence() int {
	return c.Sequence
}

func (c *Cache) SetSequence(sequence int) {
	c.Sequence = sequence
}

func (c *Cache) IncrementSequence() {
	c.Sequence++
}

func (c *Cache) SetLogLevel(level logging.Level, caller string) {
	log.Infof("set cache log level to %s (caller: %s)", level.String(), caller, c.metadata.LogPrefixes)
	c.DiffBaseDataSet.SetLogLevel(level)
	c.ToolDataSet.SetLogLevel(level)
}

func (c *Cache) getConditonDomainCreateMethod() map[string]interface{} {
	return map[string]interface{}{
		"domain":        c.metadata.Domain.Lcuuid,
		"create_method": ctrlrcommon.CREATE_METHOD_LEARN,
	}
}

func (c *Cache) getConditionDomain() map[string]string {
	return map[string]string{
		"domain": c.metadata.Domain.Lcuuid,
	}
}

func (c *Cache) getConditionDomainSubDomain() map[string]interface{} {
	return map[string]interface{}{
		"domain":     c.metadata.Domain.Lcuuid,
		"sub_domain": c.metadata.SubDomain.Lcuuid,
	}
}

func (c *Cache) getConditonDomainSubDomainCreateMethod() map[string]interface{} {
	return map[string]interface{}{
		"domain":        c.metadata.Domain.Lcuuid,
		"sub_domain":    c.metadata.SubDomain.Lcuuid,
		"create_method": ctrlrcommon.CREATE_METHOD_LEARN,
	}
}

const (
	RefreshSignalCallerSelfHeal  = "self_heal"
	RefreshSignalCallerDomain    = "domain"
	RefreshSignalCallerSubDomain = "sub_domain"
)

func (c *Cache) ResetRefreshSignal(caller string) {
	log.Infof("domain: %s reset cache refresh signal (caller: %s)", c.metadata.Domain.Lcuuid, caller, c.metadata.LogPrefixes)
	c.RefreshSignal <- struct{}{}
}

func (c *Cache) StartSelfHealing() {
	go func() {
		log.Info("recorder cache self heal started", c.metadata.LogPrefixes)
		c.ResetRefreshSignal(RefreshSignalCallerSelfHeal)
		c.TryRefresh()

		ticker := time.NewTicker(c.SelfHealInterval)
		defer ticker.Stop()

	LOOP:
		for {
			select {
			case <-ticker.C:
				c.TryRefresh()
			case <-c.ctx.Done():
				break LOOP
			}
		}
		log.Info("recorder cache self heal completed", c.metadata.LogPrefixes)
	}()
}

func (c *Cache) TryRefresh() bool {
	select {
	case <-c.RefreshSignal:
		c.Refresh()
		return true
	default:
		log.Warning("last cache refresh not completed now", c.metadata.LogPrefixes)
		return false
	}

}

// 所有缓存的刷新入口
func (c *Cache) Refresh() {
	defer c.ResetRefreshSignal(RefreshSignalCallerSelfHeal)

	c.DiffBaseDataSet = diffbase.NewDataSet(c.metadata)
	c.ToolDataSet = tool.NewDataSet(c.metadata)
	c.SetLogLevel(logging.DEBUG, RefreshSignalCallerSelfHeal)

	// 分类刷新资源的相关缓存

	// TODO refactor
	// sub domain需要使用vpc、vm的映射数据
	c.refreshRegions()
	c.refreshAZs()
	c.refreshVPCs()
	c.refreshHosts()
	c.refreshVMs()

	// 仅domain缓存需要刷新的资源
	if c.metadata.SubDomain.Lcuuid == "" {
		c.refreshSubDomains()
		vrouterIDs := c.refreshVRouters()
		c.refreshRoutingTables(vrouterIDs)
		c.refreshDHCPPorts()
		c.refreshFloatingIPs()
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
}

func (c *Cache) AddRegion(item *mysqlmodel.Region) {
	c.DiffBaseDataSet.AddRegion(item, c.Sequence)
	c.ToolDataSet.AddRegion(item)
}

func (c *Cache) AddRegions(items []*mysqlmodel.Region) {
	for _, item := range items {
		c.AddRegion(item)
	}
	var defaultRegion *mysqlmodel.Region
	err := c.metadata.DB.Where("lcuuid = ?", ctrlrcommon.DEFAULT_REGION).First(&defaultRegion).Error
	if defaultRegion != nil {
		c.ToolDataSet.AddRegion(defaultRegion)
	} else {
		log.Errorf("default region not found, %v", err, c.metadata.LogPrefixes)
	}
}

func (c *Cache) DeleteRegion(lcuuid string) {
	c.DiffBaseDataSet.DeleteRegion(lcuuid)
	c.ToolDataSet.DeleteRegion(lcuuid)
}

func (c *Cache) DeleteRegions(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DeleteRegion(lcuuid)
	}
}

func (c *Cache) refreshRegions() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_REGION_EN), c.metadata.LogPrefixes)
	var regions []*mysqlmodel.Region

	// 使用az获取domain关联的region数据，排除“系统默认”region
	var azs []*mysqlmodel.AZ
	err := c.metadata.DB.Where(c.getConditonDomainCreateMethod()).Find(&azs).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_AZ_EN, err), c.metadata.LogPrefixes)
		return
	}
	var regionLcuuids []string
	for _, az := range azs {
		if az.Region != ctrlrcommon.DEFAULT_REGION {
			regionLcuuids = append(regionLcuuids, az.Region)
		}
	}
	err = c.metadata.DB.Where(
		"create_method = ? AND lcuuid IN ?", ctrlrcommon.CREATE_METHOD_LEARN, regionLcuuids,
	).Find(&regions).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_REGION_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddRegions(regions)
}

func (c *Cache) AddAZ(item *mysqlmodel.AZ) {
	c.DiffBaseDataSet.AddAZ(item, c.Sequence)
	c.ToolDataSet.AddAZ(item)
}

func (c *Cache) AddAZs(items []*mysqlmodel.AZ) {
	for _, item := range items {
		c.AddAZ(item)
	}
}

func (c *Cache) DeleteAZ(lcuuid string) {
	c.DiffBaseDataSet.DeleteAZ(lcuuid)
	c.ToolDataSet.DeleteAZ(lcuuid)
}

func (c *Cache) DeleteAZs(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DeleteAZ(lcuuid)
	}
}

func (c *Cache) refreshAZs() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_AZ_EN), c.metadata.LogPrefixes)
	var azs []*mysqlmodel.AZ

	err := c.metadata.DB.Where(c.getConditonDomainCreateMethod()).Find(&azs).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_AZ_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddAZs(azs)
}

func (c *Cache) AddSubDomain(item *mysqlmodel.SubDomain) {
	c.DiffBaseDataSet.AddSubDomain(item, c.Sequence)
}

func (c *Cache) AddSubDomains(items []*mysqlmodel.SubDomain) {
	for _, item := range items {
		c.AddSubDomain(item)
	}
}

func (c *Cache) DeleteSubDomain(lcuuid string) {
	c.DiffBaseDataSet.DeleteSubDomain(lcuuid)
}

func (c *Cache) DeleteSubDomains(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DeleteSubDomain(lcuuid)
	}
}

func (c *Cache) refreshSubDomains() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_SUB_DOMAIN_EN), c.metadata.LogPrefixes)
	var subDomains []*mysqlmodel.SubDomain

	err := c.metadata.DB.Where(c.getConditonDomainCreateMethod()).Find(&subDomains).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_SUB_DOMAIN_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddSubDomains(subDomains)
}

func (c *Cache) AddHost(item *mysqlmodel.Host) {
	c.DiffBaseDataSet.AddHost(item, c.Sequence)
	c.ToolDataSet.AddHost(item)
}

func (c *Cache) AddHosts(items []*mysqlmodel.Host) {
	for _, item := range items {
		c.AddHost(item)
	}
}

func (c *Cache) DeleteHost(lcuuid string) {
	c.DiffBaseDataSet.DeleteHost(lcuuid)
	c.ToolDataSet.DeleteHost(lcuuid)
}

func (c *Cache) DeleteHosts(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DeleteHost(lcuuid)
	}
}

func (c *Cache) UpdateHost(cloudItem *cloudmodel.Host) {
	c.ToolDataSet.UpdateHost(cloudItem)
}

func (c *Cache) refreshHosts() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_HOST_EN), c.metadata.LogPrefixes)
	var hosts []*mysqlmodel.Host

	err := c.metadata.DB.Where(
		map[string]interface{}{
			"domain":        c.metadata.Domain.Lcuuid,
			"create_method": ctrlrcommon.CREATE_METHOD_LEARN,
		},
	).Not(
		map[string]interface{}{
			"type": ctrlrcommon.HOST_TYPE_DFI,
		},
	).Find(&hosts).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_HOST_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddHosts(hosts)
}

func (c *Cache) AddVM(item *mysqlmodel.VM) {
	c.DiffBaseDataSet.AddVM(item, c.Sequence, c.ToolDataSet)
	c.ToolDataSet.AddVM(item)
}

func (c *Cache) AddVMs(items []*mysqlmodel.VM) {
	for _, item := range items {
		c.AddVM(item)
	}
}

func (c *Cache) UpdateVM(cloudItem *cloudmodel.VM) {
	c.ToolDataSet.UpdateVM(cloudItem)
}

func (c *Cache) DeleteVM(lcuuid string) {
	c.DiffBaseDataSet.DeleteVM(lcuuid)
	c.ToolDataSet.DeleteVM(lcuuid)
}

func (c *Cache) DeleteVMs(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DeleteVM(lcuuid)
	}
}

func (c *Cache) refreshVMs() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_VM_EN), c.metadata.LogPrefixes)
	var vms []*mysqlmodel.VM

	err := c.metadata.DB.Where(c.getConditonDomainCreateMethod()).Find(&vms).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_VM_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddVMs(vms)
}

func (c *Cache) AddVPCs(items []*mysqlmodel.VPC) {
	for _, item := range items {
		c.DiffBaseDataSet.AddVPC(item, c.Sequence)
		c.ToolDataSet.AddVPC(item)
	}
}

func (c *Cache) DeleteVPCs(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeleteVPC(lcuuid)
		c.ToolDataSet.DeleteVPC(lcuuid)
	}
}

func (c *Cache) refreshVPCs() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_VPC_EN), c.metadata.LogPrefixes)
	var vpcs []*mysqlmodel.VPC

	err := c.metadata.DB.Where(c.getConditonDomainCreateMethod()).Find(&vpcs).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_VPC_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddVPCs(vpcs)
}

func (c *Cache) AddNetwork(item *mysqlmodel.Network) {
	c.DiffBaseDataSet.AddNetwork(item, c.Sequence, c.ToolDataSet)
	c.ToolDataSet.AddNetwork(item)
}

func (c *Cache) AddNetworks(items []*mysqlmodel.Network) {
	for _, item := range items {
		c.AddNetwork(item)
	}
}

func (c *Cache) UpdateNetwork(cloudItem *cloudmodel.Network) {
	c.ToolDataSet.UpdateNetwork(cloudItem)
}

func (c *Cache) DeleteNetworks(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeleteNetwork(lcuuid)
		c.ToolDataSet.DeleteNetwork(lcuuid)
	}
}

func (c *Cache) refreshNetworks() []int {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_NETWORK_EN), c.metadata.LogPrefixes)
	var networks []*mysqlmodel.Network
	networkIDs := []int{}

	err := c.metadata.DB.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL) AND create_method = ?", c.metadata.Domain.Lcuuid, c.metadata.SubDomain.Lcuuid, ctrlrcommon.CREATE_METHOD_LEARN).Find(&networks).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, err), c.metadata.LogPrefixes)
		return networkIDs
	}

	for _, item := range networks {
		networkIDs = append(networkIDs, item.ID)
		c.AddNetwork(item)
	}

	var publicNetwork *mysqlmodel.Network
	err = c.metadata.DB.Where("lcuuid = ?", rcommon.PUBLIC_NETWORK_LCUUID).First(&publicNetwork).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, err), c.metadata.LogPrefixes)
		return networkIDs
	}
	c.ToolDataSet.SetPublicNetworkID(publicNetwork.ID)

	return networkIDs
}

func (c *Cache) AddSubnets(items []*mysqlmodel.Subnet) {
	for _, item := range items {
		c.DiffBaseDataSet.AddSubnet(item, c.Sequence)
		c.ToolDataSet.AddSubnet(item)
	}
}

func (c *Cache) DeleteSubnets(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeleteSubnet(lcuuid)
		c.ToolDataSet.DeleteSubnet(lcuuid)
	}
}

func (c *Cache) refreshSubnets(networkIDs []int) {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_SUBNET_EN), c.metadata.LogPrefixes)
	var subnets []*mysqlmodel.Subnet

	err := c.metadata.DB.Where(map[string]interface{}{"vl2id": networkIDs}).Find(&subnets).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_SUBNET_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddSubnets(subnets)
}

func (c *Cache) AddVRouter(item *mysqlmodel.VRouter) {
	c.DiffBaseDataSet.AddVRouter(item, c.Sequence, c.ToolDataSet)
	c.ToolDataSet.AddVRouter(item)
}

func (c *Cache) AddVRouters(items []*mysqlmodel.VRouter) {
	for _, item := range items {
		c.AddVRouter(item)
	}
}

func (c *Cache) UpdateVRouter(cloudItem *cloudmodel.VRouter) {
	c.ToolDataSet.UpdateVRouter(cloudItem)
}

func (c *Cache) DeleteVRouters(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeleteVRouter(lcuuid)
		c.ToolDataSet.DeleteVRouter(lcuuid)
	}
}

func (c *Cache) refreshVRouters() []int {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_VROUTER_EN), c.metadata.LogPrefixes)
	var vrouters []*mysqlmodel.VRouter
	vrouterIDs := []int{}

	err := c.metadata.DB.Where(c.getConditionDomain()).Find(&vrouters).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, err), c.metadata.LogPrefixes)
		return vrouterIDs
	}

	for _, item := range vrouters {
		vrouterIDs = append(vrouterIDs, item.ID)
		c.AddVRouter(item)
	}
	return vrouterIDs
}

func (c *Cache) AddRoutingTables(items []*mysqlmodel.RoutingTable) {
	for _, item := range items {
		c.DiffBaseDataSet.AddRoutingTable(item, c.Sequence)
	}
}

func (c *Cache) DeleteRoutingTables(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeleteRoutingTable(lcuuid)
	}
}

func (c *Cache) refreshRoutingTables(vrouterIDs []int) {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_ROUTING_TABLE_EN), c.metadata.LogPrefixes)
	var routingTables []*mysqlmodel.RoutingTable

	err := c.metadata.DB.Where(map[string]interface{}{"vnet_id": vrouterIDs}).Find(&routingTables).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_ROUTING_TABLE_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddRoutingTables(routingTables)
}

func (c *Cache) AddDHCPPorts(items []*mysqlmodel.DHCPPort) {
	for _, item := range items {
		c.DiffBaseDataSet.AddDHCPPort(item, c.Sequence, c.ToolDataSet)
		c.ToolDataSet.AddDHCPPort(item)
	}
}

func (c *Cache) UpdateDHCPPort(cloudItem *cloudmodel.DHCPPort) {
	c.ToolDataSet.UpdateDHCPPort(cloudItem)
}

func (c *Cache) DeleteDHCPPorts(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeleteDHCPPort(lcuuid)
		c.ToolDataSet.DeleteDHCPPort(lcuuid)
	}
}

func (c *Cache) refreshDHCPPorts() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN), c.metadata.LogPrefixes)
	var dhcpPorts []*mysqlmodel.DHCPPort

	err := c.metadata.DB.Where(c.getConditionDomain()).Find(&dhcpPorts).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddDHCPPorts(dhcpPorts)
}

func (c *Cache) AddVInterfaces(items []*mysqlmodel.VInterface) {
	for _, item := range items {
		c.DiffBaseDataSet.AddVInterface(item, c.Sequence, c.ToolDataSet)
		c.ToolDataSet.AddVInterface(item)
	}
}

func (c *Cache) UpdateVInterface(cloudItem *cloudmodel.VInterface) {
	c.ToolDataSet.UpdateVInterface(cloudItem)
}

func (c *Cache) DeleteVInterfaces(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeleteVInterface(lcuuid)
		c.ToolDataSet.DeleteVInterface(lcuuid)
	}
}

func (c *Cache) refreshVInterfaces() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN), c.metadata.LogPrefixes)
	var vifs []*mysqlmodel.VInterface

	err := c.metadata.DB.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL) AND create_method = ?", c.metadata.Domain.Lcuuid, c.metadata.SubDomain.Lcuuid, ctrlrcommon.CREATE_METHOD_LEARN).Find(&vifs).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddVInterfaces(vifs)
}

func (c *Cache) AddWANIPs(items []*mysqlmodel.WANIP) {
	for _, item := range items {
		c.DiffBaseDataSet.AddWANIP(item, c.Sequence, c.ToolDataSet)
		c.ToolDataSet.AddWANIP(item)
	}
}

func (c *Cache) DeleteWANIPs(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeleteWANIP(lcuuid)
		c.ToolDataSet.DeleteWANIP(lcuuid)
	}
}

func (c *Cache) refreshWANIPs() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN), c.metadata.LogPrefixes)
	var wanIPs []*mysqlmodel.WANIP

	err := c.metadata.DB.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL) AND create_method = ?", c.metadata.Domain.Lcuuid, c.metadata.SubDomain.Lcuuid, ctrlrcommon.CREATE_METHOD_LEARN).Find(&wanIPs).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddWANIPs(wanIPs)
}

func (c *Cache) AddLANIPs(items []*mysqlmodel.LANIP) {
	for _, item := range items {
		c.DiffBaseDataSet.AddLANIP(item, c.Sequence, c.ToolDataSet)
		c.ToolDataSet.AddLANIP(item)
	}
}

func (c *Cache) DeleteLANIPs(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeleteLANIP(lcuuid)
		c.ToolDataSet.DeleteLANIP(lcuuid)
	}
}

func (c *Cache) refreshLANIPs() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN), c.metadata.LogPrefixes)
	var lanIPs []*mysqlmodel.LANIP

	err := c.metadata.DB.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL) AND create_method = ?", c.metadata.Domain.Lcuuid, c.metadata.SubDomain.Lcuuid, ctrlrcommon.CREATE_METHOD_LEARN).Find(&lanIPs).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddLANIPs(lanIPs)
}

func (c *Cache) AddFloatingIPs(items []*mysqlmodel.FloatingIP) {
	for _, item := range items {
		c.DiffBaseDataSet.AddFloatingIP(item, c.Sequence, c.ToolDataSet)
	}
}

func (c *Cache) DeleteFloatingIPs(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeleteFloatingIP(lcuuid)
	}
}

func (c *Cache) refreshFloatingIPs() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_FLOATING_IP_EN), c.metadata.LogPrefixes)
	var floatingIPs []*mysqlmodel.FloatingIP

	err := c.metadata.DB.Where(c.getConditionDomain()).Find(&floatingIPs).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_FLOATING_IP_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddFloatingIPs(floatingIPs)
}

func (c *Cache) AddNATGateways(items []*mysqlmodel.NATGateway) {
	for _, item := range items {
		c.DiffBaseDataSet.AddNATGateway(item, c.Sequence)
		c.ToolDataSet.AddNATGateway(item)
	}
}

func (c *Cache) UpdateNATGateway(cloudItem *cloudmodel.NATGateway) {
	c.ToolDataSet.UpdateNATGateway(cloudItem)
}

func (c *Cache) DeleteNATGateways(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeleteNATGateway(lcuuid)
		c.ToolDataSet.DeleteNATGateway(lcuuid)
	}
}

func (c *Cache) refreshNATGateways() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN), c.metadata.LogPrefixes)
	var natGateways []*mysqlmodel.NATGateway

	err := c.metadata.DB.Where(c.getConditionDomain()).Find(&natGateways).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddNATGateways(natGateways)
}

func (c *Cache) AddNATVMConnections(items []*mysqlmodel.NATVMConnection) {
	for _, item := range items {
		c.DiffBaseDataSet.AddNATVMConnection(item, c.Sequence)
	}
}

func (c *Cache) DeleteNATVMConnections(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeleteNATVMConnection(lcuuid)
	}
}

func (c *Cache) refreshNATVMConnections() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_NAT_VM_CONNECTION_EN), c.metadata.LogPrefixes)
	var natVMConnections []*mysqlmodel.NATVMConnection

	err := c.metadata.DB.Where(c.getConditionDomain()).Find(&natVMConnections).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_NAT_VM_CONNECTION_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddNATVMConnections(natVMConnections)
}

func (c *Cache) AddNATRules(items []*mysqlmodel.NATRule) {
	for _, item := range items {
		c.DiffBaseDataSet.AddNATRule(item, c.Sequence)
	}
}

func (c *Cache) DeleteNATRules(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeleteNATRule(lcuuid)
	}
}

func (c *Cache) refreshNATRules() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_NAT_RULE_EN), c.metadata.LogPrefixes)
	var natRules []*mysqlmodel.NATRule

	err := c.metadata.DB.Where(c.getConditionDomain()).Find(&natRules).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_NAT_RULE_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddNATRules(natRules)
}

func (c *Cache) AddLBs(items []*mysqlmodel.LB) {
	for _, item := range items {
		c.DiffBaseDataSet.AddLB(item, c.Sequence)
		c.ToolDataSet.AddLB(item)
	}
}

func (c *Cache) UpdateLB(cloudItem *cloudmodel.LB) {
	c.ToolDataSet.UpdateLB(cloudItem)
}

func (c *Cache) DeleteLBs(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeleteLB(lcuuid)
		c.ToolDataSet.DeleteLB(lcuuid)
	}
}

func (c *Cache) refreshLBs() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_LB_EN), c.metadata.LogPrefixes)
	var lbs []*mysqlmodel.LB

	err := c.metadata.DB.Where(c.getConditionDomain()).Find(&lbs).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_LB_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddLBs(lbs)
}

func (c *Cache) AddLBVMConnections(items []*mysqlmodel.LBVMConnection) {
	for _, item := range items {
		c.DiffBaseDataSet.AddLBVMConnection(item, c.Sequence)
	}
}

func (c *Cache) DeleteLBVMConnections(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeleteLBVMConnection(lcuuid)
	}
}

func (c *Cache) refreshLBVMConnections() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_LB_VM_CONNECTION_EN), c.metadata.LogPrefixes)
	var lbVMConnections []*mysqlmodel.LBVMConnection

	err := c.metadata.DB.Where(c.getConditionDomain()).Find(&lbVMConnections).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_LB_VM_CONNECTION_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddLBVMConnections(lbVMConnections)
}

func (c *Cache) AddLBListeners(items []*mysqlmodel.LBListener) {
	for _, item := range items {
		c.DiffBaseDataSet.AddLBListener(item, c.Sequence)
		c.ToolDataSet.AddLBListener(item)
	}
}

func (c *Cache) DeleteLBListeners(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeleteLBListener(lcuuid)
		c.ToolDataSet.DeleteLBListener(lcuuid)
	}
}

func (c *Cache) refreshLBListeners() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_LB_LISTENER_EN), c.metadata.LogPrefixes)
	var listeners []*mysqlmodel.LBListener

	err := c.metadata.DB.Where(c.getConditionDomain()).Find(&listeners).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_LB_LISTENER_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddLBListeners(listeners)
}

func (c *Cache) AddLBTargetServers(items []*mysqlmodel.LBTargetServer) {
	for _, item := range items {
		c.DiffBaseDataSet.AddLBTargetServer(item, c.Sequence)
	}
}

func (c *Cache) DeleteLBTargetServers(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeleteLBTargetServer(lcuuid)
	}
}

func (c *Cache) refreshLBTargetServers() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_LB_TARGET_SERVER_EN), c.metadata.LogPrefixes)
	var servers []*mysqlmodel.LBTargetServer

	err := c.metadata.DB.Where(c.getConditionDomain()).Find(&servers).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_LB_TARGET_SERVER_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddLBTargetServers(servers)
}

func (c *Cache) AddPeerConnections(items []*mysqlmodel.PeerConnection) {
	for _, item := range items {
		c.DiffBaseDataSet.AddPeerConnection(item, c.Sequence, c.ToolDataSet)
	}
}

func (c *Cache) DeletePeerConnections(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeletePeerConnection(lcuuid)
	}
}

func (c *Cache) refreshPeeConnections() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_PEER_CONNECTION_EN), c.metadata.LogPrefixes)
	var peerConnections []*mysqlmodel.PeerConnection

	err := c.metadata.DB.Where(c.getConditonDomainCreateMethod()).Find(&peerConnections).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_PEER_CONNECTION_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddPeerConnections(peerConnections)
}

func (c *Cache) AddCENs(items []*mysqlmodel.CEN) {
	for _, item := range items {
		c.DiffBaseDataSet.AddCEN(item, c.Sequence, c.ToolDataSet)
	}
}

func (c *Cache) DeleteCENs(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeleteCEN(lcuuid)
	}
}

func (c *Cache) refreshCENs() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_CEN_EN), c.metadata.LogPrefixes)
	var cens []*mysqlmodel.CEN

	err := c.metadata.DB.Where(c.getConditionDomain()).Find(&cens).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_CEN_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddCENs(cens)
}

func (c *Cache) AddRDSInstances(items []*mysqlmodel.RDSInstance) {
	for _, item := range items {
		c.DiffBaseDataSet.AddRDSInstance(item, c.Sequence)
		c.ToolDataSet.AddRDSInstance(item)
	}
}

func (c *Cache) UpdateRDSInstance(cloudItem *cloudmodel.RDSInstance) {
	c.ToolDataSet.UpdateRDSInstance(cloudItem)
}

func (c *Cache) DeleteRDSInstances(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeleteRDSInstance(lcuuid)
		c.ToolDataSet.DeleteRDSInstance(lcuuid)
	}
}

func (c *Cache) refreshRDSInstances() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN), c.metadata.LogPrefixes)
	var instances []*mysqlmodel.RDSInstance

	err := c.metadata.DB.Where(c.getConditionDomain()).Find(&instances).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddRDSInstances(instances)
}

func (c *Cache) AddRedisInstances(items []*mysqlmodel.RedisInstance) {
	for _, item := range items {
		c.DiffBaseDataSet.AddRedisInstance(item, c.Sequence)
		c.ToolDataSet.AddRedisInstance(item)
	}
}

func (c *Cache) UpdateRedisInstance(cloudItem *cloudmodel.RedisInstance) {
	c.ToolDataSet.UpdateRedisInstance(cloudItem)
}

func (c *Cache) DeleteRedisInstances(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeleteRedisInstance(lcuuid)
		c.ToolDataSet.DeleteRedisInstance(lcuuid)
	}
}

func (c *Cache) refreshRedisInstances() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN), c.metadata.LogPrefixes)
	var instances []*mysqlmodel.RedisInstance

	err := c.metadata.DB.Where(c.getConditionDomain()).Find(&instances).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddRedisInstances(instances)
}

func (c *Cache) AddPodClusters(items []*mysqlmodel.PodCluster) {
	for _, item := range items {
		c.DiffBaseDataSet.AddPodCluster(item, c.Sequence)
		c.ToolDataSet.AddPodCluster(item)
	}
}

func (c *Cache) DeletePodClusters(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeletePodCluster(lcuuid)
		c.ToolDataSet.DeletePodCluster(lcuuid)
	}
}

func (c *Cache) refreshPodClusters() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN), c.metadata.LogPrefixes)
	var podClusters []*mysqlmodel.PodCluster

	err := c.metadata.DB.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL)", c.metadata.Domain.Lcuuid, c.metadata.SubDomain.Lcuuid).Find(&podClusters).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddPodClusters(podClusters)
}

func (c *Cache) AddPodNodes(items []*mysqlmodel.PodNode) {
	for _, item := range items {
		c.DiffBaseDataSet.AddPodNode(item, c.Sequence)
		c.ToolDataSet.AddPodNode(item)
	}
}

func (c *Cache) UpdatePodNode(cloudItem *cloudmodel.PodNode) {
	c.ToolDataSet.UpdatePodNode(cloudItem)
}

func (c *Cache) DeletePodNodes(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeletePodNode(lcuuid)
		c.ToolDataSet.DeletePodNode(lcuuid)
	}
}

func (c *Cache) refreshPodNodes() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN), c.metadata.LogPrefixes)
	var podNodes []*mysqlmodel.PodNode

	err := c.metadata.DB.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL)", c.metadata.Domain.Lcuuid, c.metadata.SubDomain.Lcuuid).Find(&podNodes).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddPodNodes(podNodes)
}

func (c *Cache) AddVMPodNodeConnections(items []*mysqlmodel.VMPodNodeConnection) {
	for _, item := range items {
		c.DiffBaseDataSet.AddVMPodNodeConnection(item, c.Sequence)
	}
}

func (c *Cache) DeleteVMPodNodeConnections(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeleteVMPodNodeConnection(lcuuid)
	}
}

func (c *Cache) refreshVMPodNodeConnections() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN), c.metadata.LogPrefixes)
	var connections []*mysqlmodel.VMPodNodeConnection

	err := c.metadata.DB.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL)", c.metadata.Domain.Lcuuid, c.metadata.SubDomain.Lcuuid).Find(&connections).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddVMPodNodeConnections(connections)
}

func (c *Cache) AddPodNamespaces(items []*mysqlmodel.PodNamespace) {
	for _, item := range items {
		c.DiffBaseDataSet.AddPodNamespace(item, c.Sequence)
		c.ToolDataSet.AddPodNamespace(item)
	}
}

func (c *Cache) DeletePodNamespaces(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeletePodNamespace(lcuuid)
		c.ToolDataSet.DeletePodNamespace(lcuuid)
	}
}

func (c *Cache) refreshPodNamespaces() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN), c.metadata.LogPrefixes)
	var podNamespaces []*mysqlmodel.PodNamespace

	err := c.metadata.DB.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL)", c.metadata.Domain.Lcuuid, c.metadata.SubDomain.Lcuuid).Find(&podNamespaces).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddPodNamespaces(podNamespaces)
}

func (c *Cache) AddPodIngress(item *mysqlmodel.PodIngress) {
	c.DiffBaseDataSet.AddPodIngress(item, c.Sequence)
	c.ToolDataSet.AddPodIngress(item)
}

func (c *Cache) AddPodIngresses(items []*mysqlmodel.PodIngress) {
	for _, item := range items {
		c.AddPodIngress(item)
	}
}

func (c *Cache) DeletePodIngresses(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeletePodIngress(lcuuid)
		c.ToolDataSet.DeletePodIngress(lcuuid)
	}
}

func (c *Cache) refreshPodIngresses() []int {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN), c.metadata.LogPrefixes)
	var podIngresses []*mysqlmodel.PodIngress
	podIngressIDs := []int{}

	err := c.metadata.DB.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL)", c.metadata.Domain.Lcuuid, c.metadata.SubDomain.Lcuuid).Find(&podIngresses).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, err), c.metadata.LogPrefixes)
		return podIngressIDs
	}

	for _, item := range podIngresses {
		podIngressIDs = append(podIngressIDs, item.ID)
		c.AddPodIngress(item)
	}
	return podIngressIDs
}

func (c *Cache) AddPodIngressRules(items []*mysqlmodel.PodIngressRule) {
	for _, item := range items {
		c.DiffBaseDataSet.AddPodIngressRule(item, c.Sequence)
		c.ToolDataSet.AddPodIngressRule(item)
	}
}

func (c *Cache) DeletePodIngressRules(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeletePodIngressRule(lcuuid)
		c.ToolDataSet.DeletePodIngressRule(lcuuid)
	}
}

func (c *Cache) refreshPodIngressRules(podIngressIDs []int) {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN), c.metadata.LogPrefixes)
	if len(podIngressIDs) == 0 {
		return
	}
	var podIngressRules []*mysqlmodel.PodIngressRule

	err := c.metadata.DB.Where("pod_ingress_id IN ?", podIngressIDs).Find(&podIngressRules).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddPodIngressRules(podIngressRules)
}

func (c *Cache) AddPodIngressRuleBackends(items []*mysqlmodel.PodIngressRuleBackend) {
	for _, item := range items {
		c.DiffBaseDataSet.AddPodIngressRuleBackend(item, c.Sequence)
	}
}

func (c *Cache) DeletePodIngressRuleBackends(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeletePodIngressRuleBackend(lcuuid)
	}
}

func (c *Cache) refreshPodIngresseRuleBackends(podIngressIDs []int) {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN), c.metadata.LogPrefixes)
	if len(podIngressIDs) == 0 {
		return
	}
	var podIngressRuleBackends []*mysqlmodel.PodIngressRuleBackend

	err := c.metadata.DB.Where("pod_ingress_id IN ?", podIngressIDs).Find(&podIngressRuleBackends).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddPodIngressRuleBackends(podIngressRuleBackends)
}

func (c *Cache) AddPodService(item *mysqlmodel.PodService) {
	c.DiffBaseDataSet.AddPodService(item, c.Sequence, c.ToolDataSet)
	c.ToolDataSet.AddPodService(item)
}

func (c *Cache) AddPodServices(items []*mysqlmodel.PodService) {
	for _, item := range items {
		c.AddPodService(item)
	}
}

func (c *Cache) UpdatePodService(cloudItem *cloudmodel.PodService) {
	c.ToolDataSet.UpdatePodService(cloudItem)
}

func (c *Cache) DeletePodServices(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeletePodService(lcuuid)
		c.ToolDataSet.DeletePodService(lcuuid)
	}
}

func (c *Cache) refreshPodServices() []int {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN), c.metadata.LogPrefixes)
	var podServices []*mysqlmodel.PodService
	podServiceIDs := []int{}

	err := c.metadata.DB.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL)", c.metadata.Domain.Lcuuid, c.metadata.SubDomain.Lcuuid).Find(&podServices).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, err), c.metadata.LogPrefixes)
		return podServiceIDs
	}

	for _, item := range podServices {
		podServiceIDs = append(podServiceIDs, item.ID)
		c.AddPodService(item)
	}
	return podServiceIDs
}

func (c *Cache) AddPodServicePorts(items []*mysqlmodel.PodServicePort) {
	for _, item := range items {
		c.DiffBaseDataSet.AddPodServicePort(item, c.Sequence)
	}
}

func (c *Cache) DeletePodServicePorts(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeletePodServicePort(lcuuid)
	}
}

func (c *Cache) refreshPodServicePorts(podServiceIDs []int) {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_PORT_EN), c.metadata.LogPrefixes)
	if len(podServiceIDs) == 0 {
		return
	}
	var podServicePorts []*mysqlmodel.PodServicePort

	err := c.metadata.DB.Where("pod_service_id IN ?", podServiceIDs).Find(&podServicePorts).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_PORT_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddPodServicePorts(podServicePorts)
}

func (c *Cache) AddPodGroups(items []*mysqlmodel.PodGroup) {
	for _, item := range items {
		c.DiffBaseDataSet.AddPodGroup(item, c.Sequence)
		c.ToolDataSet.AddPodGroup(item)
	}
}

func (c *Cache) DeletePodGroups(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeletePodGroup(lcuuid)
		c.ToolDataSet.DeletePodGroup(lcuuid)
	}
}

func (c *Cache) refreshPodGroups() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN), c.metadata.LogPrefixes)
	var podGroups []*mysqlmodel.PodGroup

	err := c.metadata.DB.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL)", c.metadata.Domain.Lcuuid, c.metadata.SubDomain.Lcuuid).Find(&podGroups).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddPodGroups(podGroups)
}

func (c *Cache) AddPodGroupPorts(items []*mysqlmodel.PodGroupPort) {
	for _, item := range items {
		c.DiffBaseDataSet.AddPodGroupPort(item, c.Sequence)
	}
}

func (c *Cache) DeletePodGroupPorts(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeletePodGroupPort(lcuuid)
	}
}

func (c *Cache) refreshPodGroupPorts(podServiceIDs []int) {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN), c.metadata.LogPrefixes)
	if len(podServiceIDs) == 0 {
		return
	}
	var podGroupPorts []*mysqlmodel.PodGroupPort

	err := c.metadata.DB.Where("pod_service_id IN ?", podServiceIDs).Find(&podGroupPorts).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddPodGroupPorts(podGroupPorts)
}

func (c *Cache) AddPodReplicaSets(items []*mysqlmodel.PodReplicaSet) {
	for _, item := range items {
		c.DiffBaseDataSet.AddPodReplicaSet(item, c.Sequence)
		c.ToolDataSet.AddPodReplicaSet(item)
	}
}

func (c *Cache) DeletePodReplicaSets(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeletePodReplicaSet(lcuuid)
		c.ToolDataSet.DeletePodReplicaSet(lcuuid)
	}
}

func (c *Cache) refreshPodReplicaSets() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN), c.metadata.LogPrefixes)
	var podReplicaSets []*mysqlmodel.PodReplicaSet

	err := c.metadata.DB.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL)", c.metadata.Domain.Lcuuid, c.metadata.SubDomain.Lcuuid).Find(&podReplicaSets).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddPodReplicaSets(podReplicaSets)
}

func (c *Cache) AddPods(items []*mysqlmodel.Pod) {
	for _, item := range items {
		c.DiffBaseDataSet.AddPod(item, c.Sequence, c.ToolDataSet)
		c.ToolDataSet.AddPod(item)
	}
}

func (c *Cache) UpdatePod(cloudItem *cloudmodel.Pod) {
	c.ToolDataSet.UpdatePod(cloudItem)
}

func (c *Cache) DeletePods(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeletePod(lcuuid)
		c.ToolDataSet.DeletePod(lcuuid)
	}
}

func (c *Cache) refreshPods() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_POD_EN), c.metadata.LogPrefixes)
	var pods []*mysqlmodel.Pod

	err := c.metadata.DB.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL)", c.metadata.Domain.Lcuuid, c.metadata.SubDomain.Lcuuid).Find(&pods).Error
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_POD_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddPods(pods)
}

func (c *Cache) AddProcesses(items []*mysqlmodel.Process) {
	for _, item := range items {
		c.DiffBaseDataSet.AddProcess(item, c.Sequence)
		c.ToolDataSet.AddProcess(item)
	}
}

func (c *Cache) DeleteProcesses(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeleteProcess(lcuuid)
		c.ToolDataSet.DeleteProcess(lcuuid)
	}
}

func (c *Cache) refreshProcesses() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_PROCESS_EN), c.metadata.LogPrefixes)
	var processes []*mysqlmodel.Process
	processes, err := query.FindInBatches[mysqlmodel.Process](c.metadata.DB.Where("domain = ? AND (sub_domain = ? OR sub_domain IS NULL)", c.metadata.Domain.Lcuuid, c.metadata.SubDomain.Lcuuid))
	if err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_PROCESS_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddProcesses(processes)
}

func (c *Cache) AddVIPs(items []*mysqlmodel.VIP) {
	for _, item := range items {
		c.DiffBaseDataSet.AddVIP(item, c.Sequence)
	}
}

func (c *Cache) DeleteVIPs(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		c.DiffBaseDataSet.DeleteVIP(lcuuid)
	}
}

func (c *Cache) refreshVIP() {
	log.Info(refreshResource(ctrlrcommon.RESOURCE_TYPE_VIP_EN), c.metadata.LogPrefixes)
	var vips []*mysqlmodel.VIP
	if err := c.metadata.DB.Where("domain = ?", c.metadata.Domain.Lcuuid).Find(&vips).Error; err != nil {
		log.Error(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_VIP_EN, err), c.metadata.LogPrefixes)
		return
	}

	c.AddVIPs(vips)
}
