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

package cleaner

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/config"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	tagrecorderHealer "github.com/deepflowio/deepflow/server/controller/tagrecorder/healer"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("recorder.cleaner")

var (
	cleanersOnce sync.Once
	cleaners     *Cleaners
)

type Cleaners struct {
	ctx    context.Context
	cancel context.CancelFunc
	cfg    config.RecorderConfig

	mux            sync.Mutex
	orgIDToCleaner map[int]*Cleaner
}

func GetCleaners() *Cleaners {
	cleanersOnce.Do(func() {
		cleaners = new(Cleaners)
	})
	return cleaners
}

func (c *Cleaners) Init(ctx context.Context, cfg config.RecorderConfig) {
	c.ctx, c.cancel = context.WithCancel(ctx)
	c.cfg = cfg
	c.orgIDToCleaner = make(map[int]*Cleaner)
	return
}

func (c *Cleaners) Start(sContext context.Context) error {
	log.Info("resource clean started")

	err := c.checkORGs()
	if err != nil {
		return err
	}

	// 定时清理软删除资源数据
	// timed clean soft deleted resource data
	c.timedCleanDeletedData(sContext)
	// 定时删除所属上级资源已不存在（被彻底清理或软删除）的资源数据，并记录异常日志
	// timed clean the resource data of the parent resource that does not exist (means it is completely deleted or soft deleted)
	// and record error logs
	c.timedCleanDirtyData(sContext)

	return nil
}

func (c *Cleaners) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	// clear before each stop
	c.orgIDToCleaner = make(map[int]*Cleaner)
	log.Info("resource clean stopped")
}

func (c *Cleaners) timedCleanDeletedData(sContext context.Context) {
	c.cleanDeletedData()
	go func() {
		ticker := time.NewTicker(time.Duration(int(c.cfg.DeletedResourceCleanInterval)) * time.Hour)
		defer ticker.Stop()

	LOOP:
		for {
			select {
			case <-ticker.C:
				if err := c.checkORGs(); err != nil {
					continue
				}
				c.cleanDeletedData()
			case <-sContext.Done():
				break LOOP
			case <-c.ctx.Done():
				break LOOP
			}
		}
	}()
}

func (c *Cleaners) checkORGs() error {
	orgIDs, err := metadb.GetORGIDs()
	if err != nil {
		log.Errorf("failed to get db for org ids: %s", err.Error())
		return err
	}

	for _, orgID := range orgIDs {
		if _, err := c.NewCleanerIfNotExists(orgID); err != nil {
			log.Errorf("failed to cleaner for org id %d: %s", orgID, err.Error())
			return err
		}
	}
	c.removeOrRefresh(orgIDs)
	return nil
}

func (c *Cleaners) removeOrRefresh(orgIDs []int) {
	c.mux.Lock()
	defer c.mux.Unlock()

	for orgID, cleaner := range c.orgIDToCleaner {
		if slices.Contains(orgIDs, orgID) {
			cleaner.refreshStatsd()
		} else {
			cleaner.closeStatsd()
			delete(c.orgIDToCleaner, orgID)
		}
	}
}

func (c *Cleaners) cleanDeletedData() {
	for _, cl := range c.orgIDToCleaner {
		cl.cleanDeletedData(int(c.cfg.DeletedResourceRetentionTime))
	}
}

func (c *Cleaners) timedCleanDirtyData(sContext context.Context) {
	c.cleanDirtyData()
	go func() {
		ticker := time.NewTicker(time.Duration(int(c.cfg.DirtyResourceCleanInterval)) * time.Minute)
		defer ticker.Stop()
	LOOP:
		for {
			select {
			case <-ticker.C:
				if err := c.checkORGs(); err != nil {
					continue
				}
				c.cleanDirtyData()
			case <-sContext.Done():
				break LOOP
			case <-c.ctx.Done():
				break LOOP
			}
		}
	}()
}

func (c *Cleaners) cleanDirtyData() {
	for _, cl := range c.orgIDToCleaner {
		cl.cleanDirtyData()
		cl.tagrecorderHealer.Run()
	}
}

func (c *Cleaners) NewCleanerIfNotExists(orgID int) (*Cleaner, error) {
	if cl, ok := c.get(orgID); ok {
		return cl, nil
	}

	cl, err := newCleaner(c.cfg, orgID)
	if err != nil {
		return nil, err
	}

	c.set(orgID, cl)
	return cl, nil
}

func (c *Cleaners) Create(orgID int) {
	c.NewCleanerIfNotExists(orgID)
}

func (c *Cleaners) Delete(orgID int) {
	c.mux.Lock()
	defer c.mux.Unlock()

	delete(c.orgIDToCleaner, orgID)
}

func (c *Cleaners) get(orgID int) (*Cleaner, bool) {
	c.mux.Lock()
	defer c.mux.Unlock()

	cl, ok := c.orgIDToCleaner[orgID]
	return cl, ok
}

func (c *Cleaners) set(orgID int, cl *Cleaner) {
	c.mux.Lock()
	defer c.mux.Unlock()

	c.orgIDToCleaner[orgID] = cl
}

type Cleaner struct {
	org      *common.ORG
	toolData *toolData
	cfg      config.RecorderConfig

	statsdLock           sync.Mutex
	domainLcuuidToStatsd map[string]*domainStatsd

	tagrecorderHealer *tagrecorderHealer.Healers
}

func newCleaner(cfg config.RecorderConfig, orgID int) (*Cleaner, error) {
	org, err := common.NewORG(orgID)
	if err != nil {
		log.Errorf("failed to create org object: %s", err.Error())
		return nil, err
	}

	c := &Cleaner{
		org:                  org,
		cfg:                  cfg,
		toolData:             newToolData(),
		domainLcuuidToStatsd: make(map[string]*domainStatsd),

		tagrecorderHealer: tagrecorderHealer.NewDefaultDomainHealers(org.DB),
	}
	c.refreshStatsd()
	return c, nil
}

func (c *Cleaner) closeStatsd() {
	for _, statsd := range c.domainLcuuidToStatsd {
		statsd.close()
	}
}

func (c *Cleaner) refreshStatsd() {
	var domains []*metadbmodel.Domain
	if err := c.org.DB.Find(&domains).Error; err != nil {
		log.Errorf("failed to get domain: %s", err.Error(), c.org.LogPrefix)
		return
	}

	c.statsdLock.Lock()
	defer c.statsdLock.Unlock()

	domainLcuuidInfo := make(map[string]struct{})
	for _, domain := range domains {
		domainLcuuidInfo[domain.Lcuuid] = struct{}{}
		if _, ok := c.domainLcuuidToStatsd[domain.Lcuuid]; !ok {
			c.domainLcuuidToStatsd[domain.Lcuuid] = newDomainStatsd(c.org, domain)
			c.domainLcuuidToStatsd[domain.Lcuuid].start()
		}
	}
	for domainLcuuid, statsd := range c.domainLcuuidToStatsd {
		if _, ok := domainLcuuidInfo[domainLcuuid]; !ok {
			statsd.close()
			delete(c.domainLcuuidToStatsd, domainLcuuid)
		}
	}
}

func (c *Cleaner) getStatsd(domainLcuuid string, tagType string) *CleanerCounter {
	c.statsdLock.Lock()
	defer c.statsdLock.Unlock()

	if statsd, ok := c.domainLcuuidToStatsd[domainLcuuid]; ok {
		return statsd.get(tagType)
	}
	return nil
}

func (c *Cleaner) fillStatsd(domainLcuuid string, tagType string, count int) {
	if statsd := c.getStatsd(domainLcuuid, tagType); statsd != nil {
		statsd.Fill(count)
		log.Infof("%s %s statsd filled: %d, total: %d", domainLcuuid, tagType, count, atomic.LoadUint64(&statsd.Count), c.org.LogPrefix)
	} else {
		log.Error("%s %s statsd not found", domainLcuuid, tagType, c.org.LogPrefix)
	}
}

func (c *Cleaner) cleanDeletedData(retentionInterval int) {
	if err := c.toolData.load(c.org.DB); err != nil {
		log.Error("failed to load tool data", c.org.LogPrefix)
		return
	}

	expiredAt := time.Now().Add(time.Duration(-retentionInterval) * time.Hour)
	log.Infof("clean soft deleted resources (deleted_at < %s) started", expiredAt.Format(ctrlrcommon.GO_BIRTHDAY), c.org.LogPrefix)
	pageDeleteExpiredAndPublish[*message.DeletedRegions, message.DeletedRegions, metadbmodel.Region](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_REGION_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[*message.DeletedAZs, message.DeletedAZs, metadbmodel.AZ](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_AZ_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[*message.DeletedHosts, message.DeletedHosts, metadbmodel.Host](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_HOST_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[*message.DeletedVMs, message.DeletedVMs, metadbmodel.VM](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_VM_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[*message.DeletedVPCs, message.DeletedVPCs, metadbmodel.VPC](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_VPC_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[*message.DeletedNetworks, message.DeletedNetworks, metadbmodel.Network](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[*message.DeletedVRouters, message.DeletedVRouters, metadbmodel.VRouter](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[*message.DeletedDHCPPorts, message.DeletedDHCPPorts, metadbmodel.DHCPPort](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[*message.DeletedNATGateways, message.DeletedNATGateways, metadbmodel.NATGateway](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[*message.DeletedLBs, message.DeletedLBs, metadbmodel.LB](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_LB_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[*message.DeletedLBListeners, message.DeletedLBListeners, metadbmodel.LBListener](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_LB_LISTENER_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[*message.DeletedCENs, message.DeletedCENs, metadbmodel.CEN](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_CEN_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[*message.DeletedPeerConnections, message.DeletedPeerConnections, metadbmodel.PeerConnection](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_PEER_CONNECTION_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[*message.DeletedRDSInstances, message.DeletedRDSInstances, metadbmodel.RDSInstance](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[*message.DeletedRedisInstances, message.DeletedRedisInstances, metadbmodel.RedisInstance](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[*message.DeletedPodClusters, message.DeletedPodClusters, metadbmodel.PodCluster](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[*message.DeletedPodNodes, message.DeletedPodNodes, metadbmodel.PodNode](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[*message.DeletedPodNamespaces, message.DeletedPodNamespaces, metadbmodel.PodNamespace](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[*message.DeletedPodIngresses, message.DeletedPodIngresses, metadbmodel.PodIngress](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[*message.DeletedPodServices, message.DeletedPodServices, metadbmodel.PodService](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[*message.DeletedPodGroups, message.DeletedPodGroups, metadbmodel.PodGroup](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[*message.DeletedPodReplicaSets, message.DeletedPodReplicaSets, metadbmodel.PodReplicaSet](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[*message.DeletedPods, message.DeletedPods, metadbmodel.Pod](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[*message.DeletedProcesses, message.DeletedProcesses, metadbmodel.Process](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_PROCESS_EN, c.toolData, c.cfg.MySQLBatchSize)
	log.Info("clean soft deleted resources completed", c.org.LogPrefix)
}

func (c *Cleaner) cleanDirtyData() {
	if err := c.toolData.load(c.org.DB); err != nil {
		log.Error("failed to load tool data", c.org.LogPrefix)
		return
	}
	var domains []*metadbmodel.Domain
	if err := c.org.DB.Find(&domains).Error; err != nil {
		log.Errorf("failed to get domain: %s", err.Error(), c.org.LogPrefix)
		return
	}
	log.Info("clean dirty data started", c.org.LogPrefix)
	for _, domain := range domains {
		c.cleanHostDirty(domain.Lcuuid)
		c.cleanVMDirty(domain.Lcuuid)
		c.cleanNetworkDirty(domain.Lcuuid)
		c.cleanVRouterDirty(domain.Lcuuid)
		c.cleanPodClusterDirty(domain.Lcuuid)
		c.cleanPodNamespaceDirty(domain.Lcuuid)
		c.cleanPodNodeDirty(domain.Lcuuid)
		c.cleanPodIngressDirty(domain.Lcuuid)
		c.cleanPodServiceDirty(domain.Lcuuid)
		c.cleanPodGroupDirty(domain.Lcuuid)
		c.cleanPodDirty(domain.Lcuuid)
		c.cleanVInterfaceDirty(domain.Lcuuid)
	}
	log.Info("clean dirty data completed", c.org.LogPrefix)
}

func (c *Cleaner) cleanHostDirty(domainLcuuid string) {
	deviceIDs := getIDs[metadbmodel.Host](c.org.DB, domainLcuuid)
	if len(deviceIDs) != 0 {
		var vifs []*metadbmodel.VInterface
		c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("devicetype = ? AND deviceid NOT IN ?", ctrlrcommon.VIF_DEVICE_TYPE_HOST, deviceIDs).Find(&vifs)
		if len(vifs) != 0 {
			c.org.DB.Unscoped().Delete(&vifs)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_HOST_EN, vifs), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeDeviceIPConn, len(vifs))
		}
	}
}

func (c *Cleaner) cleanVMDirty(domainLcuuid string) {
	vmIDs := getIDs[metadbmodel.VM](c.org.DB, domainLcuuid)
	if len(vmIDs) != 0 {
		var vifs []*metadbmodel.VInterface
		c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("devicetype = ? AND deviceid NOT IN ?", ctrlrcommon.VIF_DEVICE_TYPE_VM, vmIDs).Find(&vifs)
		if len(vifs) != 0 {
			c.org.DB.Unscoped().Delete(&vifs)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_VM_EN, vifs), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeDeviceIPConn, len(vifs))
		}

		var vmPodNodeConns []*metadbmodel.VMPodNodeConnection
		c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("vm_id NOT IN ?", vmIDs).Find(&vmPodNodeConns)
		if len(vmPodNodeConns) != 0 {
			c.org.DB.Unscoped().Delete(&vmPodNodeConns)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, ctrlrcommon.RESOURCE_TYPE_VM_EN, vmPodNodeConns), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeCHostPodNodeConn, len(vmPodNodeConns))
		}
	}
}

func (c *Cleaner) cleanNetworkDirty(domainLcuuid string) {
	networkIDs := getIDs[metadbmodel.Network](c.org.DB, domainLcuuid)
	if len(networkIDs) != 0 {
		var subnets []*metadbmodel.Subnet
		c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("vl2id NOT IN ?", networkIDs).Find(&subnets)
		if len(subnets) != 0 {
			c.org.DB.Unscoped().Delete(&subnets)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_SUBNET_EN, ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, subnets), c.org.LogPrefix)
		}
	}
}

func (c *Cleaner) cleanVRouterDirty(domainLcuuid string) {
	vrouterIDs := getIDs[metadbmodel.VRouter](c.org.DB, domainLcuuid)
	if len(vrouterIDs) != 0 {
		var rts []*metadbmodel.RoutingTable
		c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("vnet_id NOT IN ?", vrouterIDs).Find(&rts)
		if len(rts) != 0 {
			c.org.DB.Unscoped().Delete(&rts)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_ROUTING_TABLE_EN, ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, rts), c.org.LogPrefix)
		}

		var vifs []*metadbmodel.VInterface
		c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("devicetype = ? AND deviceid NOT IN ?", ctrlrcommon.VIF_DEVICE_TYPE_VROUTER, vrouterIDs).Find(&vifs)
		if len(vifs) != 0 {
			c.org.DB.Unscoped().Delete(&vifs)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, vifs), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeDeviceIPConn, len(vifs))
		}
	}
}

func (c *Cleaner) cleanPodIngressDirty(domainLcuuid string) {
	podIngressIDs := getIDs[metadbmodel.PodIngress](c.org.DB, domainLcuuid)
	if len(podIngressIDs) != 0 {
		var podIngressRules []*metadbmodel.PodIngressRule
		c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("pod_ingress_id NOT IN ?", podIngressIDs).Find(&podIngressRules)
		if len(podIngressRules) != 0 {
			c.org.DB.Unscoped().Delete(&podIngressRules)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, podIngressRules), c.org.LogPrefix)
		}

		var podIngressRuleBkds []*metadbmodel.PodIngressRuleBackend
		c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("pod_ingress_id NOT IN ?", podIngressIDs).Find(&podIngressRuleBkds)
		if len(podIngressRuleBkds) != 0 {
			c.org.DB.Unscoped().Delete(&podIngressRuleBkds)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, podIngressRuleBkds), c.org.LogPrefix)
		}

		var podServices []*metadbmodel.PodService
		c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("pod_ingress_id NOT IN ?", podIngressIDs).Find(&podServices)
		if len(podServices) != 0 {
			if err := c.org.DB.Unscoped().Delete(&podServices).Error; err != nil {
				log.Errorf("failed to delete pod services: %s, pod ingress ids: %v", err.Error(), podIngressIDs, c.org.LogPrefix)
			} else {
				publishTagrecorder[*message.DeletedPodServices, message.DeletedPodServices, metadbmodel.PodService](c.org.DB, podServices, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, c.toolData)
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, podServices), c.org.LogPrefix)
		}
	}
}

func (c *Cleaner) cleanPodServiceDirty(domainLcuuid string) {
	podServiceIDs := getIDs[metadbmodel.PodService](c.org.DB, domainLcuuid)
	if len(podServiceIDs) == 0 {
		return
	}

	podServiceIDSet := make(map[int]struct{}, len(podServiceIDs))
	for _, id := range podServiceIDs {
		podServiceIDSet[id] = struct{}{}
	}

	// 清理 PodServicePorts
	var podServicePortRefs []struct {
		ID           int `gorm:"column:id"`
		PodServiceID int `gorm:"column:pod_service_id"`
	}
	if err := c.org.DB.Model(&metadbmodel.PodServicePort{}).
		Select("id, pod_service_id").
		Where(map[string]interface{}{"domain": domainLcuuid}).
		Find(&podServicePortRefs).Error; err != nil {
		log.Errorf("failed to query pod service port refs: %s, domain lcuuid: %s", err.Error(), domainLcuuid, c.org.LogPrefix)
		return
	}

	dirtyPodServicePortIDs := make([]int, 0)
	for _, ref := range podServicePortRefs {
		if _, exists := podServiceIDSet[ref.PodServiceID]; !exists {
			dirtyPodServicePortIDs = append(dirtyPodServicePortIDs, ref.ID)
		}
	}

	if len(dirtyPodServicePortIDs) > 0 {
		for i := 0; i < len(dirtyPodServicePortIDs); i += c.cfg.MySQLBatchSize {
			end := i + c.cfg.MySQLBatchSize
			if end > len(dirtyPodServicePortIDs) {
				end = len(dirtyPodServicePortIDs)
			}

			var podServicePorts []*metadbmodel.PodServicePort
			if err := c.org.DB.Where("id IN ?", dirtyPodServicePortIDs[i:end]).Find(&podServicePorts).Error; err != nil {
				log.Errorf("failed to query pod service ports: %s, pod service port ids: %v", err.Error(), dirtyPodServicePortIDs[i:end], c.org.LogPrefix)
				continue
			}
			if len(podServicePorts) != 0 {
				c.org.DB.Unscoped().Delete(&podServicePorts)
				log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_PORT_EN, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, podServicePorts), c.org.LogPrefix)
			}
		}
	}

	// 清理 PodGroupPorts
	var podGroupPortRefs []struct {
		ID           int `gorm:"column:id"`
		PodServiceID int `gorm:"column:pod_service_id"`
	}
	if err := c.org.DB.Model(&metadbmodel.PodGroupPort{}).
		Select("id, pod_service_id").
		Where(map[string]interface{}{"domain": domainLcuuid}).
		Find(&podGroupPortRefs).Error; err != nil {
		log.Errorf("failed to query pod group port refs: %s, domain lcuuid: %s", err.Error(), domainLcuuid, c.org.LogPrefix)
		return
	}

	dirtyPodGroupPortIDs := make([]int, 0)
	for _, ref := range podGroupPortRefs {
		if _, exists := podServiceIDSet[ref.PodServiceID]; !exists {
			dirtyPodGroupPortIDs = append(dirtyPodGroupPortIDs, ref.ID)
		}
	}

	if len(dirtyPodGroupPortIDs) > 0 {
		for i := 0; i < len(dirtyPodGroupPortIDs); i += c.cfg.MySQLBatchSize {
			end := i + c.cfg.MySQLBatchSize
			if end > len(dirtyPodGroupPortIDs) {
				end = len(dirtyPodGroupPortIDs)
			}

			var podGroupPorts []*metadbmodel.PodGroupPort
			if err := c.org.DB.Where("id IN ?", dirtyPodGroupPortIDs[i:end]).Find(&podGroupPorts).Error; err != nil {
				log.Errorf("failed to query pod group ports: %s, pod group port ids: %v", err.Error(), dirtyPodGroupPortIDs[i:end], c.org.LogPrefix)
				continue
			}
			if len(podGroupPorts) != 0 {
				c.org.DB.Unscoped().Delete(&podGroupPorts)
				log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, podGroupPorts), c.org.LogPrefix)
			}
		}
	}

	// 清理 VInterfaces
	var vifDevices []struct {
		ID       int `gorm:"column:id"`
		DeviceID int `gorm:"column:deviceid"`
	}
	if err := c.org.DB.Model(&metadbmodel.VInterface{}).
		Select("id, deviceid").
		Where(map[string]interface{}{"domain": domainLcuuid, "devicetype": ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE}).
		Find(&vifDevices).Error; err != nil {
		log.Errorf("failed to query vif devices: %s, domain lcuuid: %s", err.Error(), domainLcuuid, c.org.LogPrefix)
		return
	}

	dirtyVifDeviceIDSet := make(map[int]struct{})
	for _, vd := range vifDevices {
		if _, exists := podServiceIDSet[vd.DeviceID]; !exists {
			dirtyVifDeviceIDSet[vd.DeviceID] = struct{}{}
		}
	}

	dirtyVifDeviceIDs := make([]int, 0, len(dirtyVifDeviceIDSet))
	for deviceID := range dirtyVifDeviceIDSet {
		dirtyVifDeviceIDs = append(dirtyVifDeviceIDs, deviceID)
	}

	if len(dirtyVifDeviceIDs) > 0 {
		for i := 0; i < len(dirtyVifDeviceIDs); i += c.cfg.MySQLBatchSize {
			end := i + c.cfg.MySQLBatchSize
			if end > len(dirtyVifDeviceIDs) {
				end = len(dirtyVifDeviceIDs)
			}

			var vifs []*metadbmodel.VInterface
			if err := c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("devicetype = ? AND deviceid IN ?", ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE, dirtyVifDeviceIDs[i:end]).Find(&vifs).Error; err != nil {
				log.Errorf("failed to query vifs: %s, domain lcuuid: %s", err.Error(), domainLcuuid, c.org.LogPrefix)
				continue
			}
			if len(vifs) != 0 {
				c.org.DB.Unscoped().Delete(&vifs)
				log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, vifs), c.org.LogPrefix)

				c.fillStatsd(domainLcuuid, tagTypeDeviceIPConn, len(vifs))
			}
		}
	}
}

func (c *Cleaner) cleanPodGroupDirty(domainLcuuid string) {
	podGroupIDs := getIDs[metadbmodel.PodGroup](c.org.DB, domainLcuuid)
	if len(podGroupIDs) == 0 {
		return
	}

	podGroupIDSet := make(map[int]struct{}, len(podGroupIDs))
	for _, id := range podGroupIDs {
		podGroupIDSet[id] = struct{}{}
	}

	// 清理 PodGroupPorts
	var podGroupPortRefs []struct {
		ID         int `gorm:"column:id"`
		PodGroupID int `gorm:"column:pod_group_id"`
	}
	if err := c.org.DB.Model(&metadbmodel.PodGroupPort{}).
		Select("id, pod_group_id").
		Where(map[string]interface{}{"domain": domainLcuuid}).
		Find(&podGroupPortRefs).Error; err != nil {
		log.Errorf("failed to query pod group port refs: %s, domain lcuuid: %s", err.Error(), domainLcuuid, c.org.LogPrefix)
		return
	}

	dirtyPodGroupPortIDs := make([]int, 0)
	for _, ref := range podGroupPortRefs {
		if _, exists := podGroupIDSet[ref.PodGroupID]; !exists {
			dirtyPodGroupPortIDs = append(dirtyPodGroupPortIDs, ref.ID)
		}
	}

	if len(dirtyPodGroupPortIDs) > 0 {
		for i := 0; i < len(dirtyPodGroupPortIDs); i += c.cfg.MySQLBatchSize {
			end := i + c.cfg.MySQLBatchSize
			if end > len(dirtyPodGroupPortIDs) {
				end = len(dirtyPodGroupPortIDs)
			}

			var podGroupPorts []*metadbmodel.PodGroupPort
			if err := c.org.DB.Where("id IN ?", dirtyPodGroupPortIDs[i:end]).Find(&podGroupPorts).Error; err != nil {
				log.Errorf("failed to query pod group ports: %s, pod group port ids: %v", err.Error(), dirtyPodGroupPortIDs[i:end], c.org.LogPrefix)
				continue
			}
			if len(podGroupPorts) != 0 {
				c.org.DB.Unscoped().Delete(&podGroupPorts)
				log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN, ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, podGroupPorts), c.org.LogPrefix)
			}
		}
	}

	// 清理 Pods
	var podRefs []struct {
		ID         int `gorm:"column:id"`
		PodGroupID int `gorm:"column:pod_group_id"`
	}
	if err := c.org.DB.Model(&metadbmodel.Pod{}).
		Select("id, pod_group_id").
		Where(map[string]interface{}{"domain": domainLcuuid}).
		Find(&podRefs).Error; err != nil {
		log.Errorf("failed to query pod refs: %s, domain lcuuid: %s", err.Error(), domainLcuuid, c.org.LogPrefix)
		return
	}

	dirtyPodIDs := make([]int, 0)
	for _, ref := range podRefs {
		if _, exists := podGroupIDSet[ref.PodGroupID]; !exists {
			dirtyPodIDs = append(dirtyPodIDs, ref.ID)
		}
	}

	if len(dirtyPodIDs) > 0 {
		for i := 0; i < len(dirtyPodIDs); i += c.cfg.MySQLBatchSize {
			end := i + c.cfg.MySQLBatchSize
			if end > len(dirtyPodIDs) {
				end = len(dirtyPodIDs)
			}

			var pods []*metadbmodel.Pod
			if err := c.org.DB.Where("id IN ?", dirtyPodIDs[i:end]).Find(&pods).Error; err != nil {
				log.Errorf("failed to query pods: %s, pod ids: %v", err.Error(), dirtyPodIDs[i:end], c.org.LogPrefix)
				continue
			}
			if len(pods) != 0 {
				if err := c.org.DB.Unscoped().Delete(&pods).Error; err != nil {
					log.Errorf("failed to delete pods: %s, pod ids: %v", err.Error(), dirtyPodIDs[i:end], c.org.LogPrefix)
				} else {
					publishTagrecorder[*message.DeletedPods, message.DeletedPods, metadbmodel.Pod](c.org.DB, pods, ctrlrcommon.RESOURCE_TYPE_POD_EN, c.toolData)
				}
				log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_EN, ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, pods), c.org.LogPrefix)
			}
		}
	}

	// 清理 PodReplicaSets
	var podReplicaSetRefs []struct {
		ID         int `gorm:"column:id"`
		PodGroupID int `gorm:"column:pod_group_id"`
	}
	if err := c.org.DB.Model(&metadbmodel.PodReplicaSet{}).
		Select("id, pod_group_id").
		Where(map[string]interface{}{"domain": domainLcuuid}).
		Find(&podReplicaSetRefs).Error; err != nil {
		log.Errorf("failed to query pod replica set refs: %s, domain lcuuid: %s", err.Error(), domainLcuuid, c.org.LogPrefix)
		return
	}

	dirtyPodReplicaSetIDs := make([]int, 0)
	for _, ref := range podReplicaSetRefs {
		if _, exists := podGroupIDSet[ref.PodGroupID]; !exists {
			dirtyPodReplicaSetIDs = append(dirtyPodReplicaSetIDs, ref.ID)
		}
	}

	if len(dirtyPodReplicaSetIDs) > 0 {
		for i := 0; i < len(dirtyPodReplicaSetIDs); i += c.cfg.MySQLBatchSize {
			end := i + c.cfg.MySQLBatchSize
			if end > len(dirtyPodReplicaSetIDs) {
				end = len(dirtyPodReplicaSetIDs)
			}

			var podReplicaSets []*metadbmodel.PodReplicaSet
			if err := c.org.DB.Where("id IN ?", dirtyPodReplicaSetIDs[i:end]).Find(&podReplicaSets).Error; err != nil {
				log.Errorf("failed to query pod replica sets: %s, pod replica set ids: %v", err.Error(), dirtyPodReplicaSetIDs[i:end], c.org.LogPrefix)
				continue
			}
			if len(podReplicaSets) != 0 {
				c.org.DB.Unscoped().Delete(&podReplicaSets)
				log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, podReplicaSets), c.org.LogPrefix)
			}
		}
	}
}

func (c *Cleaner) cleanPodNodeDirty(domainLcuuid string) {
	podNodeIDs := getIDs[metadbmodel.PodNode](c.org.DB, domainLcuuid)
	if len(podNodeIDs) != 0 {
		var vifs []*metadbmodel.VInterface
		c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("devicetype = ? AND deviceid NOT IN ?", ctrlrcommon.VIF_DEVICE_TYPE_POD_NODE, podNodeIDs).Find(&vifs)
		if len(vifs) != 0 {
			c.org.DB.Unscoped().Delete(&vifs)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, vifs), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeDeviceIPConn, len(vifs))
		}

		var vmPodNodeConns []*metadbmodel.VMPodNodeConnection
		c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("pod_node_id NOT IN ?", podNodeIDs).Find(&vmPodNodeConns)
		if len(vmPodNodeConns) != 0 {
			c.org.DB.Unscoped().Delete(&vmPodNodeConns)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, vmPodNodeConns), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeCHostPodNodeConn, len(vmPodNodeConns))
		}

		var pods []*metadbmodel.Pod
		c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("pod_node_id != 0 AND pod_node_id NOT IN ?", podNodeIDs).Find(&pods)
		if len(pods) != 0 {
			if err := c.org.DB.Unscoped().Delete(&pods).Error; err != nil {
				log.Errorf("failed to delete pods: %s, pod node ids: %v", err.Error(), podNodeIDs, c.org.LogPrefix)
			} else {
				publishTagrecorder[*message.DeletedPods, message.DeletedPods, metadbmodel.Pod](c.org.DB, pods, ctrlrcommon.RESOURCE_TYPE_POD_EN, c.toolData)
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_EN, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, pods), c.org.LogPrefix)
		}
	}
}

func (c *Cleaner) cleanPodDirty(domainLcuuid string) {
	podIDs := getIDs[metadbmodel.Pod](c.org.DB, domainLcuuid)
	if len(podIDs) == 0 {
		return
	}

	var vifDevices []struct {
		ID       int `gorm:"column:id"`
		DeviceID int `gorm:"column:deviceid"`
	}
	if err := c.org.DB.Model(&metadbmodel.VInterface{}).
		Select("id, deviceid").
		Where(map[string]interface{}{"domain": domainLcuuid, "devicetype": ctrlrcommon.VIF_DEVICE_TYPE_POD}).
		Find(&vifDevices).Error; err != nil {
		log.Errorf("failed to query vif devices: %s, domain: %s", err.Error(), domainLcuuid, c.org.LogPrefix)
		return
	}

	if len(vifDevices) == 0 {
		return
	}

	// 找出所有不存在的 deviceids（不在 podIDs 中的）
	podIDSet := make(map[int]struct{}, len(podIDs))
	for _, id := range podIDs {
		podIDSet[id] = struct{}{}
	}

	dirtyDeviceIDSet := make(map[int]struct{})
	for _, vd := range vifDevices {
		if _, exists := podIDSet[vd.DeviceID]; !exists {
			dirtyDeviceIDSet[vd.DeviceID] = struct{}{}
		}
	}

	dirtyDeviceIDs := make([]int, 0, len(dirtyDeviceIDSet))
	for deviceID := range dirtyDeviceIDSet {
		dirtyDeviceIDs = append(dirtyDeviceIDs, deviceID)
	}

	// 使用脏数据的 deviceids 分批删除 vifs
	total := len(dirtyDeviceIDs)
	for i := 0; i < total; i += c.cfg.MySQLBatchSize {
		end := i + c.cfg.MySQLBatchSize
		if end > total {
			end = total
		}

		var vifs []*metadbmodel.VInterface
		if err := c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("devicetype = ? AND deviceid IN ?", ctrlrcommon.VIF_DEVICE_TYPE_POD, dirtyDeviceIDs[i:end]).Find(&vifs).Error; err != nil {
			log.Errorf("failed to query vifs: %s, dirty device ids: %v", err.Error(), dirtyDeviceIDs[i:end], c.org.LogPrefix)
			continue
		}
		if len(vifs) != 0 {
			if err := c.org.DB.Unscoped().Delete(&vifs).Error; err != nil {
				log.Errorf("failed to delete vifs: %s, dirty device ids: %v", err.Error(), dirtyDeviceIDs[i:end], c.org.LogPrefix)
				continue
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_POD_EN, vifs), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeDeviceIPConn, len(vifs))
		}
	}
}

func (c *Cleaner) cleanPodClusterDirty(domainLcuuid string) {
	podClusterIDs := getIDs[metadbmodel.PodCluster](c.org.DB, domainLcuuid)
	if len(podClusterIDs) != 0 {
		var pods []*metadbmodel.Pod
		c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("pod_cluster_id NOT IN ?", podClusterIDs).Find(&pods)
		if len(pods) != 0 {
			if err := c.org.DB.Unscoped().Delete(&pods).Error; err != nil {
				log.Errorf("failed to delete pods: %s, pod cluster ids: %v", err.Error(), podClusterIDs, c.org.LogPrefix)
			} else {
				publishTagrecorder[*message.DeletedPods, message.DeletedPods, metadbmodel.Pod](c.org.DB, pods, ctrlrcommon.RESOURCE_TYPE_POD_EN, c.toolData)
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_EN, ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, pods), c.org.LogPrefix)
		}
		var podReplicasets []*metadbmodel.PodReplicaSet
		c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("pod_cluster_id NOT IN ?", podClusterIDs).Find(&podReplicasets)
		if len(podReplicasets) != 0 {
			if err := c.org.DB.Unscoped().Delete(&podReplicasets).Error; err != nil {
				log.Errorf("failed to delete pod replicasets: %s, pod cluster ids: %v", err.Error(), podClusterIDs, c.org.LogPrefix)
			} else {
				publishTagrecorder[*message.DeletedPodReplicaSets, message.DeletedPodReplicaSets, metadbmodel.PodReplicaSet](c.org.DB, podReplicasets, ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, c.toolData)
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, podReplicasets), c.org.LogPrefix)
		}
		var podGroups []*metadbmodel.PodGroup
		c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("pod_cluster_id NOT IN ?", podClusterIDs).Find(&podGroups)
		if len(podGroups) != 0 {
			if err := c.org.DB.Unscoped().Delete(&podGroups).Error; err != nil {
				log.Errorf("failed to delete pod groups: %s, pod cluster ids: %v", err.Error(), podClusterIDs, c.org.LogPrefix)
			} else {
				publishTagrecorder[*message.DeletedPodGroups, message.DeletedPodGroups, metadbmodel.PodGroup](c.org.DB, podGroups, ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, c.toolData)
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, podGroups), c.org.LogPrefix)
		}
		var podServices []*metadbmodel.PodService
		c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("pod_cluster_id NOT IN ?", podClusterIDs).Find(&podServices)
		if len(podServices) != 0 {
			if err := c.org.DB.Unscoped().Delete(&podServices).Error; err != nil {
				log.Errorf("failed to delete pod services: %s, pod cluster ids: %v", err.Error(), podClusterIDs, c.org.LogPrefix)
			} else {
				publishTagrecorder[*message.DeletedPodServices, message.DeletedPodServices, metadbmodel.PodService](c.org.DB, podServices, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, c.toolData)
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, podServices), c.org.LogPrefix)
		}
		var podIngresses []*metadbmodel.PodIngress
		c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("pod_cluster_id NOT IN ?", podClusterIDs).Find(&podIngresses)
		if len(podIngresses) != 0 {
			if err := c.org.DB.Unscoped().Delete(&podIngresses).Error; err != nil {
				log.Errorf("failed to delete pod ingresses: %s, pod cluster ids: %v", err.Error(), podClusterIDs, c.org.LogPrefix)
			} else {
				publishTagrecorder[*message.DeletedPodIngresses, message.DeletedPodIngresses, metadbmodel.PodIngress](c.org.DB, podIngresses, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, c.toolData)
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, podIngresses), c.org.LogPrefix)
		}
		var podNamespaces []*metadbmodel.PodNamespace
		c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("pod_cluster_id NOT IN ?", podClusterIDs).Find(&podNamespaces)
		if len(podNamespaces) != 0 {
			if err := c.org.DB.Unscoped().Delete(&podNamespaces).Error; err != nil {
				log.Errorf("failed to delete pod namespaces: %s, pod cluster ids: %v", err.Error(), podClusterIDs, c.org.LogPrefix)
			} else {
				publishTagrecorder[*message.DeletedPodNamespaces, message.DeletedPodNamespaces, metadbmodel.PodNamespace](c.org.DB, podNamespaces, ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, c.toolData)
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, podNamespaces), c.org.LogPrefix)
		}
		var podNodes []*metadbmodel.PodNode
		c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("pod_cluster_id NOT IN ?", podClusterIDs).Find(&podNodes)
		if len(podNodes) != 0 {
			if err := c.org.DB.Unscoped().Delete(&podNodes).Error; err != nil {
				log.Errorf("failed to delete pod nodes: %s, pod cluster ids: %v", err.Error(), podClusterIDs, c.org.LogPrefix)
			} else {
				publishTagrecorder[*message.DeletedPodNodes, message.DeletedPodNodes, metadbmodel.PodNode](c.org.DB, podNodes, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, c.toolData)
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, podNodes), c.org.LogPrefix)
		}
	}
}

func (c *Cleaner) cleanPodNamespaceDirty(domainLcuuid string) {
	podNamespaceIDs := getIDs[metadbmodel.PodNamespace](c.org.DB, domainLcuuid)
	if len(podNamespaceIDs) != 0 {
		var pods []*metadbmodel.Pod
		c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("pod_namespace_id NOT IN ?", podNamespaceIDs).Find(&pods)
		if len(pods) != 0 {
			if err := c.org.DB.Unscoped().Delete(&pods).Error; err != nil {
				log.Errorf("failed to delete pods: %s, pod namespace ids: %v", err.Error(), podNamespaceIDs, c.org.LogPrefix)
			} else {
				publishTagrecorder[*message.DeletedPods, message.DeletedPods, metadbmodel.Pod](c.org.DB, pods, ctrlrcommon.RESOURCE_TYPE_POD_EN, c.toolData)
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_EN, ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, pods), c.org.LogPrefix)
		}
		var podGroups []*metadbmodel.PodGroup
		c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("pod_namespace_id NOT IN ?", podNamespaceIDs).Find(&podGroups)
		if len(podGroups) != 0 {
			if err := c.org.DB.Unscoped().Delete(&podGroups).Error; err != nil {
				log.Errorf("failed to delete pod groups: %s, pod namespace ids: %v", err.Error(), podNamespaceIDs, c.org.LogPrefix)
			} else {
				publishTagrecorder[*message.DeletedPodGroups, message.DeletedPodGroups, metadbmodel.PodGroup](c.org.DB, podGroups, ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, c.toolData)
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, podGroups), c.org.LogPrefix)
		}
		var podReplicasets []*metadbmodel.PodReplicaSet
		c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("pod_namespace_id NOT IN ?", podNamespaceIDs).Find(&podReplicasets)
		if len(podReplicasets) != 0 {
			if err := c.org.DB.Unscoped().Delete(&podReplicasets).Error; err != nil {
				log.Errorf("failed to delete pod replicasets: %s, pod namespace ids: %v", err.Error(), podNamespaceIDs, c.org.LogPrefix)
			} else {
				publishTagrecorder[*message.DeletedPodReplicaSets, message.DeletedPodReplicaSets, metadbmodel.PodReplicaSet](c.org.DB, podReplicasets, ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, c.toolData)
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, podReplicasets), c.org.LogPrefix)
		}
		var podIngresses []*metadbmodel.PodIngress
		c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("pod_namespace_id NOT IN ?", podNamespaceIDs).Find(&podIngresses)
		if len(podIngresses) != 0 {
			if err := c.org.DB.Unscoped().Delete(&podIngresses).Error; err != nil {
				log.Errorf("failed to delete pod ingresses: %s, pod namespace ids: %v", err.Error(), podNamespaceIDs, c.org.LogPrefix)
			} else {
				publishTagrecorder[*message.DeletedPodIngresses, message.DeletedPodIngresses, metadbmodel.PodIngress](c.org.DB, podIngresses, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, c.toolData)
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, podIngresses), c.org.LogPrefix)
		}
		var podServices []*metadbmodel.PodService
		c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
			Where("pod_namespace_id NOT IN ?", podNamespaceIDs).Find(&podServices)
		if len(podServices) != 0 {
			if err := c.org.DB.Unscoped().Delete(&podServices).Error; err != nil {
				log.Errorf("failed to delete pod services: %s, pod namespace ids: %v", err.Error(), podNamespaceIDs, c.org.LogPrefix)
			} else {
				publishTagrecorder[*message.DeletedPodServices, message.DeletedPodServices, metadbmodel.PodService](c.org.DB, podServices, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, c.toolData)
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, podServices), c.org.LogPrefix)
		}
	}
}

func (c *Cleaner) cleanVInterfaceDirty(domainLcuuid string) {
	vifIDs := getIDs[metadbmodel.VInterface](c.org.DB, domainLcuuid)
	if len(vifIDs) == 0 {
		return
	}

	vifIDSet := make(map[int]struct{}, len(vifIDs))
	for _, id := range vifIDs {
		vifIDSet[id] = struct{}{}
	}

	// 清理 LANIPs
	var lanIPRefs []struct {
		ID    int `gorm:"column:id"`
		VifID int `gorm:"column:vifid"`
	}
	if err := c.org.DB.Model(&metadbmodel.LANIP{}).
		Select("id, vifid").
		Where(map[string]interface{}{"domain": domainLcuuid}).
		Find(&lanIPRefs).Error; err != nil {
		log.Errorf("failed to query lan ip refs: %s, domain lcuuid: %s", err.Error(), domainLcuuid, c.org.LogPrefix)
		return
	}

	dirtyLANIPIDs := make([]int, 0)
	for _, ref := range lanIPRefs {
		if _, exists := vifIDSet[ref.VifID]; !exists {
			dirtyLANIPIDs = append(dirtyLANIPIDs, ref.ID)
		}
	}

	if len(dirtyLANIPIDs) > 0 {
		for i := 0; i < len(dirtyLANIPIDs); i += c.cfg.MySQLBatchSize {
			end := i + c.cfg.MySQLBatchSize
			if end > len(dirtyLANIPIDs) {
				end = len(dirtyLANIPIDs)
			}

			var lanIPs []*metadbmodel.LANIP
			if err := c.org.DB.Where("id IN ?", dirtyLANIPIDs[i:end]).Find(&lanIPs).Error; err != nil {
				log.Errorf("failed to query lan ips: %s, lan ip ids: %v", err.Error(), dirtyLANIPIDs[i:end], c.org.LogPrefix)
				continue
			}
			if len(lanIPs) != 0 {
				if err := c.org.DB.Unscoped().Delete(&lanIPs).Error; err != nil {
					log.Errorf("failed to delete lan ips: %s, lan ip ids: %v", err.Error(), dirtyLANIPIDs[i:end], c.org.LogPrefix)
					continue
				}
				log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN, ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, lanIPs), c.org.LogPrefix)
			}
		}
	}

	// 清理 WANIPs
	var wanIPRefs []struct {
		ID    int `gorm:"column:id"`
		VifID int `gorm:"column:vifid"`
	}
	if err := c.org.DB.Model(&metadbmodel.WANIP{}).
		Select("id, vifid").
		Where(map[string]interface{}{"domain": domainLcuuid}).
		Find(&wanIPRefs).Error; err != nil {
		log.Errorf("failed to query wan ip refs: %s, domain lcuuid: %s", err.Error(), domainLcuuid, c.org.LogPrefix)
		return
	}

	dirtyWANIPIDs := make([]int, 0)
	for _, ref := range wanIPRefs {
		if _, exists := vifIDSet[ref.VifID]; !exists {
			dirtyWANIPIDs = append(dirtyWANIPIDs, ref.ID)
		}
	}

	if len(dirtyWANIPIDs) > 0 {
		for i := 0; i < len(dirtyWANIPIDs); i += c.cfg.MySQLBatchSize {
			end := i + c.cfg.MySQLBatchSize
			if end > len(dirtyWANIPIDs) {
				end = len(dirtyWANIPIDs)
			}

			var wanIPs []*metadbmodel.WANIP
			if err := c.org.DB.Where("id IN ?", dirtyWANIPIDs[i:end]).Find(&wanIPs).Error; err != nil {
				log.Errorf("failed to query wan ips: %s, wan ip ids: %v", err.Error(), dirtyWANIPIDs[i:end], c.org.LogPrefix)
				continue
			}
			if len(wanIPs) != 0 {
				if err := c.org.DB.Unscoped().Delete(&wanIPs).Error; err != nil {
					log.Errorf("failed to delete wan ips: %s, wan ip ids: %v", err.Error(), dirtyWANIPIDs[i:end], c.org.LogPrefix)
					continue
				}
				log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN, ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, wanIPs), c.org.LogPrefix)
			}
		}
	}
}
