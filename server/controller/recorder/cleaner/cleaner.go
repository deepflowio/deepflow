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
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/exp/slices"

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/config"
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
	pageDeleteExpiredAndPublish[metadbmodel.Region](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_REGION_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[metadbmodel.AZ](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_AZ_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[metadbmodel.Host](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_HOST_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[metadbmodel.VM](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_VM_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[metadbmodel.VPC](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_VPC_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[metadbmodel.Network](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[metadbmodel.VRouter](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[metadbmodel.DHCPPort](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[metadbmodel.NATGateway](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[metadbmodel.LB](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_LB_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[metadbmodel.LBListener](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_LB_LISTENER_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[metadbmodel.CEN](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_CEN_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[metadbmodel.PeerConnection](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_PEER_CONNECTION_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[metadbmodel.RDSInstance](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[metadbmodel.RedisInstance](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[metadbmodel.PodCluster](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[metadbmodel.PodNode](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[metadbmodel.PodNamespace](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[metadbmodel.PodIngress](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[metadbmodel.PodService](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[metadbmodel.PodGroup](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[metadbmodel.PodReplicaSet](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[metadbmodel.Pod](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[metadbmodel.Process](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_PROCESS_EN, c.toolData, c.cfg.MySQLBatchSize)
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
		c.cleanPodIngressDirty(domain.Lcuuid)
		c.cleanPodServiceDirty(domain.Lcuuid)
		c.cleanPodNodeDirty(domain.Lcuuid)
		c.cleanPodGroupDirty(domain.Lcuuid)
		c.cleanPodDirty(domain.Lcuuid)
		c.cleanVInterfaceDirty(domain.Lcuuid)
	}
	log.Info("clean dirty data completed", c.org.LogPrefix)
}

func (c *Cleaner) cleanHostDirty(domainLcuuid string) {
	deviceIDs := getIDs[metadbmodel.Host](c.org.DB, domainLcuuid)
	if len(deviceIDs) != 0 {
		vifs, _ := WhereFindPtr[metadbmodel.VInterface](
			c.org.DB,
			"domain = ? AND devicetype = ? AND deviceid NOT IN ?", domainLcuuid, ctrlrcommon.VIF_DEVICE_TYPE_HOST, deviceIDs,
		)
		if len(vifs) != 0 {
			c.org.DB.Delete(&vifs)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_HOST_EN, vifs), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeDeviceIPConn, len(vifs))
		}
	}
}

func (c *Cleaner) cleanVMDirty(domainLcuuid string) {
	vmIDs := getIDs[metadbmodel.VM](c.org.DB, domainLcuuid)
	if len(vmIDs) != 0 {
		vifs, _ := WhereFindPtr[metadbmodel.VInterface](
			c.org.DB,
			"domain = ? AND devicetype = ? AND deviceid NOT IN ?", domainLcuuid, ctrlrcommon.VIF_DEVICE_TYPE_VM, vmIDs,
		)
		if len(vifs) != 0 {
			c.org.DB.Delete(&vifs)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_VM_EN, vifs), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeDeviceIPConn, len(vifs))
		}

		vmPodNodeConns, _ := WhereFindPtr[metadbmodel.VMPodNodeConnection](
			c.org.DB,
			"domain = ? AND vm_id NOT IN ?", domainLcuuid, vmIDs,
		)
		if len(vmPodNodeConns) != 0 {
			c.org.DB.Delete(&vmPodNodeConns)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, ctrlrcommon.RESOURCE_TYPE_VM_EN, vmPodNodeConns), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeCHostPodNodeConn, len(vmPodNodeConns))
		}
	}
}

func (c *Cleaner) cleanNetworkDirty(domainLcuuid string) {
	networkIDs := getIDs[metadbmodel.Network](c.org.DB, domainLcuuid)
	if len(networkIDs) != 0 {
		subnets, _ := WhereFindPtr[metadbmodel.Subnet](
			c.org.DB,
			"domain = ? AND vl2id NOT IN ?", domainLcuuid, networkIDs,
		)
		if len(subnets) != 0 {
			c.org.DB.Delete(&subnets)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_SUBNET_EN, ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, subnets), c.org.LogPrefix)
		}
	}
}

func (c *Cleaner) cleanVRouterDirty(domainLcuuid string) {
	vrouterIDs := getIDs[metadbmodel.VRouter](c.org.DB, domainLcuuid)
	if len(vrouterIDs) != 0 {
		rts, _ := WhereFindPtr[metadbmodel.RoutingTable](
			c.org.DB,
			"domain = ? AND vnet_id NOT IN ?", domainLcuuid, vrouterIDs,
		)
		if len(rts) != 0 {
			c.org.DB.Delete(&rts)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_ROUTING_TABLE_EN, ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, rts), c.org.LogPrefix)
		}

		vifs, _ := WhereFindPtr[metadbmodel.VInterface](
			c.org.DB,
			"domain = ? AND devicetype = ? AND deviceid NOT IN ?", domainLcuuid, ctrlrcommon.VIF_DEVICE_TYPE_VROUTER, vrouterIDs,
		)
		if len(vifs) != 0 {
			c.org.DB.Delete(&vifs)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, vifs), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeDeviceIPConn, len(vifs))
		}
	}
}

func (c *Cleaner) cleanPodIngressDirty(domainLcuuid string) {
	podIngressIDs := getIDs[metadbmodel.PodIngress](c.org.DB, domainLcuuid)
	if len(podIngressIDs) != 0 {
		podIngressRules, _ := WhereFindPtr[metadbmodel.PodIngressRule](
			c.org.DB,
			"domain = ? AND pod_ingress_id NOT IN ?", domainLcuuid, podIngressIDs,
		)
		if len(podIngressRules) != 0 {
			c.org.DB.Delete(&podIngressRules)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, podIngressRules), c.org.LogPrefix)
		}

		podIngressRuleBkds, _ := WhereFindPtr[metadbmodel.PodIngressRuleBackend](
			c.org.DB,
			"domain = ? AND pod_ingress_id NOT IN ?", domainLcuuid, podIngressIDs,
		)
		if len(podIngressRuleBkds) != 0 {
			c.org.DB.Delete(&podIngressRuleBkds)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, podIngressRuleBkds), c.org.LogPrefix)
		}
	}
}

func (c *Cleaner) cleanPodServiceDirty(domainLcuuid string) {
	podServiceIDs := getIDs[metadbmodel.PodService](c.org.DB, domainLcuuid)
	if len(podServiceIDs) != 0 {
		podServicePorts, _ := WhereFindPtr[metadbmodel.PodServicePort](
			c.org.DB,
			"domain = ? AND pod_service_id NOT IN ?", domainLcuuid, podServiceIDs,
		)
		if len(podServicePorts) != 0 {
			c.org.DB.Delete(&podServicePorts)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_PORT_EN, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, podServicePorts), c.org.LogPrefix)
		}

		podGroupPorts, _ := WhereFindPtr[metadbmodel.PodGroupPort](
			c.org.DB,
			"domain = ? AND pod_service_id NOT IN ?", domainLcuuid, podServiceIDs,
		)
		if len(podGroupPorts) != 0 {
			c.org.DB.Delete(&podGroupPorts)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, podGroupPorts), c.org.LogPrefix)
		}

		vifs, _ := WhereFindPtr[metadbmodel.VInterface](
			c.org.DB,
			"domain = ? AND devicetype = ? AND deviceid NOT IN ?", domainLcuuid, ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE, podServiceIDs,
		)
		if len(vifs) != 0 {
			c.org.DB.Delete(&vifs)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, vifs), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeDeviceIPConn, len(vifs))
		}
	}
}

func (c *Cleaner) cleanPodGroupDirty(domainLcuuid string) {
	podGroupIDs := getIDs[metadbmodel.PodGroup](c.org.DB, domainLcuuid)
	if len(podGroupIDs) != 0 {
		podGroupPorts, _ := WhereFindPtr[metadbmodel.PodGroupPort](
			c.org.DB,
			"domain = ? AND pod_group_id NOT IN ?", domainLcuuid, podGroupIDs,
		)
		if len(podGroupPorts) != 0 {
			c.org.DB.Delete(&podGroupPorts)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN, ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, podGroupPorts), c.org.LogPrefix)
		}

		pods, _ := WhereFindPtr[metadbmodel.Pod](
			c.org.DB,
			"domain = ? AND pod_group_id NOT IN ?", domainLcuuid, podGroupIDs,
		)
		if len(pods) != 0 {
			c.org.DB.Delete(&pods)
			publishTagrecorder(c.org.DB, pods, ctrlrcommon.RESOURCE_TYPE_POD_EN, c.toolData)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_EN, ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, pods), c.org.LogPrefix)
		}
	}
}

func (c *Cleaner) cleanPodNodeDirty(domainLcuuid string) {
	podNodeIDs := getIDs[metadbmodel.PodNode](c.org.DB, domainLcuuid)
	if len(podNodeIDs) != 0 {
		vifs, _ := WhereFindPtr[metadbmodel.VInterface](
			c.org.DB,
			"domain = ? AND devicetype = ? AND deviceid NOT IN ?", domainLcuuid, ctrlrcommon.VIF_DEVICE_TYPE_POD_NODE, podNodeIDs,
		)
		if len(vifs) != 0 {
			c.org.DB.Delete(&vifs)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, vifs), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeDeviceIPConn, len(vifs))
		}

		vmPodNodeConns, _ := WhereFindPtr[metadbmodel.VMPodNodeConnection](
			c.org.DB,
			"domain = ? AND pod_node_id NOT IN ?", domainLcuuid, podNodeIDs,
		)
		if len(vmPodNodeConns) != 0 {
			c.org.DB.Delete(&vmPodNodeConns)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, vmPodNodeConns), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeCHostPodNodeConn, len(vmPodNodeConns))
		}

		pods, _ := WhereFindPtr[metadbmodel.Pod](
			c.org.DB,
			"domain = ? AND pod_node_id != 0 AND pod_node_id NOT IN ?", domainLcuuid, podNodeIDs,
		)
		if len(pods) != 0 {
			c.org.DB.Delete(&pods)
			publishTagrecorder(c.org.DB, pods, ctrlrcommon.RESOURCE_TYPE_POD_EN, c.toolData)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_EN, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, pods), c.org.LogPrefix)
		}
	}
}

func (c *Cleaner) cleanPodDirty(domainLcuuid string) {
	podIDs := getIDs[metadbmodel.Pod](c.org.DB, domainLcuuid)
	if len(podIDs) != 0 {
		vifs, _ := WhereFindPtr[metadbmodel.VInterface](
			c.org.DB,
			"domain = ? AND devicetype = ? AND deviceid NOT IN ?", domainLcuuid, ctrlrcommon.VIF_DEVICE_TYPE_POD, podIDs,
		)
		if len(vifs) != 0 {
			c.org.DB.Delete(&vifs)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_POD_EN, vifs), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeDeviceIPConn, len(vifs))
		}
	}
}

func (c *Cleaner) cleanVInterfaceDirty(domainLcuuid string) {
	vifIDs := getIDs[metadbmodel.VInterface](c.org.DB, domainLcuuid)
	if len(vifIDs) != 0 {
		lanIPs, _ := WhereFindPtr[metadbmodel.LANIP](
			c.org.DB,
			"domain = ? AND vifid NOT IN ?", domainLcuuid, vifIDs,
		)
		if len(lanIPs) != 0 {
			c.org.DB.Delete(&lanIPs)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN, ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, lanIPs), c.org.LogPrefix)
		}

		wanIPs, _ := WhereFindPtr[metadbmodel.WANIP](
			c.org.DB,
			"domain = ? AND vifid NOT IN ?", domainLcuuid, vifIDs,
		)
		if len(wanIPs) != 0 {
			c.org.DB.Delete(&wanIPs)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN, ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, wanIPs), c.org.LogPrefix)
		}
	}
}
