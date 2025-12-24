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
	metadbquery "github.com/deepflowio/deepflow/server/controller/db/metadb/query"
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

	batchSize int

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
		batchSize:            int(org.DB.Config.BatchSize1),
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
	pageDeleteExpiredAndPublish[*message.DeletedRegions, message.DeletedRegions, metadbmodel.Region](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_REGION_EN, c.toolData)
	pageDeleteExpiredAndPublish[*message.DeletedAZs, message.DeletedAZs, metadbmodel.AZ](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_AZ_EN, c.toolData)
	pageDeleteExpiredAndPublish[*message.DeletedHosts, message.DeletedHosts, metadbmodel.Host](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_HOST_EN, c.toolData)
	pageDeleteExpiredAndPublish[*message.DeletedVMs, message.DeletedVMs, metadbmodel.VM](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_VM_EN, c.toolData)
	pageDeleteExpiredAndPublish[*message.DeletedVPCs, message.DeletedVPCs, metadbmodel.VPC](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_VPC_EN, c.toolData)
	pageDeleteExpiredAndPublish[*message.DeletedNetworks, message.DeletedNetworks, metadbmodel.Network](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, c.toolData)
	pageDeleteExpiredAndPublish[*message.DeletedVRouters, message.DeletedVRouters, metadbmodel.VRouter](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, c.toolData)
	pageDeleteExpiredAndPublish[*message.DeletedDHCPPorts, message.DeletedDHCPPorts, metadbmodel.DHCPPort](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN, c.toolData)
	pageDeleteExpiredAndPublish[*message.DeletedNATGateways, message.DeletedNATGateways, metadbmodel.NATGateway](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN, c.toolData)
	pageDeleteExpiredAndPublish[*message.DeletedLBs, message.DeletedLBs, metadbmodel.LB](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_LB_EN, c.toolData)
	pageDeleteExpiredAndPublish[*message.DeletedLBListeners, message.DeletedLBListeners, metadbmodel.LBListener](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_LB_LISTENER_EN, c.toolData)
	pageDeleteExpiredAndPublish[*message.DeletedCENs, message.DeletedCENs, metadbmodel.CEN](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_CEN_EN, c.toolData)
	pageDeleteExpiredAndPublish[*message.DeletedPeerConnections, message.DeletedPeerConnections, metadbmodel.PeerConnection](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_PEER_CONNECTION_EN, c.toolData)
	pageDeleteExpiredAndPublish[*message.DeletedRDSInstances, message.DeletedRDSInstances, metadbmodel.RDSInstance](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN, c.toolData)
	pageDeleteExpiredAndPublish[*message.DeletedRedisInstances, message.DeletedRedisInstances, metadbmodel.RedisInstance](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN, c.toolData)
	pageDeleteExpiredAndPublish[*message.DeletedPodClusters, message.DeletedPodClusters, metadbmodel.PodCluster](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, c.toolData)
	pageDeleteExpiredAndPublish[*message.DeletedPodNodes, message.DeletedPodNodes, metadbmodel.PodNode](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, c.toolData)
	pageDeleteExpiredAndPublish[*message.DeletedPodNamespaces, message.DeletedPodNamespaces, metadbmodel.PodNamespace](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, c.toolData)
	pageDeleteExpiredAndPublish[*message.DeletedPodIngresses, message.DeletedPodIngresses, metadbmodel.PodIngress](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, c.toolData)
	pageDeleteExpiredAndPublish[*message.DeletedPodServices, message.DeletedPodServices, metadbmodel.PodService](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, c.toolData)
	pageDeleteExpiredAndPublish[*message.DeletedPodGroups, message.DeletedPodGroups, metadbmodel.PodGroup](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, c.toolData)
	pageDeleteExpiredAndPublish[*message.DeletedPodReplicaSets, message.DeletedPodReplicaSets, metadbmodel.PodReplicaSet](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, c.toolData)
	pageDeleteExpiredAndPublish[*message.DeletedPods, message.DeletedPods, metadbmodel.Pod](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_EN, c.toolData)
	pageDeleteExpiredAndPublish[*message.DeletedProcesses, message.DeletedProcesses, metadbmodel.Process](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_PROCESS_EN, c.toolData)
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
		vifs, err := metadbquery.FindPage[metadbmodel.VInterface](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("devicetype = ? AND deviceid NOT IN ?", ctrlrcommon.VIF_DEVICE_TYPE_HOST, deviceIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get vinterface: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(vifs) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.VInterface](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				vifs,
			)
			if err != nil {
				log.Errorf("failed to delete vinterface: %s", err.Error(), c.org.LogPrefix)
				return
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_HOST_EN, vifs), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeDeviceIPConn, len(vifs))
		}
	}
}

func (c *Cleaner) cleanVMDirty(domainLcuuid string) {
	vmIDs := getIDs[metadbmodel.VM](c.org.DB, domainLcuuid)
	if len(vmIDs) != 0 {
		vifs, err := metadbquery.FindPage[metadbmodel.VInterface](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("devicetype = ? AND deviceid NOT IN ?", ctrlrcommon.VIF_DEVICE_TYPE_VM, vmIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get vinterface: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(vifs) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.VInterface](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				vifs,
			)
			if err != nil {
				log.Errorf("failed to delete vinterface: %s", err.Error(), c.org.LogPrefix)
				return
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_VM_EN, vifs), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeDeviceIPConn, len(vifs))
		}

		vmPodNodeConns, err := metadbquery.FindPage[metadbmodel.VMPodNodeConnection](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("vm_id NOT IN ?", vmIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get vm pod node connection: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(vmPodNodeConns) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.VMPodNodeConnection](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				vmPodNodeConns,
			)
			if err != nil {
				log.Errorf("failed to delete vm pod node connection: %s", err.Error(), c.org.LogPrefix)
				return
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, ctrlrcommon.RESOURCE_TYPE_VM_EN, vmPodNodeConns), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeCHostPodNodeConn, len(vmPodNodeConns))
		}
	}
}

func (c *Cleaner) cleanNetworkDirty(domainLcuuid string) {
	networkIDs := getIDs[metadbmodel.Network](c.org.DB, domainLcuuid)
	if len(networkIDs) != 0 {
		subnets, err := metadbquery.FindPage[metadbmodel.Subnet](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("vl2id NOT IN ?", networkIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get subnet: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(subnets) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.Subnet](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				subnets,
			)
			if err != nil {
				log.Errorf("failed to delete subnet: %s", err.Error(), c.org.LogPrefix)
				return
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_SUBNET_EN, ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, subnets), c.org.LogPrefix)
		}
	}
}

func (c *Cleaner) cleanVRouterDirty(domainLcuuid string) {
	vrouterIDs := getIDs[metadbmodel.VRouter](c.org.DB, domainLcuuid)
	if len(vrouterIDs) != 0 {
		rts, err := metadbquery.FindPage[metadbmodel.RoutingTable](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("vnet_id NOT IN ?", vrouterIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get routing table: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(rts) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.RoutingTable](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				rts,
			)
			if err != nil {
				log.Errorf("failed to delete routing table: %s", err.Error(), c.org.LogPrefix)
				return
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_ROUTING_TABLE_EN, ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, rts), c.org.LogPrefix)
		}

		vifs, err := metadbquery.FindPage[metadbmodel.VInterface](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("devicetype = ? AND deviceid NOT IN ?", ctrlrcommon.VIF_DEVICE_TYPE_VROUTER, vrouterIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get vinterface: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(vifs) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.VInterface](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				vifs,
			)
			if err != nil {
				log.Errorf("failed to delete vinterface: %s", err.Error(), c.org.LogPrefix)
				return
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, vifs), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeDeviceIPConn, len(vifs))
		}
	}
}

func (c *Cleaner) cleanPodIngressDirty(domainLcuuid string) {
	podIngressIDs := getIDs[metadbmodel.PodIngress](c.org.DB, domainLcuuid)
	if len(podIngressIDs) != 0 {
		podIngressRules, err := metadbquery.FindPage[metadbmodel.PodIngressRule](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("pod_ingress_id NOT IN ?", podIngressIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get pod ingress rule: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(podIngressRules) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.PodIngressRule](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				podIngressRules,
			)
			if err != nil {
				log.Errorf("failed to delete pod ingress rule: %s", err.Error(), c.org.LogPrefix)
				return
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, podIngressRules), c.org.LogPrefix)
		}

		podIngressRuleBkds, err := metadbquery.FindPage[metadbmodel.PodIngressRuleBackend](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("pod_ingress_id NOT IN ?", podIngressIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get pod ingress rule backend: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(podIngressRuleBkds) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.PodIngressRuleBackend](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				podIngressRuleBkds,
			)
			if err != nil {
				log.Errorf("failed to delete pod ingress rule backend: %s", err.Error(), c.org.LogPrefix)
				return
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, podIngressRuleBkds), c.org.LogPrefix)
		}

		podServices, err := metadbquery.FindPage[metadbmodel.PodService](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("pod_ingress_id NOT IN ?", podIngressIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get pod service: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(podServices) != 0 {
			if err := metadbquery.DeletePageData[metadbmodel.PodService](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				podServices,
			); err != nil {
				log.Errorf("failed to delete pod service: %s", err.Error(), c.org.LogPrefix)
				return
			}
			pageDeleteAndPublish[*message.DeletedPodServices, message.DeletedPodServices, metadbmodel.PodService](c.org.DB, podServices, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, c.toolData)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, podServices), c.org.LogPrefix)
		}
	}
}

func (c *Cleaner) cleanPodServiceDirty(domainLcuuid string) {
	podServiceIDs := getIDs[metadbmodel.PodService](c.org.DB, domainLcuuid)
	if len(podServiceIDs) != 0 {
		podServicePorts, err := metadbquery.FindPage[metadbmodel.PodServicePort](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("pod_service_id NOT IN ?", podServiceIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get pod service port: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(podServicePorts) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.PodServicePort](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				podServicePorts,
			)
			if err != nil {
				log.Errorf("failed to delete pod service port: %s", err.Error(), c.org.LogPrefix)
				return
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_PORT_EN, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, podServicePorts), c.org.LogPrefix)
		}

		podGroupPorts, err := metadbquery.FindPage[metadbmodel.PodGroupPort](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("pod_service_id NOT IN ?", podServiceIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get pod group port: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(podGroupPorts) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.PodGroupPort](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				podGroupPorts,
			)
			if err != nil {
				log.Errorf("failed to delete pod group port: %s", err.Error(), c.org.LogPrefix)
				return
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, podGroupPorts), c.org.LogPrefix)
		}

		vifs, err := metadbquery.FindPage[metadbmodel.VInterface](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("devicetype = ? AND deviceid NOT IN ?", ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE, podServiceIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get vinterface: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(vifs) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.VInterface](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				vifs,
			)
			if err != nil {
				log.Errorf("failed to delete vinterface: %s", err.Error(), c.org.LogPrefix)
				return
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, vifs), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeDeviceIPConn, len(vifs))
		}
	}
}

func (c *Cleaner) cleanPodGroupDirty(domainLcuuid string) {
	podGroupIDs := getIDs[metadbmodel.PodGroup](c.org.DB, domainLcuuid)
	if len(podGroupIDs) != 0 {
		podGroupPorts, err := metadbquery.FindPage[metadbmodel.PodGroupPort](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("pod_group_id NOT IN ?", podGroupIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get pod group port: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(podGroupPorts) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.PodGroupPort](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				podGroupPorts,
			)
			if err != nil {
				log.Errorf("failed to delete pod group port: %s", err.Error(), c.org.LogPrefix)
				return
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN, ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, podGroupPorts), c.org.LogPrefix)
		}

		pods, err := metadbquery.FindPage[metadbmodel.Pod](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("pod_group_id NOT IN ?", podGroupIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get pod: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(pods) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.Pod](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				pods,
			)
			if err != nil {
				log.Errorf("failed to delete pod: %s", err.Error(), c.org.LogPrefix)
				return
			}
			pageDeleteAndPublish[*message.DeletedPods, message.DeletedPods, metadbmodel.Pod](c.org.DB, pods, ctrlrcommon.RESOURCE_TYPE_POD_EN, c.toolData)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_EN, ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, pods), c.org.LogPrefix)
		}

		podReplicaSets, err := metadbquery.FindPage[metadbmodel.PodReplicaSet](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("pod_group_id NOT IN ?", podGroupIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get pod replica set: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(podReplicaSets) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.PodReplicaSet](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				podReplicaSets,
			)
			if err != nil {
				log.Errorf("failed to delete pod replica set: %s", err.Error(), c.org.LogPrefix)
				return
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, podReplicaSets), c.org.LogPrefix)
		}
	}
}

func (c *Cleaner) cleanPodNodeDirty(domainLcuuid string) {
	podNodeIDs := getIDs[metadbmodel.PodNode](c.org.DB, domainLcuuid)
	if len(podNodeIDs) != 0 {
		vifs, err := metadbquery.FindPage[metadbmodel.VInterface](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("devicetype = ? AND deviceid NOT IN ?", ctrlrcommon.VIF_DEVICE_TYPE_POD_NODE, podNodeIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get vinterface: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(vifs) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.VInterface](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				vifs,
			)
			if err != nil {
				log.Errorf("failed to delete vinterface: %s", err.Error(), c.org.LogPrefix)
				return
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, vifs), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeDeviceIPConn, len(vifs))
		}

		vmPodNodeConns, err := metadbquery.FindPage[metadbmodel.VMPodNodeConnection](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("pod_node_id NOT IN ?", podNodeIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get vm pod node connection: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(vmPodNodeConns) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.VMPodNodeConnection](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				vmPodNodeConns,
			)
			if err != nil {
				log.Errorf("failed to delete vm pod node connection: %s", err.Error(), c.org.LogPrefix)
				return
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, vmPodNodeConns), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeCHostPodNodeConn, len(vmPodNodeConns))
		}

		pods, err := metadbquery.FindPage[metadbmodel.Pod](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("pod_node_id != 0 AND pod_node_id NOT IN ?", podNodeIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get pod: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(pods) != 0 {
			pageDeleteAndPublish[*message.DeletedPods, message.DeletedPods, metadbmodel.Pod](
				c.org.DB,
				pods,
				ctrlrcommon.RESOURCE_TYPE_POD_EN,
				c.toolData,
			)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_EN, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, pods), c.org.LogPrefix)
		}
	}
}

func (c *Cleaner) cleanPodDirty(domainLcuuid string) {
	podIDs := getIDs[metadbmodel.Pod](c.org.DB, domainLcuuid)
	if len(podIDs) != 0 {
		vifs, err := metadbquery.FindPage[metadbmodel.VInterface](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("devicetype = ? AND deviceid NOT IN ?", ctrlrcommon.VIF_DEVICE_TYPE_POD, podIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get vinterface: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(vifs) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.VInterface](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				vifs,
			)
			if err != nil {
				log.Errorf("failed to delete vinterface: %s", err.Error(), c.org.LogPrefix)
				return
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_POD_EN, vifs), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeDeviceIPConn, len(vifs))
		}
	}
}

func (c *Cleaner) cleanPodClusterDirty(domainLcuuid string) {
	podClusterIDs := getIDs[metadbmodel.PodCluster](c.org.DB, domainLcuuid)
	if len(podClusterIDs) != 0 {
		pods, err := metadbquery.FindPage[metadbmodel.Pod](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("pod_cluster_id NOT IN ?", podClusterIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get pod: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(pods) != 0 {
			pageDeleteAndPublish[*message.DeletedPods, message.DeletedPods, metadbmodel.Pod](
				c.org.DB,
				pods,
				ctrlrcommon.RESOURCE_TYPE_POD_EN,
				c.toolData,
			)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_EN, ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, pods), c.org.LogPrefix)
		}
		podReplicasets, err := metadbquery.FindPage[metadbmodel.PodReplicaSet](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("pod_cluster_id NOT IN ?", podClusterIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get pod replicaset: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(podReplicasets) != 0 {
			pageDeleteAndPublish[*message.DeletedPodReplicaSets, message.DeletedPodReplicaSets, metadbmodel.PodReplicaSet](
				c.org.DB,
				podReplicasets,
				ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN,
				c.toolData,
			)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, podReplicasets), c.org.LogPrefix)
		}
		podGroups, err := metadbquery.FindPage[metadbmodel.PodGroup](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("pod_cluster_id NOT IN ?", podClusterIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get pod group: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(podGroups) != 0 {
			pageDeleteAndPublish[*message.DeletedPodGroups, message.DeletedPodGroups, metadbmodel.PodGroup](
				c.org.DB,
				podGroups,
				ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN,
				c.toolData,
			)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, podGroups), c.org.LogPrefix)
		}
		podServices, err := metadbquery.FindPage[metadbmodel.PodService](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("pod_cluster_id NOT IN ?", podClusterIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get pod service: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(podServices) != 0 {
			pageDeleteAndPublish[*message.DeletedPodServices, message.DeletedPodServices, metadbmodel.PodService](
				c.org.DB,
				podServices,
				ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN,
				c.toolData,
			)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, podServices), c.org.LogPrefix)
		}
		podIngresses, err := metadbquery.FindPage[metadbmodel.PodIngress](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("pod_cluster_id NOT IN ?", podClusterIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get pod ingress: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(podIngresses) != 0 {
			pageDeleteAndPublish[*message.DeletedPodIngresses, message.DeletedPodIngresses, metadbmodel.PodIngress](
				c.org.DB,
				podIngresses,
				ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN,
				c.toolData,
			)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, podIngresses), c.org.LogPrefix)
		}
		podNamespaces, err := metadbquery.FindPage[metadbmodel.PodNamespace](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("pod_cluster_id NOT IN ?", podClusterIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get pod namespace: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(podNamespaces) != 0 {
			pageDeleteAndPublish[*message.DeletedPodNamespaces, message.DeletedPodNamespaces, metadbmodel.PodNamespace](c.org.DB, podNamespaces, ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, c.toolData)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, podNamespaces), c.org.LogPrefix)
		}
		podNodes, err := metadbquery.FindPage[metadbmodel.PodNode](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("pod_cluster_id NOT IN ?", podClusterIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get pod node: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(podNodes) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.PodNode](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				podNodes,
			)
			if err != nil {
				log.Errorf("failed to delete pod node: %s", err.Error(), c.org.LogPrefix)
				return
			}
			pageDeleteAndPublish[*message.DeletedPodNodes, message.DeletedPodNodes, metadbmodel.PodNode](c.org.DB, podNodes, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, c.toolData)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, podNodes), c.org.LogPrefix)
		}
	}
}

func (c *Cleaner) cleanPodNamespaceDirty(domainLcuuid string) {
	podNamespaceIDs := getIDs[metadbmodel.PodNamespace](c.org.DB, domainLcuuid)
	if len(podNamespaceIDs) != 0 {
		pods, err := metadbquery.FindPage[metadbmodel.Pod](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("pod_namespace_id NOT IN ?", podNamespaceIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get pod: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(pods) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.Pod](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				pods,
			)
			if err != nil {
				log.Errorf("failed to delete pod: %s", err.Error(), c.org.LogPrefix)
				return
			}
			pageDeleteAndPublish[*message.DeletedPods, message.DeletedPods, metadbmodel.Pod](c.org.DB, pods, ctrlrcommon.RESOURCE_TYPE_POD_EN, c.toolData)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_EN, ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, pods), c.org.LogPrefix)
		}
		podGroups, err := metadbquery.FindPage[metadbmodel.PodGroup](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("pod_namespace_id NOT IN ?", podNamespaceIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get pod group: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(podGroups) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.PodGroup](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				podGroups,
			)
			if err != nil {
				log.Errorf("failed to delete pod group: %s", err.Error(), c.org.LogPrefix)
				return
			}
			pageDeleteAndPublish[*message.DeletedPodGroups, message.DeletedPodGroups, metadbmodel.PodGroup](c.org.DB, podGroups, ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, c.toolData)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, podGroups), c.org.LogPrefix)
		}
		podReplicasets, err := metadbquery.FindPage[metadbmodel.PodReplicaSet](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("pod_namespace_id NOT IN ?", podNamespaceIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get pod replica set: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(podReplicasets) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.PodReplicaSet](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				podReplicasets,
			)
			if err != nil {
				log.Errorf("failed to delete pod replica set: %s", err.Error(), c.org.LogPrefix)
				return
			}
			pageDeleteAndPublish[*message.DeletedPodReplicaSets, message.DeletedPodReplicaSets, metadbmodel.PodReplicaSet](c.org.DB, podReplicasets, ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, c.toolData)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, podReplicasets), c.org.LogPrefix)
		}
		podIngresses, err := metadbquery.FindPage[metadbmodel.PodIngress](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("pod_namespace_id NOT IN ?", podNamespaceIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get pod ingress: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(podIngresses) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.PodIngress](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				podIngresses,
			)
			if err != nil {
				log.Errorf("failed to delete pod ingress: %s", err.Error(), c.org.LogPrefix)
				return
			}
			pageDeleteAndPublish[*message.DeletedPodIngresses, message.DeletedPodIngresses, metadbmodel.PodIngress](c.org.DB, podIngresses, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, c.toolData)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, podIngresses), c.org.LogPrefix)
		}
		podServices, err := metadbquery.FindPage[metadbmodel.PodService](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("pod_namespace_id NOT IN ?", podNamespaceIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get pod service: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(podServices) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.PodService](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				podServices,
			)
			if err != nil {
				log.Errorf("failed to delete pod service: %s", err.Error(), c.org.LogPrefix)
				return
			}
			pageDeleteAndPublish[*message.DeletedPodServices, message.DeletedPodServices, metadbmodel.PodService](c.org.DB, podServices, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, c.toolData)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, podServices), c.org.LogPrefix)
		}
	}
}

func (c *Cleaner) cleanVInterfaceDirty(domainLcuuid string) {
	vifIDs := getIDs[metadbmodel.VInterface](c.org.DB, domainLcuuid)
	if len(vifIDs) != 0 {
		lanIPs, err := metadbquery.FindPage[metadbmodel.LANIP](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("vifid NOT IN ?", vifIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get lan ip: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(lanIPs) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.LANIP](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				lanIPs,
			)
			if err != nil {
				log.Errorf("failed to delete lan ip: %s", err.Error(), c.org.LogPrefix)
				return
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN, ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, lanIPs), c.org.LogPrefix)
		}

		wanIPs, err := metadbquery.FindPage[metadbmodel.WANIP](
			c.org.DB.Where(map[string]interface{}{"domain": domainLcuuid}).
				Where("vifid NOT IN ?", vifIDs),
			c.batchSize,
		)
		if err != nil {
			log.Errorf("failed to get wan ip: %s", err.Error(), c.org.LogPrefix)
			return
		}
		if len(wanIPs) != 0 {
			err := metadbquery.DeletePageData[metadbmodel.WANIP](
				c.org.DB.DB.Unscoped(),
				int(c.org.DB.Config.BatchSize1),
				wanIPs,
			)
			if err != nil {
				log.Errorf("failed to delete wan ip: %s", err.Error(), c.org.LogPrefix)
				return
			}
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN, ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, wanIPs), c.org.LogPrefix)
		}
	}
}
