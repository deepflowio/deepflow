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

// 永久删除MySQL中超过7天的软删除云平台资源数据
package recorder

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/exp/slices"

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/config"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/controller/tagrecorder"
	"github.com/deepflowio/deepflow/server/libs/stats"
)

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
	orgIDs, err := mysql.GetORGIDs()
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

	cl, err := newCleaner(orgID)
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

	statsdLock           sync.Mutex
	domainLcuuidToStatsd map[string]*domainStatsd
}

func newCleaner(orgID int) (*Cleaner, error) {
	org, err := common.NewORG(orgID)
	if err != nil {
		log.Errorf("failed to create org object: %s", err.Error())
		return nil, err
	}
	c := &Cleaner{
		org:                  org,
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
	var domains []*mysqlmodel.Domain
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
	deleteAndPublish[mysqlmodel.Region](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_REGION_EN, c.toolData)
	deleteAndPublish[mysqlmodel.AZ](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_AZ_EN, c.toolData)
	deleteAndPublish[mysqlmodel.Host](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_HOST_EN, c.toolData)
	deleteAndPublish[mysqlmodel.VM](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_VM_EN, c.toolData)
	deleteAndPublish[mysqlmodel.VPC](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_VPC_EN, c.toolData)
	deleteAndPublish[mysqlmodel.Network](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, c.toolData)
	deleteAndPublish[mysqlmodel.VRouter](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, c.toolData)
	deleteAndPublish[mysqlmodel.DHCPPort](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN, c.toolData)
	deleteAndPublish[mysqlmodel.NATGateway](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN, c.toolData)
	deleteAndPublish[mysqlmodel.LB](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_LB_EN, c.toolData)
	deleteAndPublish[mysqlmodel.LBListener](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_LB_LISTENER_EN, c.toolData)
	deleteAndPublish[mysqlmodel.CEN](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_CEN_EN, c.toolData)
	deleteAndPublish[mysqlmodel.PeerConnection](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_PEER_CONNECTION_EN, c.toolData)
	deleteAndPublish[mysqlmodel.RDSInstance](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN, c.toolData)
	deleteAndPublish[mysqlmodel.RedisInstance](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN, c.toolData)
	deleteAndPublish[mysqlmodel.PodCluster](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, c.toolData)
	deleteAndPublish[mysqlmodel.PodNode](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, c.toolData)
	deleteAndPublish[mysqlmodel.PodNamespace](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, c.toolData)
	deleteAndPublish[mysqlmodel.PodIngress](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, c.toolData)
	deleteAndPublish[mysqlmodel.PodService](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, c.toolData)
	deleteAndPublish[mysqlmodel.PodGroup](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, c.toolData)
	deleteAndPublish[mysqlmodel.PodReplicaSet](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, c.toolData)
	deleteAndPublish[mysqlmodel.Pod](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_EN, c.toolData)
	deleteAndPublish[mysqlmodel.Process](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_PROCESS_EN, c.toolData)
	log.Info("clean soft deleted resources completed", c.org.LogPrefix)
}

func (c *Cleaner) cleanDirtyData() {
	if err := c.toolData.load(c.org.DB); err != nil {
		log.Error("failed to load tool data", c.org.LogPrefix)
		return
	}
	var domains []*mysqlmodel.Domain
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
	deviceIDs := getIDs[mysqlmodel.Host](c.org.DB, domainLcuuid)
	if len(deviceIDs) != 0 {
		vifs, _ := WhereFindPtr[mysqlmodel.VInterface](
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
	vmIDs := getIDs[mysqlmodel.VM](c.org.DB, domainLcuuid)
	if len(vmIDs) != 0 {
		vifs, _ := WhereFindPtr[mysqlmodel.VInterface](
			c.org.DB,
			"domain = ? AND devicetype = ? AND deviceid NOT IN ?", domainLcuuid, ctrlrcommon.VIF_DEVICE_TYPE_VM, vmIDs,
		)
		if len(vifs) != 0 {
			c.org.DB.Delete(&vifs)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_VM_EN, vifs), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeDeviceIPConn, len(vifs))
		}

		vmPodNodeConns, _ := WhereFindPtr[mysqlmodel.VMPodNodeConnection](
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
	networkIDs := getIDs[mysqlmodel.Network](c.org.DB, domainLcuuid)
	if len(networkIDs) != 0 {
		subnets, _ := WhereFindPtr[mysqlmodel.Subnet](
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
	vrouterIDs := getIDs[mysqlmodel.VRouter](c.org.DB, domainLcuuid)
	if len(vrouterIDs) != 0 {
		rts, _ := WhereFindPtr[mysqlmodel.RoutingTable](
			c.org.DB,
			"domain = ? AND vnet_id NOT IN ?", domainLcuuid, vrouterIDs,
		)
		if len(rts) != 0 {
			c.org.DB.Delete(&rts)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_ROUTING_TABLE_EN, ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, rts), c.org.LogPrefix)
		}

		vifs, _ := WhereFindPtr[mysqlmodel.VInterface](
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
	podIngressIDs := getIDs[mysqlmodel.PodIngress](c.org.DB, domainLcuuid)
	if len(podIngressIDs) != 0 {
		podIngressRules, _ := WhereFindPtr[mysqlmodel.PodIngressRule](
			c.org.DB,
			"domain = ? AND pod_ingress_id NOT IN ?", domainLcuuid, podIngressIDs,
		)
		if len(podIngressRules) != 0 {
			c.org.DB.Delete(&podIngressRules)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, podIngressRules), c.org.LogPrefix)
		}

		podIngressRuleBkds, _ := WhereFindPtr[mysqlmodel.PodIngressRuleBackend](
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
	podServiceIDs := getIDs[mysqlmodel.PodService](c.org.DB, domainLcuuid)
	if len(podServiceIDs) != 0 {
		podServicePorts, _ := WhereFindPtr[mysqlmodel.PodServicePort](
			c.org.DB,
			"domain = ? AND pod_service_id NOT IN ?", domainLcuuid, podServiceIDs,
		)
		if len(podServicePorts) != 0 {
			c.org.DB.Delete(&podServicePorts)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_PORT_EN, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, podServicePorts), c.org.LogPrefix)
		}

		podGroupPorts, _ := WhereFindPtr[mysqlmodel.PodGroupPort](
			c.org.DB,
			"domain = ? AND pod_service_id NOT IN ?", domainLcuuid, podServiceIDs,
		)
		if len(podGroupPorts) != 0 {
			c.org.DB.Delete(&podGroupPorts)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, podGroupPorts), c.org.LogPrefix)
		}

		vifs, _ := WhereFindPtr[mysqlmodel.VInterface](
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
	podGroupIDs := getIDs[mysqlmodel.PodGroup](c.org.DB, domainLcuuid)
	if len(podGroupIDs) != 0 {
		podGroupPorts, _ := WhereFindPtr[mysqlmodel.PodGroupPort](
			c.org.DB,
			"domain = ? AND pod_group_id NOT IN ?", domainLcuuid, podGroupIDs,
		)
		if len(podGroupPorts) != 0 {
			c.org.DB.Delete(&podGroupPorts)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN, ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, podGroupPorts), c.org.LogPrefix)
		}

		pods, _ := WhereFindPtr[mysqlmodel.Pod](
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
	podNodeIDs := getIDs[mysqlmodel.PodNode](c.org.DB, domainLcuuid)
	if len(podNodeIDs) != 0 {
		vifs, _ := WhereFindPtr[mysqlmodel.VInterface](
			c.org.DB,
			"domain = ? AND devicetype = ? AND deviceid NOT IN ?", domainLcuuid, ctrlrcommon.VIF_DEVICE_TYPE_POD_NODE, podNodeIDs,
		)
		if len(vifs) != 0 {
			c.org.DB.Delete(&vifs)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, vifs), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeDeviceIPConn, len(vifs))
		}

		vmPodNodeConns, _ := WhereFindPtr[mysqlmodel.VMPodNodeConnection](
			c.org.DB,
			"domain = ? AND pod_node_id NOT IN ?", domainLcuuid, podNodeIDs,
		)
		if len(vmPodNodeConns) != 0 {
			c.org.DB.Delete(&vmPodNodeConns)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, vmPodNodeConns), c.org.LogPrefix)

			c.fillStatsd(domainLcuuid, tagTypeCHostPodNodeConn, len(vmPodNodeConns))
		}

		pods, _ := WhereFindPtr[mysqlmodel.Pod](
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
	podIDs := getIDs[mysqlmodel.Pod](c.org.DB, domainLcuuid)
	if len(podIDs) != 0 {
		vifs, _ := WhereFindPtr[mysqlmodel.VInterface](
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
	vifIDs := getIDs[mysqlmodel.VInterface](c.org.DB, domainLcuuid)
	if len(vifIDs) != 0 {
		lanIPs, _ := WhereFindPtr[mysqlmodel.LANIP](
			c.org.DB,
			"domain = ? AND vifid NOT IN ?", domainLcuuid, vifIDs,
		)
		if len(lanIPs) != 0 {
			c.org.DB.Delete(&lanIPs)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN, ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, lanIPs), c.org.LogPrefix)
		}

		wanIPs, _ := WhereFindPtr[mysqlmodel.WANIP](
			c.org.DB,
			"domain = ? AND vifid NOT IN ?", domainLcuuid, vifIDs,
		)
		if len(wanIPs) != 0 {
			c.org.DB.Delete(&wanIPs)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN, ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, wanIPs), c.org.LogPrefix)
		}
	}
}

const (
	tagTypeDeviceIPConn     = "device_ip_connection"
	tagTypeCHostPodNodeConn = "chost_pod_node_connection"
)

type domainStatsd struct {
	org    *common.ORG
	lcuuid string
	name   string
	teamID int

	deviceIPConn     *CleanerCounter
	chostPodNodeConn *CleanerCounter
}

func newDomainStatsd(org *common.ORG, domain *mysqlmodel.Domain) *domainStatsd {
	return &domainStatsd{
		org:    org,
		lcuuid: domain.Lcuuid,
		name:   domain.Name,
		teamID: domain.TeamID,

		deviceIPConn:     newCleanerCounter(),
		chostPodNodeConn: newCleanerCounter(),
	}
}

func (d *domainStatsd) close() {
	log.Info("close cleaner statsd of domain (lcuuid: %s)", d.lcuuid, d.org.LogPrefix)
	d.deviceIPConn.Closed()
	d.chostPodNodeConn.Closed()
}

func (d *domainStatsd) get(tagType string) *CleanerCounter {
	switch tagType {
	case tagTypeDeviceIPConn:
		return d.deviceIPConn
	case tagTypeCHostPodNodeConn:
		return d.chostPodNodeConn
	}
	return nil
}

func (d *domainStatsd) start() {
	log.Infof("start cleaner statsd of domain (lcuuid: %s)", d.lcuuid, d.org.LogPrefix)
	err := stats.RegisterCountableWithModulePrefix(
		"controller_",
		"resource_relation_exception",
		d.deviceIPConn,
		stats.OptionStatTags{
			"tenant_org_id":  fmt.Sprintf("%d", d.org.ID),
			"tenant_team_id": fmt.Sprintf("%d", d.teamID),
			"domain":         d.name,
			"type":           tagTypeDeviceIPConn,
		},
	)
	if err != nil {
		log.Errorf("failed to register cleaner statsd of domain (lcuuid: %s) device_ip_connection: %s", d.lcuuid, err.Error(), d.org.LogPrefix)
	}

	err = stats.RegisterCountableWithModulePrefix(
		"controller_",
		"resource_relation_exception",
		d.chostPodNodeConn,
		stats.OptionStatTags{
			"tenant_org_id":  fmt.Sprintf("%d", d.org.ID),
			"tenant_team_id": fmt.Sprintf("%d", d.teamID),
			"domain":         d.name,
			"type":           tagTypeCHostPodNodeConn,
		},
	)
	if err != nil {
		log.Errorf("failed to register cleaner statsd of domain (lcuuid: %s) chost_pod_node_connection: %s", d.lcuuid, err.Error(), d.org.LogPrefix)
	}
}

type TmpCounter struct {
	Count uint64 `statsd:"count"`
}

func (c *TmpCounter) Fill(count int) {
	atomic.AddUint64(&c.Count, uint64(count))
}

type CleanerCounter struct {
	*TmpCounter
}

func newCleanerCounter() *CleanerCounter {
	return &CleanerCounter{
		TmpCounter: &TmpCounter{},
	}
}

func (c *CleanerCounter) GetCounter() interface{} {
	counter := &TmpCounter{}
	counter, c.TmpCounter = c.TmpCounter, counter
	if counter.Count != 0 {
		log.Infof("cleaner counter count: %d", counter.Count)
	}
	return counter
}

func (c *CleanerCounter) Closed() bool {
	return false
}

func WhereFindPtr[T any](db *mysql.DB, query interface{}, args ...interface{}) ([]*T, error) {
	var result []*T
	err := db.Where(query, args...).Find(&result).Error
	return result, err
}

func formatLogDeleteABecauseBHasGone[MT constraint.MySQLModel](a, b string, items []*MT) string {
	var str string
	for _, item := range items {
		str += fmt.Sprintf("%+v ", item)
	}
	return fmt.Sprintf("%s: %+v because %s has gone", common.LogDelete(a), str, b)
}

func deleteExpired[MT constraint.MySQLSoftDeleteModel](db *mysql.DB, expiredAt time.Time) []*MT {
	var dbItems []*MT
	err := db.Unscoped().Where("deleted_at < ?", expiredAt).Find(&dbItems).Error
	if err != nil {
		log.Errorf("mysql delete resource failed: %s", err.Error(), db.LogPrefixORGID)
		return nil
	}
	if len(dbItems) == 0 {
		return nil
	}
	if err := db.Unscoped().Delete(&dbItems).Error; err != nil {
		log.Errorf("mysql delete resource failed: %s", err.Error(), db.LogPrefixORGID)
		return nil
	}
	return dbItems
}

func getIDs[MT constraint.MySQLModel](db *mysql.DB, domainLcuuid string) (ids []int) {
	var dbItems []*MT
	db.Where("domain = ?", domainLcuuid).Select("id").Find(&dbItems)
	for _, item := range dbItems {
		ids = append(ids, (*item).GetID())
	}
	return
}

func deleteAndPublish[MT constraint.MySQLSoftDeleteModel](db *mysql.DB, expiredAt time.Time, resourceType string, toolData *toolData) {
	dbItems := deleteExpired[MT](db, expiredAt)
	publishTagrecorder(db, dbItems, resourceType, toolData)
	log.Infof("clean %s completed: %d", resourceType, len(dbItems), db.LogPrefixORGID)
}

func publishTagrecorder[MT constraint.MySQLSoftDeleteModel](db *mysql.DB, dbItems []*MT, resourceType string, toolData *toolData) {
	msgMetadataToDBItems := make(map[*message.Metadata][]*MT)
	for _, item := range dbItems {
		var msgMetadata *message.Metadata
		if (*item).GetSubDomainLcuuid() != "" {
			msgMetadata = toolData.subDomainLcuuidToMsgMetadata[(*item).GetSubDomainLcuuid()]
		} else {
			msgMetadata = toolData.domainLcuuidToMsgMetadata[(*item).GetDomainLcuuid()]
		}
		if msgMetadata == nil {
			log.Errorf("failed to get metadata for %s: %#v", resourceType, item, db.LogPrefixORGID)
			continue
		}
		msgMetadataToDBItems[msgMetadata] = append(msgMetadataToDBItems[msgMetadata], item)
	}
	if len(msgMetadataToDBItems) == 0 {
		return
	}
	for _, sub := range tagrecorder.GetSubscriberManager().GetSubscribers(resourceType) {
		for msgMetadata, dbItems := range msgMetadataToDBItems {
			sub.OnResourceBatchDeleted(msgMetadata, dbItems)
		}
	}
}

type toolData struct {
	mux sync.Mutex

	domainLcuuidToMsgMetadata    map[string]*message.Metadata
	subDomainLcuuidToMsgMetadata map[string]*message.Metadata
}

func newToolData() *toolData {
	return &toolData{
		domainLcuuidToMsgMetadata:    make(map[string]*message.Metadata),
		subDomainLcuuidToMsgMetadata: make(map[string]*message.Metadata),
	}
}

func (t *toolData) clean() {
	t.domainLcuuidToMsgMetadata = make(map[string]*message.Metadata)
	t.subDomainLcuuidToMsgMetadata = make(map[string]*message.Metadata)
}

func (t *toolData) load(db *mysql.DB) error {
	t.mux.Lock()
	defer t.mux.Unlock()

	t.clean()

	var domains []*mysqlmodel.Domain
	if err := db.Find(&domains).Error; err != nil {
		log.Errorf("failed to get domain: %s", err.Error(), db.LogPrefixORGID)
		return err
	}
	domainLcuuidToID := make(map[string]int)
	for _, domain := range domains {
		domainLcuuidToID[domain.Lcuuid] = domain.ID
		t.domainLcuuidToMsgMetadata[domain.Lcuuid] = message.NewMetadata(db.ORGID, message.MetadataTeamID(domain.TeamID), message.MetadataDomainID(domain.ID))
	}
	var subDomains []*mysqlmodel.SubDomain
	if err := db.Find(&subDomains).Error; err != nil {
		log.Errorf("failed to get sub_domain: %s", err.Error(), db.LogPrefixORGID)
		return err
	}
	for _, subDomain := range subDomains {
		t.subDomainLcuuidToMsgMetadata[subDomain.Lcuuid] = message.NewMetadata(
			db.ORGID, message.MetadataTeamID(subDomain.TeamID), message.MetadataDomainID(domainLcuuidToID[subDomain.Domain]), message.MetadataSubDomainID(subDomain.ID),
		)
	}
	return nil
}
