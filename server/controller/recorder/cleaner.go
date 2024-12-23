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
	"time"

	"golang.org/x/exp/slices"

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/config"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/controller/tagrecorder"
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

	orgIDs, err := mysql.GetORGIDs()
	if err != nil {
		log.Errorf("failed to get db for org ids: %s", err.Error())
		return err
	}

	for _, id := range orgIDs {
		if _, err := c.NewCleanerIfNotExists(id); err != nil {
			log.Errorf("failed to cleaner for org id %d: %s", id, err.Error())
			return err
		}
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
	c.mux.Lock()
	defer c.mux.Unlock()
	for orgID := range c.orgIDToCleaner {
		if !slices.Contains(orgIDs, orgID) {
			delete(c.orgIDToCleaner, orgID)
		}
	}
	return nil
}

func (c *Cleaners) cleanDeletedData() {
	for _, cl := range c.orgIDToCleaner {
		cl.cleanDeletedData(int(c.cfg.DeletedResourceRetentionTime))
	}
}

func getIDsByDomainLcuuid[MT constraint.MySQLModel](db *mysql.DB, domainLcuuid string) (ids []int) {
	var dbItems []*MT
	db.Where("domain = ?", domainLcuuid).Select("id").Find(&dbItems)
	for _, item := range dbItems {
		ids = append(ids, (*item).GetID())
	}
	return
}

func (c *Cleaners) timedCleanDirtyData(sContext context.Context) {
	c.cleanDirtyData()
	go func() {
		ticker := time.NewTicker(time.Duration(int(c.cfg.CacheRefreshInterval)+50) * time.Minute)
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
}

func newCleaner(cfg config.RecorderConfig, orgID int) (*Cleaner, error) {
	org, err := common.NewORG(orgID)
	if err != nil {
		log.Errorf("failed to create org object: %s", err.Error())
		return nil, err
	}
	c := &Cleaner{cfg: cfg, org: org, toolData: newToolData()}
	return c, nil
}

func (c *Cleaner) cleanDeletedData(retentionInterval int) {
	if err := c.toolData.load(c.org.DB); err != nil {
		log.Error(c.org.Logf("failed to load tool data"))
		return
	}

	expiredAt := time.Now().Add(time.Duration(-retentionInterval) * time.Hour)
	log.Info(c.org.Logf("clean soft deleted resources (deleted_at < %s) started", expiredAt.Format(ctrlrcommon.GO_BIRTHDAY)))
	pageDeleteExpiredAndPublish[mysql.Region](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_REGION_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[mysql.AZ](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_AZ_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[mysql.Host](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_HOST_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[mysql.VM](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_VM_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[mysql.VPC](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_VPC_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[mysql.Network](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[mysql.VRouter](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[mysql.DHCPPort](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[mysql.NATGateway](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[mysql.LB](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_LB_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[mysql.LBListener](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_LB_LISTENER_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[mysql.CEN](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_CEN_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[mysql.PeerConnection](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_PEER_CONNECTION_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[mysql.RDSInstance](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[mysql.RedisInstance](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[mysql.PodCluster](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[mysql.PodNode](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[mysql.PodNamespace](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[mysql.PodIngress](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[mysql.PodService](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[mysql.PodGroup](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[mysql.PodReplicaSet](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[mysql.Pod](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_POD_EN, c.toolData, c.cfg.MySQLBatchSize)
	pageDeleteExpiredAndPublish[mysql.Process](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_PROCESS_EN, c.toolData, c.cfg.MySQLBatchSize)
	// deleteAndPublish[mysql.PrometheusTarget](c.org.DB, expiredAt, ctrlrcommon.RESOURCE_TYPE_PROMETHEUS_TARGET_EN, c.toolData)
	log.Info(c.org.Logf("clean soft deleted resources completed"))
}

func (c *Cleaner) cleanDirtyData() {
	if err := c.toolData.load(c.org.DB); err != nil {
		log.Error(c.org.Logf("failed to load tool data"))
		return
	}

	log.Info(c.org.Logf("clean dirty data started"))

	var domains []mysql.Domain
	if err := mysql.Db.Find(&domains).Error; err != nil {
		log.Errorf("failed to get domains: %v", err)
		return
	}
	for _, domain := range domains {
		c.cleanPodNodeDirty(domain.Lcuuid)
		c.cleanVMDirty(domain.Lcuuid)
	}

	c.cleanNetworkDirty()
	c.cleanVRouterDirty()
	c.cleanPodIngressDirty()
	c.cleanPodServiceDirty()
	c.cleanPodGroupDirty()
	c.cleanPodDirty()
	c.cleanVInterfaceDirty()
	log.Info(c.org.Logf("clean dirty data completed"))
}

func (c *Cleaner) cleanNetworkDirty() {
	networkIDs := getIDs[mysql.Network](c.org.DB)
	if len(networkIDs) != 0 {
		var subnets []*mysql.Subnet
		c.org.DB.Where("vl2id NOT IN ?", networkIDs).Find(&subnets)
		if len(subnets) != 0 {
			c.org.DB.Delete(&subnets)
			log.Error(c.org.Logf(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_SUBNET_EN, ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, subnets)))
		}
	}
}

func (c *Cleaner) cleanVRouterDirty() {
	vrouterIDs := getIDs[mysql.VRouter](c.org.DB)
	if len(vrouterIDs) != 0 {
		var rts []*mysql.RoutingTable
		c.org.DB.Where("vnet_id NOT IN ?", vrouterIDs).Find(&rts)
		if len(rts) != 0 {
			c.org.DB.Delete(&rts)
			log.Error(c.org.Logf(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_ROUTING_TABLE_EN, ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, rts)))
		}
	}
}

func (c *Cleaner) cleanPodIngressDirty() {
	podIngressIDs := getIDs[mysql.PodIngress](c.org.DB)
	if len(podIngressIDs) != 0 {
		var podIngressRules []*mysql.PodIngressRule
		c.org.DB.Where("pod_ingress_id NOT IN ?", podIngressIDs).Find(&podIngressRules)
		if len(podIngressRules) != 0 {
			c.org.DB.Delete(&podIngressRules)
			log.Error(c.org.Logf(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, podIngressRules)))
		}

		var podIngressRuleBkds []*mysql.PodIngressRuleBackend
		c.org.DB.Where("pod_ingress_id NOT IN ?", podIngressIDs).Find(&podIngressRuleBkds)
		if len(podIngressRuleBkds) != 0 {
			c.org.DB.Delete(&podIngressRuleBkds)
			log.Error(c.org.Logf(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, podIngressRuleBkds)))
		}
	}
}

func (c *Cleaner) cleanPodServiceDirty() {
	podServiceIDs := getIDs[mysql.PodService](c.org.DB)
	if len(podServiceIDs) != 0 {
		var podServicePorts []*mysql.PodServicePort
		c.org.DB.Where("pod_service_id NOT IN ?", podServiceIDs).Find(&podServicePorts)
		if len(podServicePorts) != 0 {
			c.org.DB.Delete(&podServicePorts)
			log.Error(c.org.Logf(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_PORT_EN, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, podServicePorts)))
		}

		var podGroupPorts []*mysql.PodGroupPort
		c.org.DB.Where("pod_service_id NOT IN ?", podServiceIDs).Find(&podGroupPorts)
		if len(podGroupPorts) != 0 {
			c.org.DB.Delete(&podGroupPorts)
			log.Error(c.org.Logf(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, podGroupPorts)))
		}

		var vifs []*mysql.VInterface
		c.org.DB.Where("devicetype = ? AND deviceid NOT IN ?", ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE, podServiceIDs).Find(&vifs)
		if len(vifs) != 0 {
			c.org.DB.Delete(&vifs)
			log.Error(c.org.Logf(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, vifs)))
		}
	}
}

func (c *Cleaner) cleanPodGroupDirty() {
	podGroupIDs := getIDs[mysql.PodGroup](c.org.DB)
	if len(podGroupIDs) != 0 {
		var podGroupPorts []*mysql.PodGroupPort
		c.org.DB.Where("pod_group_id NOT IN ?", podGroupIDs).Find(&podGroupPorts)
		if len(podGroupPorts) != 0 {
			c.org.DB.Delete(&podGroupPorts)
			log.Error(c.org.Logf(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN, ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, podGroupPorts)))
		}

		var pods []*mysql.Pod
		c.org.DB.Where("pod_group_id NOT IN ?", podGroupIDs).Find(&pods)
		if len(pods) != 0 {
			c.org.DB.Delete(&pods)
			publishTagrecorder(c.org.DB, pods, ctrlrcommon.RESOURCE_TYPE_POD_EN, c.toolData)
			log.Error(c.org.Logf(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_EN, ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, pods)))
		}
	}
}

func (c *Cleaner) cleanPodNodeDirty(domainLcuuid string) {
	podNodeIDs := getIDsByDomainLcuuid[mysql.PodNode](c.org.DB, domainLcuuid)
	if len(podNodeIDs) != 0 {
		var vifs []*mysql.VInterface
		c.org.DB.Where("domain = ? AND devicetype = ? AND deviceid NOT IN ?", domainLcuuid, ctrlrcommon.VIF_DEVICE_TYPE_POD_NODE, podNodeIDs).Find(&vifs)
		if len(vifs) != 0 {
			c.org.DB.Delete(&vifs)
			log.Error(c.org.Logf(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, vifs)))
		}

		var vmPodNodeConns []*mysql.VMPodNodeConnection
		c.org.DB.Where("domain = ? AND pod_node_id NOT IN ?", domainLcuuid, podNodeIDs).Find(&vmPodNodeConns)
		if len(vmPodNodeConns) != 0 {
			c.org.DB.Delete(&vmPodNodeConns)
			log.Error(c.org.Logf(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, vmPodNodeConns)))
		}

		var pods []*mysql.Pod
		c.org.DB.Where("domain = ? AND pod_node_id != 0 AND pod_node_id NOT IN ?", domainLcuuid, podNodeIDs).Find(&pods)
		if len(pods) != 0 {
			c.org.DB.Delete(&pods)
			publishTagrecorder(c.org.DB, pods, ctrlrcommon.RESOURCE_TYPE_POD_EN, c.toolData)
			log.Error(c.org.Logf(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_EN, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, pods)))
		}
	}
}

func (c *Cleaner) cleanVMDirty(domainLcuuid string) {
	vmIDs := getIDsByDomainLcuuid[mysql.VM](c.org.DB, domainLcuuid)
	if len(vmIDs) != 0 {
		var vifs []*mysql.VInterface
		mysql.Db.Where("domain = ? AND devicetype = ? AND deviceid NOT IN ?", domainLcuuid, ctrlrcommon.VIF_DEVICE_TYPE_VM, vmIDs).Find(&vifs)
		if len(vifs) != 0 {
			mysql.Db.Delete(&vifs)
			log.Error(c.org.Logf(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_VM_EN, vifs)))
		}

		var vmPodNodeConns []*mysql.VMPodNodeConnection
		mysql.Db.Where("domain = ? AND vm_id NOT IN ?", domainLcuuid, vmIDs).Find(&vmPodNodeConns)
		if len(vmPodNodeConns) != 0 {
			mysql.Db.Delete(&vmPodNodeConns)
			log.Error(c.org.Logf(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, ctrlrcommon.RESOURCE_TYPE_VM_EN, vmPodNodeConns)))
		}
	}
}

func (c *Cleaner) cleanPodDirty() {
	podIDs := getIDs[mysql.Pod](c.org.DB)
	if len(podIDs) != 0 {
		var vifs []*mysql.VInterface
		c.org.DB.Where("devicetype = ? AND deviceid NOT IN ?", ctrlrcommon.VIF_DEVICE_TYPE_POD, podIDs).Find(&vifs)
		if len(vifs) != 0 {
			c.org.DB.Delete(&vifs)
			log.Error(c.org.Logf(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_POD_EN, vifs)))
		}
	}
}

func (c *Cleaner) cleanVInterfaceDirty() {
	vifIDs := getIDs[mysql.VInterface](c.org.DB)
	if len(vifIDs) != 0 {
		var lanIPs []*mysql.LANIP
		c.org.DB.Where("vifid NOT IN ?", vifIDs).Find(&lanIPs)
		if len(lanIPs) != 0 {
			c.org.DB.Delete(&lanIPs)
			log.Error(c.org.Logf(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN, ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, lanIPs)))
		}
		var wanIPs []*mysql.WANIP
		c.org.DB.Where("vifid NOT IN ?", vifIDs).Find(&wanIPs)
		if len(wanIPs) != 0 {
			c.org.DB.Delete(&wanIPs)
			log.Error(c.org.Logf(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN, ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, wanIPs)))
		}
	}
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
		log.Error(db.Logf("mysql delete resource failed: %s", err.Error()))
		return nil
	}
	if len(dbItems) == 0 {
		return nil
	}
	if err := db.Unscoped().Delete(&dbItems).Error; err != nil {
		log.Error(db.Logf("mysql delete resource failed: %s", err.Error()))
		return nil
	}
	return dbItems
}

func getIDs[MT constraint.MySQLModel](db *mysql.DB) (ids []int) {
	var dbItems []*MT
	db.Select("id").Find(&dbItems)
	for _, item := range dbItems {
		ids = append(ids, (*item).GetID())
	}
	return
}

func pageDeleteExpiredAndPublish[MT constraint.MySQLSoftDeleteModel](
	db *mysql.DB, expiredAt time.Time, resourceType string, toolData *toolData, size int) {
	var items []*MT
	err := db.Unscoped().Where("deleted_at < ?", expiredAt).Find(&items).Error
	if err != nil {
		log.Errorf("mysql delete %s resource failed: %s", resourceType, err.Error())
		return
	}
	if len(items) == 0 {
		return
	}

	log.Infof("clean %s started: %d", resourceType, len(items))
	total := len(items)
	for i := 0; i < total; i += size {
		end := i + size
		if end > total {
			end = total
		}
		if err := db.Unscoped().Delete(items[i:end]).Error; err != nil {
			log.Errorf("mysql delete %s resource failed: %s", resourceType, err.Error())
		} else {
			publishTagrecorder(db, items, resourceType, toolData)
		}
	}

	log.Infof("clean %s completed: %d", resourceType, len(items))
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
			log.Error(db.Logf("failed to get metadata for %s: %#v", resourceType, item))
			continue
		}
		msgMetadataToDBItems[msgMetadata] = append(msgMetadataToDBItems[msgMetadata], item)
	}
	if len(msgMetadataToDBItems) == 0 {
		return
	}
	for _, sub := range tagrecorder.GetSubscriberManager().GetSubscribers(resourceType) {
		for msgMetadata, dbItems := range msgMetadataToDBItems {
			sub.OnResourceBatchDeleted(msgMetadata, dbItems, false)
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

	var domains []*mysql.Domain
	if err := db.Find(&domains).Error; err != nil {
		log.Error(db.Logf("failed to get domain: %s", err.Error()))
		return err
	}
	domainLcuuidToID := make(map[string]int)
	for _, domain := range domains {
		domainLcuuidToID[domain.Lcuuid] = domain.ID
		t.domainLcuuidToMsgMetadata[domain.Lcuuid] = message.NewMetadata(db.ORGID, message.MetadataTeamID(domain.TeamID), message.MetadataDomainID(domain.ID))
	}
	var subDomains []*mysql.SubDomain
	if err := db.Find(&subDomains).Error; err != nil {
		log.Error(db.Logf("failed to get sub_domain: %s", err.Error()))
		return err
	}
	for _, subDomain := range subDomains {
		t.subDomainLcuuidToMsgMetadata[subDomain.Lcuuid] = message.NewMetadata(
			db.ORGID, message.MetadataTeamID(subDomain.TeamID), message.MetadataDomainID(domainLcuuidToID[subDomain.Domain]), message.MetadataSubDomainID(subDomain.ID),
		)
	}
	return nil
}
