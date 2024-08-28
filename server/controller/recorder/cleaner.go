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
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
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
}

func newCleaner(orgID int) (*Cleaner, error) {
	org, err := common.NewORG(orgID)
	if err != nil {
		log.Errorf("failed to create org object: %s", err.Error())
		return nil, err
	}
	c := &Cleaner{org: org, toolData: newToolData()}
	return c, nil
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

	log.Info("clean dirty data started", c.org.LogPrefix)
	c.cleanVMDirty()
	c.cleanNetworkDirty()
	c.cleanVRouterDirty()
	c.cleanPodIngressDirty()
	c.cleanPodServiceDirty()
	c.cleanPodNodeDirty()
	c.cleanPodGroupDirty()
	c.cleanPodDirty()
	c.cleanVInterfaceDirty()
	log.Info("clean dirty data completed", c.org.LogPrefix)
}

func (c *Cleaner) cleanVMDirty() {
	vmIDs := getIDs[mysqlmodel.VM](c.org.DB)
	if len(vmIDs) != 0 {
		var vifs []*mysqlmodel.VInterface
		c.org.DB.Where("devicetype = ? AND deviceid NOT IN ?", ctrlrcommon.VIF_DEVICE_TYPE_VM, vmIDs).Find(&vifs)
		if len(vifs) != 0 {
			c.org.DB.Delete(&vifs)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_VM_EN, vifs), c.org.LogPrefix)
		}
	}
}

func (c *Cleaner) cleanNetworkDirty() {
	networkIDs := getIDs[mysqlmodel.Network](c.org.DB)
	if len(networkIDs) != 0 {
		var subnets []*mysqlmodel.Subnet
		c.org.DB.Where("vl2id NOT IN ?", networkIDs).Find(&subnets)
		if len(subnets) != 0 {
			c.org.DB.Delete(&subnets)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_SUBNET_EN, ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, subnets), c.org.LogPrefix)
		}
	}
}

func (c *Cleaner) cleanVRouterDirty() {
	vrouterIDs := getIDs[mysqlmodel.VRouter](c.org.DB)
	if len(vrouterIDs) != 0 {
		var rts []*mysqlmodel.RoutingTable
		c.org.DB.Where("vnet_id NOT IN ?", vrouterIDs).Find(&rts)
		if len(rts) != 0 {
			c.org.DB.Delete(&rts)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_ROUTING_TABLE_EN, ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, rts), c.org.LogPrefix)
		}
	}
}

func (c *Cleaner) cleanPodIngressDirty() {
	podIngressIDs := getIDs[mysqlmodel.PodIngress](c.org.DB)
	if len(podIngressIDs) != 0 {
		var podIngressRules []*mysqlmodel.PodIngressRule
		c.org.DB.Where("pod_ingress_id NOT IN ?", podIngressIDs).Find(&podIngressRules)
		if len(podIngressRules) != 0 {
			c.org.DB.Delete(&podIngressRules)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, podIngressRules), c.org.LogPrefix)
		}

		var podIngressRuleBkds []*mysqlmodel.PodIngressRuleBackend
		c.org.DB.Where("pod_ingress_id NOT IN ?", podIngressIDs).Find(&podIngressRuleBkds)
		if len(podIngressRuleBkds) != 0 {
			c.org.DB.Delete(&podIngressRuleBkds)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, podIngressRuleBkds), c.org.LogPrefix)
		}
	}
}

func (c *Cleaner) cleanPodServiceDirty() {
	podServiceIDs := getIDs[mysqlmodel.PodService](c.org.DB)
	if len(podServiceIDs) != 0 {
		var podServicePorts []*mysqlmodel.PodServicePort
		c.org.DB.Where("pod_service_id NOT IN ?", podServiceIDs).Find(&podServicePorts)
		if len(podServicePorts) != 0 {
			c.org.DB.Delete(&podServicePorts)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_PORT_EN, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, podServicePorts), c.org.LogPrefix)
		}

		var podGroupPorts []*mysqlmodel.PodGroupPort
		c.org.DB.Where("pod_service_id NOT IN ?", podServiceIDs).Find(&podGroupPorts)
		if len(podGroupPorts) != 0 {
			c.org.DB.Delete(&podGroupPorts)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, podGroupPorts), c.org.LogPrefix)
		}

		var vifs []*mysqlmodel.VInterface
		c.org.DB.Where("devicetype = ? AND deviceid NOT IN ?", ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE, podServiceIDs).Find(&vifs)
		if len(vifs) != 0 {
			c.org.DB.Delete(&vifs)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, vifs), c.org.LogPrefix)
		}
	}
}

func (c *Cleaner) cleanPodGroupDirty() {
	podGroupIDs := getIDs[mysqlmodel.PodGroup](c.org.DB)
	if len(podGroupIDs) != 0 {
		var podGroupPorts []*mysqlmodel.PodGroupPort
		c.org.DB.Where("pod_group_id NOT IN ?", podGroupIDs).Find(&podGroupPorts)
		if len(podGroupPorts) != 0 {
			c.org.DB.Delete(&podGroupPorts)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN, ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, podGroupPorts), c.org.LogPrefix)
		}

		var pods []*mysqlmodel.Pod
		c.org.DB.Where("pod_group_id NOT IN ?", podGroupIDs).Find(&pods)
		if len(pods) != 0 {
			c.org.DB.Delete(&pods)
			publishTagrecorder(c.org.DB, pods, ctrlrcommon.RESOURCE_TYPE_POD_EN, c.toolData)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_EN, ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, pods), c.org.LogPrefix)
		}
	}
}

func (c *Cleaner) cleanPodNodeDirty() {
	podNodeIDs := getIDs[mysqlmodel.PodNode](c.org.DB)
	if len(podNodeIDs) != 0 {
		var vifs []*mysqlmodel.VInterface
		c.org.DB.Where("devicetype = ? AND deviceid NOT IN ?", ctrlrcommon.VIF_DEVICE_TYPE_POD_NODE, podNodeIDs).Find(&vifs)
		if len(vifs) != 0 {
			c.org.DB.Delete(&vifs)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, vifs), c.org.LogPrefix)
		}

		var vmPodNodeConns []*mysqlmodel.VMPodNodeConnection
		c.org.DB.Where("pod_node_id NOT IN ?", podNodeIDs).Find(&vmPodNodeConns)
		if len(vmPodNodeConns) != 0 {
			c.org.DB.Delete(&vmPodNodeConns)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, vmPodNodeConns), c.org.LogPrefix)
		}

		var pods []*mysqlmodel.Pod
		c.org.DB.Where("pod_node_id != 0 AND pod_node_id NOT IN ?", podNodeIDs).Find(&pods)
		if len(pods) != 0 {
			c.org.DB.Delete(&pods)
			publishTagrecorder(c.org.DB, pods, ctrlrcommon.RESOURCE_TYPE_POD_EN, c.toolData)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_EN, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, pods), c.org.LogPrefix)
		}
	}
}

func (c *Cleaner) cleanPodDirty() {
	podIDs := getIDs[mysqlmodel.Pod](c.org.DB)
	if len(podIDs) != 0 {
		var vifs []*mysqlmodel.VInterface
		c.org.DB.Where("devicetype = ? AND deviceid NOT IN ?", ctrlrcommon.VIF_DEVICE_TYPE_POD, podIDs).Find(&vifs)
		if len(vifs) != 0 {
			c.org.DB.Delete(&vifs)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_POD_EN, vifs), c.org.LogPrefix)
		}
	}
}

func (c *Cleaner) cleanVInterfaceDirty() {
	vifIDs := getIDs[mysqlmodel.VInterface](c.org.DB)
	if len(vifIDs) != 0 {
		var lanIPs []*mysqlmodel.LANIP
		c.org.DB.Where("vifid NOT IN ?", vifIDs).Find(&lanIPs)
		if len(lanIPs) != 0 {
			c.org.DB.Delete(&lanIPs)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN, ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, lanIPs), c.org.LogPrefix)
		}
		var wanIPs []*mysqlmodel.WANIP
		c.org.DB.Where("vifid NOT IN ?", vifIDs).Find(&wanIPs)
		if len(wanIPs) != 0 {
			c.org.DB.Delete(&wanIPs)
			log.Error(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN, ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, wanIPs), c.org.LogPrefix)
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

func getIDs[MT constraint.MySQLModel](db *mysql.DB) (ids []int) {
	var dbItems []*MT
	db.Select("id").Find(&dbItems)
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
