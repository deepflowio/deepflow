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

func (c *Cleaners) Start() error {
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
	c.timedCleanDeletedData()
	// 定时删除所属上级资源已不存在（被彻底清理或软删除）的资源数据，并记录异常日志
	// timed clean the resource data of the parent resource that does not exist (means it is completely deleted or soft deleted)
	// and record error logs
	c.timedCleanDirtyData()

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

func (c *Cleaners) timedCleanDeletedData() {
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

func (c *Cleaners) timedCleanDirtyData() {
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
	org *common.ORG
}

func newCleaner(orgID int) (*Cleaner, error) {
	org, err := common.NewORG(orgID)
	if err != nil {
		log.Errorf("failed to create org object: %s", err.Error())
		return nil, err
	}
	c := &Cleaner{org: org}
	return c, nil
}

func (c *Cleaner) cleanDeletedData(retentionInterval int) {
	expiredAt := time.Now().Add(time.Duration(-retentionInterval) * time.Hour)
	log.Info(c.org.LogPre("clean soft deleted resources (deleted_at < %s) started", expiredAt.Format(ctrlrcommon.GO_BIRTHDAY)))
	deleteExpired[mysql.Region](c.org.DB, expiredAt)
	deleteExpired[mysql.AZ](c.org.DB, expiredAt)
	deleteExpired[mysql.Host](c.org.DB, expiredAt)
	deleteExpired[mysql.VM](c.org.DB, expiredAt)
	deleteExpired[mysql.VPC](c.org.DB, expiredAt)
	deleteExpired[mysql.Network](c.org.DB, expiredAt)
	deleteExpired[mysql.VRouter](c.org.DB, expiredAt)
	deleteExpired[mysql.DHCPPort](c.org.DB, expiredAt)
	deleteExpired[mysql.SecurityGroup](c.org.DB, expiredAt)
	deleteExpired[mysql.NATGateway](c.org.DB, expiredAt)
	deleteExpired[mysql.LB](c.org.DB, expiredAt)
	deleteExpired[mysql.LBListener](c.org.DB, expiredAt)
	deleteExpired[mysql.CEN](c.org.DB, expiredAt)
	deleteExpired[mysql.PeerConnection](c.org.DB, expiredAt)
	deleteExpired[mysql.RDSInstance](c.org.DB, expiredAt)
	deleteExpired[mysql.RedisInstance](c.org.DB, expiredAt)
	deleteExpired[mysql.PodCluster](c.org.DB, expiredAt)
	deleteExpired[mysql.PodNode](c.org.DB, expiredAt)
	deleteExpired[mysql.PodNamespace](c.org.DB, expiredAt)
	deleteExpired[mysql.PodIngress](c.org.DB, expiredAt)
	deleteExpired[mysql.PodService](c.org.DB, expiredAt)
	deleteExpired[mysql.PodGroup](c.org.DB, expiredAt)
	deleteExpired[mysql.PodReplicaSet](c.org.DB, expiredAt)
	deleteExpired[mysql.Pod](c.org.DB, expiredAt)
	deleteExpired[mysql.Process](c.org.DB, expiredAt)
	deleteExpired[mysql.PrometheusTarget](c.org.DB, expiredAt)
	log.Info(c.org.LogPre("clean soft deleted resources completed"))
}

func (c *Cleaner) cleanDirtyData() {
	log.Info(c.org.LogPre("clean dirty data started"))
	c.cleanNetworkDirty()
	c.cleanVRouterDirty()
	c.cleanSecurityGroupDirty()
	c.cleanPodIngressDirty()
	c.cleanPodServiceDirty()
	c.cleanPodNodeDirty()
	c.cleanPodDirty()
	c.cleanVInterfaceDirty()
	log.Info(c.org.LogPre("clean dirty data completed"))
}

func (c *Cleaner) cleanNetworkDirty() {
	networkIDs := getIDs[mysql.Network](c.org.DB)
	if len(networkIDs) != 0 {
		var subnets []mysql.Subnet
		c.org.DB.Where("vl2id NOT IN ?", networkIDs).Find(&subnets)
		if len(subnets) != 0 {
			c.org.DB.Delete(&subnets)
			log.Error(c.org.LogPre(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_SUBNET_EN, ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, subnets)))
		}
	}
}

func (c *Cleaner) cleanVRouterDirty() {
	vrouterIDs := getIDs[mysql.VRouter](c.org.DB)
	if len(vrouterIDs) != 0 {
		var rts []mysql.RoutingTable
		c.org.DB.Where("vnet_id NOT IN ?", vrouterIDs).Find(&rts)
		if len(rts) != 0 {
			c.org.DB.Delete(&rts)
			log.Error(c.org.LogPre(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_ROUTING_TABLE_EN, ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, rts)))
		}
	}
}
func (c *Cleaner) cleanSecurityGroupDirty() {
	securityGroupIDs := getIDs[mysql.SecurityGroup](c.org.DB)
	if len(securityGroupIDs) != 0 {
		var sgRules []mysql.SecurityGroupRule
		c.org.DB.Where("sg_id NOT IN ?", securityGroupIDs).Find(&sgRules)
		if len(sgRules) != 0 {
			c.org.DB.Delete(&sgRules)
			log.Error(c.org.LogPre(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_SECURITY_GROUP_RULE_EN, ctrlrcommon.RESOURCE_TYPE_SECURITY_GROUP_EN, sgRules)))
		}

		var vmSGs []mysql.VMSecurityGroup
		c.org.DB.Where("sg_id NOT IN ?", securityGroupIDs).Find(&vmSGs)
		if len(vmSGs) != 0 {
			c.org.DB.Delete(&vmSGs)
			log.Error(c.org.LogPre(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VM_SECURITY_GROUP_EN, ctrlrcommon.RESOURCE_TYPE_SECURITY_GROUP_EN, vmSGs)))
		}
	}
}

func (c *Cleaner) cleanPodIngressDirty() {
	podIngressIDs := getIDs[mysql.PodIngress](c.org.DB)
	if len(podIngressIDs) != 0 {
		var podIngressRules []mysql.PodIngressRule
		c.org.DB.Where("pod_ingress_id NOT IN ?", podIngressIDs).Find(&podIngressRules)
		if len(podIngressRules) != 0 {
			c.org.DB.Delete(&podIngressRules)
			log.Error(c.org.LogPre(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, podIngressRules)))
		}

		var podIngressRuleBkds []mysql.PodIngressRuleBackend
		c.org.DB.Where("pod_ingress_id NOT IN ?", podIngressIDs).Find(&podIngressRuleBkds)
		if len(podIngressRuleBkds) != 0 {
			c.org.DB.Delete(&podIngressRuleBkds)
			log.Error(c.org.LogPre(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, podIngressRuleBkds)))
		}
	}
}

func (c *Cleaner) cleanPodServiceDirty() {
	podServiceIDs := getIDs[mysql.PodService](c.org.DB)
	if len(podServiceIDs) != 0 {
		var podServicePorts []mysql.PodServicePort
		c.org.DB.Where("pod_service_id NOT IN ?", podServiceIDs).Find(&podServicePorts)
		if len(podServicePorts) != 0 {
			c.org.DB.Delete(&podServicePorts)
			log.Error(c.org.LogPre(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_PORT_EN, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, podServicePorts)))
		}

		var podGroupPorts []mysql.PodGroupPort
		c.org.DB.Where("pod_service_id NOT IN ?", podServiceIDs).Find(&podGroupPorts)
		if len(podGroupPorts) != 0 {
			c.org.DB.Delete(&podGroupPorts)
			log.Error(c.org.LogPre(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, podGroupPorts)))
		}

		var vifs []mysql.VInterface
		c.org.DB.Where("devicetype = ? AND deviceid NOT IN ?", ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE, podServiceIDs).Find(&vifs)
		if len(vifs) != 0 {
			c.org.DB.Delete(&vifs)
			log.Error(c.org.LogPre(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, vifs)))
		}
	}
}

func (c *Cleaner) cleanPodNodeDirty() {
	podNodeIDs := getIDs[mysql.PodNode](c.org.DB)
	if len(podNodeIDs) != 0 {
		var vifs []mysql.VInterface
		c.org.DB.Where("devicetype = ? AND deviceid NOT IN ?", ctrlrcommon.VIF_DEVICE_TYPE_POD_NODE, podNodeIDs).Find(&vifs)
		if len(vifs) != 0 {
			c.org.DB.Delete(&vifs)
			log.Error(c.org.LogPre(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, vifs)))
		}

		var vmPodNodeConns []mysql.VMPodNodeConnection
		c.org.DB.Where("pod_node_id NOT IN ?", podNodeIDs).Find(&vmPodNodeConns)
		if len(vmPodNodeConns) != 0 {
			c.org.DB.Delete(&vmPodNodeConns)
			log.Error(c.org.LogPre(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, vmPodNodeConns)))
		}

		var pods []mysql.Pod
		c.org.DB.Where("pod_node_id NOT IN ?", podNodeIDs).Find(&pods)
		if len(pods) != 0 {
			c.org.DB.Delete(&pods)
			log.Error(c.org.LogPre(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_EN, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, pods)))
		}
	}
}

func (c *Cleaner) cleanPodDirty() {
	podIDs := getIDs[mysql.Pod](c.org.DB)
	if len(podIDs) != 0 {
		var vifs []mysql.VInterface
		c.org.DB.Where("devicetype = ? AND deviceid NOT IN ?", ctrlrcommon.VIF_DEVICE_TYPE_POD, podIDs).Find(&vifs)
		if len(vifs) != 0 {
			c.org.DB.Delete(&vifs)
			log.Error(c.org.LogPre(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_POD_EN, vifs)))
		}
	}
}

func (c *Cleaner) cleanVInterfaceDirty() {
	vifIDs := getIDs[mysql.VInterface](c.org.DB)
	if len(vifIDs) != 0 {
		var lanIPs []mysql.LANIP
		c.org.DB.Where("vifid NOT IN ?", vifIDs).Find(&lanIPs)
		if len(lanIPs) != 0 {
			c.org.DB.Delete(&lanIPs)
			log.Error(c.org.LogPre(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN, ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, lanIPs)))
		}
		var wanIPs []mysql.WANIP
		c.org.DB.Where("vifid NOT IN ?", vifIDs).Find(&wanIPs)
		if len(wanIPs) != 0 {
			c.org.DB.Delete(&wanIPs)
			log.Error(c.org.LogPre(formatLogDeleteABecauseBHasGone(ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN, ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, wanIPs)))
		}
	}
}

func formatLogDeleteABecauseBHasGone[MT constraint.MySQLModel](a, b string, items []MT) string {
	var str string
	for _, item := range items {
		str += fmt.Sprintf("%+v ", item)
	}
	return fmt.Sprintf("delete %s: %s because %s has gone", a, str, b)
}

func deleteExpired[MT constraint.MySQLSoftDeleteModel](db *mysql.DB, expiredAt time.Time) {
	err := db.Unscoped().Where("deleted_at < ?", expiredAt).Delete(new(MT)).Error
	if err != nil {
		log.Errorf("oid: %d, mysql delete resource failed: %v", db.GetORGID(), err)
	}
}

func getIDs[MT constraint.MySQLModel](db *mysql.DB) (ids []int) {
	var dbItems []*MT
	db.Select("id").Find(&dbItems)
	for _, item := range dbItems {
		ids = append(ids, (*item).GetID())
	}
	return
}
