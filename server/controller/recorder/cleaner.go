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
	"sync"
	"time"

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	. "github.com/deepflowio/deepflow/server/controller/recorder/config"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
)

var (
	cleanerOnce sync.Once
	cleaner     *Cleaner
)

type Cleaner struct {
	ctx    context.Context
	cancel context.CancelFunc
	cfg    *RecorderConfig
}

func GetSingletonCleaner() *Cleaner {
	cleanerOnce.Do(func() {
		cleaner = new(Cleaner)
	})
	return cleaner
}

func (c *Cleaner) Init(cfg *RecorderConfig) {
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.cfg = cfg
}

func (c *Cleaner) Start() {
	log.Info("resource clean started")
	// 定时清理软删除资源数据
	// timed clean soft deleted resource data
	c.timedCleanDeletedData(int(c.cfg.DeletedResourceCleanInterval), int(c.cfg.DeletedResourceRetentionTime))
	// 定时删除所属上级资源已不存在（被彻底清理或软删除）的资源数据，并记录异常日志
	// timed clean the resource data of the parent resource that does not exist (means it is completely deleted or soft deleted)
	// and record error logs
	c.timedCleanDirtyData()
}

func (c *Cleaner) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	log.Info("resource clean stopped")
}

func (c *Cleaner) timedCleanDeletedData(cleanInterval, retentionInterval int) {
	c.cleanDeletedData(retentionInterval)
	go func() {
		ticker := time.NewTicker(time.Duration(cleanInterval) * time.Hour)
		defer ticker.Stop()
	LOOP:
		for {
			select {
			case <-ticker.C:
				c.cleanDeletedData(retentionInterval)
			case <-c.ctx.Done():
				break LOOP
			}
		}
	}()
}

// TODO better name and param
func forceDelete[MT constraint.MySQLSoftDeleteModel](expiredAt time.Time) {
	err := mysql.Db.Unscoped().Where("deleted_at < ?", expiredAt).Delete(new(MT)).Error
	if err != nil {
		log.Errorf("mysql delete resource failed: %v", err)
	}
}

func (c *Cleaner) cleanDeletedData(retentionInterval int) {
	expiredAt := time.Now().Add(time.Duration(-retentionInterval) * time.Hour)
	log.Infof("clean soft deleted resources (deleted_at < %s) started", expiredAt.Format(ctrlrcommon.GO_BIRTHDAY))
	forceDelete[mysql.Region](expiredAt)
	forceDelete[mysql.AZ](expiredAt)
	forceDelete[mysql.Host](expiredAt)
	forceDelete[mysql.VM](expiredAt)
	forceDelete[mysql.VPC](expiredAt)
	forceDelete[mysql.Network](expiredAt)
	forceDelete[mysql.VRouter](expiredAt)
	forceDelete[mysql.DHCPPort](expiredAt)
	forceDelete[mysql.SecurityGroup](expiredAt)
	forceDelete[mysql.NATGateway](expiredAt)
	forceDelete[mysql.LB](expiredAt)
	forceDelete[mysql.LBListener](expiredAt)
	forceDelete[mysql.CEN](expiredAt)
	forceDelete[mysql.PeerConnection](expiredAt)
	forceDelete[mysql.RDSInstance](expiredAt)
	forceDelete[mysql.RedisInstance](expiredAt)
	forceDelete[mysql.PodCluster](expiredAt)
	forceDelete[mysql.PodNode](expiredAt)
	forceDelete[mysql.PodNamespace](expiredAt)
	forceDelete[mysql.PodIngress](expiredAt)
	forceDelete[mysql.PodService](expiredAt)
	forceDelete[mysql.PodGroup](expiredAt)
	forceDelete[mysql.PodReplicaSet](expiredAt)
	forceDelete[mysql.Pod](expiredAt)
	forceDelete[mysql.Process](expiredAt)
	forceDelete[mysql.PrometheusTarget](expiredAt)
	log.Info("clean soft deleted resources completed")
}

func getIDs[MT constraint.MySQLModel]() (ids []int) {
	var dbItems []*MT
	mysql.Db.Select("id").Find(&dbItems)
	for _, item := range dbItems {
		ids = append(ids, (*item).GetID())
	}
	return
}

func (c *Cleaner) timedCleanDirtyData() {
	c.cleanDirtyData()
	go func() {
		ticker := time.NewTicker(time.Duration(50) * time.Minute)
		defer ticker.Stop()
	LOOP:
		for {
			select {
			case <-ticker.C:
				c.cleanDirtyData()
			case <-c.ctx.Done():
				break LOOP
			}
		}
	}()
}

func (c *Cleaner) cleanDirtyData() {
	log.Info("clean dirty data started")
	c.cleanNetworkDirty()
	c.cleanVRouterDirty()
	c.cleanSecurityGroupDirty()
	c.cleanPodIngressDirty()
	c.cleanPodServiceDirty()
	c.cleanPodNodeDirty()
	c.cleanPodDirty()
	c.cleanVInterfaceDirty()
	log.Info("clean dirty data completed")
}

func (c *Cleaner) cleanNetworkDirty() {
	networkIDs := getIDs[mysql.Network]()
	if len(networkIDs) != 0 {
		var subnets []mysql.Subnet
		mysql.Db.Where("vl2id NOT IN ?", networkIDs).Find(&subnets)
		if len(subnets) != 0 {
			mysql.Db.Delete(&subnets)
			logErrorDeleteResourceTypeABecauseResourceTypeBHasGone(ctrlrcommon.RESOURCE_TYPE_SUBNET_EN, ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, subnets)
		}
	}
}

func (c *Cleaner) cleanVRouterDirty() {
	vrouterIDs := getIDs[mysql.VRouter]()
	if len(vrouterIDs) != 0 {
		var rts []mysql.RoutingTable
		mysql.Db.Where("vnet_id NOT IN ?", vrouterIDs).Find(&rts)
		if len(rts) != 0 {
			mysql.Db.Delete(&rts)
			logErrorDeleteResourceTypeABecauseResourceTypeBHasGone(ctrlrcommon.RESOURCE_TYPE_ROUTING_TABLE_EN, ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, rts)
		}
	}
}
func (c *Cleaner) cleanSecurityGroupDirty() {
	securityGroupIDs := getIDs[mysql.SecurityGroup]()
	if len(securityGroupIDs) != 0 {
		var sgRules []mysql.SecurityGroupRule
		mysql.Db.Where("sg_id NOT IN ?", securityGroupIDs).Find(&sgRules)
		if len(sgRules) != 0 {
			mysql.Db.Delete(&sgRules)
			logErrorDeleteResourceTypeABecauseResourceTypeBHasGone(ctrlrcommon.RESOURCE_TYPE_SECURITY_GROUP_RULE_EN, ctrlrcommon.RESOURCE_TYPE_SECURITY_GROUP_EN, sgRules)
		}

		var vmSGs []mysql.VMSecurityGroup
		mysql.Db.Where("sg_id NOT IN ?", securityGroupIDs).Find(&vmSGs)
		if len(vmSGs) != 0 {
			mysql.Db.Delete(&vmSGs)
			logErrorDeleteResourceTypeABecauseResourceTypeBHasGone(ctrlrcommon.RESOURCE_TYPE_VM_SECURITY_GROUP_EN, ctrlrcommon.RESOURCE_TYPE_SECURITY_GROUP_EN, vmSGs)
		}
	}
}

func (c *Cleaner) cleanPodIngressDirty() {
	podIngressIDs := getIDs[mysql.PodIngress]()
	if len(podIngressIDs) != 0 {
		var podIngressRules []mysql.PodIngressRule
		mysql.Db.Where("pod_ingress_id NOT IN ?", podIngressIDs).Find(&podIngressRules)
		if len(podIngressRules) != 0 {
			mysql.Db.Delete(&podIngressRules)
			logErrorDeleteResourceTypeABecauseResourceTypeBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, podIngressRules)
		}

		var podIngressRuleBkds []mysql.PodIngressRuleBackend
		mysql.Db.Where("pod_ingress_id NOT IN ?", podIngressIDs).Find(&podIngressRuleBkds)
		if len(podIngressRuleBkds) != 0 {
			mysql.Db.Delete(&podIngressRuleBkds)
			logErrorDeleteResourceTypeABecauseResourceTypeBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, podIngressRuleBkds)
		}
	}
}

func (c *Cleaner) cleanPodServiceDirty() {
	podServiceIDs := getIDs[mysql.PodService]()
	if len(podServiceIDs) != 0 {
		var podServicePorts []mysql.PodServicePort
		mysql.Db.Where("pod_service_id NOT IN ?", podServiceIDs).Find(&podServicePorts)
		if len(podServicePorts) != 0 {
			mysql.Db.Delete(&podServicePorts)
			logErrorDeleteResourceTypeABecauseResourceTypeBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_PORT_EN, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, podServicePorts)
		}

		var podGroupPorts []mysql.PodGroupPort
		mysql.Db.Where("pod_service_id NOT IN ?", podServiceIDs).Find(&podGroupPorts)
		if len(podGroupPorts) != 0 {
			mysql.Db.Delete(&podGroupPorts)
			logErrorDeleteResourceTypeABecauseResourceTypeBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, podGroupPorts)
		}

		var vifs []mysql.VInterface
		mysql.Db.Where("devicetype = ? AND deviceid NOT IN ?", ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE, podServiceIDs).Find(&vifs)
		if len(vifs) != 0 {
			mysql.Db.Delete(&vifs)
			logErrorDeleteResourceTypeABecauseResourceTypeBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, vifs)
		}
	}
}

func (c *Cleaner) cleanPodNodeDirty() {
	podNodeIDs := getIDs[mysql.PodNode]()
	if len(podNodeIDs) != 0 {
		var vifs []mysql.VInterface
		mysql.Db.Where("devicetype = ? AND deviceid NOT IN ?", ctrlrcommon.VIF_DEVICE_TYPE_POD_NODE, podNodeIDs).Find(&vifs)
		if len(vifs) != 0 {
			mysql.Db.Delete(&vifs)
			logErrorDeleteResourceTypeABecauseResourceTypeBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, vifs)
		}

		var vmPodNodeConns []mysql.VMPodNodeConnection
		mysql.Db.Where("pod_node_id NOT IN ?", podNodeIDs).Find(&vmPodNodeConns)
		if len(vmPodNodeConns) != 0 {
			mysql.Db.Delete(&vmPodNodeConns)
			logErrorDeleteResourceTypeABecauseResourceTypeBHasGone(ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, vmPodNodeConns)
		}

		var pods []mysql.Pod
		mysql.Db.Where("pod_node_id NOT IN ?", podNodeIDs).Find(&pods)
		if len(pods) != 0 {
			mysql.Db.Delete(&pods)
			logErrorDeleteResourceTypeABecauseResourceTypeBHasGone(ctrlrcommon.RESOURCE_TYPE_POD_EN, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, pods)
		}
	}
}

func (c *Cleaner) cleanPodDirty() {
	podIDs := getIDs[mysql.Pod]()
	if len(podIDs) != 0 {
		var vifs []mysql.VInterface
		mysql.Db.Where("devicetype = ? AND deviceid NOT IN ?", ctrlrcommon.VIF_DEVICE_TYPE_POD, podIDs).Find(&vifs)
		if len(vifs) != 0 {
			mysql.Db.Delete(&vifs)
			logErrorDeleteResourceTypeABecauseResourceTypeBHasGone(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_POD_EN, vifs)
		}
	}
}

func (c *Cleaner) cleanVInterfaceDirty() {
	vifIDs := getIDs[mysql.VInterface]()
	if len(vifIDs) != 0 {
		var lanIPs []mysql.LANIP
		mysql.Db.Where("vifid NOT IN ?", vifIDs).Find(&lanIPs)
		if len(lanIPs) != 0 {
			mysql.Db.Delete(&lanIPs)
			logErrorDeleteResourceTypeABecauseResourceTypeBHasGone(ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN, ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, lanIPs)
		}
		var wanIPs []mysql.WANIP
		mysql.Db.Where("vifid NOT IN ?", vifIDs).Find(&wanIPs)
		if len(wanIPs) != 0 {
			mysql.Db.Delete(&wanIPs)
			logErrorDeleteResourceTypeABecauseResourceTypeBHasGone(ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN, ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, wanIPs)
		}
	}
}

func logErrorDeleteResourceTypeABecauseResourceTypeBHasGone[MT constraint.MySQLModel](a, b string, items []MT) {
	for _, item := range items {
		log.Errorf("delete %s: %+v because %s has gone", a, item, b)
	}
}
