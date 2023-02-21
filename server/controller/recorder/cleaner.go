/*
 * Copyright (c) 2022 Yunshan Networks
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
	"time"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	. "github.com/deepflowio/deepflow/server/controller/recorder/common"
	. "github.com/deepflowio/deepflow/server/controller/recorder/config"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
	"gorm.io/gorm/clause"
)

type ResourceCleaner struct {
	ctx    context.Context
	cancel context.CancelFunc
	cfg    *RecorderConfig
}

func NewResourceCleaner(cfg *RecorderConfig, ctx context.Context) *ResourceCleaner {
	cCtx, cCancel := context.WithCancel(ctx)
	return &ResourceCleaner{cfg: cfg, ctx: cCtx, cancel: cCancel}
}

func (c *ResourceCleaner) Start() {
	log.Info("resource clean started")
	// 定时清理软删除资源数据
	// timed clean soft deleted resource data
	c.timedCleanDeletedData(int(c.cfg.DeletedResourceCleanInterval), int(c.cfg.DeletedResourceRetentionTime))
	// 定时删除所属上级资源已不存在（被彻底清理或软删除）的资源数据，并记录异常日志
	// timed clean the resource data of the parent resource that does not exist (means it is completely deleted or soft deleted)
	// and record error logs
	c.timedCleanDirtyData()
}

func (c *ResourceCleaner) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	log.Info("resource clean stopped")
}

func (c *ResourceCleaner) timedCleanDeletedData(cleanInterval, retentionInterval int) {
	c.cleanDeletedData(retentionInterval)
	go func() {
		for range time.Tick(time.Duration(cleanInterval) * time.Hour) {
			c.cleanDeletedData(retentionInterval)
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

func (c *ResourceCleaner) cleanDeletedData(retentionInterval int) {
	expiredAt := time.Now().Add(time.Duration(-retentionInterval) * time.Hour)
	log.Infof("clean soft deleted resources (deleted_at < %s) started", expiredAt.Format(common.GO_BIRTHDAY))
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
	log.Info("clean soft deleted resources completed")
}

type IDDataSet struct {
	networkIDs       []int
	vrouterIDs       []int
	securityGroupIDs []int
	podIngressIDs    []int
	podServiceIDs    []int
}

func getIDs[MT constraint.MySQLModel]() (ids []int) {
	var dbItems []*MT
	mysql.Db.Select("id").Find(&dbItems)
	for _, item := range dbItems {
		ids = append(ids, (*item).GetID())
	}
	return
}

func (c *ResourceCleaner) createIDDataSet() *IDDataSet {
	idDS := &IDDataSet{}
	idDS.networkIDs = getIDs[mysql.Network]()
	idDS.vrouterIDs = getIDs[mysql.VRouter]()
	idDS.securityGroupIDs = getIDs[mysql.SecurityGroup]()
	idDS.podIngressIDs = getIDs[mysql.PodIngress]()
	idDS.podServiceIDs = getIDs[mysql.PodService]()
	return idDS
}

func (c *ResourceCleaner) timedCleanDirtyData() {
	c.cleanDirtyData()
	go func() {
		for range time.Tick(time.Duration(50) * time.Minute) {
			c.cleanDirtyData()
		}
	}()
}

func (c *ResourceCleaner) cleanDirtyData() {
	log.Info("clean dirty data started")
	idDS := c.createIDDataSet()
	if len(idDS.networkIDs) != 0 {
		var subnets []mysql.Subnet
		mysql.Db.Clauses(clause.Returning{}).Where("vl2id NOT IN ?", idDS.networkIDs).Delete(&subnets)
		logErrorDeleteResourceTypeABecuaseResourceTypeBHasGone(RESOURCE_TYPE_SUBNET_EN, RESOURCE_TYPE_NETWORK_EN, subnets)
	}
	if len(idDS.vrouterIDs) != 0 {
		var routingTables []mysql.RoutingTable
		mysql.Db.Clauses(clause.Returning{}).Where("vnet_id NOT IN ?", idDS.vrouterIDs).Delete(&routingTables)
		logErrorDeleteResourceTypeABecuaseResourceTypeBHasGone(RESOURCE_TYPE_ROUTING_TABLE_EN, RESOURCE_TYPE_VROUTER_EN, routingTables)
	}
	if len(idDS.securityGroupIDs) != 0 {
		var sgRules []mysql.SecurityGroupRule
		mysql.Db.Clauses(clause.Returning{}).Where("sg_id NOT IN ?", idDS.securityGroupIDs).Delete(&sgRules)
		logErrorDeleteResourceTypeABecuaseResourceTypeBHasGone(RESOURCE_TYPE_SECURITY_GROUP_RULE_EN, RESOURCE_TYPE_SECURITY_GROUP_EN, sgRules)

		var vmSGs []mysql.VMSecurityGroup
		mysql.Db.Clauses(clause.Returning{}).Where("sg_id NOT IN ?", idDS.securityGroupIDs).Delete(&vmSGs)
		logErrorDeleteResourceTypeABecuaseResourceTypeBHasGone(RESOURCE_TYPE_VM_SECURITY_GROUP_EN, RESOURCE_TYPE_SECURITY_GROUP_EN, vmSGs)
	}
	if len(idDS.podIngressIDs) != 0 {
		var podIngressRules []mysql.PodIngressRule
		mysql.Db.Clauses(clause.Returning{}).Where("pod_ingress_id NOT IN ?", idDS.podIngressIDs).Delete(&podIngressRules)
		logErrorDeleteResourceTypeABecuaseResourceTypeBHasGone(RESOURCE_TYPE_POD_INGRESS_RULE_EN, RESOURCE_TYPE_POD_INGRESS_EN, podIngressRules)

		var podIngressRuleBkds []mysql.PodIngressRuleBackend
		mysql.Db.Clauses(clause.Returning{}).Where("pod_ingress_id NOT IN ?", idDS.podIngressIDs).Delete(&podIngressRuleBkds)
		logErrorDeleteResourceTypeABecuaseResourceTypeBHasGone(RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN, RESOURCE_TYPE_POD_INGRESS_EN, podIngressRuleBkds)
	}
	if len(idDS.podServiceIDs) != 0 {
		var podServicePorts []mysql.PodServicePort
		mysql.Db.Clauses(clause.Returning{}).Where("pod_service_id NOT IN ?", idDS.podServiceIDs).Delete(&podServicePorts)
		logErrorDeleteResourceTypeABecuaseResourceTypeBHasGone(RESOURCE_TYPE_POD_SERVICE_PORT_EN, RESOURCE_TYPE_POD_SERVICE_EN, podServicePorts)

		var podGroupPorts []mysql.PodGroupPort
		mysql.Db.Clauses(clause.Returning{}).Where("pod_service_id NOT IN ?", idDS.podServiceIDs).Delete(&podGroupPorts)
		logErrorDeleteResourceTypeABecuaseResourceTypeBHasGone(RESOURCE_TYPE_POD_GROUP_PORT_EN, RESOURCE_TYPE_POD_SERVICE_EN, podGroupPorts)
	}
	log.Info("clean dirty data completed")
}

func logErrorDeleteResourceTypeABecuaseResourceTypeBHasGone[MT constraint.MySQLModel](a, b string, items []MT) {
	if len(items) != 0 {
		log.Errorf("delete %s: %+v because %s has gone", a, items, b)
	}
}
