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

package resource

import (
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/common"
	"github.com/deepflowio/deepflow/server/controller/http/service"
)

const (
	TEST_DB_FILE = "./domain_test.db"
)

type SuiteTest struct {
	suite.Suite
	db *gorm.DB
}

func TestSuite(t *testing.T) {
	if _, err := os.Stat(TEST_DB_FILE); err == nil {
		os.Remove(TEST_DB_FILE)
	}
	mysql.Db = GetDB()
	suite.Run(t, new(SuiteTest))
}

func (t *SuiteTest) SetupSuite() {
	t.db = mysql.Db
	for _, val := range getMySQLModels() {
		t.db.AutoMigrate(val)
	}
}

func (t *SuiteTest) TearDownSuite() {
	sqlDB, _ := t.db.DB()
	sqlDB.Close()
	os.Remove(TEST_DB_FILE)
}

func GetDB() *gorm.DB {
	db, err := gorm.Open(
		sqlite.Open(TEST_DB_FILE),
		&gorm.Config{NamingStrategy: schema.NamingStrategy{SingularTable: true}},
	)
	if err != nil {
		fmt.Printf("create sqlite database failed: %s\n", err.Error())
		os.Exit(1)
	}

	sqlDB, _ := db.DB()
	sqlDB.SetMaxIdleConns(50)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)
	return db
}

func getMySQLModels() []interface{} {
	return []interface{}{
		&mysql.Domain{}, &mysql.AZ{}, &mysql.SubDomain{}, &mysql.Host{}, &mysql.VM{},
		&mysql.VPC{}, &mysql.Network{}, &mysql.Subnet{}, &mysql.VRouter{}, &mysql.RoutingTable{},
		&mysql.DHCPPort{}, &mysql.VInterface{}, &mysql.WANIP{}, &mysql.LANIP{}, &mysql.FloatingIP{},
		&mysql.SecurityGroup{}, &mysql.SecurityGroupRule{}, &mysql.VMSecurityGroup{}, &mysql.LB{},
		&mysql.LBListener{}, &mysql.LBTargetServer{}, &mysql.NATGateway{}, &mysql.NATRule{},
		&mysql.NATVMConnection{}, &mysql.LBVMConnection{}, &mysql.CEN{}, &mysql.PeerConnection{},
		&mysql.RDSInstance{}, &mysql.RedisInstance{},
		&mysql.PodCluster{}, &mysql.PodNode{}, &mysql.PodNamespace{}, &mysql.VMPodNodeConnection{},
		&mysql.PodIngress{}, &mysql.PodIngressRule{}, &mysql.PodIngressRuleBackend{},
		&mysql.PodService{}, &mysql.PodServicePort{}, &mysql.PodGroup{}, &mysql.PodGroupPort{},
		&mysql.PodReplicaSet{}, &mysql.Pod{}, &mysql.AZControllerConnection{}, &mysql.Controller{},
	}
}

func randID() int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(999)
}

func (t *SuiteTest) TestDeleteDomain() {
	domain := mysql.Domain{Base: mysql.Base{Lcuuid: uuid.NewString()}}
	t.db.Create(&domain)
	r := t.db.Create(&mysql.AZ{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.SubDomain{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.Host{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.VM{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.VPC{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	networkID := randID()
	r = t.db.Create(&mysql.Network{Base: mysql.Base{ID: networkID, Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.Subnet{Base: mysql.Base{Lcuuid: uuid.NewString()}, NetworkID: networkID})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	vRouterID := randID()
	r = t.db.Create(&mysql.VRouter{Base: mysql.Base{ID: vRouterID, Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.RoutingTable{Base: mysql.Base{Lcuuid: uuid.NewString()}, VRouterID: vRouterID})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.DHCPPort{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.VInterface{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.WANIP{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.LANIP{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.FloatingIP{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	sgID := randID()
	r = t.db.Create(&mysql.SecurityGroup{Base: mysql.Base{ID: sgID, Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.SecurityGroupRule{Base: mysql.Base{Lcuuid: uuid.NewString()}, SecurityGroupID: sgID})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.VMSecurityGroup{Base: mysql.Base{Lcuuid: uuid.NewString()}, SecurityGroupID: sgID})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.LB{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.LBListener{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.LBTargetServer{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.NATGateway{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.NATRule{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.NATVMConnection{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.LBVMConnection{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.CEN{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.PeerConnection{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.RDSInstance{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.RedisInstance{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.PodCluster{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.PodNode{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.PodNamespace{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.VMPodNodeConnection{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	podIngressID := randID()
	r = t.db.Create(&mysql.PodIngress{Base: mysql.Base{ID: podIngressID, Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.PodIngressRule{Base: mysql.Base{Lcuuid: uuid.NewString()}, PodIngressID: podIngressID})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.PodIngressRuleBackend{Base: mysql.Base{Lcuuid: uuid.NewString()}, PodIngressID: podIngressID})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	podServiceID := randID()
	r = t.db.Create(&mysql.PodService{Base: mysql.Base{ID: podServiceID, Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.PodServicePort{Base: mysql.Base{Lcuuid: uuid.NewString()}, PodServiceID: podServiceID})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.PodGroupPort{Base: mysql.Base{Lcuuid: uuid.NewString()}, PodServiceID: podServiceID})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.PodGroup{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.PodReplicaSet{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.Pod{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))

	DeleteDomainByNameOrUUID(domain.Lcuuid, &mysql.DB{DB: t.db, ORGID: common.DEFAULT_ORG_ID}, &service.UserInfo{}, &config.ControllerConfig{})

	var azs []mysql.AZ
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&azs)
	assert.Equal(t.T(), len(azs), 0)
	var subDomains []mysql.SubDomain
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&subDomains)
	assert.Equal(t.T(), len(subDomains), 0)
	var vpcs []mysql.VPC
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&vpcs)
	assert.Equal(t.T(), len(vpcs), 0)
	var hosts []mysql.Host
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&hosts)
	assert.Equal(t.T(), len(hosts), 0)
	var vms []mysql.VM
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&vms)
	assert.Equal(t.T(), len(vms), 0)
	var networks []mysql.Network
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&networks)
	assert.Equal(t.T(), len(networks), 0)
	var subnets []mysql.Subnet
	t.db.Unscoped().Where("vl2id = ?", networkID).Find(&subnets)
	assert.Equal(t.T(), len(subnets), 0)
	var vRouters []mysql.VRouter
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&vRouters)
	assert.Equal(t.T(), len(vRouters), 0)
	var routingRules []mysql.RoutingTable
	t.db.Unscoped().Where("vnet_id = ?", vRouterID).Find(&routingRules)
	assert.Equal(t.T(), len(routingRules), 0)
	var dhcpPorts []mysql.DHCPPort
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&dhcpPorts)
	assert.Equal(t.T(), len(dhcpPorts), 0)
	var fIPs []mysql.FloatingIP
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&fIPs)
	assert.Equal(t.T(), len(fIPs), 0)
	var vifs []mysql.VInterface
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&vifs)
	assert.Equal(t.T(), len(vifs), 0)
	var wanIPs []mysql.WANIP
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&wanIPs)
	assert.Equal(t.T(), len(wanIPs), 0)
	var lanIPs []mysql.LANIP
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&lanIPs)
	assert.Equal(t.T(), len(lanIPs), 0)
	var sgs []mysql.SecurityGroup
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&sgs)
	assert.Equal(t.T(), len(sgs), 0)
	var sgRules []mysql.SecurityGroupRule
	t.db.Unscoped().Where("sg_id = ?", sgID).Find(&sgRules)
	assert.Equal(t.T(), len(sgRules), 0)
	var vmSGs []mysql.VMSecurityGroup
	t.db.Unscoped().Where("sg_id = ?", sgID).Find(&vmSGs)
	assert.Equal(t.T(), len(vmSGs), 0)
	var nats []mysql.NATGateway
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&nats)
	assert.Equal(t.T(), len(nats), 0)
	var natRules []mysql.NATRule
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&natRules)
	assert.Equal(t.T(), len(natRules), 0)
	var natVMs []mysql.NATVMConnection
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&natVMs)
	assert.Equal(t.T(), len(natVMs), 0)
	var lbs []mysql.LB
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&lbs)
	assert.Equal(t.T(), len(lbs), 0)
	var lbListeners []mysql.LBListener
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&lbListeners)
	assert.Equal(t.T(), len(lbListeners), 0)
	var lbTSs []mysql.LBTargetServer
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&lbTSs)
	assert.Equal(t.T(), len(lbTSs), 0)
	var lbVMs []mysql.LBVMConnection
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&lbVMs)
	assert.Equal(t.T(), len(lbVMs), 0)
	var pns []mysql.PeerConnection
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&pns)
	assert.Equal(t.T(), len(pns), 0)
	var cens []mysql.CEN
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&cens)
	assert.Equal(t.T(), len(cens), 0)
	var podClusters []mysql.PodCluster
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&podClusters)
	assert.Equal(t.T(), len(podClusters), 0)
	var podNodes []mysql.PodNode
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&podNodes)
	assert.Equal(t.T(), len(podNodes), 0)
	var vmPodNodes []mysql.VMPodNodeConnection
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&vmPodNodes)
	assert.Equal(t.T(), len(vmPodNodes), 0)
	var podNamespaces []mysql.PodNamespace
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&podNamespaces)
	assert.Equal(t.T(), len(podNamespaces), 0)
	var podServices []mysql.PodService
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&podServices)
	assert.Equal(t.T(), len(podServices), 0)
	var podServicePorts []mysql.PodServicePort
	t.db.Unscoped().Where("pod_service_id = ?", podServiceID).Find(&podServicePorts)
	assert.Equal(t.T(), len(podServicePorts), 0)
	var podGroupPorts []mysql.PodGroupPort
	t.db.Unscoped().Where("pod_service_id = ?", podServiceID).Find(&podGroupPorts)
	assert.Equal(t.T(), len(podGroupPorts), 0)
	var podIngresses []mysql.PodIngress
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&podIngresses)
	assert.Equal(t.T(), len(podIngresses), 0)
	var podIngressRules []mysql.PodIngressRule
	t.db.Unscoped().Where("pod_ingress_id = ?", podIngressID).Find(&podIngressRules)
	assert.Equal(t.T(), len(podIngressRules), 0)
	var podIngressRuleBkends []mysql.PodIngressRuleBackend
	t.db.Unscoped().Where("pod_ingress_id = ?", podIngressID).Find(&podIngressRuleBkends)
	assert.Equal(t.T(), len(podIngressRuleBkends), 0)
	var podGroups []mysql.PodGroup
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&podGroups)
	assert.Equal(t.T(), len(podGroups), 0)
	var podRSs []mysql.PodReplicaSet
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&podRSs)
	assert.Equal(t.T(), len(podRSs), 0)
	var pods []mysql.Pod
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&pods)
	assert.Equal(t.T(), len(pods), 0)
}

func (t *SuiteTest) TestDeleteSubDomain() {
	lcuuid := uuid.NewString()
	subDomain := mysql.SubDomain{Base: mysql.Base{Lcuuid: lcuuid}}
	t.db.Create(&subDomain)
	podCluster := mysql.PodCluster{Base: mysql.Base{Lcuuid: lcuuid}}
	t.db.Create(&podCluster)
	r := t.db.Create(&mysql.Network{Base: mysql.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.Subnet{Base: mysql.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.VInterface{Base: mysql.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.WANIP{Base: mysql.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.LANIP{Base: mysql.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.PodCluster{Base: mysql.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.PodNode{Base: mysql.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.PodNamespace{Base: mysql.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.VMPodNodeConnection{Base: mysql.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.PodIngress{Base: mysql.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.PodIngressRule{Base: mysql.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.PodIngressRuleBackend{Base: mysql.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.PodService{Base: mysql.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.PodServicePort{Base: mysql.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.PodGroupPort{Base: mysql.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.PodGroup{Base: mysql.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.PodReplicaSet{Base: mysql.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysql.Pod{Base: mysql.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))

	DeleteSubDomain(lcuuid, &mysql.DB{DB: t.db, ORGID: common.DEFAULT_ORG_ID}, &service.UserInfo{}, &config.ControllerConfig{})

	var networks []mysql.Network
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&networks)
	assert.Equal(t.T(), len(networks), 0)
	var subnets []mysql.Subnet
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&subnets)
	assert.Equal(t.T(), len(subnets), 0)
	var vifs []mysql.VInterface
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&vifs)
	assert.Equal(t.T(), len(vifs), 0)
	var wanIPs []mysql.WANIP
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&wanIPs)
	assert.Equal(t.T(), len(wanIPs), 0)
	var lanIPs []mysql.LANIP
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&lanIPs)
	assert.Equal(t.T(), len(lanIPs), 0)
	var podClusters []mysql.PodCluster
	t.db.Unscoped().Where("lcuuid = ?", lcuuid).Find(&podClusters)
	assert.Equal(t.T(), len(podClusters), 0)
	var podNodes []mysql.PodNode
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podNodes)
	assert.Equal(t.T(), len(podNodes), 0)
	var vmPodNodes []mysql.VMPodNodeConnection
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&vmPodNodes)
	assert.Equal(t.T(), len(vmPodNodes), 0)
	var podNamespaces []mysql.PodNamespace
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podNamespaces)
	assert.Equal(t.T(), len(podNamespaces), 0)
	var podServices []mysql.PodService
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podServices)
	assert.Equal(t.T(), len(podServices), 0)
	var podServicePorts []mysql.PodServicePort
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podServicePorts)
	assert.Equal(t.T(), len(podServicePorts), 0)
	var podGroupPorts []mysql.PodGroupPort
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podGroupPorts)
	assert.Equal(t.T(), len(podGroupPorts), 0)
	var podIngresses []mysql.PodIngress
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podIngresses)
	assert.Equal(t.T(), len(podIngresses), 0)
	var podIngressRules []mysql.PodIngressRule
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podIngressRules)
	assert.Equal(t.T(), len(podIngressRules), 0)
	var podIngressRuleBkends []mysql.PodIngressRuleBackend
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podIngressRuleBkends)
	assert.Equal(t.T(), len(podIngressRuleBkends), 0)
	var podGroups []mysql.PodGroup
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podGroups)
	assert.Equal(t.T(), len(podGroups), 0)
	var podRSs []mysql.PodReplicaSet
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podRSs)
	assert.Equal(t.T(), len(podRSs), 0)
	var pods []mysql.Pod
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&pods)
	assert.Equal(t.T(), len(pods), 0)
}

func (t *SuiteTest) TestDeleteSoftDeletedResource() {
	domainLcuuid := uuid.NewString()
	t.db.Create(&mysql.AZ{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: domainLcuuid})
	t.db.Create(&mysql.AZ{Base: mysql.Base{Lcuuid: uuid.NewString()}, Domain: uuid.NewString()})
	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.AZ{})
	var azs []mysql.AZ
	t.db.Find(&azs)
	assert.Equal(t.T(), 0, len(azs))
	t.db.Unscoped().Find(&azs)
	assert.Equal(t.T(), 2, len(azs))
	t.db.Unscoped().Where("domain = ?", domainLcuuid).Find(&azs)
	assert.Equal(t.T(), 1, len(azs))

	cleanSoftDeletedResource(&mysql.DB{DB: t.db, ORGID: common.DEFAULT_ORG_ID}, domainLcuuid)
	t.db.Unscoped().Find(&azs)
	assert.Equal(t.T(), 1, len(azs))
	t.db.Unscoped().Where("domain = ?", domainLcuuid).Find(&azs)
	assert.Equal(t.T(), 0, len(azs))
}

// func (t *SuiteTest) TestCheckAndAllocateDomainController() {
// 	domainLcuuid := uuid.NewString()
// 	regionLcuuid := "ffffffff-ffff-ffff-ffff-ffffffffffff"
// 	normalControllerIP := "1.1.1.1"
// 	unnormalControllerIP := "1.1.1.2"
// 	t.db.Create(&mysql.AZControllerConnection{Region: regionLcuuid, ControllerIP: normalControllerIP, Lcuuid: uuid.NewString()})
// 	t.db.Create(&mysql.AZControllerConnection{Region: regionLcuuid, ControllerIP: unnormalControllerIP, Lcuuid: uuid.NewString()})
// 	t.db.Create(&mysql.Controller{IP: normalControllerIP, State: 2, Lcuuid: uuid.NewString()})
// 	t.db.Create(&mysql.Controller{IP: unnormalControllerIP, State: 1, Lcuuid: uuid.NewString()})
// 	t.db.Create(&mysql.Domain{Base: mysql.Base{Lcuuid: domainLcuuid}, ControllerIP: unnormalControllerIP, Config: `{"region_uuid": "ffffffff-ffff-ffff-ffff-ffffffffffff"}`})
// 	CheckAndAllocateDomainController()
// 	var domain mysql.Domain
// 	t.db.Where("lcuuid = ?", domainLcuuid).Find(&domain)
// 	assert.Equal(t.T(), normalControllerIP, domain.ControllerIP)
// }
