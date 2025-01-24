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
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
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
	mysql.DefaultDB = GetDB()
	suite.Run(t, new(SuiteTest))
}

func (t *SuiteTest) SetupSuite() {
	t.db = mysql.DefaultDB
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
		&mysqlmodel.Domain{}, &mysqlmodel.AZ{}, &mysqlmodel.SubDomain{}, &mysqlmodel.Host{}, &mysqlmodel.VM{},
		&mysqlmodel.VPC{}, &mysqlmodel.Network{}, &mysqlmodel.Subnet{}, &mysqlmodel.VRouter{}, &mysqlmodel.RoutingTable{},
		&mysqlmodel.DHCPPort{}, &mysqlmodel.VInterface{}, &mysqlmodel.WANIP{}, &mysqlmodel.LANIP{}, &mysqlmodel.FloatingIP{},
		&mysqlmodel.LB{},
		&mysqlmodel.LBListener{}, &mysqlmodel.LBTargetServer{}, &mysqlmodel.NATGateway{}, &mysqlmodel.NATRule{},
		&mysqlmodel.NATVMConnection{}, &mysqlmodel.LBVMConnection{}, &mysqlmodel.CEN{}, &mysqlmodel.PeerConnection{},
		&mysqlmodel.RDSInstance{}, &mysqlmodel.RedisInstance{},
		&mysqlmodel.PodCluster{}, &mysqlmodel.PodNode{}, &mysqlmodel.PodNamespace{}, &mysqlmodel.VMPodNodeConnection{},
		&mysqlmodel.PodIngress{}, &mysqlmodel.PodIngressRule{}, &mysqlmodel.PodIngressRuleBackend{},
		&mysqlmodel.PodService{}, &mysqlmodel.PodServicePort{}, &mysqlmodel.PodGroup{}, &mysqlmodel.PodGroupPort{},
		&mysqlmodel.PodReplicaSet{}, &mysqlmodel.Pod{}, &mysqlmodel.AZControllerConnection{}, &mysqlmodel.Controller{},
	}
}

func randID() int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(999)
}

func (t *SuiteTest) TestDeleteDomain() {
	domain := mysqlmodel.Domain{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}}
	t.db.Create(&domain)
	r := t.db.Create(&mysqlmodel.AZ{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.SubDomain{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.Host{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.VM{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.VPC{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	networkID := randID()
	r = t.db.Create(&mysqlmodel.Network{Base: mysqlmodel.Base{ID: networkID, Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.Subnet{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, NetworkID: networkID})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	vRouterID := randID()
	r = t.db.Create(&mysqlmodel.VRouter{Base: mysqlmodel.Base{ID: vRouterID, Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.RoutingTable{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, VRouterID: vRouterID})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.DHCPPort{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.VInterface{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.WANIP{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.LANIP{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.FloatingIP{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.LB{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.LBListener{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.LBTargetServer{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.NATGateway{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.NATRule{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.NATVMConnection{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.LBVMConnection{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.CEN{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.PeerConnection{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.RDSInstance{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.RedisInstance{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.PodCluster{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.PodNode{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.PodNamespace{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.VMPodNodeConnection{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	podIngressID := randID()
	r = t.db.Create(&mysqlmodel.PodIngress{Base: mysqlmodel.Base{ID: podIngressID, Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.PodIngressRule{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, PodIngressID: podIngressID})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.PodIngressRuleBackend{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, PodIngressID: podIngressID})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	podServiceID := randID()
	r = t.db.Create(&mysqlmodel.PodService{Base: mysqlmodel.Base{ID: podServiceID, Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.PodServicePort{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, PodServiceID: podServiceID})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.PodGroupPort{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, PodServiceID: podServiceID})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.PodGroup{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.PodReplicaSet{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.Pod{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))

	DeleteDomainByNameOrUUID(domain.Lcuuid, &mysql.DB{DB: t.db, ORGID: common.DEFAULT_ORG_ID}, &httpcommon.UserInfo{}, &config.ControllerConfig{})

	var azs []mysqlmodel.AZ
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&azs)
	assert.Equal(t.T(), len(azs), 0)
	var subDomains []mysqlmodel.SubDomain
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&subDomains)
	assert.Equal(t.T(), len(subDomains), 0)
	var vpcs []mysqlmodel.VPC
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&vpcs)
	assert.Equal(t.T(), len(vpcs), 0)
	var hosts []mysqlmodel.Host
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&hosts)
	assert.Equal(t.T(), len(hosts), 0)
	var vms []mysqlmodel.VM
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&vms)
	assert.Equal(t.T(), len(vms), 0)
	var networks []mysqlmodel.Network
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&networks)
	assert.Equal(t.T(), len(networks), 0)
	var subnets []mysqlmodel.Subnet
	t.db.Unscoped().Where("vl2id = ?", networkID).Find(&subnets)
	assert.Equal(t.T(), len(subnets), 0)
	var vRouters []mysqlmodel.VRouter
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&vRouters)
	assert.Equal(t.T(), len(vRouters), 0)
	var routingRules []mysqlmodel.RoutingTable
	t.db.Unscoped().Where("vnet_id = ?", vRouterID).Find(&routingRules)
	assert.Equal(t.T(), len(routingRules), 0)
	var dhcpPorts []mysqlmodel.DHCPPort
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&dhcpPorts)
	assert.Equal(t.T(), len(dhcpPorts), 0)
	var fIPs []mysqlmodel.FloatingIP
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&fIPs)
	assert.Equal(t.T(), len(fIPs), 0)
	var vifs []mysqlmodel.VInterface
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&vifs)
	assert.Equal(t.T(), len(vifs), 0)
	var wanIPs []mysqlmodel.WANIP
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&wanIPs)
	assert.Equal(t.T(), len(wanIPs), 0)
	var lanIPs []mysqlmodel.LANIP
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&lanIPs)
	assert.Equal(t.T(), len(lanIPs), 0)
	var nats []mysqlmodel.NATGateway
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&nats)
	assert.Equal(t.T(), len(nats), 0)
	var natRules []mysqlmodel.NATRule
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&natRules)
	assert.Equal(t.T(), len(natRules), 0)
	var natVMs []mysqlmodel.NATVMConnection
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&natVMs)
	assert.Equal(t.T(), len(natVMs), 0)
	var lbs []mysqlmodel.LB
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&lbs)
	assert.Equal(t.T(), len(lbs), 0)
	var lbListeners []mysqlmodel.LBListener
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&lbListeners)
	assert.Equal(t.T(), len(lbListeners), 0)
	var lbTSs []mysqlmodel.LBTargetServer
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&lbTSs)
	assert.Equal(t.T(), len(lbTSs), 0)
	var lbVMs []mysqlmodel.LBVMConnection
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&lbVMs)
	assert.Equal(t.T(), len(lbVMs), 0)
	var pns []mysqlmodel.PeerConnection
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&pns)
	assert.Equal(t.T(), len(pns), 0)
	var cens []mysqlmodel.CEN
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&cens)
	assert.Equal(t.T(), len(cens), 0)
	var podClusters []mysqlmodel.PodCluster
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&podClusters)
	assert.Equal(t.T(), len(podClusters), 0)
	var podNodes []mysqlmodel.PodNode
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&podNodes)
	assert.Equal(t.T(), len(podNodes), 0)
	var vmPodNodes []mysqlmodel.VMPodNodeConnection
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&vmPodNodes)
	assert.Equal(t.T(), len(vmPodNodes), 0)
	var podNamespaces []mysqlmodel.PodNamespace
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&podNamespaces)
	assert.Equal(t.T(), len(podNamespaces), 0)
	var podServices []mysqlmodel.PodService
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&podServices)
	assert.Equal(t.T(), len(podServices), 0)
	var podServicePorts []mysqlmodel.PodServicePort
	t.db.Unscoped().Where("pod_service_id = ?", podServiceID).Find(&podServicePorts)
	assert.Equal(t.T(), len(podServicePorts), 0)
	var podGroupPorts []mysqlmodel.PodGroupPort
	t.db.Unscoped().Where("pod_service_id = ?", podServiceID).Find(&podGroupPorts)
	assert.Equal(t.T(), len(podGroupPorts), 0)
	var podIngresses []mysqlmodel.PodIngress
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&podIngresses)
	assert.Equal(t.T(), len(podIngresses), 0)
	var podIngressRules []mysqlmodel.PodIngressRule
	t.db.Unscoped().Where("pod_ingress_id = ?", podIngressID).Find(&podIngressRules)
	assert.Equal(t.T(), len(podIngressRules), 0)
	var podIngressRuleBkends []mysqlmodel.PodIngressRuleBackend
	t.db.Unscoped().Where("pod_ingress_id = ?", podIngressID).Find(&podIngressRuleBkends)
	assert.Equal(t.T(), len(podIngressRuleBkends), 0)
	var podGroups []mysqlmodel.PodGroup
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&podGroups)
	assert.Equal(t.T(), len(podGroups), 0)
	var podRSs []mysqlmodel.PodReplicaSet
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&podRSs)
	assert.Equal(t.T(), len(podRSs), 0)
	var pods []mysqlmodel.Pod
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&pods)
	assert.Equal(t.T(), len(pods), 0)
}

func (t *SuiteTest) TestDeleteSubDomain() {
	lcuuid := uuid.NewString()
	subDomain := mysqlmodel.SubDomain{Base: mysqlmodel.Base{Lcuuid: lcuuid}}
	t.db.Create(&subDomain)
	podCluster := mysqlmodel.PodCluster{Base: mysqlmodel.Base{Lcuuid: lcuuid}}
	t.db.Create(&podCluster)
	r := t.db.Create(&mysqlmodel.Network{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.Subnet{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.VInterface{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.WANIP{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.LANIP{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.PodCluster{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.PodNode{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.PodNamespace{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.VMPodNodeConnection{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.PodIngress{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.PodIngressRule{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.PodIngressRuleBackend{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.PodService{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.PodServicePort{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.PodGroupPort{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.PodGroup{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.PodReplicaSet{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&mysqlmodel.Pod{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))

	DeleteSubDomain(lcuuid, &mysql.DB{DB: t.db, ORGID: common.DEFAULT_ORG_ID}, &httpcommon.UserInfo{}, &config.ControllerConfig{})

	var networks []mysqlmodel.Network
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&networks)
	assert.Equal(t.T(), len(networks), 0)
	var subnets []mysqlmodel.Subnet
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&subnets)
	assert.Equal(t.T(), len(subnets), 0)
	var vifs []mysqlmodel.VInterface
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&vifs)
	assert.Equal(t.T(), len(vifs), 0)
	var wanIPs []mysqlmodel.WANIP
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&wanIPs)
	assert.Equal(t.T(), len(wanIPs), 0)
	var lanIPs []mysqlmodel.LANIP
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&lanIPs)
	assert.Equal(t.T(), len(lanIPs), 0)
	var podClusters []mysqlmodel.PodCluster
	t.db.Unscoped().Where("lcuuid = ?", lcuuid).Find(&podClusters)
	assert.Equal(t.T(), len(podClusters), 0)
	var podNodes []mysqlmodel.PodNode
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podNodes)
	assert.Equal(t.T(), len(podNodes), 0)
	var vmPodNodes []mysqlmodel.VMPodNodeConnection
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&vmPodNodes)
	assert.Equal(t.T(), len(vmPodNodes), 0)
	var podNamespaces []mysqlmodel.PodNamespace
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podNamespaces)
	assert.Equal(t.T(), len(podNamespaces), 0)
	var podServices []mysqlmodel.PodService
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podServices)
	assert.Equal(t.T(), len(podServices), 0)
	var podServicePorts []mysqlmodel.PodServicePort
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podServicePorts)
	assert.Equal(t.T(), len(podServicePorts), 0)
	var podGroupPorts []mysqlmodel.PodGroupPort
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podGroupPorts)
	assert.Equal(t.T(), len(podGroupPorts), 0)
	var podIngresses []mysqlmodel.PodIngress
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podIngresses)
	assert.Equal(t.T(), len(podIngresses), 0)
	var podIngressRules []mysqlmodel.PodIngressRule
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podIngressRules)
	assert.Equal(t.T(), len(podIngressRules), 0)
	var podIngressRuleBkends []mysqlmodel.PodIngressRuleBackend
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podIngressRuleBkends)
	assert.Equal(t.T(), len(podIngressRuleBkends), 0)
	var podGroups []mysqlmodel.PodGroup
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podGroups)
	assert.Equal(t.T(), len(podGroups), 0)
	var podRSs []mysqlmodel.PodReplicaSet
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podRSs)
	assert.Equal(t.T(), len(podRSs), 0)
	var pods []mysqlmodel.Pod
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&pods)
	assert.Equal(t.T(), len(pods), 0)
}

func (t *SuiteTest) TestDeleteSoftDeletedResource() {
	domainLcuuid := uuid.NewString()
	t.db.Create(&mysqlmodel.AZ{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: domainLcuuid})
	t.db.Create(&mysqlmodel.AZ{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, Domain: uuid.NewString()})
	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysqlmodel.AZ{})
	var azs []mysqlmodel.AZ
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
// 	t.db.Create(&mysqlmodel.AZControllerConnection{Region: regionLcuuid, ControllerIP: normalControllerIP, Lcuuid: uuid.NewString()})
// 	t.db.Create(&mysqlmodel.AZControllerConnection{Region: regionLcuuid, ControllerIP: unnormalControllerIP, Lcuuid: uuid.NewString()})
// 	t.db.Create(&mysqlmodel.Controller{IP: normalControllerIP, State: 2, Lcuuid: uuid.NewString()})
// 	t.db.Create(&mysqlmodel.Domainller{IP: unnormalControllerIP, State: 1, Lcuuid: uuid.NewString()})
// 	t.db.Create(&mysqlmodel.Domain{Base: mysqlmodel.Base{Lcuuid: domainLcuuid}, ControllerIP: unnormalControllerIP, Config: `{"region_uuid": "ffffffff-ffff-ffff-ffff-ffffffffffff"}`})
// 	CheckAndAllmysqlmodel.Domainontroller()
// 	var domain mysqlmodel.Domain
// 	t.db.Where("lcuuid = ?", domainLcuuid).Find(&domain)
// 	assert.Equal(t.T(), normalControllerIP, domain.ControllerIP)
// }
