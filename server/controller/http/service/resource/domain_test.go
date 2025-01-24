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
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
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
	metadb.DefaultDB = GetDB()
	suite.Run(t, new(SuiteTest))
}

func (t *SuiteTest) SetupSuite() {
	t.db = metadb.DefaultDB
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
		&metadbmodel.Domain{}, &metadbmodel.AZ{}, &metadbmodel.SubDomain{}, &metadbmodel.Host{}, &metadbmodel.VM{},
		&metadbmodel.VPC{}, &metadbmodel.Network{}, &metadbmodel.Subnet{}, &metadbmodel.VRouter{}, &metadbmodel.RoutingTable{},
		&metadbmodel.DHCPPort{}, &metadbmodel.VInterface{}, &metadbmodel.WANIP{}, &metadbmodel.LANIP{}, &metadbmodel.FloatingIP{},
		&metadbmodel.LB{},
		&metadbmodel.LBListener{}, &metadbmodel.LBTargetServer{}, &metadbmodel.NATGateway{}, &metadbmodel.NATRule{},
		&metadbmodel.NATVMConnection{}, &metadbmodel.LBVMConnection{}, &metadbmodel.CEN{}, &metadbmodel.PeerConnection{},
		&metadbmodel.RDSInstance{}, &metadbmodel.RedisInstance{},
		&metadbmodel.PodCluster{}, &metadbmodel.PodNode{}, &metadbmodel.PodNamespace{}, &metadbmodel.VMPodNodeConnection{},
		&metadbmodel.PodIngress{}, &metadbmodel.PodIngressRule{}, &metadbmodel.PodIngressRuleBackend{},
		&metadbmodel.PodService{}, &metadbmodel.PodServicePort{}, &metadbmodel.PodGroup{}, &metadbmodel.PodGroupPort{},
		&metadbmodel.PodReplicaSet{}, &metadbmodel.Pod{}, &metadbmodel.AZControllerConnection{}, &metadbmodel.Controller{},
	}
}

func randID() int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(999)
}

func (t *SuiteTest) TestDeleteDomain() {
	domain := metadbmodel.Domain{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}}
	t.db.Create(&domain)
	r := t.db.Create(&metadbmodel.AZ{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.SubDomain{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.Host{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.VM{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.VPC{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	networkID := randID()
	r = t.db.Create(&metadbmodel.Network{Base: metadbmodel.Base{ID: networkID, Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.Subnet{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, NetworkID: networkID})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	vRouterID := randID()
	r = t.db.Create(&metadbmodel.VRouter{Base: metadbmodel.Base{ID: vRouterID, Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.RoutingTable{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, VRouterID: vRouterID})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.DHCPPort{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.VInterface{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.WANIP{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.LANIP{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.FloatingIP{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.LB{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.LBListener{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.LBTargetServer{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.NATGateway{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.NATRule{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.NATVMConnection{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.LBVMConnection{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.CEN{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.PeerConnection{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.RDSInstance{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.RedisInstance{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.PodCluster{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.PodNode{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.PodNamespace{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.VMPodNodeConnection{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	podIngressID := randID()
	r = t.db.Create(&metadbmodel.PodIngress{Base: metadbmodel.Base{ID: podIngressID, Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.PodIngressRule{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, PodIngressID: podIngressID})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.PodIngressRuleBackend{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, PodIngressID: podIngressID})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	podServiceID := randID()
	r = t.db.Create(&metadbmodel.PodService{Base: metadbmodel.Base{ID: podServiceID, Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.PodServicePort{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, PodServiceID: podServiceID})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.PodGroupPort{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, PodServiceID: podServiceID})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.PodGroup{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.PodReplicaSet{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.Pod{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domain.Lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))

	DeleteDomainByNameOrUUID(domain.Lcuuid, &metadb.DB{DB: t.db, ORGID: common.DEFAULT_ORG_ID}, &httpcommon.UserInfo{}, &config.ControllerConfig{})

	var azs []metadbmodel.AZ
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&azs)
	assert.Equal(t.T(), len(azs), 0)
	var subDomains []metadbmodel.SubDomain
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&subDomains)
	assert.Equal(t.T(), len(subDomains), 0)
	var vpcs []metadbmodel.VPC
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&vpcs)
	assert.Equal(t.T(), len(vpcs), 0)
	var hosts []metadbmodel.Host
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&hosts)
	assert.Equal(t.T(), len(hosts), 0)
	var vms []metadbmodel.VM
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&vms)
	assert.Equal(t.T(), len(vms), 0)
	var networks []metadbmodel.Network
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&networks)
	assert.Equal(t.T(), len(networks), 0)
	var subnets []metadbmodel.Subnet
	t.db.Unscoped().Where("vl2id = ?", networkID).Find(&subnets)
	assert.Equal(t.T(), len(subnets), 0)
	var vRouters []metadbmodel.VRouter
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&vRouters)
	assert.Equal(t.T(), len(vRouters), 0)
	var routingRules []metadbmodel.RoutingTable
	t.db.Unscoped().Where("vnet_id = ?", vRouterID).Find(&routingRules)
	assert.Equal(t.T(), len(routingRules), 0)
	var dhcpPorts []metadbmodel.DHCPPort
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&dhcpPorts)
	assert.Equal(t.T(), len(dhcpPorts), 0)
	var fIPs []metadbmodel.FloatingIP
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&fIPs)
	assert.Equal(t.T(), len(fIPs), 0)
	var vifs []metadbmodel.VInterface
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&vifs)
	assert.Equal(t.T(), len(vifs), 0)
	var wanIPs []metadbmodel.WANIP
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&wanIPs)
	assert.Equal(t.T(), len(wanIPs), 0)
	var lanIPs []metadbmodel.LANIP
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&lanIPs)
	assert.Equal(t.T(), len(lanIPs), 0)
	assert.Equal(t.T(), len(vmSGs), 0)
	var nats []metadbmodel.NATGateway
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&nats)
	assert.Equal(t.T(), len(nats), 0)
	var natRules []metadbmodel.NATRule
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&natRules)
	assert.Equal(t.T(), len(natRules), 0)
	var natVMs []metadbmodel.NATVMConnection
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&natVMs)
	assert.Equal(t.T(), len(natVMs), 0)
	var lbs []metadbmodel.LB
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&lbs)
	assert.Equal(t.T(), len(lbs), 0)
	var lbListeners []metadbmodel.LBListener
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&lbListeners)
	assert.Equal(t.T(), len(lbListeners), 0)
	var lbTSs []metadbmodel.LBTargetServer
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&lbTSs)
	assert.Equal(t.T(), len(lbTSs), 0)
	var lbVMs []metadbmodel.LBVMConnection
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&lbVMs)
	assert.Equal(t.T(), len(lbVMs), 0)
	var pns []metadbmodel.PeerConnection
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&pns)
	assert.Equal(t.T(), len(pns), 0)
	var cens []metadbmodel.CEN
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&cens)
	assert.Equal(t.T(), len(cens), 0)
	var podClusters []metadbmodel.PodCluster
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&podClusters)
	assert.Equal(t.T(), len(podClusters), 0)
	var podNodes []metadbmodel.PodNode
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&podNodes)
	assert.Equal(t.T(), len(podNodes), 0)
	var vmPodNodes []metadbmodel.VMPodNodeConnection
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&vmPodNodes)
	assert.Equal(t.T(), len(vmPodNodes), 0)
	var podNamespaces []metadbmodel.PodNamespace
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&podNamespaces)
	assert.Equal(t.T(), len(podNamespaces), 0)
	var podServices []metadbmodel.PodService
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&podServices)
	assert.Equal(t.T(), len(podServices), 0)
	var podServicePorts []metadbmodel.PodServicePort
	t.db.Unscoped().Where("pod_service_id = ?", podServiceID).Find(&podServicePorts)
	assert.Equal(t.T(), len(podServicePorts), 0)
	var podGroupPorts []metadbmodel.PodGroupPort
	t.db.Unscoped().Where("pod_service_id = ?", podServiceID).Find(&podGroupPorts)
	assert.Equal(t.T(), len(podGroupPorts), 0)
	var podIngresses []metadbmodel.PodIngress
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&podIngresses)
	assert.Equal(t.T(), len(podIngresses), 0)
	var podIngressRules []metadbmodel.PodIngressRule
	t.db.Unscoped().Where("pod_ingress_id = ?", podIngressID).Find(&podIngressRules)
	assert.Equal(t.T(), len(podIngressRules), 0)
	var podIngressRuleBkends []metadbmodel.PodIngressRuleBackend
	t.db.Unscoped().Where("pod_ingress_id = ?", podIngressID).Find(&podIngressRuleBkends)
	assert.Equal(t.T(), len(podIngressRuleBkends), 0)
	var podGroups []metadbmodel.PodGroup
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&podGroups)
	assert.Equal(t.T(), len(podGroups), 0)
	var podRSs []metadbmodel.PodReplicaSet
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&podRSs)
	assert.Equal(t.T(), len(podRSs), 0)
	var pods []metadbmodel.Pod
	t.db.Unscoped().Where("domain = ?", domain.Lcuuid).Find(&pods)
	assert.Equal(t.T(), len(pods), 0)
}

func (t *SuiteTest) TestDeleteSubDomain() {
	lcuuid := uuid.NewString()
	subDomain := metadbmodel.SubDomain{Base: metadbmodel.Base{Lcuuid: lcuuid}}
	t.db.Create(&subDomain)
	podCluster := metadbmodel.PodCluster{Base: metadbmodel.Base{Lcuuid: lcuuid}}
	t.db.Create(&podCluster)
	r := t.db.Create(&metadbmodel.Network{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.Subnet{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.VInterface{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.WANIP{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.LANIP{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.PodCluster{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.PodNode{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.PodNamespace{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.VMPodNodeConnection{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.PodIngress{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.PodIngressRule{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.PodIngressRuleBackend{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.PodService{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.PodServicePort{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.PodGroupPort{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.PodGroup{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.PodReplicaSet{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))
	r = t.db.Create(&metadbmodel.Pod{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, SubDomain: lcuuid})
	assert.Equal(t.T(), r.RowsAffected, int64(1))

	DeleteSubDomain(lcuuid, &metadb.DB{DB: t.db, ORGID: common.DEFAULT_ORG_ID}, &httpcommon.UserInfo{}, &config.ControllerConfig{})

	var networks []metadbmodel.Network
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&networks)
	assert.Equal(t.T(), len(networks), 0)
	var subnets []metadbmodel.Subnet
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&subnets)
	assert.Equal(t.T(), len(subnets), 0)
	var vifs []metadbmodel.VInterface
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&vifs)
	assert.Equal(t.T(), len(vifs), 0)
	var wanIPs []metadbmodel.WANIP
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&wanIPs)
	assert.Equal(t.T(), len(wanIPs), 0)
	var lanIPs []metadbmodel.LANIP
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&lanIPs)
	assert.Equal(t.T(), len(lanIPs), 0)
	var podClusters []metadbmodel.PodCluster
	t.db.Unscoped().Where("lcuuid = ?", lcuuid).Find(&podClusters)
	assert.Equal(t.T(), len(podClusters), 0)
	var podNodes []metadbmodel.PodNode
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podNodes)
	assert.Equal(t.T(), len(podNodes), 0)
	var vmPodNodes []metadbmodel.VMPodNodeConnection
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&vmPodNodes)
	assert.Equal(t.T(), len(vmPodNodes), 0)
	var podNamespaces []metadbmodel.PodNamespace
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podNamespaces)
	assert.Equal(t.T(), len(podNamespaces), 0)
	var podServices []metadbmodel.PodService
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podServices)
	assert.Equal(t.T(), len(podServices), 0)
	var podServicePorts []metadbmodel.PodServicePort
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podServicePorts)
	assert.Equal(t.T(), len(podServicePorts), 0)
	var podGroupPorts []metadbmodel.PodGroupPort
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podGroupPorts)
	assert.Equal(t.T(), len(podGroupPorts), 0)
	var podIngresses []metadbmodel.PodIngress
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podIngresses)
	assert.Equal(t.T(), len(podIngresses), 0)
	var podIngressRules []metadbmodel.PodIngressRule
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podIngressRules)
	assert.Equal(t.T(), len(podIngressRules), 0)
	var podIngressRuleBkends []metadbmodel.PodIngressRuleBackend
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podIngressRuleBkends)
	assert.Equal(t.T(), len(podIngressRuleBkends), 0)
	var podGroups []metadbmodel.PodGroup
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podGroups)
	assert.Equal(t.T(), len(podGroups), 0)
	var podRSs []metadbmodel.PodReplicaSet
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&podRSs)
	assert.Equal(t.T(), len(podRSs), 0)
	var pods []metadbmodel.Pod
	t.db.Unscoped().Where("sub_domain = ?", lcuuid).Find(&pods)
	assert.Equal(t.T(), len(pods), 0)
}

func (t *SuiteTest) TestDeleteSoftDeletedResource() {
	domainLcuuid := uuid.NewString()
	t.db.Create(&metadbmodel.AZ{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: domainLcuuid})
	t.db.Create(&metadbmodel.AZ{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, Domain: uuid.NewString()})
	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&metadbmodel.AZ{})
	var azs []metadbmodel.AZ
	t.db.Find(&azs)
	assert.Equal(t.T(), 0, len(azs))
	t.db.Unscoped().Find(&azs)
	assert.Equal(t.T(), 2, len(azs))
	t.db.Unscoped().Where("domain = ?", domainLcuuid).Find(&azs)
	assert.Equal(t.T(), 1, len(azs))

	cleanSoftDeletedResource(&metadb.DB{DB: t.db, ORGID: common.DEFAULT_ORG_ID}, domainLcuuid)
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
// 	t.db.Create(&metadbmodel.AZControllerConnection{Region: regionLcuuid, ControllerIP: normalControllerIP, Lcuuid: uuid.NewString()})
// 	t.db.Create(&metadbmodel.AZControllerConnection{Region: regionLcuuid, ControllerIP: unnormalControllerIP, Lcuuid: uuid.NewString()})
// 	t.db.Create(&metadbmodel.Controller{IP: normalControllerIP, State: 2, Lcuuid: uuid.NewString()})
// 	t.db.Create(&metadbmodel.Domainller{IP: unnormalControllerIP, State: 1, Lcuuid: uuid.NewString()})
// 	t.db.Create(&metadbmodel.Domain{Base: metadbmodel.Base{Lcuuid: domainLcuuid}, ControllerIP: unnormalControllerIP, Config: `{"region_uuid": "ffffffff-ffff-ffff-ffff-ffffffffffff"}`})
// 	CheckAndAllmysqlmodel.Domainontroller()
// 	var domain metadbmodel.Domain
// 	t.db.Where("lcuuid = ?", domainLcuuid).Find(&domain)
// 	assert.Equal(t.T(), normalControllerIP, domain.ControllerIP)
// }
