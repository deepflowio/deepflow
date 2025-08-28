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

package recorder

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/deepflowio/deepflow/server/controller/db/metadb"
)

func (t *SuiteTest) TestForceDelete() {
	vm := metadbmodel.VM{Base: metadbmodel.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String()}
	metadb.DefaultDB.Create(&vm)
	metadb.DefaultDB.Model(metadbmodel.VM{}).Where("lcuuid = ?", vm.Lcuuid).Updates(map[string]interface{}{"deleted_at": time.Now().Add(time.Duration(-24) * time.Hour)})
	var addedVM metadbmodel.VM
	metadb.DefaultDB.Unscoped().Where("lcuuid = ?", vm.Lcuuid).Find(&addedVM)
	if addedVM.ID == 0 {
		fmt.Println("addedVM should not be null")
	}
	deleteExpired[metadbmodel.VM](time.Now().Add(time.Duration(-1) * time.Hour))
	metadb.DefaultDB.Unscoped().Where("lcuuid = ?", vm.Lcuuid).Find(&addedVM)
	if addedVM.ID != 0 {
		fmt.Println("addedVM should be null")
	}
}

func (t *SuiteTest) TestCleanDirtyData() {
	networks := []metadbmodel.Network{{Base: metadbmodel.Base{ID: 1, Lcuuid: uuid.NewString()}}, {Base: metadbmodel.Base{ID: 10, Lcuuid: uuid.NewString()}}}
	metadb.DefaultDB.Create(&networks)
	metadb.DefaultDB.Where("id = ?", 10).Delete(&metadbmodel.Network{})
	subnet := metadbmodel.Subnet{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, NetworkID: 10}
	metadb.DefaultDB.Create(&subnet)
	var subnets []metadbmodel.Subnet
	metadb.DefaultDB.Find(&subnets)

	vrouter := metadbmodel.VRouter{Base: metadbmodel.Base{ID: 2, Lcuuid: uuid.NewString()}}
	metadb.DefaultDB.Create(&vrouter)
	routingTable := metadbmodel.RoutingTable{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, VRouterID: 20}
	metadb.DefaultDB.Create(&routingTable)
	var routingTables []metadbmodel.RoutingTable
	metadb.DefaultDB.Find(&routingTables)

	sg := metadb.SecurityGroup{Base: metadbmodel.Base{ID: 3, Lcuuid: uuid.NewString()}}
	metadb.DefaultDB.Create(&sg)
	sgRule := metadb.SecurityGroupRule{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, SecurityGroupID: 30}
	metadb.DefaultDB.Create(&sgRule)
	var sgRules []metadb.SecurityGroupRule
	metadb.DefaultDB.Find(&sgRules)
	vmSG := metadb.VMSecurityGroup{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, VMID: 1, SecurityGroupID: 30}
	metadb.DefaultDB.Create(&vmSG)
	var vmSGs []metadb.VMSecurityGroup
	metadb.DefaultDB.Find(&vmSGs)

	podIngress := metadbmodel.PodIngress{Base: metadbmodel.Base{ID: 4, Lcuuid: uuid.NewString()}}
	metadb.DefaultDB.Create(&podIngress)
	podIngressRule := metadbmodel.PodIngressRule{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, PodIngressID: 40}
	metadb.DefaultDB.Create(&podIngressRule)
	var podIngressRules []metadbmodel.PodIngressRule
	metadb.DefaultDB.Find(&podIngressRules)
	podIngressRuleBkd := metadbmodel.PodIngressRuleBackend{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, PodIngressID: 40}
	metadb.DefaultDB.Create(&podIngressRuleBkd)
	var podIngressRuleBkds []metadbmodel.PodIngressRuleBackend
	metadb.DefaultDB.Find(&podIngressRuleBkds)

	podService := metadbmodel.PodService{Base: metadbmodel.Base{ID: 5, Lcuuid: uuid.NewString()}}
	metadb.DefaultDB.Create(&podService)
	podServicePort := metadbmodel.PodServicePort{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, PodServiceID: 50}
	metadb.DefaultDB.Create(&podServicePort)
	var podServicePorts []metadbmodel.PodServicePort
	metadb.DefaultDB.Find(&podServicePorts)
	podGroupPort := metadbmodel.PodGroupPort{Base: metadbmodel.Base{Lcuuid: uuid.NewString()}, PodGroupID: 1, PodServiceID: 50}
	metadb.DefaultDB.Create(&podGroupPort)
	var podGroupPorts []metadbmodel.PodGroupPort
	metadb.DefaultDB.Find(&podGroupPorts)

	assert.Equal(t.T(), 1, len(subnets))
	assert.Equal(t.T(), 1, len(routingTables))
	assert.Equal(t.T(), 1, len(sgRules))
	assert.Equal(t.T(), 1, len(vmSGs))
	assert.Equal(t.T(), 1, len(podIngressRules))
	assert.Equal(t.T(), 1, len(podIngressRuleBkds))
	assert.Equal(t.T(), 1, len(podServicePorts))
	assert.Equal(t.T(), 1, len(podGroupPorts))

	cleaner := GetSingletonCleaner()
	cleaner.cleanDirtyData()
	metadb.DefaultDB.Find(&subnets)
	assert.Equal(t.T(), 0, len(subnets))
	metadb.DefaultDB.Find(&routingTables)
	assert.Equal(t.T(), 0, len(routingTables))
	metadb.DefaultDB.Find(&sgRules)
	assert.Equal(t.T(), 0, len(sgRules))
	metadb.DefaultDB.Find(&vmSGs)
	assert.Equal(t.T(), 0, len(vmSGs))
	metadb.DefaultDB.Find(&podIngressRules)
	assert.Equal(t.T(), 0, len(podIngressRules))
	metadb.DefaultDB.Find(&podIngressRuleBkds)
	assert.Equal(t.T(), 0, len(podIngressRuleBkds))
	metadb.DefaultDB.Find(&podServicePorts)
	assert.Equal(t.T(), 0, len(podServicePorts))
	metadb.DefaultDB.Find(&podGroupPorts)
	assert.Equal(t.T(), 0, len(podGroupPorts))
}
