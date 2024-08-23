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

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

func (t *SuiteTest) TestForceDelete() {
	vm := mysql.VM{Base: mysql.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String()}
	mysql.DefaultDB.Create(&vm)
	mysql.DefaultDB.Model(mysql.VM{}).Where("lcuuid = ?", vm.Lcuuid).Updates(map[string]interface{}{"deleted_at": time.Now().Add(time.Duration(-24) * time.Hour)})
	var addedVM mysql.VM
	mysql.DefaultDB.Unscoped().Where("lcuuid = ?", vm.Lcuuid).Find(&addedVM)
	if addedVM.ID == 0 {
		fmt.Println("addedVM should not be null")
	}
	deleteExpired[mysql.VM](time.Now().Add(time.Duration(-1) * time.Hour))
	mysql.DefaultDB.Unscoped().Where("lcuuid = ?", vm.Lcuuid).Find(&addedVM)
	if addedVM.ID != 0 {
		fmt.Println("addedVM should be null")
	}
}

func (t *SuiteTest) TestCleanDirtyData() {
	networks := []mysql.Network{{Base: mysql.Base{ID: 1, Lcuuid: uuid.NewString()}}, {Base: mysql.Base{ID: 10, Lcuuid: uuid.NewString()}}}
	mysql.DefaultDB.Create(&networks)
	mysql.DefaultDB.Where("id = ?", 10).Delete(&mysql.Network{})
	subnet := mysql.Subnet{Base: mysql.Base{Lcuuid: uuid.NewString()}, NetworkID: 10}
	mysql.DefaultDB.Create(&subnet)
	var subnets []mysql.Subnet
	mysql.DefaultDB.Find(&subnets)

	vrouter := mysql.VRouter{Base: mysql.Base{ID: 2, Lcuuid: uuid.NewString()}}
	mysql.DefaultDB.Create(&vrouter)
	routingTable := mysql.RoutingTable{Base: mysql.Base{Lcuuid: uuid.NewString()}, VRouterID: 20}
	mysql.DefaultDB.Create(&routingTable)
	var routingTables []mysql.RoutingTable
	mysql.DefaultDB.Find(&routingTables)

	sg := mysql.SecurityGroup{Base: mysql.Base{ID: 3, Lcuuid: uuid.NewString()}}
	mysql.DefaultDB.Create(&sg)
	sgRule := mysql.SecurityGroupRule{Base: mysql.Base{Lcuuid: uuid.NewString()}, SecurityGroupID: 30}
	mysql.DefaultDB.Create(&sgRule)
	var sgRules []mysql.SecurityGroupRule
	mysql.DefaultDB.Find(&sgRules)
	vmSG := mysql.VMSecurityGroup{Base: mysql.Base{Lcuuid: uuid.NewString()}, VMID: 1, SecurityGroupID: 30}
	mysql.DefaultDB.Create(&vmSG)
	var vmSGs []mysql.VMSecurityGroup
	mysql.DefaultDB.Find(&vmSGs)

	podIngress := mysql.PodIngress{Base: mysql.Base{ID: 4, Lcuuid: uuid.NewString()}}
	mysql.DefaultDB.Create(&podIngress)
	podIngressRule := mysql.PodIngressRule{Base: mysql.Base{Lcuuid: uuid.NewString()}, PodIngressID: 40}
	mysql.DefaultDB.Create(&podIngressRule)
	var podIngressRules []mysql.PodIngressRule
	mysql.DefaultDB.Find(&podIngressRules)
	podIngressRuleBkd := mysql.PodIngressRuleBackend{Base: mysql.Base{Lcuuid: uuid.NewString()}, PodIngressID: 40}
	mysql.DefaultDB.Create(&podIngressRuleBkd)
	var podIngressRuleBkds []mysql.PodIngressRuleBackend
	mysql.DefaultDB.Find(&podIngressRuleBkds)

	podService := mysql.PodService{Base: mysql.Base{ID: 5, Lcuuid: uuid.NewString()}}
	mysql.DefaultDB.Create(&podService)
	podServicePort := mysql.PodServicePort{Base: mysql.Base{Lcuuid: uuid.NewString()}, PodServiceID: 50}
	mysql.DefaultDB.Create(&podServicePort)
	var podServicePorts []mysql.PodServicePort
	mysql.DefaultDB.Find(&podServicePorts)
	podGroupPort := mysql.PodGroupPort{Base: mysql.Base{Lcuuid: uuid.NewString()}, PodGroupID: 1, PodServiceID: 50}
	mysql.DefaultDB.Create(&podGroupPort)
	var podGroupPorts []mysql.PodGroupPort
	mysql.DefaultDB.Find(&podGroupPorts)

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
	mysql.DefaultDB.Find(&subnets)
	assert.Equal(t.T(), 0, len(subnets))
	mysql.DefaultDB.Find(&routingTables)
	assert.Equal(t.T(), 0, len(routingTables))
	mysql.DefaultDB.Find(&sgRules)
	assert.Equal(t.T(), 0, len(sgRules))
	mysql.DefaultDB.Find(&vmSGs)
	assert.Equal(t.T(), 0, len(vmSGs))
	mysql.DefaultDB.Find(&podIngressRules)
	assert.Equal(t.T(), 0, len(podIngressRules))
	mysql.DefaultDB.Find(&podIngressRuleBkds)
	assert.Equal(t.T(), 0, len(podIngressRuleBkds))
	mysql.DefaultDB.Find(&podServicePorts)
	assert.Equal(t.T(), 0, len(podServicePorts))
	mysql.DefaultDB.Find(&podGroupPorts)
	assert.Equal(t.T(), 0, len(podGroupPorts))
}
