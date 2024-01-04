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
	mysql.Db.Create(&vm)
	mysql.Db.Model(mysql.VM{}).Where("lcuuid = ?", vm.Lcuuid).Updates(map[string]interface{}{"deleted_at": time.Now().Add(time.Duration(-24) * time.Hour)})
	var addedVM mysql.VM
	mysql.Db.Unscoped().Where("lcuuid = ?", vm.Lcuuid).Find(&addedVM)
	if addedVM.ID == 0 {
		fmt.Println("addedVM should not be null")
	}
	forceDelete[mysql.VM](time.Now().Add(time.Duration(-1) * time.Hour))
	mysql.Db.Unscoped().Where("lcuuid = ?", vm.Lcuuid).Find(&addedVM)
	if addedVM.ID != 0 {
		fmt.Println("addedVM should be null")
	}
}

func (t *SuiteTest) TestCleanDirtyData() {
	networks := []mysql.Network{{Base: mysql.Base{ID: 1, Lcuuid: uuid.NewString()}}, {Base: mysql.Base{ID: 10, Lcuuid: uuid.NewString()}}}
	mysql.Db.Create(&networks)
	mysql.Db.Where("id = ?", 10).Delete(&mysql.Network{})
	subnet := mysql.Subnet{Base: mysql.Base{Lcuuid: uuid.NewString()}, NetworkID: 10}
	mysql.Db.Create(&subnet)
	var subnets []mysql.Subnet
	mysql.Db.Find(&subnets)

	vrouter := mysql.VRouter{Base: mysql.Base{ID: 2, Lcuuid: uuid.NewString()}}
	mysql.Db.Create(&vrouter)
	routingTable := mysql.RoutingTable{Base: mysql.Base{Lcuuid: uuid.NewString()}, VRouterID: 20}
	mysql.Db.Create(&routingTable)
	var routingTables []mysql.RoutingTable
	mysql.Db.Find(&routingTables)

	sg := mysql.SecurityGroup{Base: mysql.Base{ID: 3, Lcuuid: uuid.NewString()}}
	mysql.Db.Create(&sg)
	sgRule := mysql.SecurityGroupRule{Base: mysql.Base{Lcuuid: uuid.NewString()}, SecurityGroupID: 30}
	mysql.Db.Create(&sgRule)
	var sgRules []mysql.SecurityGroupRule
	mysql.Db.Find(&sgRules)
	vmSG := mysql.VMSecurityGroup{Base: mysql.Base{Lcuuid: uuid.NewString()}, VMID: 1, SecurityGroupID: 30}
	mysql.Db.Create(&vmSG)
	var vmSGs []mysql.VMSecurityGroup
	mysql.Db.Find(&vmSGs)

	podIngress := mysql.PodIngress{Base: mysql.Base{ID: 4, Lcuuid: uuid.NewString()}}
	mysql.Db.Create(&podIngress)
	podIngressRule := mysql.PodIngressRule{Base: mysql.Base{Lcuuid: uuid.NewString()}, PodIngressID: 40}
	mysql.Db.Create(&podIngressRule)
	var podIngressRules []mysql.PodIngressRule
	mysql.Db.Find(&podIngressRules)
	podIngressRuleBkd := mysql.PodIngressRuleBackend{Base: mysql.Base{Lcuuid: uuid.NewString()}, PodIngressID: 40}
	mysql.Db.Create(&podIngressRuleBkd)
	var podIngressRuleBkds []mysql.PodIngressRuleBackend
	mysql.Db.Find(&podIngressRuleBkds)

	podService := mysql.PodService{Base: mysql.Base{ID: 5, Lcuuid: uuid.NewString()}}
	mysql.Db.Create(&podService)
	podServicePort := mysql.PodServicePort{Base: mysql.Base{Lcuuid: uuid.NewString()}, PodServiceID: 50}
	mysql.Db.Create(&podServicePort)
	var podServicePorts []mysql.PodServicePort
	mysql.Db.Find(&podServicePorts)
	podGroupPort := mysql.PodGroupPort{Base: mysql.Base{Lcuuid: uuid.NewString()}, PodGroupID: 1, PodServiceID: 50}
	mysql.Db.Create(&podGroupPort)
	var podGroupPorts []mysql.PodGroupPort
	mysql.Db.Find(&podGroupPorts)

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
	mysql.Db.Find(&subnets)
	assert.Equal(t.T(), 0, len(subnets))
	mysql.Db.Find(&routingTables)
	assert.Equal(t.T(), 0, len(routingTables))
	mysql.Db.Find(&sgRules)
	assert.Equal(t.T(), 0, len(sgRules))
	mysql.Db.Find(&vmSGs)
	assert.Equal(t.T(), 0, len(vmSGs))
	mysql.Db.Find(&podIngressRules)
	assert.Equal(t.T(), 0, len(podIngressRules))
	mysql.Db.Find(&podIngressRuleBkds)
	assert.Equal(t.T(), 0, len(podIngressRuleBkds))
	mysql.Db.Find(&podServicePorts)
	assert.Equal(t.T(), 0, len(podServicePorts))
	mysql.Db.Find(&podGroupPorts)
	assert.Equal(t.T(), 0, len(podGroupPorts))
}
