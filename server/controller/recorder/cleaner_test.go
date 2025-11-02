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

	mysql "github.com/deepflowio/deepflow/server/controller/db/metadb"
)

func (t *SuiteTest) TestForceDelete() {
	vm := mysqlmodel.VM{Base: mysqlmodel.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String()}
	mysql.DefaultDB.Create(&vm)
	mysql.DefaultDB.Model(mysqlmodel.VM{}).Where("lcuuid = ?", vm.Lcuuid).Updates(map[string]interface{}{"deleted_at": time.Now().Add(time.Duration(-24) * time.Hour)})
	var addedVM mysqlmodel.VM
	mysql.DefaultDB.Unscoped().Where("lcuuid = ?", vm.Lcuuid).Find(&addedVM)
	if addedVM.ID == 0 {
		fmt.Println("addedVM should not be null")
	}
	deleteExpired[mysqlmodel.VM](time.Now().Add(time.Duration(-1) * time.Hour))
	mysql.DefaultDB.Unscoped().Where("lcuuid = ?", vm.Lcuuid).Find(&addedVM)
	if addedVM.ID != 0 {
		fmt.Println("addedVM should be null")
	}
}

func (t *SuiteTest) TestCleanDirtyData() {
	networks := []mysqlmodel.Network{{Base: mysqlmodel.Base{ID: 1, Lcuuid: uuid.NewString()}}, {Base: mysqlmodel.Base{ID: 10, Lcuuid: uuid.NewString()}}}
	mysql.DefaultDB.Create(&networks)
	mysql.DefaultDB.Where("id = ?", 10).Delete(&mysqlmodel.Network{})
	subnet := mysqlmodel.Subnet{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, NetworkID: 10}
	mysql.DefaultDB.Create(&subnet)
	var subnets []mysqlmodel.Subnet
	mysql.DefaultDB.Find(&subnets)

	vrouter := mysqlmodel.VRouter{Base: mysqlmodel.Base{ID: 2, Lcuuid: uuid.NewString()}}
	mysql.DefaultDB.Create(&vrouter)
	routingTable := mysqlmodel.RoutingTable{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, VRouterID: 20}
	mysql.DefaultDB.Create(&routingTable)
	var routingTables []mysqlmodel.RoutingTable
	mysql.DefaultDB.Find(&routingTables)

	sg := mysql.SecurityGroup{Base: mysqlmodel.Base{ID: 3, Lcuuid: uuid.NewString()}}
	mysql.DefaultDB.Create(&sg)
	sgRule := mysql.SecurityGroupRule{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, SecurityGroupID: 30}
	mysql.DefaultDB.Create(&sgRule)
	var sgRules []mysql.SecurityGroupRule
	mysql.DefaultDB.Find(&sgRules)
	vmSG := mysql.VMSecurityGroup{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, VMID: 1, SecurityGroupID: 30}
	mysql.DefaultDB.Create(&vmSG)
	var vmSGs []mysql.VMSecurityGroup
	mysql.DefaultDB.Find(&vmSGs)

	podIngress := mysqlmodel.PodIngress{Base: mysqlmodel.Base{ID: 4, Lcuuid: uuid.NewString()}}
	mysql.DefaultDB.Create(&podIngress)
	podIngressRule := mysqlmodel.PodIngressRule{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, PodIngressID: 40}
	mysql.DefaultDB.Create(&podIngressRule)
	var podIngressRules []mysqlmodel.PodIngressRule
	mysql.DefaultDB.Find(&podIngressRules)
	podIngressRuleBkd := mysqlmodel.PodIngressRuleBackend{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, PodIngressID: 40}
	mysql.DefaultDB.Create(&podIngressRuleBkd)
	var podIngressRuleBkds []mysqlmodel.PodIngressRuleBackend
	mysql.DefaultDB.Find(&podIngressRuleBkds)

	podService := mysqlmodel.PodService{Base: mysqlmodel.Base{ID: 5, Lcuuid: uuid.NewString()}}
	mysql.DefaultDB.Create(&podService)
	podServicePort := mysqlmodel.PodServicePort{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, PodServiceID: 50}
	mysql.DefaultDB.Create(&podServicePort)
	var podServicePorts []mysqlmodel.PodServicePort
	mysql.DefaultDB.Find(&podServicePorts)
	podGroupPort := mysqlmodel.PodGroupPort{Base: mysqlmodel.Base{Lcuuid: uuid.NewString()}, PodGroupID: 1, PodServiceID: 50}
	mysql.DefaultDB.Create(&podGroupPort)
	var podGroupPorts []mysqlmodel.PodGroupPort
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
