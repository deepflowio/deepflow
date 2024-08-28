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

package tagrecorder

import (
	"math/rand"
	"time"

	"github.com/bxcodec/faker/v3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/common"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
)

func RandID() int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(999)
}

func newDBWANIP(vifID int) mysqlmodel.WANIP {
	var wanip mysqlmodel.WANIP
	wanip.Lcuuid = uuid.NewString()
	wanip.VInterfaceID = vifID
	wanip.IP = faker.IPv4()
	return wanip
}

func newDBLANIP(vifID int) mysqlmodel.LANIP {
	var lanip mysqlmodel.LANIP
	lanip.Lcuuid = uuid.NewString()
	lanip.VInterfaceID = vifID
	lanip.IP = faker.IPv4()
	return lanip
}

func newDBVInterface(deviceType, deviceID int) mysqlmodel.VInterface {
	var vif mysqlmodel.VInterface
	vif.Lcuuid = uuid.NewString()
	vif.DeviceType = deviceType
	vif.DeviceID = deviceID
	return vif
}

func newDBVM() mysqlmodel.VM {
	var vm mysqlmodel.VM
	vm.Lcuuid = uuid.NewString()
	vm.Name = vm.Lcuuid[:6]
	vm.VPCID = RandID()
	return vm
}

func newDBNATGateway() mysqlmodel.NATGateway {
	var nat mysqlmodel.NATGateway
	nat.Lcuuid = uuid.NewString()
	nat.Name = nat.Lcuuid[:6]
	nat.VPCID = RandID()
	return nat
}

func newDBNATVMConnection(natID, vmID int) mysqlmodel.NATVMConnection {
	var connection mysqlmodel.NATVMConnection
	connection.Lcuuid = uuid.NewString()
	connection.NATGatewayID = natID
	connection.VMID = vmID
	return connection
}

func newDBNATRule(natID int) mysqlmodel.NATRule {
	var rule mysqlmodel.NATRule
	rule.Lcuuid = uuid.NewString()
	rule.NATGatewayID = natID
	rule.FixedIP = faker.IPv4()
	return rule
}

func newDBLB() mysqlmodel.LB {
	var lb mysqlmodel.LB
	lb.Lcuuid = uuid.NewString()
	lb.Name = lb.Lcuuid[:6]
	lb.VPCID = RandID()
	return lb
}

func newLBVMConnection(lbID, vmID int) mysqlmodel.LBVMConnection {
	var connection mysqlmodel.LBVMConnection
	connection.Lcuuid = uuid.NewString()
	connection.LBID = lbID
	connection.VMID = vmID
	return connection
}

func newDBLBListener(lbID int) mysqlmodel.LBListener {
	var listener mysqlmodel.LBListener
	listener.Lcuuid = uuid.NewString()
	listener.LBID = lbID
	listener.IPs = faker.IPv4()
	return listener
}

func newDBLBTargetServer(lbID, lbListenerID int) mysqlmodel.LBTargetServer {
	var server mysqlmodel.LBTargetServer
	server.Lcuuid = uuid.NewString()
	server.LBID = lbID
	server.LBListenerID = lbListenerID
	server.IP = faker.IPv4()
	return server
}

func newDBPodIngress() mysqlmodel.PodIngress {
	var ingress mysqlmodel.PodIngress
	ingress.Lcuuid = uuid.NewString()
	ingress.Name = ingress.Lcuuid[:6]
	return ingress
}

func newDBPodService(podIngressID int) mysqlmodel.PodService {
	var service mysqlmodel.PodService
	service.Lcuuid = uuid.NewString()
	service.Name = service.Lcuuid[:6]
	service.PodIngressID = podIngressID
	service.VPCID = RandID()
	return service
}

func newDBPodGroup() mysqlmodel.PodGroup {
	var group mysqlmodel.PodGroup
	group.Lcuuid = uuid.NewString()
	group.Name = group.Lcuuid[:6]
	return group
}

func newDBPodGroupPort(podServiceID, podGroupID int) mysqlmodel.PodGroupPort {
	var port mysqlmodel.PodGroupPort
	port.Lcuuid = uuid.NewString()
	port.PodGroupID = podGroupID
	port.PodServiceID = podServiceID
	return port
}

func newDBPod(podGroupID int) mysqlmodel.Pod {
	var pod mysqlmodel.Pod
	pod.Lcuuid = uuid.NewString()
	pod.Name = pod.Lcuuid[:6]
	pod.PodGroupID = podGroupID
	return pod
}

func clearIPRelationDB(db *gorm.DB) {
	db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysqlmodel.WANIP{})
	db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysqlmodel.LANIP{})
	db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysqlmodel.VInterface{})
	db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysqlmodel.VM{})
	db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysqlmodel.NATVMConnection{})
	db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysqlmodel.NATRule{})
	db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysqlmodel.NATGateway{})
	db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysqlmodel.LBVMConnection{})
	db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysqlmodel.LBListener{})
	db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysqlmodel.LBTargetServer{})
	db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysqlmodel.LB{})
	db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysqlmodel.PodService{})
	db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysqlmodel.PodIngress{})
	db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysqlmodel.PodGroupPort{})
	db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysqlmodel.PodGroup{})
	db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysqlmodel.Pod{})
}

func (t *SuiteTest) TestNewToolDataSet() {
	vm := newDBVM()
	t.db.Create(&vm)
	vmVIF := newDBVInterface(common.VIF_DEVICE_TYPE_VM, vm.ID)
	t.db.Create(&vmVIF)
	vmWANIP := newDBWANIP(vmVIF.ID)
	t.db.Create(&vmWANIP)
	nat := newDBNATGateway()
	t.db.Create(&nat)
	natVIF := newDBVInterface(common.VIF_DEVICE_TYPE_NAT_GATEWAY, nat.ID)
	t.db.Create(&natVIF)
	natLANIP := newDBLANIP(natVIF.ID)
	t.db.Create(&natLANIP)
	natVMConnection := newDBNATVMConnection(nat.ID, vm.ID)
	t.db.Create(&natVMConnection)
	natRule := newDBNATRule(nat.ID)
	t.db.Create(&natRule)
	lb := newDBLB()
	t.db.Create(&lb)
	lbVIF := newDBVInterface(common.VIF_DEVICE_TYPE_LB, lb.ID)
	t.db.Create(&lbVIF)
	lbWANIP := newDBWANIP(lbVIF.ID)
	t.db.Create(&lbWANIP)
	lbVMConnection := newLBVMConnection(lb.ID, vm.ID)
	t.db.Create(&lbVMConnection)
	lbListener := newDBLBListener(lb.ID)
	t.db.Create(&lbListener)
	ipLBTS := newDBLBTargetServer(lb.ID, lbListener.ID)
	t.db.Create(&ipLBTS)
	tsVM := newDBVM()
	t.db.Create(&tsVM)
	tsVMVIF := newDBVInterface(common.VIF_DEVICE_TYPE_VM, tsVM.ID)
	t.db.Create(&tsVMVIF)
	tsVMLANIP := newDBLANIP(tsVMVIF.ID)
	t.db.Create(&tsVMLANIP)
	vmLBTS := newDBLBTargetServer(lb.ID, lbListener.ID)
	vmLBTS.VMID = tsVM.ID
	t.db.Create(&vmLBTS)
	podIngress := newDBPodIngress()
	t.db.Create(&podIngress)
	podService := newDBPodService(podIngress.ID)
	t.db.Create(&podService)
	podServiceVIF := newDBVInterface(common.VIF_DEVICE_TYPE_POD_SERVICE, podService.ID)
	t.db.Create(&podServiceVIF)
	podServiceWANIP := newDBWANIP(podServiceVIF.ID)
	t.db.Create(&podServiceWANIP)
	podGroup := newDBPodGroup()
	t.db.Create(&podGroup)
	podGroupPort := newDBPodGroupPort(podService.ID, podGroup.ID)
	t.db.Create(&podGroupPort)
	pod := newDBPod(podGroup.ID)
	t.db.Create(&pod)
	podVIF := newDBVInterface(common.VIF_DEVICE_TYPE_POD, pod.ID)
	t.db.Create(&podVIF)
	podLANIP := newDBLANIP(podVIF.ID)
	t.db.Create(&podLANIP)

	updater := NewChIPRelation()
	toolDS, ok := updater.newToolDataSet()
	assert.True(t.T(), ok)
	assert.Equal(t.T(), map[int][]int{vm.ID: {vmVIF.ID}, tsVM.ID: {tsVMVIF.ID}}, toolDS.vmIDToVIFIDs)
	assert.Equal(t.T(), map[int]int{vm.ID: vm.VPCID, tsVM.ID: tsVM.VPCID}, toolDS.vmIDToVPCID)
	assert.Equal(t.T(), map[int][]int{nat.ID: {natVIF.ID}}, toolDS.natGatewayIDToVIFIDs)
	assert.Equal(t.T(), map[int][]int{lb.ID: {lbVIF.ID}}, toolDS.lbIDToVIFIDs)
	assert.Equal(t.T(), map[int][]int{podService.ID: {podServiceVIF.ID}}, toolDS.podServiceIDToVIFIDs)
	assert.Equal(t.T(), map[int][]int{pod.ID: {podVIF.ID}}, toolDS.podIDToVIFIDs)
	assert.Equal(t.T(), 6, len(toolDS.vifIDToIPs))
	clearIPRelationDB(t.db)
}

func (t *SuiteTest) TestGenerateFromNATGateway() {
	vm := newDBVM()
	t.db.Create(&vm)
	vmVIF := newDBVInterface(common.VIF_DEVICE_TYPE_VM, vm.ID)
	t.db.Create(&vmVIF)
	vmWANIP := newDBWANIP(vmVIF.ID)
	t.db.Create(&vmWANIP)
	nat := newDBNATGateway()
	t.db.Create(&nat)
	natVIF := newDBVInterface(common.VIF_DEVICE_TYPE_NAT_GATEWAY, nat.ID)
	t.db.Create(&natVIF)
	natLANIP := newDBLANIP(natVIF.ID)
	t.db.Create(&natLANIP)
	natVMConnection := newDBNATVMConnection(nat.ID, vm.ID)
	t.db.Create(&natVMConnection)
	natRule := newDBNATRule(nat.ID)
	t.db.Create(&natRule)

	updater := NewChIPRelation()
	toolDS, _ := updater.newToolDataSet()
	keyToDBItem := make(map[IPRelationKey]mysqlmodel.ChIPRelation)
	updater.generateFromNATGateway(keyToDBItem, toolDS)

	assert.Equal(t.T(), 3, len(keyToDBItem))
	expectedKeys := []IPRelationKey{
		{L3EPCID: nat.VPCID, IP: vmWANIP.IP}, {L3EPCID: nat.VPCID, IP: natLANIP.IP}, {L3EPCID: nat.VPCID, IP: natRule.FixedIP},
	}
	for key, value := range keyToDBItem {
		assert.Equal(t.T(), nat.ID, value.NATGWID)
		assert.Equal(t.T(), nat.Name, value.NATGWName)
		assert.Contains(t.T(), expectedKeys, key)
		assert.Equal(t.T(), nat.VPCID, value.L3EPCID)
		assert.NotNil(t.T(), value.IP)
		assert.Equal(t.T(), 0, value.LBID)
		assert.Equal(t.T(), 0, value.PodServiceID)
	}
	clearIPRelationDB(t.db)
}

func (t *SuiteTest) TestGenerateFromLB() {
	vm := newDBVM()
	t.db.Create(&vm)
	vmVIF := newDBVInterface(common.VIF_DEVICE_TYPE_VM, vm.ID)
	t.db.Create(&vmVIF)
	vmWANIP := newDBWANIP(vmVIF.ID)
	t.db.Create(&vmWANIP)
	lb := newDBLB()
	t.db.Create(&lb)
	lbVIF := newDBVInterface(common.VIF_DEVICE_TYPE_LB, lb.ID)
	t.db.Create(&lbVIF)
	lbLANIP := newDBLANIP(lbVIF.ID)
	t.db.Create(&lbLANIP)
	lbVMConnection := newLBVMConnection(lb.ID, vm.ID)
	t.db.Create(&lbVMConnection)
	lbListener := newDBLBListener(lb.ID)
	t.db.Create(&lbListener)
	ipLBTS := newDBLBTargetServer(lb.ID, lbListener.ID)
	t.db.Create(&ipLBTS)
	tsVM := newDBVM()
	t.db.Create(&tsVM)
	tsVMVIF := newDBVInterface(common.VIF_DEVICE_TYPE_VM, tsVM.ID)
	t.db.Create(&tsVMVIF)
	tsVMLANIP := newDBLANIP(tsVMVIF.ID)
	t.db.Create(&tsVMLANIP)
	vmLBTS := newDBLBTargetServer(lb.ID, lbListener.ID)
	vmLBTS.VMID = tsVM.ID
	t.db.Create(&vmLBTS)

	updater := NewChIPRelation()
	toolDS, _ := updater.newToolDataSet()
	keyToDBItem := make(map[IPRelationKey]mysqlmodel.ChIPRelation)
	updater.generateFromLB(keyToDBItem, toolDS)

	assert.Equal(t.T(), 5, len(keyToDBItem))
	expectedKeys := []IPRelationKey{
		{L3EPCID: lb.VPCID, IP: lbLANIP.IP}, {L3EPCID: lb.VPCID, IP: lbListener.IPs}, {L3EPCID: tsVM.VPCID, IP: vmLBTS.IP},
		{L3EPCID: lb.VPCID, IP: vmWANIP.IP}, {L3EPCID: lb.VPCID, IP: ipLBTS.IP},
	}
	for key, value := range keyToDBItem {
		if value.IP == lbLANIP.IP || value.IP == vmWANIP.IP {
			assert.Equal(t.T(), lb.ID, value.LBID)
			assert.Equal(t.T(), lb.Name, value.LBName)
		} else if value.IP == lbListener.IPs {
			assert.Equal(t.T(), lbListener.ID, value.LBListenerID)
			assert.Equal(t.T(), lbListener.Name, value.LBListenerName)
		} else {
			assert.Equal(t.T(), lb.ID, value.LBID)
			assert.Equal(t.T(), lb.Name, value.LBName)
			assert.Equal(t.T(), lbListener.ID, value.LBListenerID)
			assert.Equal(t.T(), lbListener.Name, value.LBListenerName)
		}
		assert.Contains(t.T(), expectedKeys, key)
		assert.Contains(t.T(), []int{lb.VPCID, tsVM.VPCID}, value.L3EPCID)
		assert.NotNil(t.T(), value.IP)
		assert.Equal(t.T(), 0, value.NATGWID)
		assert.Equal(t.T(), 0, value.PodServiceID)
	}
	clearIPRelationDB(t.db)
}

func (t *SuiteTest) TestGenerateFromPodService() {
	podIngress := newDBPodIngress()
	t.db.Create(&podIngress)
	podService := newDBPodService(podIngress.ID)
	t.db.Create(&podService)
	podServiceVIF := newDBVInterface(common.VIF_DEVICE_TYPE_POD_SERVICE, podService.ID)
	t.db.Create(&podServiceVIF)
	podServiceWANIP := newDBWANIP(podServiceVIF.ID)
	t.db.Create(&podServiceWANIP)
	podGroup := newDBPodGroup()
	t.db.Create(&podGroup)
	podGroupPort := newDBPodGroupPort(podService.ID, podGroup.ID)
	t.db.Create(&podGroupPort)
	pod := newDBPod(podGroup.ID)
	t.db.Create(&pod)
	podVIF := newDBVInterface(common.VIF_DEVICE_TYPE_POD, pod.ID)
	t.db.Create(&podVIF)
	podLANIP := newDBLANIP(podVIF.ID)
	t.db.Create(&podLANIP)

	updater := NewChIPRelation()
	toolDS, _ := updater.newToolDataSet()
	keyToDBItem := make(map[IPRelationKey]mysqlmodel.ChIPRelation)
	updater.generateFromPodService(keyToDBItem, toolDS)

	assert.Equal(t.T(), 2, len(keyToDBItem))
	expectedKeys := []IPRelationKey{
		{L3EPCID: podService.VPCID, IP: podLANIP.IP}, {L3EPCID: podService.VPCID, IP: podServiceWANIP.IP},
	}
	for key, value := range keyToDBItem {
		assert.Equal(t.T(), podService.ID, value.PodServiceID)
		assert.Equal(t.T(), podService.Name, value.PodServiceName)
		assert.Equal(t.T(), podIngress.ID, value.PodIngressID)
		assert.Equal(t.T(), podIngress.Name, value.PodIngressName)
		assert.Contains(t.T(), expectedKeys, key)
		assert.Equal(t.T(), podService.VPCID, value.L3EPCID)
		assert.Contains(t.T(), []string{podLANIP.IP, podServiceWANIP.IP}, value.IP)
		assert.Equal(t.T(), 0, value.NATGWID)
		assert.Equal(t.T(), 0, value.LBID)
	}
	clearIPRelationDB(t.db)
}

func (t *SuiteTest) TestGenerateIPRelationUpdateInfo() {
	newIPRelation := mysqlmodel.ChIPRelation{L3EPCID: 1, IP: "1.1.1.1", LBID: 1, LBName: "lb1", LBListenerID: 1, LBListenerName: "lbListener1"}
	oldIPRelation := mysqlmodel.ChIPRelation{L3EPCID: 1, IP: "1.1.1.1", LBID: 1, LBName: "lb1", LBListenerID: 1, LBListenerName: "lbListener1"}
	updater := NewChIPRelation()
	updateInfo, _ := updater.generateUpdateInfo(newIPRelation, oldIPRelation)
	assert.Equal(t.T(), 0, len(updateInfo))
	oldIPRelation.LBID = 2
	oldIPRelation.NATGWName = "nat1"
	oldIPRelation.PodServiceID = 1
	updateInfo, _ = updater.generateUpdateInfo(newIPRelation, oldIPRelation)
	assert.Equal(t.T(), 3, len(updateInfo))
	assert.Equal(t.T(), 2, updateInfo["lb_id"])
}
