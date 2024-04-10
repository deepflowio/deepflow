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
	"strings"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

// 以VPCID和IP为key，获取IP关联的NAT网关、负载均衡、负载均衡监听器、容器Ingress和容器服务数据
type ChIPRelation struct {
	UpdaterComponent[mysql.ChIPRelation, IPRelationKey]
}

func NewChIPRelation() *ChIPRelation {
	updater := &ChIPRelation{
		newUpdaterComponent[mysql.ChIPRelation, IPRelationKey](
			RESOURCE_TYPE_CH_IP_RELATION,
		),
	}
	updater.updaterDG = updater
	return updater
}

func (i *ChIPRelation) generateNewData(db *mysql.DB) (map[IPRelationKey]mysql.ChIPRelation, bool) {
	toolDS, ok := i.newToolDataSet(db)
	if !ok {
		return nil, false
	}
	keyToDBItem := make(map[IPRelationKey]mysql.ChIPRelation)
	if ok := i.generateFromNATGateway(keyToDBItem, toolDS, db); !ok {
		return nil, false
	}
	if ok := i.generateFromLB(keyToDBItem, toolDS, db); !ok {
		return nil, false
	}
	if ok := i.generateFromPodService(keyToDBItem, toolDS, db); !ok {
		return nil, false
	}
	return keyToDBItem, true
}

func (i *ChIPRelation) generateKey(dbItem mysql.ChIPRelation) IPRelationKey {
	return IPRelationKey{
		L3EPCID: dbItem.L3EPCID,
		IP:      dbItem.IP,
	}
}

func (i *ChIPRelation) generateUpdateInfo(oldItem, newItem mysql.ChIPRelation) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.NATGWID != newItem.NATGWID {
		updateInfo["natgw_id"] = newItem.NATGWID
	}
	if oldItem.NATGWName != newItem.NATGWName {
		updateInfo["natgw_name"] = newItem.NATGWName
	}
	if oldItem.LBID != newItem.LBID {
		updateInfo["lb_id"] = newItem.LBID
	}
	if oldItem.LBName != newItem.LBName {
		updateInfo["lb_name"] = newItem.LBName
	}
	if oldItem.LBListenerID != newItem.LBListenerID {
		updateInfo["lb_listener_id"] = newItem.LBListenerID
	}
	if oldItem.LBListenerName != newItem.LBListenerName {
		updateInfo["lb_listener_name"] = newItem.LBListenerName
	}
	if oldItem.PodIngressID != newItem.PodIngressID {
		updateInfo["pod_ingress_id"] = newItem.PodIngressID
	}
	if oldItem.PodIngressName != newItem.PodIngressName {
		updateInfo["pod_ingress_name"] = newItem.PodIngressName
	}
	if oldItem.PodServiceID != newItem.PodServiceID {
		updateInfo["pod_service_id"] = newItem.PodServiceID
	}
	if oldItem.PodServiceName != newItem.PodServiceName {
		updateInfo["pod_service_name"] = newItem.PodServiceName
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

type toolDataSet struct {
	vmIDToVIFIDs         map[int][]int
	vmIDToVPCID          map[int]int
	natGatewayIDToVIFIDs map[int][]int
	lbIDToVIFIDs         map[int][]int
	podServiceIDToVIFIDs map[int][]int
	podIDToVIFIDs        map[int][]int
	vifIDToIPs           map[int][]string
}

func (i *ChIPRelation) newToolDataSet(db *mysql.DB) (*toolDataSet, bool) {
	toolDS := &toolDataSet{
		vmIDToVIFIDs:         make(map[int][]int),
		vmIDToVPCID:          make(map[int]int),
		natGatewayIDToVIFIDs: make(map[int][]int),
		lbIDToVIFIDs:         make(map[int][]int),
		podServiceIDToVIFIDs: make(map[int][]int),
		podIDToVIFIDs:        make(map[int][]int),
		vifIDToIPs:           make(map[int][]string),
	}

	var vms []*mysql.VM
	if err := db.Unscoped().Find(&vms).Error; err != nil {
		log.Error(dbQueryResourceFailed(RESOURCE_TYPE_VM, err))
		return nil, false
	}
	for _, vm := range vms {
		toolDS.vmIDToVPCID[vm.ID] = vm.VPCID
	}

	var vifs []*mysql.VInterface
	if err := db.Where(
		"devicetype IN ?",
		[]int{
			common.VIF_DEVICE_TYPE_VM,
			common.VIF_DEVICE_TYPE_NAT_GATEWAY,
			common.VIF_DEVICE_TYPE_LB,
			common.VIF_DEVICE_TYPE_POD_SERVICE,
			common.VIF_DEVICE_TYPE_POD,
		},
	).Unscoped().Find(&vifs).Error; err != nil {
		log.Error(dbQueryResourceFailed(RESOURCE_TYPE_VINTERFACE, err))
		return nil, false
	}

	for _, vif := range vifs {
		if vif.DeviceType == common.VIF_DEVICE_TYPE_VM {
			toolDS.vmIDToVIFIDs[vif.DeviceID] = append(toolDS.vmIDToVIFIDs[vif.DeviceID], vif.ID)
		} else if vif.DeviceType == common.VIF_DEVICE_TYPE_NAT_GATEWAY {
			toolDS.natGatewayIDToVIFIDs[vif.DeviceID] = append(toolDS.natGatewayIDToVIFIDs[vif.DeviceID], vif.ID)
		} else if vif.DeviceType == common.VIF_DEVICE_TYPE_LB {
			toolDS.lbIDToVIFIDs[vif.DeviceID] = append(toolDS.lbIDToVIFIDs[vif.DeviceID], vif.ID)
		} else if vif.DeviceType == common.VIF_DEVICE_TYPE_POD_SERVICE {
			toolDS.podServiceIDToVIFIDs[vif.DeviceID] = append(toolDS.podServiceIDToVIFIDs[vif.DeviceID], vif.ID)
		} else if vif.DeviceType == common.VIF_DEVICE_TYPE_POD {
			toolDS.podIDToVIFIDs[vif.DeviceID] = append(toolDS.podIDToVIFIDs[vif.DeviceID], vif.ID)
		}
	}

	var wanIPs []*mysql.WANIP
	if err := db.Unscoped().Find(&wanIPs).Error; err != nil {
		log.Error(dbQueryResourceFailed(RESOURCE_TYPE_WANIP, err))
		return nil, false
	}
	var lanIPs []*mysql.LANIP
	if err := db.Unscoped().Find(&lanIPs).Error; err != nil {
		log.Error(dbQueryResourceFailed(RESOURCE_TYPE_LANIP, err))
		return nil, false
	}

	for _, wanIP := range wanIPs {
		toolDS.vifIDToIPs[wanIP.VInterfaceID] = append(toolDS.vifIDToIPs[wanIP.VInterfaceID], wanIP.IP)
	}
	for _, lanIP := range lanIPs {
		toolDS.vifIDToIPs[lanIP.VInterfaceID] = append(toolDS.vifIDToIPs[lanIP.VInterfaceID], lanIP.IP)
	}
	return toolDS, true
}

func (i *ChIPRelation) generateFromNATGateway(keyToDBItem map[IPRelationKey]mysql.ChIPRelation, toolDS *toolDataSet, db *mysql.DB) bool {
	var natGateways []*mysql.NATGateway
	if err := db.Unscoped().Find(&natGateways).Error; err != nil {
		log.Error(dbQueryResourceFailed(RESOURCE_TYPE_NAT_GATEWAY, err))
		return false
	}
	var natRules []*mysql.NATRule
	if err := db.Unscoped().Find(&natRules).Error; err != nil {
		log.Error(dbQueryResourceFailed(RESOURCE_TYPE_NAT_RULE, err))
		return false
	}
	natGatewayIDToNatRules := make(map[int][]*mysql.NATRule)
	for _, natRule := range natRules {
		natGatewayIDToNatRules[natRule.NATGatewayID] = append(natGatewayIDToNatRules[natRule.NATGatewayID], natRule)
	}
	var natVMConns []*mysql.NATVMConnection
	if err := db.Unscoped().Find(&natVMConns).Error; err != nil {
		log.Error(dbQueryResourceFailed(RESOURCE_TYPE_NAT_VM_CONNECTION, err))
		return false
	}
	for _, natGateway := range natGateways {
		// VPCID：网关VPC
		// IP：网关自身IP
		for _, vif := range toolDS.natGatewayIDToVIFIDs[natGateway.ID] {
			for _, ip := range toolDS.vifIDToIPs[vif] {
				keyToDBItem[IPRelationKey{L3EPCID: natGateway.VPCID, IP: ip}] = mysql.ChIPRelation{
					L3EPCID:   natGateway.VPCID,
					IP:        ip,
					NATGWID:   natGateway.ID,
					NATGWName: natGateway.Name,
					TeamID:    DomainToTeamID[natGateway.Domain],
				}
			}
		}
		// VPCID：网关VPC
		// IP：网关关联的云服务器自身IP
		for _, natVMConn := range natVMConns {
			if natVMConn.NATGatewayID != natGateway.ID {
				continue
			}
			for _, vifID := range toolDS.vmIDToVIFIDs[natVMConn.VMID] {
				for _, ip := range toolDS.vifIDToIPs[vifID] {
					keyToDBItem[IPRelationKey{L3EPCID: natGateway.VPCID, IP: ip}] = mysql.ChIPRelation{
						L3EPCID:   natGateway.VPCID,
						IP:        ip,
						NATGWID:   natGateway.ID,
						NATGWName: natGateway.Name,
						TeamID:    DomainToTeamID[natGateway.Domain],
					}
				}
			}
		}
		// VPCID：网关VPC
		// IP：SNAT前IP、DNAT后IP
		for _, natRule := range natGatewayIDToNatRules[natGateway.ID] {
			keyToDBItem[IPRelationKey{L3EPCID: natGateway.VPCID, IP: natRule.FixedIP}] = mysql.ChIPRelation{
				L3EPCID:   natGateway.VPCID,
				IP:        natRule.FixedIP,
				NATGWID:   natGateway.ID,
				NATGWName: natGateway.Name,
				TeamID:    DomainToTeamID[natGateway.Domain],
			}
		}
	}
	return true
}

func (i *ChIPRelation) generateFromLB(keyToDBItem map[IPRelationKey]mysql.ChIPRelation, toolDS *toolDataSet, db *mysql.DB) bool {
	var lbs []*mysql.LB
	if err := db.Unscoped().Find(&lbs).Error; err != nil {
		log.Error(dbQueryResourceFailed(RESOURCE_TYPE_LB, err))
		return false
	}
	var lbListeners []*mysql.LBListener
	if err := db.Unscoped().Find(&lbListeners).Error; err != nil {
		log.Error(dbQueryResourceFailed(RESOURCE_TYPE_LB_LISTENER, err))
		return false
	}
	lbIDToLBListeners := make(map[int][]*mysql.LBListener)
	for _, lbListener := range lbListeners {
		lbIDToLBListeners[lbListener.LBID] = append(lbIDToLBListeners[lbListener.LBID], lbListener)
	}
	var lbTargetServers []*mysql.LBTargetServer
	if err := db.Unscoped().Find(&lbTargetServers).Error; err != nil {
		log.Error(dbQueryResourceFailed(RESOURCE_TYPE_LB_TARGET_SERVER, err))
		return false
	}
	lbIDToLBTargetServers := make(map[int][]*mysql.LBTargetServer)
	lbListenerIDToLBTargetServers := make(map[int][]*mysql.LBTargetServer)
	for _, lbTS := range lbTargetServers {
		lbIDToLBTargetServers[lbTS.LBID] = append(lbIDToLBTargetServers[lbTS.LBID], lbTS)
		lbListenerIDToLBTargetServers[lbTS.LBListenerID] = append(lbListenerIDToLBTargetServers[lbTS.LBListenerID], lbTS)
	}
	var lbVMConns []*mysql.LBVMConnection
	if err := db.Unscoped().Find(&lbVMConns).Error; err != nil {
		log.Error(dbQueryResourceFailed(RESOURCE_TYPE_LB_VM_CONNECTION, err))
		return false
	}
	for _, lb := range lbs {
		// VPCID：负载均衡器VPC
		// IP：负载均衡器自身IP
		for _, vif := range toolDS.lbIDToVIFIDs[lb.ID] {
			for _, ip := range toolDS.vifIDToIPs[vif] {
				keyToDBItem[IPRelationKey{L3EPCID: lb.VPCID, IP: ip}] = mysql.ChIPRelation{
					L3EPCID: lb.VPCID,
					IP:      ip,
					LBID:    lb.ID,
					LBName:  lb.Name,
					TeamID:  DomainToTeamID[lb.Domain],
				}
			}
		}
		// VPCID：负载均衡器VPC
		// IP：负载均衡器关联的云服务器自身IP
		for _, lbVMConn := range lbVMConns {
			if lbVMConn.LBID != lb.ID {
				continue
			}
			for _, vifID := range toolDS.vmIDToVIFIDs[lbVMConn.VMID] {
				for _, ip := range toolDS.vifIDToIPs[vifID] {
					keyToDBItem[IPRelationKey{L3EPCID: lb.VPCID, IP: ip}] = mysql.ChIPRelation{
						L3EPCID: lb.VPCID,
						IP:      ip,
						LBID:    lb.ID,
						LBName:  lb.Name,
						TeamID:  DomainToTeamID[lb.Domain],
					}
				}
			}
		}
		for _, lbListener := range lbIDToLBListeners[lb.ID] {
			// VPCID：负载均衡器VPC
			// IP：负载均衡监听器自身IP
			for _, ip := range strings.Split(lbListener.IPs, ",") {
				keyToDBItem[IPRelationKey{L3EPCID: lb.VPCID, IP: ip}] = mysql.ChIPRelation{
					L3EPCID:        lb.VPCID,
					IP:             ip,
					LBID:           lb.ID,
					LBName:         lb.Name,
					LBListenerID:   lbListener.ID,
					LBListenerName: lbListener.Name,
					TeamID:         DomainToTeamID[lb.Domain],
				}
			}
			// VPCID：负载均衡器VPC、后端主机云服务器VPC
			// IP：后端主机IP
			for _, lbTS := range lbListenerIDToLBTargetServers[lbListener.ID] {
				var vpcID int
				if lbTS.VMID != 0 {
					vpcID = toolDS.vmIDToVPCID[lbTS.VMID]
				} else {
					vpcID = lb.VPCID
				}
				if vpcID == 0 {
					continue
				}
				keyToDBItem[IPRelationKey{L3EPCID: vpcID, IP: lbTS.IP}] = mysql.ChIPRelation{
					L3EPCID:        vpcID,
					IP:             lbTS.IP,
					LBID:           lb.ID,
					LBName:         lb.Name,
					LBListenerID:   lbListener.ID,
					LBListenerName: lbListener.Name,
					TeamID:         DomainToTeamID[lb.Domain],
				}
			}
		}
	}
	return true
}

func (i *ChIPRelation) generateFromPodService(keyToDBItem map[IPRelationKey]mysql.ChIPRelation, toolDS *toolDataSet, db *mysql.DB) bool {
	var pods []*mysql.Pod
	if err := db.Unscoped().Find(&pods).Error; err != nil {
		log.Error(dbQueryResourceFailed(RESOURCE_TYPE_POD, err))
		return false
	}
	podGroupIDToPodIDs := make(map[int][]int)
	for _, pod := range pods {
		podGroupIDToPodIDs[pod.PodGroupID] = append(podGroupIDToPodIDs[pod.PodGroupID], pod.ID)
	}
	var podGroupPorts []*mysql.PodGroupPort
	if err := db.Unscoped().Find(&podGroupPorts).Error; err != nil {
		log.Error(dbQueryResourceFailed(RESOURCE_TYPE_POD_GROUP_PORT, err))
		return false
	}
	podServiceIDToPodIDs := make(map[int][]int)
	for _, podGroupPort := range podGroupPorts {
		for _, podID := range podGroupIDToPodIDs[podGroupPort.PodGroupID] {
			podServiceIDToPodIDs[podGroupPort.PodServiceID] = append(podServiceIDToPodIDs[podGroupPort.PodServiceID], podID)
		}
	}
	var podIngresses []*mysql.PodIngress
	if err := db.Unscoped().Find(&podIngresses).Error; err != nil {
		log.Error(dbQueryResourceFailed(RESOURCE_TYPE_POD_INGRESS, err))
		return false
	}
	podIngressIDToName := make(map[int]string)
	for _, podIngress := range podIngresses {
		podIngressIDToName[podIngress.ID] = podIngress.Name
	}
	var podServices []*mysql.PodService
	if err := db.Unscoped().Find(&podServices).Error; err != nil {
		log.Error(dbQueryResourceFailed(RESOURCE_TYPE_POD_SERVICE, err))
		return false
	}
	for _, podService := range podServices {
		// VPCID：容器服务VPC
		// IP：容器服务自身IP
		for _, vifID := range toolDS.podServiceIDToVIFIDs[podService.ID] {
			for _, ip := range toolDS.vifIDToIPs[vifID] {
				dbItem := mysql.ChIPRelation{
					L3EPCID:        podService.VPCID,
					IP:             ip,
					PodServiceID:   podService.ID,
					PodServiceName: podService.Name,
					TeamID:         DomainToTeamID[podService.Domain],
				}
				if podService.PodIngressID != 0 {
					dbItem.PodIngressID = podService.PodIngressID
					dbItem.PodIngressName = podIngressIDToName[podService.PodIngressID]
				}
				keyToDBItem[IPRelationKey{L3EPCID: podService.VPCID, IP: ip}] = dbItem
			}
		}
		// VPCID：容器服务VPC
		// IP：容器服务关联的POD自身IP
		for _, podID := range podServiceIDToPodIDs[podService.ID] {
			for _, vifID := range toolDS.podIDToVIFIDs[podID] {
				for _, ip := range toolDS.vifIDToIPs[vifID] {
					dbItem := mysql.ChIPRelation{
						L3EPCID:        podService.VPCID,
						IP:             ip,
						PodServiceID:   podService.ID,
						PodServiceName: podService.Name,
						TeamID:         DomainToTeamID[podService.Domain],
					}
					if podService.PodIngressID != 0 {
						dbItem.PodIngressID = podService.PodIngressID
						dbItem.PodIngressName = podIngressIDToName[podService.PodIngressID]
					}
					keyToDBItem[IPRelationKey{L3EPCID: podService.VPCID, IP: ip}] = dbItem
				}
			}
		}
	}
	return true
}
