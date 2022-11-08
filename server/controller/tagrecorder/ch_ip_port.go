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

package tagrecorder

import (
	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
)

type ChIPPort struct {
	UpdaterBase[mysql.ChIPPort, PortIPKey]
}

func NewChIPPort() *ChIPPort {
	updater := &ChIPPort{
		UpdaterBase[mysql.ChIPPort, PortIPKey]{
			resourceTypeName: RESOURCE_TYPE_CH_IP_PORT,
		},
	}
	updater.dataGenerator = updater
	return updater
}

type IPSubnet struct {
	IP       string
	SubnetID int
}

// - 获取负载均衡器和监听器
//   - 查找IP所属资源为负载均衡器的负载均衡器和监听器，并匹配协议和端口
//   - 查找IP所属资源为负载均衡器后端资源的负载均衡器和监听器，并匹配协议和端口
// - 获取容器服务
//   - 查找IP所属资源为容器服务的容器服务，并匹配协议和端口
//   - 查找IP所属资源为容器节点的容器服务
//     - NodePort类型: 查找节点所在集群的NodePort类型服务，并匹配协议和端口
//     - ClusterIP类型：查找节点所在集群的ClusterIP类型服务，并匹配协议和端口
//   - 查找IP所属资源为容器POD的容器服务，并匹配协议和端口
func (i *ChIPPort) generateNewData() (map[PortIPKey]mysql.ChIPPort, bool) {
	log.Infof("generate data for %s", i.resourceTypeName)
	keyToItem := make(map[PortIPKey]mysql.ChIPPort)
	ok := i.generatePortPodServiceData(keyToItem)
	if !ok {
		return nil, false
	}
	ok = i.generatePortLBData(keyToItem)
	if !ok {
		return nil, false
	}
	return keyToItem, true
}

func (i *ChIPPort) generateKey(dbItem mysql.ChIPPort) PortIPKey {
	return PortIPKey{IP: dbItem.IP, SubnetID: dbItem.SubnetID, Protocol: dbItem.Protocol, Port: dbItem.Port}
}

func (i *ChIPPort) generateUpdateInfo(oldItem, newItem mysql.ChIPPort) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.PortPodServiceID != newItem.PortPodServiceID {
		updateInfo["port_pod_service_id"] = newItem.PortPodServiceID
	}
	if oldItem.PortPodServiceName != newItem.PortPodServiceName {
		updateInfo["port_pod_service_name"] = newItem.PortPodServiceName
	}
	if oldItem.PortLBID != newItem.PortLBID {
		updateInfo["port_lb_id"] = newItem.PortLBID
	}
	if oldItem.PortLBName != newItem.PortLBName {
		updateInfo["port_lb_name"] = newItem.PortLBName
	}
	if oldItem.PortLBListenerID != newItem.PortLBListenerID {
		updateInfo["port_lb_listener_id"] = newItem.PortLBListenerID
	}
	if oldItem.PortLBListenerName != newItem.PortLBListenerName {
		updateInfo["port_lb_listener_name"] = newItem.PortLBListenerName
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (i *ChIPPort) generatePortPodServiceData(keyToItem map[PortIPKey]mysql.ChIPPort) bool {
	var podServices []mysql.PodService
	var vInterfaceIPs []mysql.LANIP
	var podServiceVInterfaces []mysql.VInterface
	var podNodeVInterfaces []mysql.VInterface
	var vmVInterfaces []mysql.VInterface
	var podVInterfaces []mysql.VInterface
	var vmPodNodeConnections []mysql.VMPodNodeConnection
	var podServicePorts []mysql.PodServicePort
	var podNodes []mysql.PodNode
	var pods []mysql.Pod
	var podGroupPorts []mysql.PodGroupPort
	var ipResources []mysql.WANIP
	var networks []mysql.Network
	err := mysql.Db.Find(&podServices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(i.resourceTypeName, err))
		return false
	}
	err = mysql.Db.Find(&vInterfaceIPs).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(i.resourceTypeName, err))
		return false
	}
	err = mysql.Db.Where("devicetype = ?", common.VIF_DEVICE_TYPE_POD_SERVICE).Find(&podServiceVInterfaces).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(i.resourceTypeName, err))
		return false
	}
	err = mysql.Db.Where("devicetype = ?", common.VIF_DEVICE_TYPE_POD_NODE).Find(&podNodeVInterfaces).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(i.resourceTypeName, err))
		return false
	}
	err = mysql.Db.Where("devicetype = ?", common.VIF_DEVICE_TYPE_VM).Find(&vmVInterfaces).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(i.resourceTypeName, err))
		return false
	}
	err = mysql.Db.Where("devicetype = ?", common.VIF_DEVICE_TYPE_POD).Find(&podVInterfaces).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(i.resourceTypeName, err))
		return false
	}
	err = mysql.Db.Find(&vmPodNodeConnections).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(i.resourceTypeName, err))
		return false
	}
	err = mysql.Db.Find(&podServicePorts).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(i.resourceTypeName, err))
		return false
	}
	err = mysql.Db.Find(&podNodes).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(i.resourceTypeName, err))
		return false
	}
	err = mysql.Db.Find(&pods).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(i.resourceTypeName, err))
		return false
	}
	err = mysql.Db.Find(&podGroupPorts).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(i.resourceTypeName, err))
		return false
	}
	err = mysql.Db.Find(&ipResources).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(i.resourceTypeName, err))
		return false
	}
	err = mysql.Db.Find(&networks).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(i.resourceTypeName, err))
		return false
	}

	serviceIDToName := make(map[int]string)
	serviceIDToClusterID := make(map[int]int)
	vifIDToIPSubnetIDs := make(map[int][]IPSubnet)
	serviceIDToVifIDs := make(map[int][]int)
	podNodeIDToVifIDs := make(map[int][]int)
	vmIDToVifIDs := make(map[int][]int)
	podIDToVifIDs := make(map[int][]int)
	podNodeIDToVMIDs := make(map[int][]int)
	podClusterIDToPodNodeIDs := make(map[int][]int)
	podGroupIDToPodNodeIDs := make(map[int][]int)
	podGroupIDToPodIDs := make(map[int][]int)
	for _, podService := range podServices {
		serviceIDToName[podService.ID] = podService.Name
		serviceIDToClusterID[podService.ID] = podService.PodClusterID
	}
	for _, vInterfaceIP := range vInterfaceIPs {
		vifIDToIPSubnetIDs[vInterfaceIP.VInterfaceID] = append(vifIDToIPSubnetIDs[vInterfaceIP.VInterfaceID], IPSubnet{IP: vInterfaceIP.IP, SubnetID: vInterfaceIP.NetworkID})
	}
	for _, podServiceVInterface := range podServiceVInterfaces {
		serviceIDToVifIDs[podServiceVInterface.DeviceID] = append(serviceIDToVifIDs[podServiceVInterface.DeviceID], podServiceVInterface.ID)
	}
	for _, podNodeVInterface := range podNodeVInterfaces {
		podNodeIDToVifIDs[podNodeVInterface.DeviceID] = append(podNodeIDToVifIDs[podNodeVInterface.DeviceID], podNodeVInterface.ID)
	}
	for _, vmVInterface := range vmVInterfaces {
		vmIDToVifIDs[vmVInterface.DeviceID] = append(vmIDToVifIDs[vmVInterface.DeviceID], vmVInterface.ID)
	}
	for _, vmPodNodeConnection := range vmPodNodeConnections {
		podNodeIDToVMIDs[vmPodNodeConnection.PodNodeID] = append(podNodeIDToVMIDs[vmPodNodeConnection.PodNodeID], vmPodNodeConnection.VMID)
	}
	for _, podNode := range podNodes {
		podClusterIDToPodNodeIDs[podNode.PodClusterID] = append(podClusterIDToPodNodeIDs[podNode.PodClusterID], podNode.ID)
	}

	for _, podServicePort := range podServicePorts {
		if common.ProtocolMap[podServicePort.Protocol] == 0 || podServicePort.PodServiceID == 0 {
			continue
		}
		portVifIDs := make([]int, 0)
		nodePortVifIDs := make([]int, 0)
		// devicetype=容器服务
		portVifIDs = append(portVifIDs, serviceIDToVifIDs[podServicePort.PodServiceID]...)
		// devicetype=容器节点，获取NodePort类型的容器服务
		podClusterID := serviceIDToClusterID[podServicePort.PodServiceID]
		podNodeIDs := podClusterIDToPodNodeIDs[podClusterID]
		for _, podNodeID := range podNodeIDs {
			vifIDs, ok := podNodeIDToVifIDs[podNodeID]
			if ok {
				nodePortVifIDs = append(nodePortVifIDs, vifIDs...)
			}
			vmIDs, ok := podNodeIDToVMIDs[podNodeID]
			if ok {
				for _, vmID := range vmIDs {
					nodePortVifIDs = append(nodePortVifIDs, vmIDToVifIDs[vmID]...)
				}
			}
		}
		for _, portVifID := range portVifIDs {
			ipSubnetIDs, ok := vifIDToIPSubnetIDs[portVifID]
			if !ok {
				continue
			}
			for _, ipSubnetID := range ipSubnetIDs {
				if ipSubnetID.IP == "" || podServicePort.Port == 0 {
					continue
				}
				key := PortIPKey{
					IP:       ipSubnetID.IP,
					SubnetID: ipSubnetID.SubnetID,
					Protocol: common.ProtocolMap[podServicePort.Protocol],
					Port:     podServicePort.Port,
				}
				keyToItem[key] = mysql.ChIPPort{
					IP:                 ipSubnetID.IP,
					SubnetID:           ipSubnetID.SubnetID,
					Protocol:           common.ProtocolMap[podServicePort.Protocol],
					Port:               podServicePort.Port,
					PortPodServiceID:   podServicePort.PodServiceID,
					PortPodServiceName: serviceIDToName[podServicePort.PodServiceID],
				}
			}
		}

		for _, nodePortVifID := range nodePortVifIDs {
			ipSubnetIDs, ok := vifIDToIPSubnetIDs[nodePortVifID]
			if !ok {
				continue
			}
			for _, ipSubnetID := range ipSubnetIDs {
				if ipSubnetID.IP == "" || podServicePort.NodePort == 0 {
					continue
				}
				key := PortIPKey{
					IP:       ipSubnetID.IP,
					SubnetID: ipSubnetID.SubnetID,
					Protocol: common.ProtocolMap[podServicePort.Protocol],
					Port:     podServicePort.NodePort,
				}
				keyToItem[key] = mysql.ChIPPort{
					IP:                 ipSubnetID.IP,
					SubnetID:           ipSubnetID.SubnetID,
					Protocol:           common.ProtocolMap[podServicePort.Protocol],
					Port:               podServicePort.NodePort,
					PortPodServiceID:   podServicePort.PodServiceID,
					PortPodServiceName: serviceIDToName[podServicePort.PodServiceID],
				}
			}
		}
	}
	for _, pod := range pods {
		podGroupIDToPodNodeIDs[pod.PodGroupID] = append(podGroupIDToPodNodeIDs[pod.PodGroupID], pod.PodNodeID)
		podGroupIDToPodIDs[pod.PodGroupID] = append(podGroupIDToPodIDs[pod.PodGroupID], pod.ID)
	}
	for _, podVInterface := range podVInterfaces {
		podIDToVifIDs[podVInterface.DeviceID] = append(podIDToVifIDs[podVInterface.DeviceID], podVInterface.ID)
	}
	for _, podGroupPort := range podGroupPorts {
		if podGroupPort.Port == 0 || common.ProtocolMap[podGroupPort.Protocol] == 0 || podGroupPort.PodGroupID == 0 {
			continue
		}
		podNodeIDs := podGroupIDToPodNodeIDs[podGroupPort.PodGroupID]
		podIDs := podGroupIDToPodIDs[podGroupPort.PodGroupID]
		VifIDs := make([]int, 0)
		// devicetype=容器节点，获取容器节点上pod的ClusterIP类型的服务
		for _, podNodeID := range podNodeIDs {
			_, ok := podNodeIDToVifIDs[podNodeID]
			if ok {
				VifIDs = append(VifIDs, podNodeIDToVifIDs[podNodeID]...)
			}
			vmIDs, ok := podNodeIDToVMIDs[podNodeID]
			if ok {
				for _, vmID := range vmIDs {
					VifIDs = append(VifIDs, vmID)
				}

			}
		}
		// devicetype=容器POD
		for _, podID := range podIDs {
			_, ok := podIDToVifIDs[podID]
			if ok {
				VifIDs = append(VifIDs, podIDToVifIDs[podID]...)
			}
		}
		for _, vifID := range VifIDs {
			ipSubnetIDs, ok := vifIDToIPSubnetIDs[vifID]
			if !ok {
				continue
			}
			for _, ipSubnetID := range ipSubnetIDs {
				if ipSubnetID.IP == "" {
					continue
				}
				key := PortIPKey{
					IP:       ipSubnetID.IP,
					SubnetID: ipSubnetID.SubnetID,
					Protocol: common.ProtocolMap[podGroupPort.Protocol],
					Port:     podGroupPort.Port,
				}
				keyToItem[key] = mysql.ChIPPort{
					IP:                 ipSubnetID.IP,
					SubnetID:           ipSubnetID.SubnetID,
					Protocol:           common.ProtocolMap[podGroupPort.Protocol],
					Port:               podGroupPort.Port,
					PortPodServiceID:   podGroupPort.PodServiceID,
					PortPodServiceName: serviceIDToName[podGroupPort.PodServiceID],
				}
			}
		}
	}
	return true
}

func (i *ChIPPort) generatePortLBData(keyToItem map[PortIPKey]mysql.ChIPPort) bool {
	var vInterfaceIPs []mysql.LANIP
	var lbVInterfaces []mysql.VInterface
	var vmVInterfaces []mysql.VInterface
	var ipResources []mysql.WANIP
	var lbs []mysql.LB
	var lbListeners []mysql.LBListener
	var networks []mysql.Network
	var lbTargetServers []mysql.LBTargetServer
	err := mysql.Db.Find(&vInterfaceIPs).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(i.resourceTypeName, err))
		return false
	}
	err = mysql.Db.Find(&ipResources).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(i.resourceTypeName, err))
		return false
	}
	err = mysql.Db.Where("devicetype = ?", common.VIF_DEVICE_TYPE_LB).Find(&lbVInterfaces).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(i.resourceTypeName, err))
		return false
	}
	err = mysql.Db.Where("devicetype = ?", common.VIF_DEVICE_TYPE_VM).Find(&vmVInterfaces).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(i.resourceTypeName, err))
		return false
	}
	err = mysql.Db.Find(&lbs).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(i.resourceTypeName, err))
		return false
	}
	err = mysql.Db.Find(&lbListeners).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(i.resourceTypeName, err))
		return false
	}
	err = mysql.Db.Find(&networks).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(i.resourceTypeName, err))
		return false
	}
	err = mysql.Db.Find(&lbTargetServers).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(i.resourceTypeName, err))
		return false
	}

	vInterfaceIPToSubnetIDs := make(map[string][]int)
	lbIDToName := make(map[int]string)
	lbListenerIDToName := make(map[int]string)
	vifIDToIPSubnetIDs := make(map[int][]IPSubnet)
	lbIDToVifIDs := make(map[int][]int)
	ipResourceIPToSubnetIDs := make(map[string][]int)
	for _, vInterfaceIP := range vInterfaceIPs {
		vInterfaceIPToSubnetIDs[vInterfaceIP.IP] = append(vInterfaceIPToSubnetIDs[vInterfaceIP.IP], vInterfaceIP.NetworkID)
	}
	for _, vmVInterface := range vmVInterfaces {
		for _, ipResource := range ipResources {
			if vmVInterface.ID != ipResource.VInterfaceID {
				continue
			}
			ipResourceIPToSubnetIDs[ipResource.IP] = append(ipResourceIPToSubnetIDs[ipResource.IP], vmVInterface.NetworkID)
		}
	}
	for _, lbVInterface := range lbVInterfaces {
		lbIDToVifIDs[lbVInterface.DeviceID] = append(lbIDToVifIDs[lbVInterface.DeviceID], lbVInterface.ID)
		for _, ipResource := range ipResources {
			if lbVInterface.ID != ipResource.VInterfaceID {
				continue
			}
			vifIDToIPSubnetIDs[ipResource.VInterfaceID] = append(vifIDToIPSubnetIDs[ipResource.VInterfaceID], IPSubnet{IP: ipResource.IP, SubnetID: lbVInterface.NetworkID})
		}
	}
	for _, lb := range lbs {
		lbIDToName[lb.ID] = lb.Name
	}
	for _, lbListener := range lbListeners {
		lbListenerIDToName[lbListener.ID] = lbListener.Name
		if lbListener.Port == 0 || common.ProtocolMap[lbListener.Protocol] == 0 || lbListener.LBID == 0 {
			continue
		}
		vifIDs := lbIDToVifIDs[lbListener.LBID]
		for vifID := range vifIDs {
			ipSubnetIDs, ok := vifIDToIPSubnetIDs[vifID]
			if !ok {
				continue
			}
			for _, ipSubnetID := range ipSubnetIDs {
				if ipSubnetID.IP == "" {
					continue
				}
				key := PortIPKey{
					IP:       ipSubnetID.IP,
					SubnetID: ipSubnetID.SubnetID,
					Protocol: common.ProtocolMap[lbListener.Protocol],
					Port:     lbListener.Port,
				}
				ipPort, ok := keyToItem[key]
				if ok {
					ipPort.PortLBID = lbListener.LBID
					ipPort.PortLBName = lbIDToName[lbListener.LBID]
					ipPort.PortLBListenerID = lbListener.ID
					ipPort.PortLBListenerName = lbListener.Name

				} else {
					keyToItem[key] = mysql.ChIPPort{
						IP:                 ipSubnetID.IP,
						SubnetID:           ipSubnetID.SubnetID,
						Protocol:           common.ProtocolMap[lbListener.Protocol],
						Port:               lbListener.Port,
						PortLBID:           lbListener.LBID,
						PortLBName:         lbIDToName[lbListener.LBID],
						PortLBListenerID:   lbListener.ID,
						PortLBListenerName: lbListener.Name,
					}
				}
			}
		}
	}
	for _, lbTargetServer := range lbTargetServers {
		if common.ProtocolMap[lbTargetServer.Protocol] == 0 {
			continue
		}
		for _, network := range networks {
			if network.VPCID != lbTargetServer.VPCID || network.VPCID == 0 || lbTargetServer.VPCID == 0 || lbTargetServer.IP == "" {
				continue
			}
			isData := false
			lanSubnetIDs := vInterfaceIPToSubnetIDs[lbTargetServer.IP]
			for _, lanSubnetID := range lanSubnetIDs {
				if lanSubnetID == network.ID {
					log.Infof("lan %s:%d", lbTargetServer.IP, lanSubnetID)
					isData = true
					break
				}
			}
			if !isData {
				wanSubnetIDs := ipResourceIPToSubnetIDs[lbTargetServer.IP]
				for _, wanSubnetID := range wanSubnetIDs {
					if wanSubnetID == network.ID {
						log.Infof("wan %s:%d", lbTargetServer.IP, wanSubnetID)
						isData = true
						break
					}
				}
			}
			if !isData {
				continue
			}
			key := PortIPKey{
				IP:       lbTargetServer.IP,
				SubnetID: network.ID,
				Protocol: common.ProtocolMap[lbTargetServer.Protocol],
				Port:     lbTargetServer.Port,
			}
			ipPort, ok := keyToItem[key]
			if ok {
				ipPort.PortLBID = lbTargetServer.LBID
				ipPort.PortLBName = lbIDToName[lbTargetServer.LBID]
				ipPort.PortLBListenerID = lbTargetServer.LBListenerID
				ipPort.PortLBListenerName = lbListenerIDToName[lbTargetServer.LBListenerID]

			} else {
				keyToItem[key] = mysql.ChIPPort{
					IP:                 lbTargetServer.IP,
					SubnetID:           network.ID,
					Protocol:           common.ProtocolMap[lbTargetServer.Protocol],
					Port:               lbTargetServer.Port,
					PortLBID:           lbTargetServer.LBID,
					PortLBName:         lbIDToName[lbTargetServer.LBID],
					PortLBListenerID:   lbTargetServer.LBListenerID,
					PortLBListenerName: lbListenerIDToName[lbTargetServer.LBListenerID],
				}
			}
		}
	}
	return true
}
