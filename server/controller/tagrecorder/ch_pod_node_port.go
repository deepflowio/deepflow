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

type ChPodNodePort struct {
	UpdaterBase[mysql.ChPodNodePort, PortIDKey]
}

func NewChPodNodePort() *ChPodNodePort {
	updater := &ChPodNodePort{
		UpdaterBase[mysql.ChPodNodePort, PortIDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_POD_NODE_PORT,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (p *ChPodNodePort) generateNewData() (map[PortIDKey]mysql.ChPodNodePort, bool) {
	var podServices []mysql.PodService
	var podNodes []mysql.PodNode
	var podServicePorts []mysql.PodServicePort
	var pods []mysql.Pod
	var podGroupPorts []mysql.PodGroupPort
	err := mysql.Db.Unscoped().Find(&podServices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}
	err = mysql.Db.Unscoped().Find(&podNodes).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}
	err = mysql.Db.Unscoped().Find(&podServicePorts).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}
	err = mysql.Db.Unscoped().Find(&pods).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}
	err = mysql.Db.Unscoped().Find(&podGroupPorts).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}

	serviceIDToName := make(map[int]string)
	serviceIDToPodClusterID := make(map[int]int)
	for _, podService := range podServices {
		serviceIDToName[podService.ID] = podService.Name
		serviceIDToPodClusterID[podService.ID] = podService.PodClusterID
	}
	podClusterIDToPodNodeIDs := make(map[int][]int)
	for _, podNode := range podNodes {
		podClusterIDToPodNodeIDs[podNode.PodClusterID] = append(podClusterIDToPodNodeIDs[podNode.PodClusterID], podNode.ID)
	}
	podGroupIDToPodNodeIDs := make(map[int][]int)
	for _, pod := range pods {
		podGroupIDToPodNodeIDs[pod.PodGroupID] = append(podGroupIDToPodNodeIDs[pod.PodGroupID], pod.PodNodeID)
	}

	keyToItem := make(map[PortIDKey]mysql.ChPodNodePort)
	for _, podServicePort := range podServicePorts {
		if podServicePort.NodePort == 0 || podServicePort.PodServiceID == 0 || common.ProtocolMap[podServicePort.Protocol] == 0 {
			continue
		}
		podClusterID := serviceIDToPodClusterID[podServicePort.PodServiceID]
		podNodeIDs := podClusterIDToPodNodeIDs[podClusterID]
		for _, podNodeID := range podNodeIDs {
			if podNodeID == 0 {
				continue
			}
			key := PortIDKey{
				ID:       podNodeID,
				Protocol: common.ProtocolMap[podServicePort.Protocol],
				Port:     podServicePort.NodePort,
			}
			keyToItem[key] = mysql.ChPodNodePort{
				ID:                 podNodeID,
				Protocol:           common.ProtocolMap[podServicePort.Protocol],
				Port:               podServicePort.NodePort,
				PortPodServiceID:   podServicePort.PodServiceID,
				PortPodServiceName: serviceIDToName[podServicePort.PodServiceID],
			}
		}
	}
	for _, podGroupPort := range podGroupPorts {
		if podGroupPort.Port == 0 || podGroupPort.PodGroupID == 0 || common.ProtocolMap[podGroupPort.Protocol] == 0 {
			continue
		}
		podNodeIDs := podGroupIDToPodNodeIDs[podGroupPort.PodGroupID]
		for _, podNodeID := range podNodeIDs {
			if podNodeID == 0 {
				continue
			}
			key := PortIDKey{
				ID:       podNodeID,
				Protocol: common.ProtocolMap[podGroupPort.Protocol],
				Port:     podGroupPort.Port,
			}
			keyToItem[key] = mysql.ChPodNodePort{
				ID:                 podNodeID,
				Protocol:           common.ProtocolMap[podGroupPort.Protocol],
				Port:               podGroupPort.Port,
				PortPodServiceID:   podGroupPort.PodServiceID,
				PortPodServiceName: serviceIDToName[podGroupPort.PodServiceID],
			}
		}
	}
	return keyToItem, true
}

func (p *ChPodNodePort) generateKey(dbItem mysql.ChPodNodePort) PortIDKey {
	return PortIDKey{ID: dbItem.ID, Protocol: dbItem.Protocol, Port: dbItem.Port}
}

func (p *ChPodNodePort) generateUpdateInfo(oldItem, newItem mysql.ChPodNodePort) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.PortPodServiceID != newItem.PortPodServiceID {
		updateInfo["port_pod_service_id"] = newItem.PortPodServiceID
	}
	if oldItem.PortPodServiceName != newItem.PortPodServiceName {
		updateInfo["port_pod_service_name"] = newItem.PortPodServiceName
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
