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

type ChPodPort struct {
	UpdaterBase[mysql.ChPodPort, PortIDKey]
}

func NewChPodPort() *ChPodPort {
	updater := &ChPodPort{
		UpdaterBase[mysql.ChPodPort, PortIDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_POD_PORT,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (p *ChPodPort) generateNewData() (map[PortIDKey]mysql.ChPodPort, bool) {
	var podServices []mysql.PodService
	var pods []mysql.Pod
	var podGroupPorts []mysql.PodGroupPort
	err := mysql.Db.Unscoped().Find(&podServices).Error
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
	for _, podService := range podServices {
		serviceIDToName[podService.ID] = podService.Name
	}
	podGroupIDToPodIDs := make(map[int][]int)
	for _, pod := range pods {
		podGroupIDToPodIDs[pod.PodGroupID] = append(podGroupIDToPodIDs[pod.PodGroupID], pod.ID)
	}

	keyToItem := make(map[PortIDKey]mysql.ChPodPort)
	for _, podGroupPort := range podGroupPorts {
		if podGroupPort.Port == 0 || podGroupPort.PodGroupID == 0 || common.ProtocolMap[podGroupPort.Protocol] == 0 {
			continue
		}
		podIDs := podGroupIDToPodIDs[podGroupPort.PodGroupID]
		for _, podID := range podIDs {
			if podID == 0 {
				continue
			}
			key := PortIDKey{
				ID:       podID,
				Protocol: common.ProtocolMap[podGroupPort.Protocol],
				Port:     podGroupPort.Port,
			}
			keyToItem[key] = mysql.ChPodPort{
				ID:                 podID,
				Protocol:           common.ProtocolMap[podGroupPort.Protocol],
				Port:               podGroupPort.Port,
				PortPodServiceID:   podGroupPort.PodServiceID,
				PortPodServiceName: serviceIDToName[podGroupPort.PodServiceID],
			}
		}
	}
	return keyToItem, true
}

func (p *ChPodPort) generateKey(dbItem mysql.ChPodPort) PortIDKey {
	return PortIDKey{ID: dbItem.ID, Protocol: dbItem.Protocol, Port: dbItem.Port}
}

func (p *ChPodPort) generateUpdateInfo(oldItem, newItem mysql.ChPodPort) (map[string]interface{}, bool) {
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
