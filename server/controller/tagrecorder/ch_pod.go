/*
 * Copyright (c) 2023 Yunshan Networks
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
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type ChPod struct {
	UpdaterBase[mysql.ChPod, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChPod(resourceTypeToIconID map[IconKey]int) *ChPod {
	updater := &ChPod{
		UpdaterBase[mysql.ChPod, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_POD,
		},
		resourceTypeToIconID,
	}
	updater.dataGenerator = updater
	return updater
}

func (p *ChPod) generateNewData() (map[IDKey]mysql.ChPod, bool) {
	var (
		pods          []mysql.Pod
		podGroupPorts []mysql.PodGroupPort
	)
	err := mysql.Db.Unscoped().Find(&pods).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}
	err = mysql.Db.Unscoped().Select("pod_group_id", "pod_service_id").
		Find(&podGroupPorts).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}

	groupToService := make(map[int]int, len(podGroupPorts))
	for _, podGroupPort := range podGroupPorts {
		groupToService[podGroupPort.PodGroupID] = podGroupPort.PodServiceID
	}

	keyToItem := make(map[IDKey]mysql.ChPod)
	for _, pod := range pods {
		podServiceID := groupToService[pod.ID]
		if pod.DeletedAt.Valid {
			keyToItem[IDKey{ID: pod.ID}] = mysql.ChPod{
				ID:           pod.ID,
				Name:         pod.Name + " (deleted)",
				IconID:       p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD}],
				PodClusterID: pod.PodClusterID,
				PodNsID:      pod.PodNamespaceID,
				PodNodeID:    pod.PodNodeID,
				PodGroupID:   pod.PodGroupID,
				PodServiceID: podServiceID,
			}
		} else {
			keyToItem[IDKey{ID: pod.ID}] = mysql.ChPod{
				ID:           pod.ID,
				Name:         pod.Name,
				IconID:       p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD}],
				PodClusterID: pod.PodClusterID,
				PodNsID:      pod.PodNamespaceID,
				PodNodeID:    pod.PodNodeID,
				PodGroupID:   pod.PodGroupID,
				PodServiceID: podServiceID,
			}
		}
	}
	return keyToItem, true
}

func (p *ChPod) generateKey(dbItem mysql.ChPod) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (p *ChPod) generateUpdateInfo(oldItem, newItem mysql.ChPod) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if oldItem.IconID != newItem.IconID {
		updateInfo["icon_id"] = newItem.IconID
	}
	if oldItem.PodClusterID != newItem.PodClusterID {
		updateInfo["pod_cluster_id"] = newItem.PodClusterID
	}
	if oldItem.PodNsID != newItem.PodNsID {
		updateInfo["pod_ns_id"] = newItem.PodNsID
	}
	if oldItem.PodNodeID != newItem.PodNodeID {
		updateInfo["pod_node_id"] = newItem.PodNodeID
	}
	if oldItem.PodGroupID != newItem.PodGroupID {
		updateInfo["pod_group_id"] = newItem.PodGroupID
	}
	if oldItem.PodServiceID != newItem.PodServiceID {
		updateInfo["pod_service_id"] = newItem.PodServiceID
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
