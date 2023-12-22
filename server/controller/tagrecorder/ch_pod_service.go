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

type ChPodService struct {
	UpdaterBase[mysql.ChPodService, IDKey]
}

func NewChPodService() *ChPodService {
	updater := &ChPodService{
		UpdaterBase[mysql.ChPodService, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_POD_SERVICE,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (p *ChPodService) getNewData() ([]mysql.ChPodService, bool) {
	var podServices []mysql.PodService
	err := mysql.Db.Unscoped().Find(&podServices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}

	items := make([]mysql.ChPodService, len(podServices))
	for i, podService := range podServices {
		items[i] = mysql.ChPodService{
			ID:           podService.ID,
			Name:         podService.Name,
			PodClusterID: podService.PodClusterID,
			PodNsID:      podService.PodNamespaceID,
		}
		if podService.DeletedAt.Valid {
			items[i].Name = podService.Name + " (deleted)"
		}
	}
	return items, true
}

func (p *ChPodService) generateNewData() (map[IDKey]mysql.ChPodService, bool) {
	items, ok := p.getNewData()
	if !ok {
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChPodService)
	for _, item := range items {
		keyToItem[IDKey{ID: item.ID}] = item
	}
	return keyToItem, true
}

func (p *ChPodService) generateKey(dbItem mysql.ChPodService) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (p *ChPodService) generateUpdateInfo(oldItem, newItem mysql.ChPodService) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if oldItem.PodClusterID != newItem.PodClusterID {
		updateInfo["pod_cluster_id"] = newItem.PodClusterID
	}
	if oldItem.PodClusterID != newItem.PodClusterID {
		updateInfo["pod_ns_id"] = newItem.PodNsID
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
