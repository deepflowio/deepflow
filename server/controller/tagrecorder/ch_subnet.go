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

type ChNetwork struct {
	UpdaterBase[mysql.ChNetwork, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChNetwork(resourceTypeToIconID map[IconKey]int) *ChNetwork {
	updater := &ChNetwork{
		UpdaterBase[mysql.ChNetwork, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_NETWORK,
		},
		resourceTypeToIconID,
	}

	updater.dataGenerator = updater
	return updater
}

func (n *ChNetwork) generateNewData() (map[IDKey]mysql.ChNetwork, bool) {
	var networks []mysql.Network
	err := mysql.Db.Unscoped().Find(&networks).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(n.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChNetwork)
	for _, network := range networks {
		networkName := network.Name
		if network.DeletedAt.Valid {
			networkName += " (deleted)"
		}
		keyToItem[IDKey{ID: network.ID}] = mysql.ChNetwork{
			ID:     network.ID,
			Name:   networkName,
			IconID: n.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_VL2}],
		}
	}
	return keyToItem, true
}

func (n *ChNetwork) generateKey(dbItem mysql.ChNetwork) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (n *ChNetwork) generateUpdateInfo(oldItem, newItem mysql.ChNetwork) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if oldItem.IconID != newItem.IconID && newItem.IconID != 0 {
		updateInfo["icon_id"] = newItem.IconID
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
