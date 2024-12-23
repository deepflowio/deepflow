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
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/tagrecorder"
)

type ChNetwork struct {
	UpdaterBase[metadbmodel.ChNetwork, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChNetwork(resourceTypeToIconID map[IconKey]int) *ChNetwork {
	updater := &ChNetwork{
		UpdaterBase[metadbmodel.ChNetwork, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_NETWORK,
		},
		resourceTypeToIconID,
	}

	updater.dataGenerator = updater
	return updater
}

func (n *ChNetwork) generateNewData() (map[IDKey]metadbmodel.ChNetwork, bool) {
	var networks []metadbmodel.Network
	err := n.db.Unscoped().Find(&networks).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(n.resourceTypeName, err), n.db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[IDKey]metadbmodel.ChNetwork)
	for _, network := range networks {
		teamID, err := tagrecorder.GetTeamID(network.Domain, network.SubDomain)
		if err != nil {
			log.Errorf("resource(%s) %s, resource: %#v", n.resourceTypeName, err.Error(), network, n.db.LogPrefixORGID)
		}

		networkName := network.Name
		if network.DeletedAt.Valid {
			networkName += " (deleted)"
		}
		keyToItem[IDKey{ID: network.ID}] = metadbmodel.ChNetwork{
			ID:          network.ID,
			Name:        networkName,
			IconID:      n.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_VL2}],
			TeamID:      teamID,
			DomainID:    tagrecorder.DomainToDomainID[network.Domain],
			SubDomainID: tagrecorder.SubDomainToSubDomainID[network.SubDomain],
		}
	}
	return keyToItem, true
}

func (n *ChNetwork) generateKey(dbItem metadbmodel.ChNetwork) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (n *ChNetwork) generateUpdateInfo(oldItem, newItem metadbmodel.ChNetwork) (map[string]interface{}, bool) {
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
