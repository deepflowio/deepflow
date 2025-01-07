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
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/tagrecorder"
)

type ChNetwork struct {
	UpdaterBase[mysqlmodel.ChNetwork, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChNetwork(resourceTypeToIconID map[IconKey]int) *ChNetwork {
	updater := &ChNetwork{
		UpdaterBase[mysqlmodel.ChNetwork, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_NETWORK,
		},
		resourceTypeToIconID,
	}

	updater.dataGenerator = updater
	return updater
}

func (n *ChNetwork) generateNewData() (map[IDKey]mysqlmodel.ChNetwork, bool) {
	var networks []mysqlmodel.Network
	err := n.db.Unscoped().Find(&networks).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(n.resourceTypeName, err), n.db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[IDKey]mysqlmodel.ChNetwork)
	for _, network := range networks {
		teamID, err := tagrecorder.GetTeamID(network.Domain, network.SubDomain)
		if err != nil {
			log.Errorf("resource(%s) %s, resource: %#v", n.resourceTypeName, err.Error(), network, n.db.LogPrefixORGID)
		}

		networkName := network.Name
		if network.DeletedAt.Valid {
			networkName += " (deleted)"
		}
		keyToItem[IDKey{ID: network.ID}] = mysqlmodel.ChNetwork{
			ID:          network.ID,
			Name:        networkName,
			IconID:      n.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_VL2}],
			TeamID:      teamID,
			DomainID:    tagrecorder.DomainToDomainID[network.Domain],
			SubDomainID: tagrecorder.SubDomainToSubDomainID[network.SubDomain],
			L3EPCID:     network.VPCID,
		}
	}
	return keyToItem, true
}

func (n *ChNetwork) generateKey(dbItem mysqlmodel.ChNetwork) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (n *ChNetwork) generateUpdateInfo(oldItem, newItem mysqlmodel.ChNetwork) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if oldItem.IconID != newItem.IconID && newItem.IconID != 0 {
		updateInfo["icon_id"] = newItem.IconID
	}
	if oldItem.L3EPCID != newItem.L3EPCID {
		updateInfo["l3_epc_id"] = newItem.L3EPCID
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
