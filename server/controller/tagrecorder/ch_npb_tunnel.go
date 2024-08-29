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
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
)

type ChNpbTunnel struct {
	UpdaterComponent[mysqlmodel.ChNpbTunnel, IDKey]
}

func NewChNpbTunnel() *ChNpbTunnel {
	updater := &ChNpbTunnel{
		newUpdaterComponent[mysqlmodel.ChNpbTunnel, IDKey](
			RESOURCE_TYPE_CH_NPB_TUNNEL,
		),
	}
	updater.updaterDG = updater
	return updater
}

func (p *ChNpbTunnel) generateNewData(db *mysql.DB) (map[IDKey]mysqlmodel.ChNpbTunnel, bool) {
	var npbTunnels []mysqlmodel.NpbTunnel
	err := db.Unscoped().Select("id", "name", "team_id").Find(&npbTunnels).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err), db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[IDKey]mysqlmodel.ChNpbTunnel)
	for _, npbTunnel := range npbTunnels {
		keyToItem[IDKey{ID: npbTunnel.ID}] = mysqlmodel.ChNpbTunnel{
			ID:     npbTunnel.ID,
			Name:   npbTunnel.Name,
			TeamID: npbTunnel.TeamID,
		}
	}
	return keyToItem, true
}

func (p *ChNpbTunnel) generateKey(dbItem mysqlmodel.ChNpbTunnel) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (p *ChNpbTunnel) generateUpdateInfo(oldItem, newItem mysqlmodel.ChNpbTunnel) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
