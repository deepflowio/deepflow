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
)

type ChVPC struct {
	UpdaterComponent[mysql.ChVPC, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChVPC(resourceTypeToIconID map[IconKey]int) *ChVPC {
	updater := &ChVPC{
		newUpdaterComponent[mysql.ChVPC, IDKey](
			RESOURCE_TYPE_CH_VPC,
		),
		resourceTypeToIconID,
	}
	updater.updaterDG = updater
	return updater
}

func (v *ChVPC) generateNewData() (map[IDKey]mysql.ChVPC, bool) {
	var vpcs []mysql.VPC
	err := mysql.Db.Unscoped().Find(&vpcs).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChVPC)
	for _, vpc := range vpcs {
		if vpc.DeletedAt.Valid {
			keyToItem[IDKey{ID: vpc.ID}] = mysql.ChVPC{
				ID:     vpc.ID,
				Name:   vpc.Name + " (deleted)",
				UID:    vpc.UID,
				IconID: v.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_VPC}],
			}
		} else {
			keyToItem[IDKey{ID: vpc.ID}] = mysql.ChVPC{
				ID:     vpc.ID,
				Name:   vpc.Name,
				UID:    vpc.UID,
				IconID: v.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_VPC}],
			}
		}
	}
	return keyToItem, true
}

func (v *ChVPC) generateKey(dbItem mysql.ChVPC) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (v *ChVPC) generateUpdateInfo(oldItem, newItem mysql.ChVPC) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if oldItem.IconID != newItem.IconID && newItem.IconID != 0 {
		updateInfo["icon_id"] = newItem.IconID
	}
	if oldItem.UID != newItem.UID {
		updateInfo["uid"] = newItem.UID
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
