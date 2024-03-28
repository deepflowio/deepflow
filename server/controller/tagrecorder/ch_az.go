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
	"gorm.io/gorm/clause"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ChAZ struct {
	SubscriberComponent[*message.AZFieldsUpdate, message.AZFieldsUpdate, mysql.AZ, mysql.ChAZ, IDKey]
	domainLcuuidToIconID map[string]int
	resourceTypeToIconID map[IconKey]int
}

func NewChAZ(domainLcuuidToIconID map[string]int, resourceTypeToIconID map[IconKey]int) *ChAZ {
	mng := &ChAZ{
		newSubscriberComponent[*message.AZFieldsUpdate, message.AZFieldsUpdate, mysql.AZ, mysql.ChAZ, IDKey](
			common.RESOURCE_TYPE_AZ_EN, RESOURCE_TYPE_CH_AZ,
		),
		domainLcuuidToIconID,
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (a *ChAZ) onResourceUpdated(sourceID int, fieldsUpdate *message.AZFieldsUpdate) {
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	// if oldItem.IconID != newItem.IconID { // TODO need icon id
	// 	updateInfo["icon_id"] = newItem.IconID
	// }
	// TODO refresh control
	if len(updateInfo) > 0 {
		var chItem mysql.ChAZ
		mysql.Db.Where("id = ?", sourceID).First(&chItem) // TODO use query to update ?
		a.SubscriberComponent.dbOperator.update(chItem, updateInfo, IDKey{ID: sourceID})
	}
}

// onResourceUpdated implements SubscriberDataGenerator
func (a *ChAZ) sourceToTarget(az *mysql.AZ) (keys []IDKey, targets []mysql.ChAZ) {
	iconID := a.domainLcuuidToIconID[az.Domain]
	if iconID == 0 {
		key := IconKey{
			NodeType: RESOURCE_TYPE_AZ,
		}
		iconID = a.resourceTypeToIconID[key]
	}
	keys = append(keys, IDKey{ID: az.ID})
	name := az.Name
	if az.DeletedAt.Valid {
		name += " (deleted)"
	}
	targets = append(targets, mysql.ChAZ{
		ID:     az.ID,
		Name:   name,
		IconID: iconID,
	})
	return
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (a *ChAZ) softDeletedTargetsUpdated(targets []mysql.ChAZ) {
	mysql.Db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}
