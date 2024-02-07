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
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ChAZ struct {
	SubscriberComponent[*message.AZFieldsUpdate, message.AZFieldsUpdate, mysql.AZ, mysql.ChAZ, IDKey]
	// UpdaterComponent[mysql.ChAZ, IDKey]
	domainLcuuidToIconID map[string]int
	resourceTypeToIconID map[IconKey]int
}

func NewChAZ(domainLcuuidToIconID map[string]int, resourceTypeToIconID map[IconKey]int) *ChAZ {
	mng := &ChAZ{
		newSubscriberComponent[*message.AZFieldsUpdate, message.AZFieldsUpdate, mysql.AZ, mysql.ChAZ, IDKey](
			common.RESOURCE_TYPE_AZ_EN, RESOURCE_TYPE_CH_AZ,
		),
		// newUpdaterComponent[mysql.ChAZ, IDKey](
		// 	RESOURCE_TYPE_CH_AZ,
		// ),
		domainLcuuidToIconID,
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	// az.updaterDG = az
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

// func (a *ChAZ) generateNewData() (map[IDKey]mysql.ChAZ, bool) {
// 	log.Infof("generate data for %s", a.resourceTypeName)
// 	var azs []mysql.AZ
// 	err := mysql.Db.Unscoped().Find(&azs).Error
// 	if err != nil {
// 		log.Errorf(dbQueryResourceFailed(a.resourceTypeName, err))
// 		return nil, false
// 	}

// 	keyToItem := make(map[IDKey]mysql.ChAZ)

// 	for _, az := range azs {
// 		iconID := a.domainLcuuidToIconID[az.Domain]
// 		if iconID == 0 {
// 			key := IconKey{
// 				NodeType: RESOURCE_TYPE_AZ,
// 			}
// 			iconID = a.resourceTypeToIconID[key]
// 		}
// 		if az.DeletedAt.Valid {
// 			keyToItem[IDKey{ID: az.ID}] = mysql.ChAZ{
// 				ID:     az.ID,
// 				Name:   az.Name + " (deleted)",
// 				IconID: iconID,
// 			}
// 		} else {
// 			keyToItem[IDKey{ID: az.ID}] = mysql.ChAZ{
// 				ID:     az.ID,
// 				Name:   az.Name,
// 				IconID: iconID,
// 			}
// 		}

// 	}
// 	return keyToItem, true
// }

// func (a *ChAZ) generateKey(dbItem mysql.ChAZ) IDKey {
// 	return IDKey{ID: dbItem.ID}
// }

// func (a *ChAZ) generateUpdateInfo(oldItem, newItem mysql.ChAZ) (map[string]interface{}, bool) {
// 	updateInfo := make(map[string]interface{})
// 	if oldItem.Name != newItem.Name {
// 		updateInfo["name"] = newItem.Name
// 	}
// 	if oldItem.IconID != newItem.IconID && newItem.IconID != 0 {
// 		updateInfo["icon_id"] = newItem.IconID
// 	}
// 	if len(updateInfo) > 0 {
// 		return updateInfo, true
// 	}
// 	return nil, false
// }
