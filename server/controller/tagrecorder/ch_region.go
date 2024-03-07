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

type ChRegion struct {
	SubscriberComponent[*message.RegionFieldsUpdate, message.RegionFieldsUpdate, mysql.Region, mysql.ChRegion, IDKey]
	domainLcuuidToIconID map[string]int
	resourceTypeToIconID map[IconKey]int
}

func NewChRegion(domainLcuuidToIconID map[string]int, resourceTypeToIconID map[IconKey]int) *ChRegion {
	mng := &ChRegion{
		newSubscriberComponent[*message.RegionFieldsUpdate, message.RegionFieldsUpdate, mysql.Region, mysql.ChRegion, IDKey](
			common.RESOURCE_TYPE_REGION_EN, RESOURCE_TYPE_CH_REGION,
		),
		domainLcuuidToIconID,
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChRegion) sourceToTarget(source *mysql.Region) (keys []IDKey, targets []mysql.ChRegion) {
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	// TODO require special handling
	iconId := c.generateIconId(source)

	keys = append(keys, IDKey{ID: source.ID})
	targets = append(targets, mysql.ChRegion{
		ID:     source.ID,
		Name:   sourceName,
		IconID: iconId,
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChRegion) onResourceUpdated(sourceID int, fieldsUpdate *message.RegionFieldsUpdate) {
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	// if oldItem.IconID != newItem.IconID { // TODO need icon id
	// 	updateInfo["icon_id"] = newItem.IconID
	// }
	if len(updateInfo) > 0 {
		var chItem mysql.ChRegion
		mysql.Db.Where("id = ?", sourceID).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, IDKey{ID: sourceID})
	}
}

// TODO
func (c *ChRegion) generateIconId(source *mysql.Region) int {
	return c.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_REGION}]
}
