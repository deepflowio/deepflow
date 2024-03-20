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

type ChPodNode struct {
	SubscriberComponent[*message.PodNodeFieldsUpdate, message.PodNodeFieldsUpdate, mysql.PodNode, mysql.ChPodNode, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodNode(resourceTypeToIconID map[IconKey]int) *ChPodNode {
	mng := &ChPodNode{
		newSubscriberComponent[*message.PodNodeFieldsUpdate, message.PodNodeFieldsUpdate, mysql.PodNode, mysql.ChPodNode, IDKey](
			common.RESOURCE_TYPE_POD_NODE_EN, RESOURCE_TYPE_CH_POD_NODE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodNode) sourceToTarget(source *mysql.PodNode) (keys []IDKey, targets []mysql.ChPodNode) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_POD_NODE,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, IDKey{ID: source.ID})
	targets = append(targets, mysql.ChPodNode{
		ID:     source.ID,
		Name:   sourceName,
		IconID: iconID,
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodNode) onResourceUpdated(sourceID int, fieldsUpdate *message.PodNodeFieldsUpdate) {
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	// if oldItem.IconID != newItem.IconID { // TODO need icon id
	// 	updateInfo["icon_id"] = newItem.IconID
	// }
	if len(updateInfo) > 0 {
		var chItem mysql.ChPodNode
		mysql.Db.Where("id = ?", sourceID).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, IDKey{ID: sourceID})
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodNode) softDeletedTargetsUpdated(targets []mysql.ChPodNode) {
	mysql.Db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}
