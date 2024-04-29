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

type ChNetwork struct {
	SubscriberComponent[*message.NetworkFieldsUpdate, message.NetworkFieldsUpdate, mysql.Network, mysql.ChNetwork, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChNetwork(resourceTypeToIconID map[IconKey]int) *ChNetwork {
	mng := &ChNetwork{
		newSubscriberComponent[*message.NetworkFieldsUpdate, message.NetworkFieldsUpdate, mysql.Network, mysql.ChNetwork, IDKey](
			common.RESOURCE_TYPE_NETWORK_EN, RESOURCE_TYPE_CH_NETWORK,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng

	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChNetwork) sourceToTarget(md *message.Metadata, source *mysql.Network) (keys []IDKey, targets []mysql.ChNetwork) {
	networkName := source.Name
	if source.DeletedAt.Valid {
		networkName += " (deleted)"
	}

	keys = append(keys, IDKey{ID: source.ID})
	targets = append(targets, mysql.ChNetwork{
		ID:   source.ID,
		Name: networkName,
		IconID: c.resourceTypeToIconID[IconKey{
			NodeType: RESOURCE_TYPE_VL2,
		}],
		TeamID:   md.TeamID,
		DomainID: md.DomainID,
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChNetwork) onResourceUpdated(sourceID int, fieldsUpdate *message.NetworkFieldsUpdate, db *mysql.DB) {
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if len(updateInfo) > 0 {
		var chItem mysql.ChNetwork
		db.Where("id = ?", sourceID).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, IDKey{ID: sourceID}, db)
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChNetwork) softDeletedTargetsUpdated(targets []mysql.ChNetwork, db *mysql.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}
