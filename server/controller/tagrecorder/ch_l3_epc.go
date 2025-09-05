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
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ChVPC struct {
	SubscriberComponent[
		*message.AddedVPCs,
		message.AddedVPCs,
		*message.UpdatedVPC,
		message.UpdatedVPC,
		*message.DeletedVPCs,
		message.DeletedVPCs,
		mysqlmodel.VPC,
		mysqlmodel.ChVPC,
		IDKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChVPC(resourceTypeToIconID map[IconKey]int) *ChVPC {
	mng := &ChVPC{
		newSubscriberComponent[
			*message.AddedVPCs,
			message.AddedVPCs,
			*message.UpdatedVPC,
			message.UpdatedVPC,
			*message.DeletedVPCs,
			message.DeletedVPCs,
			mysqlmodel.VPC,
			mysqlmodel.ChVPC,
			IDKey,
		](
			common.RESOURCE_TYPE_VPC_EN, RESOURCE_TYPE_CH_VPC,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	mng.softDelete = true
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChVPC) sourceToTarget(md *message.Metadata, source *mysqlmodel.VPC) (keys []IDKey, targets []mysqlmodel.ChVPC) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_VPC,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, IDKey{ID: source.ID})
	targets = append(targets, mysqlmodel.ChVPC{
		ChIDBase: mysqlmodel.ChIDBase{ID: source.ID},
		Name:     sourceName,
		UID:      source.UID,
		IconID:   iconID,
		TeamID:   md.GetTeamID(),
		DomainID: md.GetDomainID(),
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChVPC) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedVPC) {
	db := md.GetDB()
	fieldsUpdate := updateMessage.GetFields().(*message.UpdatedVPCFields)
	newSource := updateMessage.GetNewMySQL().(*mysqlmodel.VPC)
	sourceID := newSource.ID
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if fieldsUpdate.UID.IsDifferent() {
		updateInfo["uid"] = fieldsUpdate.UID.GetNew()
	}
	c.updateOrSync(db, IDKey{ID: sourceID}, updateInfo)
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChVPC) softDeletedTargetsUpdated(targets []mysqlmodel.ChVPC, db *mysql.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}
