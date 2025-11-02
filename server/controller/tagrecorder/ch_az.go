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
	mysql "github.com/deepflowio/deepflow/server/controller/db/metadb"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ChAZ struct {
	SubscriberComponent[
		*message.AddedAZs,
		message.AddedAZs,
		*message.UpdatedAZ,
		message.UpdatedAZ,
		*message.DeletedAZs,
		message.DeletedAZs,
		mysqlmodel.AZ,
		mysqlmodel.ChAZ,
		IDKey,
	]
	domainLcuuidToIconID map[string]int
	resourceTypeToIconID map[IconKey]int
}

func NewChAZ(domainLcuuidToIconID map[string]int, resourceTypeToIconID map[IconKey]int) *ChAZ {
	mng := &ChAZ{
		newSubscriberComponent[
			*message.AddedAZs,
			message.AddedAZs,
			*message.UpdatedAZ,
			message.UpdatedAZ,
			*message.DeletedAZs,
			message.DeletedAZs,
			mysqlmodel.AZ,
			mysqlmodel.ChAZ,
			IDKey,
		](
			common.RESOURCE_TYPE_AZ_EN, RESOURCE_TYPE_CH_AZ,
		),
		domainLcuuidToIconID,
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	mng.softDelete = true
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (a *ChAZ) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedAZ) {
}

// onResourceUpdated implements SubscriberDataGenerator
func (a *ChAZ) sourceToTarget(md *message.Metadata, az *mysqlmodel.AZ) (keys []IDKey, targets []mysqlmodel.ChAZ) {
	iconID := a.domainLcuuidToIconID[az.Domain]
	var err error
	if iconID == 0 {
		a.domainLcuuidToIconID, a.resourceTypeToIconID, err = GetIconInfo(a.cfg)
		if err == nil {
			iconID = a.domainLcuuidToIconID[az.Domain]
		}
		if iconID == 0 {
			key := IconKey{
				NodeType: RESOURCE_TYPE_AZ,
			}
			iconID = a.resourceTypeToIconID[key]
		}
	}
	keys = append(keys, IDKey{ID: az.ID})
	name := az.Name
	if az.DeletedAt.Valid {
		name += " (deleted)"
	}
	targets = append(targets, mysqlmodel.ChAZ{
		ChIDBase: mysqlmodel.ChIDBase{ID: az.ID},
		Name:     name,
		IconID:   iconID,
		TeamID:   md.GetTeamID(),
		DomainID: md.GetDomainID(),
	})
	return
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (a *ChAZ) softDeletedTargetsUpdated(targets []mysqlmodel.ChAZ, db *mysql.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}
