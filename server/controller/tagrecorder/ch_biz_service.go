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
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ChBizService struct {
	SubscriberComponent[
		*message.AddedCustomServices,
		message.AddedCustomServices,
		*message.UpdatedCustomService,
		message.UpdatedCustomService,
		*message.DeletedCustomServices,
		message.DeletedCustomServices,
		metadbmodel.CustomService,
		metadbmodel.ChBizService,
		IDKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChBizService(resourceTypeToIconID map[IconKey]int) *ChBizService {
	mng := &ChBizService{
		newSubscriberComponent[
			*message.AddedCustomServices,
			message.AddedCustomServices,
			*message.UpdatedCustomService,
			message.UpdatedCustomService,
			*message.DeletedCustomServices,
			message.DeletedCustomServices,
			metadbmodel.CustomService,
			metadbmodel.ChBizService,
			IDKey,
		](
			common.RESOURCE_TYPE_CUSTOM_SERVICE_EN, RESOURCE_TYPE_CH_BIZ_SERVICE,
		),
		resourceTypeToIconID,
	}
	mng.setSubscribeRecorder(false)
	mng.subscriberDG = mng
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChBizService) sourceToTarget(md *message.Metadata, source *metadbmodel.CustomService) (keys []IDKey, targets []metadbmodel.ChBizService) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_CUSTOM_SERVICE,
	}]
	sourceName := source.Name
	keys = append(keys, IDKey{ID: source.ID})
	targets = append(targets, metadbmodel.ChBizService{
		ChIDBase:         metadbmodel.ChIDBase{ID: source.ID},
		Name:             sourceName,
		ServiceGroupName: source.ServiceGroupName,
		IconID:           iconID,
		TeamID:           md.GetTeamID(),
		DomainID:         md.GetDomainID(),
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChBizService) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedCustomService) {
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChBizService) softDeletedTargetsUpdated(targets []metadbmodel.ChBizService, db *metadb.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}
