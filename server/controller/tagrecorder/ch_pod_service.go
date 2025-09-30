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

type ChPodService struct {
	SubscriberComponent[
		*message.AddedPodServices,
		message.AddedPodServices,
		*message.UpdatedPodService,
		message.UpdatedPodService,
		*message.DeletedPodServices,
		message.DeletedPodServices,
		metadbmodel.PodService,
		metadbmodel.ChPodService,
		IDKey,
	]
}

func NewChPodService() *ChPodService {
	mng := &ChPodService{
		newSubscriberComponent[
			*message.AddedPodServices,
			message.AddedPodServices,
			*message.UpdatedPodService,
			message.UpdatedPodService,
			*message.DeletedPodServices,
			message.DeletedPodServices,
			metadbmodel.PodService,
			metadbmodel.ChPodService,
			IDKey,
		](
			common.RESOURCE_TYPE_POD_SERVICE_EN, RESOURCE_TYPE_CH_POD_SERVICE,
		),
	}
	mng.subscriberDG = mng
	mng.softDelete = true
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodService) sourceToTarget(md *message.Metadata, source *metadbmodel.PodService) (keys []IDKey, targets []metadbmodel.ChPodService) {
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, IDKey{ID: source.ID})
	targets = append(targets, metadbmodel.ChPodService{
		ChIDBase:     metadbmodel.ChIDBase{ID: source.ID},
		Name:         sourceName,
		PodClusterID: source.PodClusterID,
		PodNsID:      source.PodNamespaceID,
		TeamID:       md.GetTeamID(),
		DomainID:     md.GetDomainID(),
		SubDomainID:  md.GetSubDomainID(),
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodService) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedPodService) {
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodService) softDeletedTargetsUpdated(targets []metadbmodel.ChPodService, db *metadb.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}
