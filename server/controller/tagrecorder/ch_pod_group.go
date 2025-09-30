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

type ChPodGroup struct {
	SubscriberComponent[
		*message.AddedPodGroups,
		message.AddedPodGroups,
		*message.UpdatedPodGroup,
		message.UpdatedPodGroup,
		*message.DeletedPodGroups,
		message.DeletedPodGroups,
		metadbmodel.PodGroup,
		metadbmodel.ChPodGroup,
		IDKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodGroup(resourceTypeToIconID map[IconKey]int) *ChPodGroup {
	mng := &ChPodGroup{
		newSubscriberComponent[
			*message.AddedPodGroups,
			message.AddedPodGroups,
			*message.UpdatedPodGroup,
			message.UpdatedPodGroup,
			*message.DeletedPodGroups,
			message.DeletedPodGroups,
			metadbmodel.PodGroup,
			metadbmodel.ChPodGroup,
			IDKey,
		](
			common.RESOURCE_TYPE_POD_GROUP_EN, RESOURCE_TYPE_CH_POD_GROUP,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	mng.softDelete = true
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodGroup) sourceToTarget(md *message.Metadata, source *metadbmodel.PodGroup) (keys []IDKey, targets []metadbmodel.ChPodGroup) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_POD_GROUP,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, IDKey{ID: source.ID})
	targets = append(targets, metadbmodel.ChPodGroup{
		ChIDBase:     metadbmodel.ChIDBase{ID: source.ID},
		Name:         sourceName,
		IconID:       iconID,
		PodGroupType: common.RESOURCE_POD_GROUP_TYPE_MAP[source.Type],
		PodClusterID: source.PodClusterID,
		PodNsID:      source.PodNamespaceID,
		TeamID:       md.GetTeamID(),
		DomainID:     md.GetDomainID(),
		SubDomainID:  md.GetSubDomainID(),
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodGroup) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedPodGroup) {
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodGroup) softDeletedTargetsUpdated(targets []metadbmodel.ChPodGroup, db *metadb.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}
