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

type ChPodNamespace struct {
	SubscriberComponent[
		*message.AddedPodNamespaces,
		message.AddedPodNamespaces,
		*message.UpdatedPodNamespace,
		message.UpdatedPodNamespace,
		*message.DeletedPodNamespaces,
		message.DeletedPodNamespaces,
		metadbmodel.PodNamespace,
		metadbmodel.ChPodNamespace,
		IDKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodNamespace(resourceTypeToIconID map[IconKey]int) *ChPodNamespace {
	mng := &ChPodNamespace{
		newSubscriberComponent[
			*message.AddedPodNamespaces,
			message.AddedPodNamespaces,
			*message.UpdatedPodNamespace,
			message.UpdatedPodNamespace,
			*message.DeletedPodNamespaces,
			message.DeletedPodNamespaces,
			metadbmodel.PodNamespace,
			metadbmodel.ChPodNamespace,
			IDKey,
		](
			common.RESOURCE_TYPE_POD_NAMESPACE_EN, RESOURCE_TYPE_CH_POD_NAMESPACE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	mng.softDelete = true
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodNamespace) sourceToTarget(md *message.Metadata, source *metadbmodel.PodNamespace) (keys []IDKey, targets []metadbmodel.ChPodNamespace) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_POD_NAMESPACE,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, IDKey{ID: source.ID})
	targets = append(targets, metadbmodel.ChPodNamespace{
		ChIDBase:     metadbmodel.ChIDBase{ID: source.ID},
		Name:         sourceName,
		PodClusterID: source.PodClusterID,
		IconID:       iconID,
		TeamID:       md.GetTeamID(),
		DomainID:     md.GetDomainID(),
		SubDomainID:  md.GetSubDomainID(),
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodNamespace) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedPodNamespace) {
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodNamespace) softDeletedTargetsUpdated(targets []metadbmodel.ChPodNamespace, db *metadb.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}
