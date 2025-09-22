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

type ChPodIngress struct {
	SubscriberComponent[
		*message.AddedPodIngresses,
		message.AddedPodIngresses,
		*message.UpdatedPodIngress,
		message.UpdatedPodIngress,
		*message.DeletedPodIngresses,
		message.DeletedPodIngresses,
		metadbmodel.PodIngress,
		metadbmodel.ChPodIngress,
		IDKey,
	]
}

func NewChPodIngress() *ChPodIngress {
	mng := &ChPodIngress{
		newSubscriberComponent[
			*message.AddedPodIngresses,
			message.AddedPodIngresses,
			*message.UpdatedPodIngress,
			message.UpdatedPodIngress,
			*message.DeletedPodIngresses,
			message.DeletedPodIngresses,
			metadbmodel.PodIngress,
			metadbmodel.ChPodIngress,
			IDKey,
		](
			common.RESOURCE_TYPE_POD_INGRESS_EN, RESOURCE_TYPE_CH_POD_INGRESS,
		),
	}
	mng.subscriberDG = mng
	mng.softDelete = true
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodIngress) sourceToTarget(md *message.Metadata, source *metadbmodel.PodIngress) (keys []IDKey, targets []metadbmodel.ChPodIngress) {
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, IDKey{ID: source.ID})
	targets = append(targets, metadbmodel.ChPodIngress{
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
func (c *ChPodIngress) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedPodIngress) {
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodIngress) softDeletedTargetsUpdated(targets []metadbmodel.ChPodIngress, db *metadb.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}
