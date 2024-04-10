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

type ChPodNamespace struct {
	SubscriberComponent[*message.PodNamespaceFieldsUpdate, message.PodNamespaceFieldsUpdate, mysql.PodNamespace, mysql.ChPodNamespace, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodNamespace(resourceTypeToIconID map[IconKey]int) *ChPodNamespace {
	mng := &ChPodNamespace{
		newSubscriberComponent[*message.PodNamespaceFieldsUpdate, message.PodNamespaceFieldsUpdate, mysql.PodNamespace, mysql.ChPodNamespace, IDKey](
			common.RESOURCE_TYPE_POD_NAMESPACE_EN, RESOURCE_TYPE_CH_POD_NAMESPACE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodNamespace) sourceToTarget(source *mysql.PodNamespace) (keys []IDKey, targets []mysql.ChPodNamespace) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_POD_NAMESPACE,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, IDKey{ID: source.ID})
	targets = append(targets, mysql.ChPodNamespace{
		ID:           source.ID,
		Name:         sourceName,
		PodClusterID: source.PodClusterID,
		IconID:       iconID,
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodNamespace) onResourceUpdated(sourceID int, fieldsUpdate *message.PodNamespaceFieldsUpdate, db *mysql.DB) {
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if fieldsUpdate.PodClusterID.IsDifferent() {
		updateInfo["pod_cluster_id"] = fieldsUpdate.PodClusterID.GetNew()
	}
	if len(updateInfo) > 0 {
		var chItem mysql.ChPodNamespace
		db.Where("id = ?", sourceID).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, IDKey{ID: sourceID}, db)
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodNamespace) softDeletedTargetsUpdated(targets []mysql.ChPodNamespace, db *mysql.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}
