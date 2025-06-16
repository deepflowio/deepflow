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

type ChPodGroup struct {
	SubscriberComponent[
		*message.PodGroupAdd,
		message.PodGroupAdd,
		*message.PodGroupFieldsUpdate,
		message.PodGroupFieldsUpdate,
		*message.PodGroupDelete,
		message.PodGroupDelete,
		mysqlmodel.PodGroup,
		mysqlmodel.ChPodGroup,
		IDKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodGroup(resourceTypeToIconID map[IconKey]int) *ChPodGroup {
	mng := &ChPodGroup{
		newSubscriberComponent[
			*message.PodGroupAdd,
			message.PodGroupAdd,
			*message.PodGroupFieldsUpdate,
			message.PodGroupFieldsUpdate,
			*message.PodGroupDelete,
			message.PodGroupDelete,
			mysqlmodel.PodGroup,
			mysqlmodel.ChPodGroup,
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
func (c *ChPodGroup) sourceToTarget(md *message.Metadata, source *mysqlmodel.PodGroup) (keys []IDKey, targets []mysqlmodel.ChPodGroup) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_POD_GROUP,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, IDKey{ID: source.ID})
	targets = append(targets, mysqlmodel.ChPodGroup{
		ChIDBase:     mysqlmodel.ChIDBase{ID: source.ID},
		Name:         sourceName,
		IconID:       iconID,
		PodGroupType: RESOURCE_POD_GROUP_TYPE_MAP[source.Type],
		PodClusterID: source.PodClusterID,
		PodNsID:      source.PodNamespaceID,
		TeamID:       md.GetTeamID(),
		DomainID:     md.GetDomainID(),
		SubDomainID:  md.GetSubDomainID(),
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodGroup) onResourceUpdated(sourceID int, fieldsUpdate *message.PodGroupFieldsUpdate, db *mysql.DB) {
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if fieldsUpdate.Type.IsDifferent() {
		updateInfo["pod_group_type"] = RESOURCE_POD_GROUP_TYPE_MAP[fieldsUpdate.Type.GetNew()]
	}
	if fieldsUpdate.PodClusterID.IsDifferent() {
		updateInfo["pod_cluster_id"] = fieldsUpdate.PodClusterID.GetNew()
	}
	if fieldsUpdate.PodNamespaceID.IsDifferent() {
		updateInfo["pod_ns_id"] = fieldsUpdate.PodNamespaceID.GetNew()
	}
	c.updateOrSync(db, IDKey{ID: sourceID}, updateInfo)
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodGroup) softDeletedTargetsUpdated(targets []mysqlmodel.ChPodGroup, db *mysql.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}
