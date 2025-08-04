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

type ChPodNode struct {
	SubscriberComponent[
		*message.PodNodeAdd,
		message.PodNodeAdd,
		*message.PodNodeUpdate,
		message.PodNodeUpdate,
		*message.PodNodeDelete,
		message.PodNodeDelete,
		mysqlmodel.PodNode,
		mysqlmodel.ChPodNode,
		IDKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodNode(resourceTypeToIconID map[IconKey]int) *ChPodNode {
	mng := &ChPodNode{
		newSubscriberComponent[
			*message.PodNodeAdd,
			message.PodNodeAdd,
			*message.PodNodeUpdate,
			message.PodNodeUpdate,
			*message.PodNodeDelete,
			message.PodNodeDelete,
			mysqlmodel.PodNode,
			mysqlmodel.ChPodNode,
			IDKey,
		](
			common.RESOURCE_TYPE_POD_NODE_EN, RESOURCE_TYPE_CH_POD_NODE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	mng.softDelete = true
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodNode) sourceToTarget(md *message.Metadata, source *mysqlmodel.PodNode) (keys []IDKey, targets []mysqlmodel.ChPodNode) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_POD_NODE,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, IDKey{ID: source.ID})
	targets = append(targets, mysqlmodel.ChPodNode{
		ChIDBase:     mysqlmodel.ChIDBase{ID: source.ID},
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
func (c *ChPodNode) onResourceUpdated(md *message.Metadata, updateMessage *message.PodNodeUpdate) {
	db := md.GetDB()
	fieldsUpdate := updateMessage.GetFields().(*message.PodNodeFieldsUpdate)
	newSource := updateMessage.GetNewMySQL().(*mysqlmodel.PodNode)
	sourceID := newSource.ID
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	c.updateOrSync(db, IDKey{ID: sourceID}, updateInfo)
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodNode) softDeletedTargetsUpdated(targets []mysqlmodel.ChPodNode, db *mysql.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}
