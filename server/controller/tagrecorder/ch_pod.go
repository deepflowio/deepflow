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

type ChPod struct {
	SubscriberComponent[
		*message.PodAdd,
		message.PodAdd,
		*message.PodFieldsUpdate,
		message.PodFieldsUpdate,
		*message.PodDelete,
		message.PodDelete,
		metadbmodel.Pod,
		metadbmodel.ChPod,
		IDKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChPod(resourceTypeToIconID map[IconKey]int) *ChPod {
	mng := &ChPod{
		newSubscriberComponent[
			*message.PodAdd,
			message.PodAdd,
			*message.PodFieldsUpdate,
			message.PodFieldsUpdate,
			*message.PodDelete,
			message.PodDelete,
			metadbmodel.Pod,
			metadbmodel.ChPod,
			IDKey,
		](
			common.RESOURCE_TYPE_POD_EN, RESOURCE_TYPE_CH_POD,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	mng.softDelete = true
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPod) sourceToTarget(md *message.Metadata, source *metadbmodel.Pod) (keys []IDKey, targets []metadbmodel.ChPod) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_POD,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, IDKey{ID: source.ID})
	targets = append(targets, metadbmodel.ChPod{
		ChIDBase:     metadbmodel.ChIDBase{ID: source.ID},
		Name:         sourceName,
		PodClusterID: source.PodClusterID,
		PodNsID:      source.PodNamespaceID,
		PodNodeID:    source.PodNodeID,
		PodGroupID:   source.PodGroupID,
		IconID:       iconID,
		PodServiceID: source.PodServiceID,
		TeamID:       md.TeamID,
		DomainID:     md.DomainID,
		SubDomainID:  md.SubDomainID,
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPod) onResourceUpdated(sourceID int, fieldsUpdate *message.PodFieldsUpdate, db *metadb.DB) {
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if fieldsUpdate.PodClusterID.IsDifferent() {
		updateInfo["pod_cluster_id"] = fieldsUpdate.PodClusterID.GetNew()
	}
	if fieldsUpdate.PodNamespaceID.IsDifferent() {
		updateInfo["pod_ns_id"] = fieldsUpdate.PodNamespaceID.GetNew()
	}
	if fieldsUpdate.PodNodeID.IsDifferent() {
		updateInfo["pod_node_id"] = fieldsUpdate.PodNodeID.GetNew()
	}
	if fieldsUpdate.PodGroupID.IsDifferent() {
		updateInfo["pod_group_id"] = fieldsUpdate.PodGroupID.GetNew()
	}
	if fieldsUpdate.PodServiceID.IsDifferent() {
		updateInfo["pod_service_id"] = fieldsUpdate.PodServiceID.GetNew()
	}
	c.updateOrSync(db, IDKey{ID: sourceID}, updateInfo)
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPod) softDeletedTargetsUpdated(targets []metadbmodel.ChPod, db *metadb.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}
