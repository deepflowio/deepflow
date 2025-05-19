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

type ChPodService struct {
	SubscriberComponent[
		*message.PodServiceAdd,
		message.PodServiceAdd,
		*message.PodServiceFieldsUpdate,
		message.PodServiceFieldsUpdate,
		*message.PodServiceDelete,
		message.PodServiceDelete,
		mysqlmodel.PodService,
		mysqlmodel.ChPodService,
		IDKey,
	]
}

func NewChPodService() *ChPodService {
	mng := &ChPodService{
		newSubscriberComponent[
			*message.PodServiceAdd,
			message.PodServiceAdd,
			*message.PodServiceFieldsUpdate,
			message.PodServiceFieldsUpdate,
			*message.PodServiceDelete,
			message.PodServiceDelete,
			mysqlmodel.PodService,
			mysqlmodel.ChPodService,
			IDKey,
		](
			common.RESOURCE_TYPE_POD_SERVICE_EN, RESOURCE_TYPE_CH_POD_SERVICE,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodService) sourceToTarget(md *message.Metadata, source *mysqlmodel.PodService) (keys []IDKey, targets []mysqlmodel.ChPodService) {
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, IDKey{ID: source.ID})
	targets = append(targets, mysqlmodel.ChPodService{
		ChIDBase:     mysqlmodel.ChIDBase{ID: source.ID},
		Name:         sourceName,
		PodClusterID: source.PodClusterID,
		PodNsID:      source.PodNamespaceID,
		TeamID:       md.TeamID,
		DomainID:     md.DomainID,
		SubDomainID:  md.SubDomainID,
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodService) onResourceUpdated(sourceID int, fieldsUpdate *message.PodServiceFieldsUpdate, db *mysql.DB) {
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
	c.updateOrSync(db, IDKey{ID: sourceID}, updateInfo)
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodService) softDeletedTargetsUpdated(targets []mysqlmodel.ChPodService, db *mysql.DB) {

	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}
