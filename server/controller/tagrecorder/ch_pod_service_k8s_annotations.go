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
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ChPodServiceK8sAnnotations struct {
	SubscriberComponent[
		*message.PodServiceAdd,
		message.PodServiceAdd,
		*message.PodServiceFieldsUpdate,
		message.PodServiceFieldsUpdate,
		*message.PodServiceDelete,
		message.PodServiceDelete,
		mysqlmodel.PodService,
		mysqlmodel.ChPodServiceK8sAnnotations,
		IDKey,
	]
}

func NewChPodServiceK8sAnnotations() *ChPodServiceK8sAnnotations {
	mng := &ChPodServiceK8sAnnotations{
		newSubscriberComponent[
			*message.PodServiceAdd,
			message.PodServiceAdd,
			*message.PodServiceFieldsUpdate,
			message.PodServiceFieldsUpdate,
			*message.PodServiceDelete,
			message.PodServiceDelete,
			mysqlmodel.PodService,
			mysqlmodel.ChPodServiceK8sAnnotations,
			IDKey,
		](
			common.RESOURCE_TYPE_POD_SERVICE_EN, RESOURCE_TYPE_CH_POD_SERVICE_K8S_ANNOTATIONS,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodServiceK8sAnnotations) onResourceUpdated(sourceID int, fieldsUpdate *message.PodServiceFieldsUpdate, db *mysql.DB) {
	updateInfo := make(map[string]interface{})
	var chItem mysqlmodel.ChPodServiceK8sAnnotations

	if fieldsUpdate.Annotation.IsDifferent() {
		annotations, _ := common.StrToJsonAndMap(fieldsUpdate.Annotation.GetNew())
		if annotations != "" {
			updateInfo["annotations"] = annotations
		}
	}
	targetKey := IDKey{ID: sourceID}
	if len(updateInfo) > 0 {
		db.Where("id = ?", sourceID).First(&chItem)
		if chItem.ID == 0 {
			c.SubscriberComponent.dbOperator.add(
				[]IDKey{targetKey},
				[]mysqlmodel.ChPodServiceK8sAnnotations{{
					ChIDBase:    mysqlmodel.ChIDBase{ID: sourceID},
					Annotations: updateInfo["annotations"].(string),
				}},
				db,
			)
		}
	}
	c.updateOrSync(db, targetKey, updateInfo)
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodServiceK8sAnnotations) sourceToTarget(md *message.Metadata, source *mysqlmodel.PodService) (keys []IDKey, targets []mysqlmodel.ChPodServiceK8sAnnotations) {
	if source.Annotation == "" {
		return
	}
	annotations, _ := common.StrToJsonAndMap(source.Annotation)
	return []IDKey{{ID: source.ID}}, []mysqlmodel.ChPodServiceK8sAnnotations{{
		ChIDBase:    mysqlmodel.ChIDBase{ID: source.ID},
		Annotations: annotations,
		TeamID:      md.GetTeamID(),
		DomainID:    md.GetDomainID(),
		SubDomainID: md.GetSubDomainID(),
	}}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodServiceK8sAnnotations) softDeletedTargetsUpdated(targets []mysqlmodel.ChPodServiceK8sAnnotations, db *mysql.DB) {

}
