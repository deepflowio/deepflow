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

type ChPodServiceK8sLabels struct {
	SubscriberComponent[
		*message.AddedPodServices,
		message.AddedPodServices,
		*message.UpdatedPodService,
		message.UpdatedPodService,
		*message.DeletedPodServices,
		message.DeletedPodServices,
		mysqlmodel.PodService,
		mysqlmodel.ChPodServiceK8sLabels,
		IDKey,
	]
}

func NewChPodServiceK8sLabels() *ChPodServiceK8sLabels {
	mng := &ChPodServiceK8sLabels{
		newSubscriberComponent[
			*message.AddedPodServices,
			message.AddedPodServices,
			*message.UpdatedPodService,
			message.UpdatedPodService,
			*message.DeletedPodServices,
			message.DeletedPodServices,
			mysqlmodel.PodService,
			mysqlmodel.ChPodServiceK8sLabels,
			IDKey,
		](
			common.RESOURCE_TYPE_POD_SERVICE_EN, RESOURCE_TYPE_CH_POD_SERVICE_K8S_LABELS,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodServiceK8sLabels) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedPodService) {
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodServiceK8sLabels) sourceToTarget(md *message.Metadata, source *mysqlmodel.PodService) (keys []IDKey, targets []mysqlmodel.ChPodServiceK8sLabels) {
	if source.Label == "" {
		return
	}
	labels, _ := common.StrToJsonAndMap(source.Label)
	return []IDKey{{ID: source.ID}}, []mysqlmodel.ChPodServiceK8sLabels{{
		ChIDBase:    mysqlmodel.ChIDBase{ID: source.ID},
		Labels:      labels,
		L3EPCID:     source.VPCID,
		PodNsID:     source.PodNamespaceID,
		TeamID:      md.GetTeamID(),
		DomainID:    md.GetDomainID(),
		SubDomainID: md.GetSubDomainID(),
	}}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodServiceK8sLabels) softDeletedTargetsUpdated(targets []mysqlmodel.ChPodServiceK8sLabels, db *mysql.DB) {

}
