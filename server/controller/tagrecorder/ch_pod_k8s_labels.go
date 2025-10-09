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

type ChPodK8sLabels struct {
	SubscriberComponent[
		*message.AddedPods,
		message.AddedPods,
		*message.UpdatedPod,
		message.UpdatedPod,
		*message.DeletedPods,
		message.DeletedPods,
		mysqlmodel.Pod,
		mysqlmodel.ChPodK8sLabels,
		IDKey,
	]
}

func NewChPodK8sLabels() *ChPodK8sLabels {
	mng := &ChPodK8sLabels{
		newSubscriberComponent[
			*message.AddedPods,
			message.AddedPods,
			*message.UpdatedPod,
			message.UpdatedPod,
			*message.DeletedPods,
			message.DeletedPods,
			mysqlmodel.Pod,
			mysqlmodel.ChPodK8sLabels,
			IDKey,
		](
			common.RESOURCE_TYPE_POD_EN, RESOURCE_TYPE_CH_POD_K8S_LABELS,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodK8sLabels) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedPod) {
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodK8sLabels) sourceToTarget(md *message.Metadata, source *mysqlmodel.Pod) (keys []IDKey, targets []mysqlmodel.ChPodK8sLabels) {
	if source.Label == "" {
		return
	}
	labels, _ := common.StrToJsonAndMap(source.Label)
	return []IDKey{{ID: source.ID}}, []mysqlmodel.ChPodK8sLabels{{
		ChIDBase:    mysqlmodel.ChIDBase{ID: source.ID},
		Labels:      labels,
		TeamID:      md.GetTeamID(),
		DomainID:    md.GetDomainID(),
		SubDomainID: md.GetSubDomainID(),
	}}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodK8sLabels) softDeletedTargetsUpdated(targets []mysqlmodel.ChPodK8sLabels, db *mysql.DB) {

}
