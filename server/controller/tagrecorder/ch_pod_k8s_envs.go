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
	mysql "github.com/deepflowio/deepflow/server/controller/db/metadb"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ChPodK8sEnvs struct {
	SubscriberComponent[
		*message.AddedPods,
		message.AddedPods,
		*message.UpdatedPod,
		message.UpdatedPod,
		*message.DeletedPods,
		message.DeletedPods,
		mysqlmodel.Pod,
		mysqlmodel.ChPodK8sEnvs,
		IDKey,
	]
}

func NewChPodK8sEnvs() *ChPodK8sEnvs {
	mng := &ChPodK8sEnvs{
		newSubscriberComponent[
			*message.AddedPods,
			message.AddedPods,
			*message.UpdatedPod,
			message.UpdatedPod,
			*message.DeletedPods,
			message.DeletedPods,
			mysqlmodel.Pod,
			mysqlmodel.ChPodK8sEnvs,
			IDKey,
		](
			common.RESOURCE_TYPE_POD_EN, RESOURCE_TYPE_CH_POD_K8S_ENVS,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodK8sEnvs) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedPod) {
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodK8sEnvs) sourceToTarget(md *message.Metadata, source *mysqlmodel.Pod) (keys []IDKey, targets []mysqlmodel.ChPodK8sEnvs) {
	if source.ENV == "" {
		return
	}
	envs, _ := common.StrToJsonAndMap(source.ENV)
	return []IDKey{{ID: source.ID}}, []mysqlmodel.ChPodK8sEnvs{{
		ChIDBase:    mysqlmodel.ChIDBase{ID: source.ID},
		Envs:        envs,
		TeamID:      md.GetTeamID(),
		DomainID:    md.GetDomainID(),
		SubDomainID: md.GetSubDomainID(),
	}}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodK8sEnvs) softDeletedTargetsUpdated(targets []mysqlmodel.ChPodK8sEnvs, db *mysql.DB) {

}
