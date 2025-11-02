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

type ChPodK8sEnv struct {
	SubscriberComponent[
		*message.AddedPods,
		message.AddedPods,
		*message.UpdatedPod,
		message.UpdatedPod,
		*message.DeletedPods,
		message.DeletedPods,
		mysqlmodel.Pod,
		mysqlmodel.ChPodK8sEnv,
		IDKeyKey,
	]
}

func NewChPodK8sEnv() *ChPodK8sEnv {
	mng := &ChPodK8sEnv{
		newSubscriberComponent[
			*message.AddedPods,
			message.AddedPods,
			*message.UpdatedPod,
			message.UpdatedPod,
			*message.DeletedPods,
			message.DeletedPods,
			mysqlmodel.Pod,
			mysqlmodel.ChPodK8sEnv,
			IDKeyKey,
		](
			common.RESOURCE_TYPE_POD_EN, RESOURCE_TYPE_CH_POD_K8S_ENV,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodK8sEnv) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedPod) {
	db := md.GetDB()
	fieldsUpdate := updateMessage.GetFields().(*message.UpdatedPodFields)
	newSource := updateMessage.GetNewMySQL().(*mysqlmodel.Pod)
	sourceID := newSource.ID
	keysToDelete := make([]IDKeyKey, 0)
	targetsToDelete := make([]mysqlmodel.ChPodK8sEnv, 0)

	if fieldsUpdate.ENV.IsDifferent() {
		_, new := common.StrToJsonAndMap(fieldsUpdate.ENV.GetNew())
		_, old := common.StrToJsonAndMap(fieldsUpdate.ENV.GetOld())

		for k := range old {
			if _, ok := new[k]; !ok {
				keysToDelete = append(keysToDelete, NewIDKeyKey(sourceID, k))
				targetsToDelete = append(targetsToDelete, mysqlmodel.ChPodK8sEnv{
					ChIDBase: mysqlmodel.ChIDBase{ID: sourceID},
					Key:      k,
				})
			}
		}
	}
	if len(keysToDelete) > 0 {
		c.SubscriberComponent.dbOperator.delete(keysToDelete, targetsToDelete, db)
	}
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodK8sEnv) sourceToTarget(md *message.Metadata, source *mysqlmodel.Pod) (keys []IDKeyKey, targets []mysqlmodel.ChPodK8sEnv) {
	_, envMap := common.StrToJsonAndMap(source.ENV)

	for k, v := range envMap {
		keys = append(keys, NewIDKeyKey(source.ID, k))
		targets = append(targets, mysqlmodel.ChPodK8sEnv{
			ChIDBase:    mysqlmodel.ChIDBase{ID: source.ID},
			Key:         k,
			Value:       v,
			TeamID:      md.GetTeamID(),
			DomainID:    md.GetDomainID(),
			SubDomainID: md.GetSubDomainID(),
		})
	}
	return
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodK8sEnv) softDeletedTargetsUpdated(targets []mysqlmodel.ChPodK8sEnv, db *mysql.DB) {

}
