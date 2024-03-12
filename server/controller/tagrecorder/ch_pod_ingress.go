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
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ChPodIngress struct {
	SubscriberComponent[*message.PodIngressFieldsUpdate, message.PodIngressFieldsUpdate, mysql.PodIngress, mysql.ChPodIngress, IDKey]
}

func NewChPodIngress() *ChPodIngress {
	mng := &ChPodIngress{
		newSubscriberComponent[*message.PodIngressFieldsUpdate, message.PodIngressFieldsUpdate, mysql.PodIngress, mysql.ChPodIngress, IDKey](
			common.RESOURCE_TYPE_POD_INGRESS_EN, RESOURCE_TYPE_CH_POD_INGRESS,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodIngress) sourceToTarget(source *mysql.PodIngress) (keys []IDKey, targets []mysql.ChPodIngress) {
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, IDKey{ID: source.ID})
	targets = append(targets, mysql.ChPodIngress{
		ID:   source.ID,
		Name: sourceName,
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodIngress) onResourceUpdated(sourceID int, fieldsUpdate *message.PodIngressFieldsUpdate) {
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if len(updateInfo) > 0 {
		var chItem mysql.ChPodIngress
		mysql.Db.Where("id = ?", sourceID).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, IDKey{ID: sourceID})
	}
}
