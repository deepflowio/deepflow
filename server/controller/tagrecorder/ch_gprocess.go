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

type ChGProcess struct {
	SubscriberComponent[*message.ProcessFieldsUpdate, message.ProcessFieldsUpdate, mysql.Process, mysql.ChGProcess, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChGProcess(resourceTypeToIconID map[IconKey]int) *ChGProcess {
	mng := &ChGProcess{
		newSubscriberComponent[*message.ProcessFieldsUpdate, message.ProcessFieldsUpdate, mysql.Process, mysql.ChGProcess, IDKey](
			common.RESOURCE_TYPE_PROCESS_EN, RESOURCE_TYPE_CH_GPROCESS,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChGProcess) sourceToTarget(source *mysql.Process) (keys []IDKey, targets []mysql.ChGProcess) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_GPROCESS,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, IDKey{ID: source.ID})
	targets = append(targets, mysql.ChGProcess{
		ID:      source.ID,
		Name:    sourceName,
		CHostID: source.VMID,
		L3EPCID: source.VPCID,
		IconID:  iconID,
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChGProcess) onResourceUpdated(sourceID int, fieldsUpdate *message.ProcessFieldsUpdate) {
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if fieldsUpdate.VMID.IsDifferent() {
		updateInfo["chost_id"] = fieldsUpdate.VMID.GetNew()
	}
	if fieldsUpdate.VPCID.IsDifferent() {
		updateInfo["l3_epc_id"] = fieldsUpdate.VPCID.GetNew()
	}
	// if oldItem.IconID != newItem.IconID { // TODO need icon id
	// 	updateInfo["icon_id"] = newItem.IconID
	// }
	if len(updateInfo) > 0 {
		var chItem mysql.ChGProcess
		mysql.Db.Where("id = ?", sourceID).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, IDKey{ID: sourceID})
	}
}
