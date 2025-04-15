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
	"slices"

	"gorm.io/gorm/clause"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ChGProcess struct {
	SubscriberComponent[
		*message.ProcessAdd,
		message.ProcessAdd,
		*message.ProcessFieldsUpdate,
		message.ProcessFieldsUpdate,
		*message.ProcessDelete,
		message.ProcessDelete,
		mysqlmodel.Process,
		mysqlmodel.ChGProcess,
		IDKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChGProcess(resourceTypeToIconID map[IconKey]int) *ChGProcess {
	mng := &ChGProcess{
		newSubscriberComponent[
			*message.ProcessAdd,
			message.ProcessAdd,
			*message.ProcessFieldsUpdate,
			message.ProcessFieldsUpdate,
			*message.ProcessDelete,
			message.ProcessDelete,
			mysqlmodel.Process,
			mysqlmodel.ChGProcess,
			IDKey,
		](
			common.RESOURCE_TYPE_PROCESS_EN, RESOURCE_TYPE_CH_GPROCESS,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	mng.hookers[hookerDeletePage] = mng
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChGProcess) sourceToTarget(md *message.Metadata, source *mysqlmodel.Process) (keys []IDKey, targets []mysqlmodel.ChGProcess) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_GPROCESS,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}
	gid := int(source.GID)
	keys = append(keys, IDKey{ID: gid})
	targets = append(targets, mysqlmodel.ChGProcess{
		ID:          gid,
		Name:        sourceName,
		CHostID:     source.VMID,
		L3EPCID:     source.VPCID,
		IconID:      iconID,
		TeamID:      md.TeamID,
		DomainID:    md.DomainID,
		SubDomainID: md.SubDomainID,
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChGProcess) onResourceUpdated(sourceID int, fieldsUpdate *message.ProcessFieldsUpdate, db *mysql.DB) {
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
	if len(updateInfo) > 0 {
		gid := fieldsUpdate.GID.GetNew()
		var chItem mysqlmodel.ChGProcess
		db.Where("id = ?", gid).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, IDKey{ID: int(gid)}, db)
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChGProcess) softDeletedTargetsUpdated(targets []mysqlmodel.ChGProcess, db *mysql.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

func (c *ChGProcess) beforeDeletePage(dbData []*mysqlmodel.Process, msg *message.ProcessDelete) []*mysqlmodel.Process {
	gids := msg.GetAddition().(*message.ProcessDeleteAddition).DeletedGIDs
	newDatas := []*mysqlmodel.Process{}
	for _, item := range dbData {
		if slices.Contains(gids, item.GID) {
			newDatas = append(newDatas, item)
		}
	}
	return newDatas
}
