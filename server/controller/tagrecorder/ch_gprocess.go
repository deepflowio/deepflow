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
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ChGProcess struct {
	SubscriberComponent[
		*message.AddedProcesses,
		message.AddedProcesses,
		*message.UpdatedProcess,
		message.UpdatedProcess,
		*message.DeletedProcesses,
		message.DeletedProcesses,
		metadbmodel.Process,
		metadbmodel.ChGProcess,
		IDKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChGProcess(resourceTypeToIconID map[IconKey]int) *ChGProcess {
	mng := &ChGProcess{
		newSubscriberComponent[
			*message.AddedProcesses,
			message.AddedProcesses,
			*message.UpdatedProcess,
			message.UpdatedProcess,
			*message.DeletedProcesses,
			message.DeletedProcesses,
			metadbmodel.Process,
			metadbmodel.ChGProcess,
			IDKey,
		](
			common.RESOURCE_TYPE_PROCESS_EN, RESOURCE_TYPE_CH_GPROCESS,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	mng.hookers[hookerDeletePage] = mng
	mng.softDelete = true
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChGProcess) sourceToTarget(md *message.Metadata, source *metadbmodel.Process) (keys []IDKey, targets []metadbmodel.ChGProcess) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_GPROCESS,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}
	gid := int(source.GID)
	keys = append(keys, IDKey{ID: gid})
	targets = append(targets, metadbmodel.ChGProcess{
		ChIDBase:    metadbmodel.ChIDBase{ID: gid},
		Name:        sourceName,
		CHostID:     source.VMID,
		L3EPCID:     source.VPCID,
		IconID:      iconID,
		TeamID:      md.GetTeamID(),
		DomainID:    md.GetDomainID(),
		SubDomainID: md.GetSubDomainID(),
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChGProcess) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedProcess) {
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChGProcess) softDeletedTargetsUpdated(targets []metadbmodel.ChGProcess, db *metadb.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

func (c *ChGProcess) beforeDeletePage(dbData []*metadbmodel.Process, msg *message.DeletedProcesses) []*metadbmodel.Process {
	gids := msg.GetAddition().(*message.ProcessDeleteAddition).DeletedGIDs
	newDatas := []*metadbmodel.Process{}
	for _, item := range dbData {
		if slices.Contains(gids, item.GID) {
			newDatas = append(newDatas, item)
		}
	}
	return newDatas
}
