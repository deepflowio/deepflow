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

type ChNetwork struct {
	SubscriberComponent[
		*message.AddedNetworks,
		message.AddedNetworks,
		*message.UpdatedNetwork,
		message.UpdatedNetwork,
		*message.DeletedNetworks,
		message.DeletedNetworks,
		mysqlmodel.Network,
		mysqlmodel.ChNetwork,
		IDKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChNetwork(resourceTypeToIconID map[IconKey]int) *ChNetwork {
	mng := &ChNetwork{
		newSubscriberComponent[
			*message.AddedNetworks,
			message.AddedNetworks,
			*message.UpdatedNetwork,
			message.UpdatedNetwork,
			*message.DeletedNetworks,
			message.DeletedNetworks,
			mysqlmodel.Network,
			mysqlmodel.ChNetwork,
			IDKey,
		](
			common.RESOURCE_TYPE_NETWORK_EN, RESOURCE_TYPE_CH_NETWORK,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	mng.softDelete = true
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChNetwork) sourceToTarget(md *message.Metadata, source *mysqlmodel.Network) (keys []IDKey, targets []mysqlmodel.ChNetwork) {
	networkName := source.Name
	if source.DeletedAt.Valid {
		networkName += " (deleted)"
	}

	keys = append(keys, IDKey{ID: source.ID})
	targets = append(targets, mysqlmodel.ChNetwork{
		ChIDBase: mysqlmodel.ChIDBase{ID: source.ID},
		Name:     networkName,
		IconID: c.resourceTypeToIconID[IconKey{
			NodeType: RESOURCE_TYPE_VL2,
		}],
		TeamID:      md.GetTeamID(),
		DomainID:    md.GetDomainID(),
		SubDomainID: md.GetSubDomainID(),
		L3EPCID:     source.VPCID,
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChNetwork) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedNetwork) {
	db := md.GetDB()
	fieldsUpdate := updateMessage.GetFields().(*message.UpdatedNetworkFields)
	newSource := updateMessage.GetNewMySQL().(*mysqlmodel.Network)
	sourceID := newSource.ID
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if fieldsUpdate.VPCID.IsDifferent() {
		updateInfo["l3_epc_id"] = fieldsUpdate.VPCID.GetNew()
	}
	c.updateOrSync(db, IDKey{ID: sourceID}, updateInfo)
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChNetwork) softDeletedTargetsUpdated(targets []mysqlmodel.ChNetwork, db *mysql.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}
