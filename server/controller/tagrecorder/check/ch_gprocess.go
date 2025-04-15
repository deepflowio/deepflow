/*
 * Copyright (c) 2023 Yunshan Networks
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
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/query"
	"github.com/deepflowio/deepflow/server/controller/tagrecorder"
)

type ChGProcess struct {
	UpdaterBase[mysqlmodel.ChGProcess, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChGProcess(resourceTypeToIconID map[IconKey]int) *ChGProcess {
	updater := &ChGProcess{
		UpdaterBase[mysqlmodel.ChGProcess, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_GPROCESS,
		},
		resourceTypeToIconID,
	}
	updater.dataGenerator = updater
	return updater
}

func (p *ChGProcess) generateNewData() (map[IDKey]mysqlmodel.ChGProcess, bool) {
	processes, err := query.FindInBatches[mysqlmodel.Process](p.db.Unscoped())
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err), p.db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[IDKey]mysqlmodel.ChGProcess)
	for _, process := range processes {
		teamID, err := tagrecorder.GetTeamID(process.Domain, process.SubDomain)
		if err != nil {
			log.Errorf("resource(%s) %s, resource: %#v", p.resourceTypeName, err.Error(), process, p.db.LogPrefixORGID)
		}
		gid := int(process.GID)
		if process.DeletedAt.Valid {
			keyToItem[IDKey{ID: gid}] = mysqlmodel.ChGProcess{
				ID:          gid,
				Name:        process.Name + " (deleted)",
				IconID:      p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_GPROCESS}],
				CHostID:     process.VMID,
				L3EPCID:     process.VPCID,
				TeamID:      teamID,
				DomainID:    tagrecorder.DomainToDomainID[process.Domain],
				SubDomainID: tagrecorder.SubDomainToSubDomainID[process.SubDomain],
			}
		} else {
			keyToItem[IDKey{ID: gid}] = mysqlmodel.ChGProcess{
				ID:          gid,
				Name:        process.Name,
				IconID:      p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_GPROCESS}],
				CHostID:     process.VMID,
				L3EPCID:     process.VPCID,
				TeamID:      teamID,
				DomainID:    tagrecorder.DomainToDomainID[process.Domain],
				SubDomainID: tagrecorder.SubDomainToSubDomainID[process.SubDomain],
			}
		}
	}
	return keyToItem, true
}

func (p *ChGProcess) generateKey(dbItem mysqlmodel.ChGProcess) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (p *ChGProcess) generateUpdateInfo(oldItem, newItem mysqlmodel.ChGProcess) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if oldItem.IconID != newItem.IconID && newItem.IconID != 0 {
		updateInfo["icon_id"] = newItem.IconID
	}
	if oldItem.CHostID != newItem.CHostID {
		updateInfo["chost_id"] = newItem.CHostID
	}
	if oldItem.L3EPCID != newItem.L3EPCID {
		updateInfo["l3_epc_id"] = newItem.L3EPCID
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
