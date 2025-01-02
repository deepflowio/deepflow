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
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/tagrecorder"
)

type ChChost struct {
	UpdaterBase[metadbmodel.ChChost, IDKey]
}

func NewChChost() *ChChost {
	updater := &ChChost{
		UpdaterBase[metadbmodel.ChChost, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_CHOST,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (p *ChChost) generateNewData() (map[IDKey]metadbmodel.ChChost, bool) {
	var (
		chosts []metadbmodel.VM
		hosts  []metadbmodel.Host
	)
	err := p.db.Unscoped().Find(&chosts).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err), p.db.LogPrefixORGID)
		return nil, false
	}
	err = p.db.Unscoped().Select("id", "ip").Find(&hosts).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err), p.db.LogPrefixORGID)
		return nil, false
	}

	ipToHostID := make(map[string]int, len(hosts))
	for _, host := range hosts {
		ipToHostID[host.IP] = host.ID
	}

	keyToItem := make(map[IDKey]metadbmodel.ChChost)
	for _, chost := range chosts {
		if chost.DeletedAt.Valid {
			keyToItem[IDKey{ID: chost.ID}] = metadbmodel.ChChost{
				ID:       chost.ID,
				Name:     chost.Name + " (deleted)",
				L3EPCID:  chost.VPCID,
				HostID:   ipToHostID[chost.LaunchServer],
				Hostname: chost.Hostname,
				IP:       chost.IP,
				SubnetID: chost.NetworkID,
				TeamID:   tagrecorder.DomainToTeamID[chost.Domain],
				DomainID: tagrecorder.DomainToDomainID[chost.Domain],
			}
		} else {
			keyToItem[IDKey{ID: chost.ID}] = metadbmodel.ChChost{
				ID:       chost.ID,
				Name:     chost.Name,
				L3EPCID:  chost.VPCID,
				HostID:   ipToHostID[chost.LaunchServer],
				Hostname: chost.Hostname,
				IP:       chost.IP,
				SubnetID: chost.NetworkID,
				TeamID:   tagrecorder.DomainToTeamID[chost.Domain],
				DomainID: tagrecorder.DomainToDomainID[chost.Domain],
			}
		}
	}
	return keyToItem, true
}

func (p *ChChost) generateKey(dbItem metadbmodel.ChChost) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (p *ChChost) generateUpdateInfo(oldItem, newItem metadbmodel.ChChost) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if oldItem.L3EPCID != newItem.L3EPCID {
		updateInfo["l3_epc_id"] = newItem.L3EPCID
	}
	if oldItem.HostID != newItem.HostID {
		updateInfo["host_id"] = newItem.HostID
	}
	if oldItem.Hostname != newItem.Hostname {
		updateInfo["host_name"] = newItem.Hostname
	}
	if oldItem.IP != newItem.IP {
		updateInfo["ip"] = newItem.IP
	}
	if oldItem.SubnetID != newItem.SubnetID {
		updateInfo["subnet_id"] = newItem.SubnetID
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
