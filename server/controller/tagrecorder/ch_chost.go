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
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type ChChost struct {
	UpdaterBase[mysql.ChChost, IDKey]
}

func NewChChost() *ChChost {
	updater := &ChChost{
		UpdaterBase[mysql.ChChost, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_CHOST,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (p *ChChost) getNewData() ([]mysql.ChChost, bool) {
	var (
		chosts []mysql.VM
		hosts  []mysql.Host
	)
	err := mysql.Db.Unscoped().Find(&chosts).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}
	err = mysql.Db.Unscoped().Select("id", "ip").Find(&hosts).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}

	ipToHostID := make(map[string]int, len(hosts))
	for _, host := range hosts {
		ipToHostID[host.IP] = host.ID
	}

	items := make([]mysql.ChChost, len(chosts))
	for i, chost := range chosts {
		items[i] = mysql.ChChost{
			ID:     chost.ID,
			Name:   chost.Name,
			VPCID:  chost.VPCID,
			HostID: ipToHostID[chost.LaunchServer],
		}
		if chost.DeletedAt.Valid {
			items[i].Name = chost.Name + " (deleted)"
		}
	}
	return items, true
}

func (p *ChChost) generateNewData() (map[IDKey]mysql.ChChost, bool) {
	items, ok := p.getNewData()
	if !ok {
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChChost)
	for _, item := range items {
		keyToItem[IDKey{ID: item.ID}] = item
	}
	return keyToItem, true
}

func (p *ChChost) generateKey(dbItem mysql.ChChost) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (p *ChChost) generateUpdateInfo(oldItem, newItem mysql.ChChost) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if oldItem.VPCID != newItem.VPCID {
		updateInfo["vpc_id"] = newItem.VPCID
	}
	if oldItem.HostID != newItem.HostID {
		updateInfo["host_id"] = newItem.HostID
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
