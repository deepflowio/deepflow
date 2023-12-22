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

type ChLbListener struct {
	UpdaterBase[mysql.ChLBListener, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChLbListener(resourceTypeToIconID map[IconKey]int) *ChLbListener {
	updater := &ChLbListener{
		UpdaterBase[mysql.ChLBListener, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_LB_LISTENER,
		},
		resourceTypeToIconID,
	}

	updater.dataGenerator = updater
	return updater
}

func (l *ChLbListener) getNewData() ([]mysql.ChLBListener, bool) {
	var lbListeners []mysql.LBListener
	var lbTargetServers []mysql.LBTargetServer
	err := mysql.Db.Unscoped().Find(&lbListeners).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, false
	}
	err = mysql.Db.Unscoped().Find(&lbTargetServers).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, false
	}

	lbTargetSertverMap := make(map[int]int)
	for _, lbTargetServer := range lbTargetServers {
		lbTargetSertverMap[lbTargetServer.LBListenerID] += 1
	}

	keyToItem := make([]mysql.ChLBListener, len(lbListeners))
	i := 0
	for _, lbListener := range lbListeners {
		if lbTargetSertverMap[lbListener.ID] == 0 {
			continue
		}
		keyToItem[i] = mysql.ChLBListener{
			ID:   lbListener.ID,
			Name: lbListener.Name,
		}
		if lbListener.DeletedAt.Valid {
			keyToItem[i].Name = lbListener.Name + " (deleted)"
		}
		i++
	}
	return keyToItem, true
}

func (l *ChLbListener) generateNewData() (map[IDKey]mysql.ChLBListener, bool) {
	items, ok := l.getNewData()
	if !ok {
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChLBListener)
	for _, item := range items {
		keyToItem[IDKey{ID: item.ID}] = item
	}
	return keyToItem, true
}

func (l *ChLbListener) generateKey(dbItem mysql.ChLBListener) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (l *ChLbListener) generateUpdateInfo(oldItem, newItem mysql.ChLBListener) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
