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
	"time"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/query"
	"github.com/deepflowio/deepflow/server/controller/tagrecorder/config"
)

type ChResourceUpdater interface {
	// 刷新ch资源入口
	// 基于资源基础数据，构建新的ch数据
	// 直接查询ch表，构建旧的ch数据
	// 遍历新的ch数据，若key不在旧的ch数据中，则新增；否则检查是否有更新，若有更新，则更新
	// 遍历旧的ch数据，若key不在新的ch数据中，则删除
	Refresh() bool
	SetConfig(cfg config.TagRecorderConfig)
}

type updaterDataGenerator[MT MySQLChModel, KT ChModelKey] interface {
	// 根据db中的基础资源数据，构建最新的ch资源数据
	generateNewData() (map[KT]MT, bool)
	// 构建ch资源的结构体key
	generateKey(MT) KT
	// 根据新旧数据对比，构建需要更新的ch资源数据
	generateUpdateInfo(MT, MT) (map[string]interface{}, bool)
}

type UpdaterComponent[MT MySQLChModel, KT ChModelKey] struct {
	cfg              config.TagRecorderConfig
	resourceTypeName string
	updaterDG        updaterDataGenerator[MT, KT]
	dbOperator       operator[MT, KT]
}

func newUpdaterComponent[MT MySQLChModel, KT ChModelKey](resourceTypeName string) UpdaterComponent[MT, KT] {
	u := UpdaterComponent[MT, KT]{
		resourceTypeName: resourceTypeName,
	}
	u.initDBOperator()
	return u
}

func (b *UpdaterComponent[MT, KT]) SetConfig(cfg config.TagRecorderConfig) {
	b.cfg = cfg
	b.dbOperator.setConfig(cfg)
}

func (b *UpdaterComponent[MT, KT]) initDBOperator() {
	b.dbOperator = newOperator[MT, KT](b.resourceTypeName)
}

func (b *UpdaterComponent[MT, KT]) Refresh() bool {
	newKeyToDBItem, newOK := b.updaterDG.generateNewData()
	oldKeyToDBItem, oldOK := b.generateOldData()
	keysToAdd := []KT{}
	itemsToAdd := []MT{}
	keysToDelete := []KT{}
	itemsToDelete := []MT{}
	isUpdate := false
	if newOK && oldOK {
		for key, newDBItem := range newKeyToDBItem {
			oldDBItem, exists := oldKeyToDBItem[key]
			if !exists {
				keysToAdd = append(keysToAdd, key)
				itemsToAdd = append(itemsToAdd, newDBItem)
			} else {
				updateInfo, ok := b.updaterDG.generateUpdateInfo(oldDBItem, newDBItem)
				if ok {
					b.dbOperator.update(oldDBItem, updateInfo, key)
					isUpdate = true
				}
			}
		}
		if len(itemsToAdd) > 0 {
			b.dbOperator.batchPage(keysToAdd, itemsToAdd, b.dbOperator.add)
		}

		for key, oldDBItem := range oldKeyToDBItem {
			_, exists := newKeyToDBItem[key]
			if !exists {
				keysToDelete = append(keysToDelete, key)
				itemsToDelete = append(itemsToDelete, oldDBItem)
			}
		}
		if len(itemsToDelete) > 0 {
			b.dbOperator.batchPage(keysToDelete, itemsToDelete, b.dbOperator.delete)
		}

		if len(itemsToDelete) > 0 && len(itemsToAdd) == 0 && !isUpdate {
			updateDBItem, updateOK := b.generateOneData()
			if updateOK {
				for key, updateDBItem := range updateDBItem {
					updateTimeInfo := make(map[string]interface{})
					now := time.Now()
					updateTimeInfo["updated_at"] = now.Format("2006-01-02 15:04:05")
					b.dbOperator.update(updateDBItem, updateTimeInfo, key)
				}
			}
		}
		if (isUpdate || len(itemsToDelete) > 0 || len(itemsToAdd) > 0) && (b.resourceTypeName == RESOURCE_TYPE_CH_APP_LABEL || b.resourceTypeName == RESOURCE_TYPE_CH_TARGET_LABEL) {
			return true
		}
	}
	return false
}

func (b *UpdaterComponent[MT, KT]) generateOldData() (map[KT]MT, bool) {
	var items []MT
	var err error
	if b.resourceTypeName == RESOURCE_TYPE_CH_GPROCESS {
		items, err = query.FindInBatchesObj[MT](mysql.Db.Unscoped())
	} else {
		err = mysql.Db.Unscoped().Find(&items).Error
	}
	if err != nil {
		log.Errorf(dbQueryResourceFailed(b.resourceTypeName, err))
		return nil, false
	}
	idToItem := make(map[KT]MT)
	for _, item := range items {
		idToItem[b.updaterDG.generateKey(item)] = item
	}
	return idToItem, true
}

func (b *UpdaterComponent[MT, KT]) generateOneData() (map[KT]MT, bool) {
	var items []MT
	err := mysql.Db.Unscoped().First(&items).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(b.resourceTypeName, err))
		return nil, false
	}
	idToItem := make(map[KT]MT)
	for _, item := range items {
		idToItem[b.updaterDG.generateKey(item)] = item
	}
	return idToItem, true
}
