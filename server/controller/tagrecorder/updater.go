/*
 * Copyright (c) 2022 Yunshan Networks
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

type ChResourceUpdater interface {
	// 刷新ch资源入口
	// 基于资源基础数据，构建新的ch数据
	// 直接查询ch表，构建旧的ch数据
	// 遍历新的ch数据，若key不在旧的ch数据中，则新增；否则检查是否有更新，若有更新，则更新
	// 遍历旧的ch数据，若key不在新的ch数据中，则删除
	Refresh()
}

type DataGenerator[MT MySQLChModel, KT ChModelKey] interface {
	// 根据db中的基础资源数据，构建最新的ch资源数据
	generateNewData() (map[KT]MT, bool)
	// 构建ch资源的结构体key
	generateKey(MT) KT
	// 根据新旧数据对比，构建需要更新的ch资源数据
	generateUpdateInfo(MT, MT) (map[string]interface{}, bool)
}

type UpdaterBase[MT MySQLChModel, KT ChModelKey] struct {
	resourceTypeName string
	dataGenerator    DataGenerator[MT, KT]
}

func (b *UpdaterBase[MT, KT]) Refresh() {
	newKeyToDBItem, newOK := b.dataGenerator.generateNewData()
	oldKeyToDBItem, oldOK := b.generateOldData()
	if newOK && oldOK {
		for key, newDBItem := range newKeyToDBItem {
			oldDBItem, exists := oldKeyToDBItem[key]
			if !exists {
				b.add(newDBItem, key)
			} else {
				updateInfo, ok := b.dataGenerator.generateUpdateInfo(oldDBItem, newDBItem)
				if ok {
					b.update(oldDBItem, updateInfo, key)
				}
			}
		}
		for key, oldDBItem := range oldKeyToDBItem {
			_, exists := newKeyToDBItem[key]
			if !exists {
				b.delete(oldDBItem, key)
			}
		}
	}
}

func (b *UpdaterBase[MT, KT]) generateOldData() (map[KT]MT, bool) {
	var items []MT
	err := mysql.Db.Unscoped().Find(&items).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(b.resourceTypeName, err))
		return nil, false
	}
	idToItem := make(map[KT]MT)
	for _, item := range items {
		idToItem[b.dataGenerator.generateKey(item)] = item
	}
	return idToItem, true
}

// TODO 是否需要批量处理
func (b *UpdaterBase[MT, KT]) add(dbItem MT, key KT) {
	err := mysql.Db.Create(&dbItem).Error
	if err != nil {
		log.Errorf("add %s %v (%+v) failed: %s", b.resourceTypeName, key, dbItem, err)
		return
	}
	log.Infof("add %s %v (%+v) success", b.resourceTypeName, key, dbItem)
}

func (b *UpdaterBase[MT, KT]) update(oldDBItem MT, updateInfo map[string]interface{}, key KT) {
	err := mysql.Db.Model(&oldDBItem).Updates(updateInfo).Error
	if err != nil {
		log.Errorf("update %s %v (%+v) failed: %s", b.resourceTypeName, key, oldDBItem, err)
		return
	}
	log.Infof("update %s %v (%+v, %v) success", b.resourceTypeName, key, oldDBItem, updateInfo)
}

func (b *UpdaterBase[MT, KT]) delete(dbItem MT, key KT) {
	err := mysql.Db.Delete(&dbItem).Error
	if err != nil {
		log.Errorf("delete %s %v (%+v) failed: %s", b.resourceTypeName, key, dbItem, err)
		return
	}
	log.Infof("delete %s %v (%+v) success", b.resourceTypeName, key, dbItem)
}
