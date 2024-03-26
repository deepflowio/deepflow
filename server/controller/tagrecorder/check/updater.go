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
	"github.com/deepflowio/deepflow/server/controller/db/mysql/query"
	"github.com/deepflowio/deepflow/server/controller/tagrecorder/config"
)

type ChResourceUpdater interface {
	// 刷新ch资源入口
	// 基于资源基础数据，构建新的ch数据
	// 直接查询ch表，构建旧的ch数据
	// 遍历新的ch数据，若key不在旧的ch数据中，则新增；否则检查是否有更新，若有更新，则更新
	// 遍历旧的ch数据，若key不在新的ch数据中，则删除
	// Refresh() bool
	SetConfig(cfg config.TagRecorderConfig)
	Check() error
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
	cfg              config.TagRecorderConfig
	resourceTypeName string
	dataGenerator    DataGenerator[MT, KT]
}

func (b *UpdaterBase[MT, KT]) SetConfig(cfg config.TagRecorderConfig) {
	b.cfg = cfg
}

func (b *UpdaterBase[MT, KT]) generateOldData() ([]MT, bool) {
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

	return items, true
}

func (b *UpdaterBase[MT, KT]) generateOneData() (map[KT]MT, bool) {
	var items []MT
	err := mysql.Db.Unscoped().First(&items).Error
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

func (b *UpdaterBase[MT, KT]) operateBatch(keys []KT, items []MT, operateFunc func([]KT, []MT)) {
	count := len(items)
	offset := b.cfg.MySQLBatchSize
	var pages int
	if count%offset == 0 {
		pages = count / offset
	} else {
		pages = count/offset + 1
	}
	for i := 0; i < pages; i++ {
		start := i * offset
		end := (i + 1) * offset
		if end > count {
			end = count
		}
		operateFunc(keys[start:end], items[start:end])
	}
}

func (b *UpdaterBase[MT, KT]) add(keys []KT, dbItems []MT) {
	err := mysql.Db.Create(&dbItems).Error
	if err != nil {
		for i := range keys {
			log.Errorf("add %s (key: %+v value: %+v) failed: %s", b.resourceTypeName, keys[i], dbItems[i], err.Error())
		}
		return
	}
	for i := range keys {
		log.Infof("add %s (key: %+v value: %+v) success", b.resourceTypeName, keys[i], dbItems[i])
	}
}

func (b *UpdaterBase[MT, KT]) update(oldDBItem MT, updateInfo map[string]interface{}, key KT) {
	err := mysql.Db.Model(&oldDBItem).Updates(updateInfo).Error
	if err != nil {
		log.Errorf("update %s (key: %+v value: %+v) failed: %s", b.resourceTypeName, key, oldDBItem, err.Error())
		return
	}
	log.Infof("update %s (key: %+v value: %+v, update info: %v) success", b.resourceTypeName, key, oldDBItem, updateInfo)
}

func (b *UpdaterBase[MT, KT]) delete(keys []KT, dbItems []MT) {
	err := mysql.Db.Delete(&dbItems).Error
	if err != nil {
		for i := range keys {
			log.Errorf("delete %s (key: %+v value: %+v) failed: %s", b.resourceTypeName, keys[i], dbItems[i], err.Error())
		}
		return
	}
	for i := range keys {
		log.Infof("delete %s (key: %+v value: %+v) success", b.resourceTypeName, keys[i], dbItems[i])
	}
}
