/**
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

	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
)

type operator[MT MySQLChModel, KT ChModelKey] interface {
	batchPage(keys []KT, items []MT, operateFunc func([]KT, []MT, *metadb.DB), db *metadb.DB)
	add(keys []KT, dbItems []MT, db *metadb.DB)
	update(oldDBItem MT, updateInfo map[string]interface{}, key KT, db *metadb.DB)
	delete(keys []KT, dbItems []MT, db *metadb.DB)
	setConfig(config.ControllerConfig)
}

type operatorComponent[MT MySQLChModel, KT ChModelKey] struct {
	cfg              config.ControllerConfig
	resourceTypeName string
}

func newOperator[MT MySQLChModel, KT ChModelKey](resourceTypeName string) *operatorComponent[MT, KT] {
	return &operatorComponent[MT, KT]{
		resourceTypeName: resourceTypeName,
	}
}

func (b *operatorComponent[MT, KT]) setConfig(cfg config.ControllerConfig) {
	b.cfg = cfg
}

func (b *operatorComponent[MT, KT]) batchPage(keys []KT, items []MT, operateFunc func([]KT, []MT, *metadb.DB), db *metadb.DB) {
	count := len(items)
	offset := b.cfg.TagRecorderCfg.MySQLBatchSize
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
		operateFunc(keys[start:end], items[start:end], db)
	}
}

func (b *operatorComponent[MT, KT]) add(keys []KT, dbItems []MT, db *metadb.DB) {
	err := db.Clauses(clause.OnConflict{
		UpdateAll: true,
	}).Create(&dbItems).Error
	if err != nil {
		log.Errorf("add %s (keys: %+v values: %+v) failed: %s", b.resourceTypeName, keys, dbItems, err.Error(), db.LogPrefixORGID) // TODO is key needed?
		return
	}
	log.Infof("add %s (keys: %+v values: %+v) success", b.resourceTypeName, keys, dbItems, db.LogPrefixORGID)
}

func (b *operatorComponent[MT, KT]) update(oldDBItem MT, updateInfo map[string]interface{}, key KT, db *metadb.DB) {
	err := db.Model(&oldDBItem).Updates(updateInfo).Error
	if err != nil {
		log.Errorf("update %s (key: %+v value: %+v) failed: %s", b.resourceTypeName, key, oldDBItem, err.Error(), db.LogPrefixORGID)
		return
	}
	log.Infof("update %s (key: %+v value: %+v, update info: %v) success", b.resourceTypeName, key, oldDBItem, updateInfo, db.LogPrefixORGID)
}

func (b *operatorComponent[MT, KT]) delete(keys []KT, dbItems []MT, db *metadb.DB) {
	err := db.Delete(&dbItems).Error
	if err != nil {
		log.Errorf("delete %s (keys: %+v values: %+v) failed: %s", b.resourceTypeName, keys, dbItems, err.Error(), db.LogPrefixORGID)
		return
	}
	log.Infof("delete %s (keys: %+v values: %+v) success", b.resourceTypeName, keys, dbItems, db.LogPrefixORGID)
}
