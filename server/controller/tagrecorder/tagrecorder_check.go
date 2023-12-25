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
	"encoding/json"
	"fmt"
	"hash/fnv"
	"reflect"
	"sort"

	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

// Check performs a comparison between the table with ch_ prefix and the resource table data.
// If an inconsistency is found, it clears the ch_ prefixed table and regenerates new data for insertion.
// This function is only executed during startup.
func (b *UpdaterComponent[MT, KT]) Check() (oldHash, newHash uint64) {
	newItems, newOK := b.updaterDG.generateNewData()
	oldItems, oldOK := b.generateOldData()
	newStr := make([]string, len(newItems))
	oldStr := make([]string, len(oldItems))
	newValues := reflect.ValueOf(newItems)
	oldValues := reflect.ValueOf(oldItems)
	for i, key := range newValues.MapKeys() {
		newStr[i] = fmt.Sprintf("%v", newValues.MapIndex(key).Interface())
	}
	for i, key := range oldValues.MapKeys() {
		oldStr[i] = fmt.Sprintf("%v", oldValues.MapIndex(key).Interface())
	}
	sort.Strings(newStr)
	sort.Strings(oldStr)

	newStrByte, err := json.Marshal(newStr)
	if err != nil {
		log.Error(err)
	}
	oldStrByte, err := json.Marshal(oldStr)
	if err != nil {
		log.Error(err)
	}
	h64 := fnv.New64()
	h64.Write(newStrByte)
	newHash = h64.Sum64()
	h64 = fnv.New64()
	h64.Write(oldStrByte)
	oldHash = h64.Sum64()

	if !newOK || !oldOK {
		return
	}
	var t MT
	if oldHash != newHash {
		log.Infof("truncate table %v, old len(%v) hash(%v), new len(%v) hash(%v)", reflect.TypeOf(t), len(newItems), oldHash, len(oldItems), newHash)
		var deleteItems []*MT
		for _, item := range oldItems {
			deleteItems = append(deleteItems, &item)
		}

		mysql.Db.Transaction(func(tx *gorm.DB) error {
			m := new(MT)
			if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&m).Error; err != nil {
				log.Error(err)
				return err
			}

			var addItems []MT
			for _, item := range newItems {
				addItems = append(addItems, item)
			}
			if err := tx.Create(&addItems).Error; err != nil {
				log.Error(err)
				return err
			}
			return nil
		})
	}
	return
}
