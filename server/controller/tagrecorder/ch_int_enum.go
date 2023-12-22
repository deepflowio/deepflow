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
	"sort"
	"strconv"
	"strings"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/tag"
)

type ChIntEnum struct {
	UpdaterBase[mysql.ChIntEnum, IntEnumTagKey]
}

func NewChIntEnum() *ChIntEnum {
	updater := &ChIntEnum{
		UpdaterBase[mysql.ChIntEnum, IntEnumTagKey]{
			resourceTypeName: RESOURCE_TYPE_CH_INT_ENUM,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (e *ChIntEnum) getNewData() ([]mysql.ChIntEnum, bool) {
	keyToItem, ok := e.generateNewData()
	if !ok {
		return nil, false
	}

	items := make([]mysql.ChIntEnum, len(keyToItem))
	i := 0
	for _, data := range keyToItem {
		items[i] = data
		i++
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].TagName < items[i].TagName
	})
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].Value < items[i].Value
	})
	return items, true
}

func (e *ChIntEnum) generateNewData() (map[IntEnumTagKey]mysql.ChIntEnum, bool) {
	sql := "show tag all_int_enum values from tagrecorder"
	db := "tagrecorder"
	table := "tagrecorder"
	keyToItem := make(map[IntEnumTagKey]mysql.ChIntEnum)
	respMap, err := tag.GetEnumTagValues(db, table, sql)
	if err != nil {
		log.Errorf("read failed: %v", err)
	}

	for name, tagValues := range respMap {
		tagName := strings.TrimSuffix(name, "."+config.Cfg.Language)
		for _, valueAndName := range tagValues {
			tagValue := valueAndName.([]interface{})[0]
			tagDisplayName := valueAndName.([]interface{})[1]
			tagDescription := valueAndName.([]interface{})[2]
			tagValueInt, err := strconv.Atoi(tagValue.(string))
			if err == nil {
				key := IntEnumTagKey{
					TagName:  tagName,
					TagValue: tagValueInt,
				}
				keyToItem[key] = mysql.ChIntEnum{
					TagName:     tagName,
					Value:       tagValueInt,
					Name:        tagDisplayName.(string),
					Description: tagDescription.(string),
				}
			}

		}
	}

	return keyToItem, true
}

func (e *ChIntEnum) generateKey(dbItem mysql.ChIntEnum) IntEnumTagKey {
	return IntEnumTagKey{TagName: dbItem.TagName, TagValue: dbItem.Value}
}

func (e *ChIntEnum) generateUpdateInfo(oldItem, newItem mysql.ChIntEnum) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.TagName != newItem.TagName {
		updateInfo["tag_name"] = newItem.TagName
	}
	if oldItem.Value != newItem.Value {
		updateInfo["value"] = newItem.Value
	}
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if oldItem.Description != newItem.Description {
		updateInfo["description"] = newItem.Description
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
