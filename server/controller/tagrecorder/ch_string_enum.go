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
	"strings"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/tag"
)

type ChStringEnum struct {
	UpdaterComponent[mysql.ChStringEnum, StringEnumTagKey]
}

func NewChStringEnum() *ChStringEnum {
	updater := &ChStringEnum{
		newUpdaterComponent[mysql.ChStringEnum, StringEnumTagKey](
			RESOURCE_TYPE_CH_STRING_ENUM,
		),
	}
	updater.updaterDG = updater
	return updater
}

func (e *ChStringEnum) generateNewData(dbClient *mysql.DB) (map[StringEnumTagKey]mysql.ChStringEnum, bool) {
	sql := "show tag all_string_enum values from tagrecorder"
	db := "tagrecorder"
	table := "tagrecorder"
	keyToItem := make(map[StringEnumTagKey]mysql.ChStringEnum)
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
			key := StringEnumTagKey{
				TagName:  tagName,
				TagValue: tagValue.(string),
			}
			keyToItem[key] = mysql.ChStringEnum{
				TagName:     tagName,
				Value:       tagValue.(string),
				Name:        tagDisplayName.(string),
				Description: tagDescription.(string),
			}
		}
	}

	return keyToItem, true
}

func (e *ChStringEnum) generateKey(dbItem mysql.ChStringEnum) StringEnumTagKey {
	return StringEnumTagKey{TagName: dbItem.TagName, TagValue: dbItem.Value}
}

func (e *ChStringEnum) generateUpdateInfo(oldItem, newItem mysql.ChStringEnum) (map[string]interface{}, bool) {
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
