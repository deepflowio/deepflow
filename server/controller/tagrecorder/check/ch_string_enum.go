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
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/tag"
)

type ChStringEnum struct {
	UpdaterBase[metadbmodel.ChStringEnum, StringEnumTagKey]
}

func NewChStringEnum() *ChStringEnum {
	updater := &ChStringEnum{
		UpdaterBase[metadbmodel.ChStringEnum, StringEnumTagKey]{
			resourceTypeName: RESOURCE_TYPE_CH_STRING_ENUM,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (e *ChStringEnum) generateNewData() (map[StringEnumTagKey]metadbmodel.ChStringEnum, bool) {
	sql := "show tag all_string_enum values from tagrecorder"
	db := "tagrecorder"
	table := "tagrecorder"
	keyToItem := make(map[StringEnumTagKey]metadbmodel.ChStringEnum)
	respMap, err := tag.GetEnumTagValues(db, table, sql)
	if err != nil {
		log.Errorf("read failed: %v", err, e.db.LogPrefixORGID)
	}

	for name, tagValues := range respMap {
		for _, valueAndName := range tagValues {
			tagValue := valueAndName.([]interface{})[0]
			tagDisplayNameZH := valueAndName.([]interface{})[1]
			tagDisplayNameEN := valueAndName.([]interface{})[2]
			tagDescriptionZH := valueAndName.([]interface{})[3]
			tagDescriptionEN := valueAndName.([]interface{})[4]
			key := StringEnumTagKey{
				TagName:  name,
				TagValue: tagValue.(string),
			}
			keyToItem[key] = metadbmodel.ChStringEnum{
				TagName:       name,
				Value:         tagValue.(string),
				NameZH:        tagDisplayNameZH.(string),
				NameEN:        tagDisplayNameEN.(string),
				DescriptionZH: tagDescriptionZH.(string),
				DescriptionEN: tagDescriptionEN.(string),
			}
		}
	}
	return keyToItem, true
}

func (e *ChStringEnum) generateKey(dbItem metadbmodel.ChStringEnum) StringEnumTagKey {
	return StringEnumTagKey{TagName: dbItem.TagName, TagValue: dbItem.Value}
}

func (e *ChStringEnum) generateUpdateInfo(oldItem, newItem metadbmodel.ChStringEnum) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.TagName != newItem.TagName {
		updateInfo["tag_name"] = newItem.TagName
	}
	if oldItem.Value != newItem.Value {
		updateInfo["value"] = newItem.Value
	}
	if oldItem.NameZH != newItem.NameZH {
		updateInfo["name_zh"] = newItem.NameZH
	}
	if oldItem.NameEN != newItem.NameEN {
		updateInfo["name_en"] = newItem.NameEN
	}
	if oldItem.DescriptionZH != newItem.DescriptionZH {
		updateInfo["description_zh"] = newItem.DescriptionZH
	}
	if oldItem.DescriptionEN != newItem.DescriptionEN {
		updateInfo["description_en"] = newItem.DescriptionEN
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
