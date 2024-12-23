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

type ChIntEnum struct {
	UpdaterBase[metadbmodel.ChIntEnum, IntEnumTagKey]
}

func NewChIntEnum() *ChIntEnum {
	updater := &ChIntEnum{
		UpdaterBase[metadbmodel.ChIntEnum, IntEnumTagKey]{
			resourceTypeName: RESOURCE_TYPE_CH_INT_ENUM,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (e *ChIntEnum) generateNewData() (map[IntEnumTagKey]metadbmodel.ChIntEnum, bool) {
	sql := "show tag all_int_enum values from tagrecorder"
	db := "tagrecorder"
	table := "tagrecorder"
	keyToItem := make(map[IntEnumTagKey]metadbmodel.ChIntEnum)
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
			tagValueInt, ok := tagValue.(int)
			if ok {
				key := IntEnumTagKey{
					TagName:  name,
					TagValue: tagValueInt,
				}
				keyToItem[key] = metadbmodel.ChIntEnum{
					TagName:       name,
					Value:         tagValueInt,
					NameZH:        tagDisplayNameZH.(string),
					NameEN:        tagDisplayNameEN.(string),
					DescriptionZH: tagDescriptionZH.(string),
					DescriptionEN: tagDescriptionEN.(string),
				}
			}
		}
	}

	return keyToItem, true
}

func (e *ChIntEnum) generateKey(dbItem metadbmodel.ChIntEnum) IntEnumTagKey {
	return IntEnumTagKey{TagName: dbItem.TagName, TagValue: dbItem.Value}
}

func (e *ChIntEnum) generateUpdateInfo(oldItem, newItem metadbmodel.ChIntEnum) (map[string]interface{}, bool) {
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
