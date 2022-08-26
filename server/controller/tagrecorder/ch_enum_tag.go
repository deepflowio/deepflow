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
	"bytes"
	"encoding/json"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"io/ioutil"
	"net/http"
	"reflect"
	"strconv"
	"time"
)

type ChEnum struct {
	UpdaterBase[mysql.ChEnum, EnumTagKey]
}

func NewChEnum() *ChEnum {
	updater := &ChEnum{
		UpdaterBase[mysql.ChEnum, EnumTagKey]{
			resourceTypeName: RESOURCE_TYPE_CH_ENUM,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (e *ChEnum) generateNewData() (map[EnumTagKey]mysql.ChEnum, bool) {
	log.Infof("generate data for %s", e.resourceTypeName)
	url := "http://deepflow-server:20416/v1/query/"
	sql := "show tag all_enum values from tagrecorder"
	db := "tagrecorder"
	keyToItem := make(map[EnumTagKey]mysql.ChEnum)
	postParams := make(map[string]string)
	postParams["sql"] = sql
	postParams["db"] = db
	bodyStr, _ := json.Marshal(&postParams)
	req, err := http.NewRequest("POST", url, bytes.NewReader(bodyStr))
	if err != nil {
		log.Errorf("new  request failed, (%v)", err)
		return keyToItem, false
	}
	client := &http.Client{Timeout: time.Second * 30}
	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("curl (%s) failed, (%v)", url, err)
		return keyToItem, false
	} else if resp.StatusCode != http.StatusOK {
		log.Errorf("curl (%s) failed, (%v)", url, resp)
		return keyToItem, false
		defer resp.Body.Close()
	}

	respMap := make(map[string]interface{})
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("read failed: %v", err)
		return keyToItem, false
	}
	err = json.Unmarshal(respBody, &respMap)
	enums := respMap["result"].(map[string]interface{})

	for tagName, tagValues := range enums {
		for _, valueAndName := range tagValues.([]interface{}) {
			tagValue := valueAndName.([]interface{})[0]
			tagDisplayName := valueAndName.([]interface{})[1]
			tagValueStr := ""
			if reflect.TypeOf(tagValue).Kind() == reflect.Float64 {
				tagValueStr = strconv.FormatFloat(tagValue.(float64), 'f', 0, 32)
			} else if reflect.TypeOf(tagValue).Kind() == reflect.String {
				tagValueStr = tagValue.(string)
			}
			keyToItem[EnumTagKey{TagName: tagName, TagValue: tagValueStr}] = mysql.ChEnum{
				TagName: tagName,
				Value:   tagValueStr,
				Name:    tagDisplayName.(string),
			}
		}
	}

	return keyToItem, true
}

func (e *ChEnum) generateKey(dbItem mysql.ChEnum) EnumTagKey {
	return EnumTagKey{TagName: dbItem.TagName, TagValue: dbItem.Value}
}

func (e *ChEnum) generateUpdateInfo(oldItem, newItem mysql.ChEnum) (map[string]interface{}, bool) {
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
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
