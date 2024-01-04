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

package common

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// CheckJSONParam check json parameters for redundancy.
// Does not support map[string]interface type in struct.
func CheckJSONParam(jsonString string, v interface{}) error {
	jsonTags := GetJsonTags(v)
	keyMap, err := GetAllKeys(jsonString)
	if err != nil {
		return err
	}

	for key := range keyMap {
		if _, ok := jsonTags[key]; !ok {
			return fmt.Errorf("rogue field(%s)", key)
		}
	}
	return nil
}

// GetJsonTags get all json tags of struct.
// Does not support map[string]interface type in struct.
func GetJsonTags(v interface{}) map[string]bool {
	tagMap := make(map[string]bool)
	getAllJSONTags(reflect.TypeOf(v), tagMap)
	return tagMap
}

func getAllJSONTags(typ reflect.Type, tagMap map[string]bool) {
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		return
	}

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		tag := field.Tag.Get("json")
		if tag == "" {
			continue
		}
		tag = strings.TrimSuffix(tag, ",omitempty")
		tagMap[tag] = true

		switch field.Type.Kind() {
		case reflect.Struct, reflect.Ptr:
			getAllJSONTags(field.Type, tagMap)
		case reflect.Array, reflect.Slice, reflect.Map:
			getAllJSONTags(field.Type.Elem(), tagMap)
		}
	}
}

// GetAllKeys gets all json keys.
// Does not support map[string]interface type in struct.
func GetAllKeys(jsonString string) (map[string]bool, error) {
	var data map[string]interface{}
	err := json.Unmarshal([]byte(jsonString), &data)
	if err != nil {
		return nil, fmt.Errorf("not a valid JSON string: %s\nerr: %s", jsonString, err)
	}

	keyMap := make(map[string]bool)
	getAllKeys(data, keyMap)
	return keyMap, nil
}

func getAllKeys(data interface{}, keys map[string]bool) {
	switch value := data.(type) {
	case map[string]interface{}:
		for key := range value {
			keys[key] = true
			getAllKeys(value[key], keys)
		}
	case []interface{}:
		for _, item := range value {
			getAllKeys(item, keys)
		}
	}
}
