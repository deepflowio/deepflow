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
	"strings"
)

type Comparable interface {
	~int | ~string
}

func Contains[T Comparable](slice []T, val T) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

// a:b,c:d -> {"a":"b","c":"d"}, map[string]string{"a":"b","c":"d"}
func StrToJsonAndMap(str string) (resJson string, resMap map[string]string) {
	if str == "" {
		return
	}
	m := map[string]string{}
	multiPairStr := strings.Split(str, ",")
	for _, pairStr := range multiPairStr {
		pair := strings.Split(pairStr, ":")
		if len(pair) == 2 {
			m[strings.Trim(pair[0], " ")] = strings.Trim(pair[1], " ")
		}
	}
	resMap = m
	if len(m) == 0 {
		return
	}
	jsonStr, err := json.Marshal(m)
	if err != nil {
		log.Error(err)
		return
	}
	resJson = string(jsonStr)
	return
}
