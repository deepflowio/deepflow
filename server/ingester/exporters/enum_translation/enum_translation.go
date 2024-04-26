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

package enum_translation

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/deepflowio/deepflow/server/querier/db_descriptions"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("exporters.translation")

type EnumTranslation struct {
	intMaps    map[string]map[int]string
	stringMaps map[string]map[string]string
}

func NewEnumTranslation() *EnumTranslation {
	t := &EnumTranslation{
		intMaps:    make(map[string]map[int]string),
		stringMaps: make(map[string]map[string]string),
	}
	err := t.Load()
	if err != nil {
		log.Error(err)
	}
	return t
}

func (t *EnumTranslation) GetMaps(file string) (map[int]string, map[string]string) {
	return t.intMaps[file], t.stringMaps[file]
}

func (t *EnumTranslation) Load() error {
	files, err := db_descriptions.EnumFiles.ReadDir("clickhouse/tag/enum")
	if err != nil {
		return fmt.Errorf("error reading directory: %s", err)
	}

	for _, file := range files {
		filename := file.Name()
		if !strings.HasSuffix(filename, ".ch") {
			content, err := db_descriptions.EnumFiles.ReadFile("clickhouse/tag/enum/" + filename)
			if err != nil {
				fmt.Printf("error reading file %s: %v\n", filename, err)
				continue
			}
			stringMap, intMap := parseContent(string(content))
			if strings.HasSuffix(filename, ".en") {
				filename = filename[:len(filename)-3]
			}
			t.intMaps[filename] = intMap
			t.stringMaps[filename] = stringMap
		}
	}
	return nil
}

func parseContent(content string) (map[string]string, map[int]string) {
	stringMap := make(map[string]string)
	intMap := make(map[int]string)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if !strings.HasPrefix(line, "#") && line != "" {
			fields := strings.Split(line, ",")
			if len(fields) >= 2 {
				key := strings.TrimSpace(fields[0])
				value := strings.TrimSpace(fields[1])

				if i, err := strconv.Atoi(key); err == nil {
					intMap[i] = value
				}
				stringMap[key] = value
			}
		}
	}
	return stringMap, intMap
}
