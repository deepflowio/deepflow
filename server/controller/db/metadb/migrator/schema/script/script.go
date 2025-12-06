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

package script

import (
	"reflect"
	"strings"

	"github.com/op/go-logging"
	"gorm.io/gorm"
)

var log = logging.MustGetLogger("db.metadb.migration.script")

type scripts struct{}

func (s scripts) exec(db *gorm.DB, version string) error {
	if version == "" {
		return nil
	}

	// Replace '.' with '_' in version string
	methodName := "version" + strings.ReplaceAll(version, ".", "_")

	// Use reflection to get the method
	method := reflect.ValueOf(s).MethodByName(methodName)
	if !method.IsValid() {
		log.Debugf("No script method found for version %s", version)
		return nil
	}

	// Call the method with db as argument
	results := method.Call([]reflect.Value{reflect.ValueOf(db)})

	// Check if the method returned an error
	if len(results) > 0 && !results[0].IsNil() {
		return results[0].Interface().(error)
	}

	return nil
}

func ExecuteScript(db *gorm.DB, version string) error {
	return scripts{}.exec(db, version)
}
