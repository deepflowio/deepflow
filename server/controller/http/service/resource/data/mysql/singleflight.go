/**
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

package mysql

import (
	"strings"

	"golang.org/x/sync/singleflight"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
)

var (
	sfg singleflight.Group
)

// TODO use
func singleFlightFind[T constraint.MySQLModel](resourceType string, fields []string) ([]T, error) {
	key := resourceType + ":" + strings.Join(fields, ",")
	result, err, _ := sfg.Do(key, func() (interface{}, error) {
		var r []T
		err := mysql.Db.Select(fields).Find(&r).Error
		if err != nil {
			return r, err
		}
		return r, err
	})
	return result.([]T), err
}
