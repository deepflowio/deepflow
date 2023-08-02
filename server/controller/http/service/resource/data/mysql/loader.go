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
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/constraint"
)

func Select[T constraint.MySQLModel](fields []string) ([]T, error) {
	var result []T
	err := mysql.Db.Select(fields).Find(&result).Error
	return result, err
}

// TODO SelectWhere
func SelectWithQuery[T constraint.MySQLModel](fields []string, query interface{}, args ...interface{}) ([]T, error) {
	var result []T
	err := mysql.Db.Select(fields).Where(query, args...).Find(&result).Error
	return result, err
}

func GetAll[T any]() ([]T, error) {
	var result []T
	err := mysql.Db.Find(&result).Error
	return result, err
}

func FindWhereObj[T any](query interface{}, args ...interface{}) ([]T, error) {
	var result []T
	err := mysql.Db.Where(query, args...).Find(&result).Error
	return result, err
}

func FindWhere[T any](query interface{}, args ...interface{}) ([]*T, error) {
	var result []*T
	err := mysql.Db.Where(query, args...).Find(&result).Error
	return result, err
}

func Find[T any]() ([]*T, error) {
	var result []*T
	err := mysql.Db.Find(&result).Error
	return result, err
}

func UnscopedFind[T any]() ([]T, error) {
	var result []T
	err := mysql.Db.Unscoped().Find(&result).Error
	return result, err
}

func UnscopedOrderFind[T any](order interface{}) ([]T, error) {
	var result []T
	err := mysql.Db.Unscoped().Order(order).Find(&result).Error
	return result, err
}
