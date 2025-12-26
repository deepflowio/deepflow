/**
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
package query

import (
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/db/metadb"
)

// FindInBatches gets all data that meets the query conditions in batches
func FindInBatches[T any](query *gorm.DB) ([]*T, error) {
	data := make([]*T, 0)
	pageIndex := 0
	pageCount := int(metadb.GetConfig().BatchSize0)
	pageData := make([]*T, 0)
	for pageIndex == 0 || len(pageData) == pageCount {
		err := query.Find(&pageData).Limit(pageCount).Offset(pageIndex * pageCount).Error
		if err != nil {
			return []*T{}, err
		}
		data = append(data, pageData...)
		pageIndex++
	}
	return data, nil
}

// FindInBatchesObj gets all data that meets the query conditions in batches
func FindInBatchesObj[T any](query *gorm.DB) ([]T, error) { // TODO unify return pointer or struct
	data := make([]T, 0)
	pageIndex := 0
	pageCount := int(metadb.GetConfig().BatchSize0)
	pageData := make([]T, 0)
	for pageIndex == 0 || len(pageData) == pageCount {
		err := query.Find(&pageData).Limit(pageCount).Offset(pageIndex * pageCount).Error
		if err != nil {
			return []T{}, err
		}
		data = append(data, pageData...)
		pageIndex++
	}
	return data, nil
}

func FindPage[T any](query *gorm.DB, pageSize int) ([]*T, error) {
	data := make([]*T, 0)
	pageIndex := 0
	pageData := make([]*T, 0)
	for pageIndex == 0 || len(pageData) == pageSize {
		err := query.Find(&pageData).Limit(pageSize).Offset(pageIndex * pageSize).Error
		if err != nil {
			return []*T{}, err
		}
		data = append(data, pageData...)
		pageIndex++
	}
	return data, nil
}

func DeletePageData[T any](query *gorm.DB, pageSize int, data []*T) error {
	total := len(data)
	var err error
	for i := 0; i < total; i += pageSize {
		end := i + pageSize
		if end > total {
			end = total
		}
		err = query.Delete(data[i:end]).Error
	}
	return err
}
