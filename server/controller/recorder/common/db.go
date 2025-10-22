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

func PageWhereFind[MT any](md *Metadata, query interface{}, args ...interface{}) ([]*MT, error) {
	pageSize := md.Config.MySQLBatchSize
	var items []*MT
	for pageNum := 1; ; pageNum++ {
		var pageItems []*MT
		err := md.DB.Where(query, args...).Limit(pageSize).Offset((pageNum - 1) * pageSize).Find(&pageItems).Error
		if err != nil {
			log.Errorf("failed to find data: %s", err.Error(), md.LogPrefixes)
			return nil, err
		}
		items = append(items, pageItems...)
		if len(pageItems) < pageSize {
			break
		}
	}
	return items, nil
}

func PageSelectWhereFind[MT any](md *Metadata, selectFields []string, query interface{}, args ...interface{}) ([]*MT, error) {
	pageSize := md.Config.MySQLBatchSize
	var items []*MT
	for pageNum := 1; ; pageNum++ {
		var pageItems []*MT
		err := md.DB.Select(selectFields).Where(query, args...).Limit(pageSize).Offset((pageNum - 1) * pageSize).Find(&pageItems).Error
		if err != nil {
			log.Errorf("failed to find data: %s", err.Error(), md.LogPrefixes)
			return nil, err
		}
		items = append(items, pageItems...)
		if len(pageItems) < pageSize {
			break
		}
	}
	return items, nil
}
