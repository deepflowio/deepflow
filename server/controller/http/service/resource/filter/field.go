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

package filter

import (
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type FieldFilter struct {
	IncludedFields []string
	ExcludedFields []string
}

func (f *FieldFilter) SetIncludedFields(fields []string) {
	f.IncludedFields = fields
}

func (f *FieldFilter) SetExcludedFields(fields []string) {
	f.ExcludedFields = fields
}

// Filter implements Filter interface
func (f *FieldFilter) Filter(data []common.ResponseElem) ([]common.ResponseElem, error) {
	var result []common.ResponseElem
	for _, elem := range data {
		newElem := f.normalize(elem)
		result = append(result, newElem)
	}

	return result, nil
}

func (f *FieldFilter) normalize(elem common.ResponseElem) common.ResponseElem {
	newElem := make(common.ResponseElem)
	if len(f.IncludedFields) == 0 {
		for k, v := range elem {
			newElem[k] = v
		}
	} else {
		for _, field := range f.IncludedFields {
			newElem[field] = elem[field]
		}
	}
	for _, field := range f.ExcludedFields {
		delete(newElem, field)
	}
	return newElem
}
