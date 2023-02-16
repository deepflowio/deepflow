/*
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
	. "github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type PartialFilter struct {
	includedFields []string
	excludedFields []string
}

func (f *PartialFilter) SetIncludedFields(fields []string) {
	f.includedFields = fields
}

func (f *PartialFilter) SetExcludedFields(fields []string) {
	f.excludedFields = fields
}

func (f *PartialFilter) Filter(data []ResponseElem) ([]ResponseElem, error) {
	var result []ResponseElem
	for _, elem := range data {
		newElem := f.normalize(elem)
		result = append(result, newElem)
	}

	return result, nil
}

func (f *PartialFilter) normalize(elem ResponseElem) ResponseElem {
	newElem := make(ResponseElem)
	if len(f.includedFields) == 0 {
		for k, v := range elem {
			newElem[k] = v
		}
	} else {
		for _, field := range f.includedFields {
			newElem[field] = elem[field]
		}
	}
	for _, field := range f.excludedFields {
		delete(newElem, field)
	}
	return newElem
}

func (f *PartialFilter) Merge(other *PartialFilter) {
	f.includedFields = append(f.includedFields, other.includedFields...)
	f.excludedFields = append(f.excludedFields, other.excludedFields...)
	return
}
