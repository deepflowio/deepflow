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
	"github.com/goccy/go-json"

	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/data/provider"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
)

type DataProvider struct {
	resourceType string
	generator    generator
}

func newDataProvider(resourceType string) DataProvider {
	return DataProvider{resourceType: resourceType}
}

func (dp *DataProvider) setGenerator(g generator) {
	dp.generator = g
}

// Get implements provider.DataProvider interface
func (dp *DataProvider) Get(ctx *provider.DataContext) ([]common.ResponseElem, error) {
	data, err := dp.generator.generate()
	if err != nil {
		return []common.ResponseElem{}, err
	}
	if ctx == nil {
		return data, nil
	}
	return ctx.ApplyFilters(data)
}

// Refresh implements provider.DataProvider interface
func (d *DataProvider) Refresh(ctx *provider.DataContext) error {
	return nil
}

type generator interface {
	generate() ([]common.ResponseElem, error)
}

func MySQLModelToMap[T constraint.MySQLModel](dbItem T) common.ResponseElem {
	bs, _ := json.Marshal(dbItem)
	respElem := make(common.ResponseElem)
	_ = json.Unmarshal(bs, &respElem)
	return respElem
}
