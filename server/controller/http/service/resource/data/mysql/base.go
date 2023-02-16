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

package mysql

import (
	json "github.com/goccy/go-json"

	. "github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/data/provider"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
)

type DataProvider struct {
	resourceType string
	generator    dataGenerator
}

func newDataProvider(resourceType string) DataProvider {
	return DataProvider{resourceType: resourceType}
}

func (d *DataProvider) setGenerator(g dataGenerator) {
	d.generator = g
}

func (d *DataProvider) Get(ctx *provider.DataContext) ([]ResponseElem, error) {
	data, err := d.generator.generate()
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		return data, nil
	}
	return ctx.ApplyFilters(data)
}

func (d *DataProvider) Refresh(ctx *provider.DataContext) (err error) {
	return
}

type dataGenerator interface {
	generate() ([]ResponseElem, error)
}

func MySQLModelToMap[T constraint.MySQLModel](dbItem T) ResponseElem {
	s, _ := json.Marshal(dbItem)
	d := make(ResponseElem)
	_ = json.Unmarshal(s, &d)
	return d
}
