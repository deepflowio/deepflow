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

package provider

import (
	"github.com/deepflowio/deepflow/server/controller/http/model"
	. "github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/filter"
)

type DataContext struct {
	URLInfo         *model.URLInfo         // use to generate redis key
	UserInfo        *model.UserInfo        // use to check permission and generate redis key
	FilterGenerator filter.FilterGenerator // generate filters from URLInfo and UserInfo
}

func NewDataContext() *DataContext {
	return &DataContext{}
}

func (c *DataContext) SetURLInfo(u *model.URLInfo) {
	c.URLInfo = u
}

func (c *DataContext) SetUserInfo(u *model.UserInfo) {
	c.UserInfo = u
}

func (c *DataContext) SetFilterGenerator(fg filter.FilterGenerator) {
	c.FilterGenerator = fg
}

func (c *DataContext) GetFilters() []filter.Filter {
	return c.FilterGenerator.Generate(c.URLInfo, c.UserInfo)
}

func (c *DataContext) ApplyFilters(data []ResponseElem) ([]ResponseElem, error) {
	filters := c.GetFilters()
	if filters == nil {
		return []ResponseElem{}, nil
	}
	var err error
	result := data
	for _, f := range c.GetFilters() {
		result, err = f.Filter(result)
	}
	return result, err
}
