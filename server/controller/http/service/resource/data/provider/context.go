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

package provider

import (
	"github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/http/model"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/filter/generator"
)

var log = logging.MustGetLogger("service.resource.data.provider")

type DataContext struct {
	URLInfo         *model.URLInfo            // use to generate redis key
	UserInfo        *model.UserInfo           // use to check permission and generate redis key
	FilterGenerator generator.FilterGenerator // generate filters from URLInfo and UserInfo
}

func NewDataContext(url *model.URLInfo, user *model.UserInfo, fg generator.FilterGenerator) *DataContext {
	return &DataContext{URLInfo: url, UserInfo: user, FilterGenerator: fg}
}

func (c *DataContext) SetURLInfo(u *model.URLInfo) {
	c.URLInfo = u
}

func (c *DataContext) SetUserInfo(u *model.UserInfo) {
	c.UserInfo = u
}

func (c *DataContext) SetFilterGenerator(fg generator.FilterGenerator) {
	c.FilterGenerator = fg
}

func (c *DataContext) ApplyFilters(data []common.ResponseElem) ([]common.ResponseElem, error) {
	log.Infof("%#v", c.URLInfo) // TODO delete
	log.Infof("%#v", c.UserInfo)
	filters, dropAll := c.FilterGenerator.Generate(c.URLInfo, c.UserInfo)
	if dropAll {
		return []common.ResponseElem{}, nil
	}
	var err error
	result := data
	for _, f := range filters {
		log.Info(f.GetFilterConditions())
		result, err = f.Filter(result)
		if err != nil {
			return []common.ResponseElem{}, err
		}
	}
	return result, nil
}
