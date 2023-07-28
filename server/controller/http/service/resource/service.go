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

package resource

import (
	"github.com/deepflowio/deepflow/server/controller/http/model"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/data/provider"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/filter/generator"
)

type ServiceGet struct {
	resourceType string
	dataProvider provider.DataProvider
	dataContext  *provider.DataContext
}

func newServiceGet(resourceType string, dp provider.DataProvider) ServiceGet {
	return ServiceGet{resourceType: resourceType, dataProvider: dp}
}

func (s *ServiceGet) generateDataContext(urlInfo *model.URLInfo, userInfo *model.UserInfo, fg generator.FilterGenerator) {
	dCtx := provider.NewDataContext()
	dCtx.SetURLInfo(urlInfo)
	dCtx.SetUserInfo(userInfo)
	dCtx.SetFilterGenerator(fg)
	s.dataContext = dCtx
}

func (s *ServiceGet) RefreshCache() (map[string]int, error) {
	// TODO call master controller to get a refresh task id
	return map[string]int{"TASK_ID": 0}, nil
}

func (s *ServiceGet) Get() ([]common.ResponseElem, error) {
	return s.dataProvider.Get(s.dataContext)
}
