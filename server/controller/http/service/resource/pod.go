/*
 * Copyright (c) 2022 Yunshan Networks
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
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/redis"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	. "github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/data"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/filter"
)

type Pod struct {
	ServiceGetBase
}

func NewPod(urlInfo *model.URLInfo, userInfo *model.UserInfo, redisCfg redis.RedisConfig, fpermitCfg config.FPermit) *Pod {
	s := &Pod{newServiceGetBase(common.RESOURCE_TYPE_POD_EN, data.GetDataProvider(common.RESOURCE_TYPE_POD_EN, redisCfg))}
	fg := filter.NewPodFilterGenerator(fpermitCfg)
	fg.SetFPermit(fpermitCfg)
	s.GenerateDataContext(urlInfo, userInfo, fg)
	return s
}

func (s *Pod) GetPods() ([]ResponseElem, error) {
	return s.Get()
}

func (s *Pod) RefreshPodCache() (map[string]int, error) {
	return s.RefreshCache()
}
