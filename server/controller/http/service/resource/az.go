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
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/redis"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/data"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/filter/generator"
)

type AZ struct {
	ServiceGet
}

func NewAZGet(urlInfo *model.URLInfo, userInfo *model.UserInfo, redisCfg redis.Config) *AZ {
	s := &AZ{newServiceGet(ctrlrcommon.RESOURCE_TYPE_AZ_EN, data.GetDataProvider(ctrlrcommon.RESOURCE_TYPE_AZ_EN, redisCfg))}
	s.generateDataContext(urlInfo, userInfo, generator.NewAZ())
	return s
}
