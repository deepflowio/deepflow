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
	"github.com/gin-gonic/gin"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/redis"
	. "github.com/deepflowio/deepflow/server/controller/http/config"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	. "github.com/deepflowio/deepflow/server/controller/http/router/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource"
)

type Pod struct {
	httpConfig    HTTPConfig
	redisConfig   redis.RedisConfig
	fpermitConfig config.FPermit
}

func NewPod(hCfg HTTPConfig, rCfg redis.RedisConfig, fCfg config.FPermit) *Pod {
	return &Pod{httpConfig: hCfg, redisConfig: rCfg, fpermitConfig: fCfg}
}

func (p *Pod) RegisterTo(ge *gin.Engine) {
	ge.GET("/v2/pods/", p.Get)
}

func (p *Pod) Get(c *gin.Context) {
	headerV := NewHeaderValidator(c.Request.Header)
	queryV := NewQueryValidator[model.PodQuery](c.Request.URL.Query())
	validator := NewCombinedValidator(headerV, queryV)
	err := validator.Validate()
	if err != nil {
		BadRequestResponse(c, common.INVALID_POST_DATA, err.Error()) // TODO new opt_status
		return
	}

	urlInfo := model.NewURLInfo(c.Request.URL.String(), queryV.query.IncludedFields, queryV.query.PodQueryFilterConditions.ToMapOmitEmpty(), queryV.query.UserID)
	service := resource.NewPod(urlInfo, headerV.userInfo, p.redisConfig, p.fpermitConfig)
	if queryV.query.RefreshCache {
		data, err := service.RefreshPodCache()
		JsonResponse(c, data, err)
	} else {
		data, err := service.GetPods()
		JsonResponse(c, data, err)
	}
}

func (p *Pod) Update(c *gin.Context) {

}
