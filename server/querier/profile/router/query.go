/*
 * Copyright (c) 2024 Yunshan Networks
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

package router

import (
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/profile/model"
	"github.com/deepflowio/deepflow/server/querier/profile/service"
	"github.com/deepflowio/deepflow/server/querier/router"
)

func ProfileRouter(e *gin.Engine, cfg *config.QuerierConfig) {
	e.POST("/v1/profile/ProfileTracing", profileTracing(cfg))

}

func profileTracing(cfg *config.QuerierConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var profileTracing model.ProfileTracing

		// 参数校验
		err := c.ShouldBindBodyWith(&profileTracing, binding.JSON)
		if err != nil {
			router.BadRequestResponse(c, common.INVALID_POST_DATA, err.Error())
			return
		}
		profileTracing.Context = c.Request.Context()
		result, debug, err := service.Tracing(profileTracing, cfg)
		if err == nil && !profileTracing.Debug {
			debug = nil
		}
		router.JsonResponse(c, result, debug, err)
	})
}
