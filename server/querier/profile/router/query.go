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

package router

import (
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"github.com/deepflowio/deepflow/server/querier/profile/common"
	"github.com/deepflowio/deepflow/server/querier/profile/model"
	"github.com/deepflowio/deepflow/server/querier/profile/service"
)

func ProfileRouter(e *gin.Engine) {
	e.POST("/v1/profile/ProfileTracing", profileTracing())

}

func profileTracing() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var profileTracing model.ProfileTracing

		// 参数校验
		err := c.ShouldBindBodyWith(&profileTracing, binding.JSON)
		if err != nil {
			BadRequestResponse(c, common.INVALID_POST_DATA, err.Error())
			return
		}
		result, err := service.Tracing(profileTracing)
		JsonResponse(c, result, err)
	})
}
