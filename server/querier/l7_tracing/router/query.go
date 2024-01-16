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

package router

import (
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/l7_tracing/common"
	"github.com/deepflowio/deepflow/server/querier/l7_tracing/model"
	"github.com/deepflowio/deepflow/server/querier/l7_tracing/service"
	"github.com/deepflowio/deepflow/server/querier/router"
)

func L7TracingRouter(e *gin.Engine, cfg *config.QuerierConfig) {
	e.POST("/v1/l7_tracing/L7FlowTracing", l7FlowTracing(cfg))

}

func l7FlowTracing(cfg *config.QuerierConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var l7Tracing model.L7Tracing

		// 参数校验
		err := c.ShouldBindBodyWith(&l7Tracing, binding.JSON)
		if err != nil {
			router.BadRequestResponse(c, common.INVALID_POST_DATA, err.Error())
			return
		}
		l7Tracing.Context = c.Request.Context()
		result, debug, err := service.Tracing(l7Tracing, cfg)
		if err == nil && !l7Tracing.Debug {
			debug = nil
		}
		router.JsonResponse(c, result, debug, err)
	})
}
