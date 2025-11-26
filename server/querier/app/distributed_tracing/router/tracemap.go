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
	"github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/querier/app/distributed_tracing/common"
	"github.com/deepflowio/deepflow/server/querier/app/distributed_tracing/model"
	"github.com/deepflowio/deepflow/server/querier/app/distributed_tracing/service/tracemap"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/router"
)

var log = logging.MustGetLogger("tracemap")

func TraceMapRouter(e *gin.Engine, cfg *config.QuerierConfig, generator *tracemap.TraceMapGenerator) {
	e.POST("/v1/trace_map", traceMap(cfg, generator))
	e.POST("/v1/flow_map", flowMap(cfg, generator))
}

func traceMap(cfg *config.QuerierConfig, generator *tracemap.TraceMapGenerator) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var args model.TraceMap

		// 参数校验
		err := c.ShouldBindBodyWith(&args, binding.JSON)
		if err != nil {
			router.BadRequestResponse(c, common.INVALID_POST_DATA, err.Error())
			return
		}
		args.Context = c.Request.Context()
		args.OrgID = c.Request.Header.Get(common.HEADER_KEY_X_ORG_ID)
		c.Header("Content-Type", "application/json")
		done := make(chan bool)
		defer close(done)
		go tracemap.TraceMap(args, cfg, c, done, generator)
		<-done
	})
}

func flowMap(cfg *config.QuerierConfig, generator *tracemap.TraceMapGenerator) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var args model.FlowMap

		// 参数校验
		err := c.ShouldBindBodyWith(&args, binding.JSON)
		if err != nil {
			router.BadRequestResponse(c, common.INVALID_POST_DATA, err.Error())
			return
		}
		args.Context = c.Request.Context()
		args.OrgID = c.Request.Header.Get(common.HEADER_KEY_X_ORG_ID)
		c.Header("Content-Type", "application/json")
		tracemap.FlowMap(args, cfg, c, generator)
	})
}
