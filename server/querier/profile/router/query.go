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
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/profile/common"
	"github.com/deepflowio/deepflow/server/querier/profile/model"
	"github.com/deepflowio/deepflow/server/querier/profile/service"
	"github.com/deepflowio/deepflow/server/querier/router"
)

func ProfileRouter(e *gin.Engine, cfg *config.QuerierConfig) {
	e.POST("/v1/profile/ProfileTracing", profile(cfg))
	e.POST("/v1/profile/ProfileGrafana", profileGrafana(cfg))
}

func profile(cfg *config.QuerierConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var args model.Profile

		// 参数校验
		err := c.ShouldBindBodyWith(&args, binding.JSON)
		if err != nil {
			router.BadRequestResponse(c, common.INVALID_POST_DATA, err.Error())
			return
		}
		args.Context = c.Request.Context()
		args.OrgID = c.Request.Header.Get(common.HEADER_KEY_X_ORG_ID)
		if args.MaxKernelStackDepth == nil {
			var maxKernelStackDepth = common.MAX_KERNEL_STACK_DEPTH_DEFAULT
			args.MaxKernelStackDepth = &maxKernelStackDepth
		}
		result, debug, err := service.Profile(args, cfg)
		if err == nil && !args.Debug {
			debug = nil
		}
		router.JsonResponse(c, result, debug, err)
	})
}

func profileGrafana(cfg *config.QuerierConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := model.ProfileGrafana{}
		args.Sql = c.PostForm("sql")
		args.ProfileEventType = c.PostForm("profile_event_type")

		var profileArgs model.Profile
		profileArgs.Debug, _ = strconv.ParseBool(c.DefaultQuery("debug", "false"))
		profileArgs.Context = c.Request.Context()
		profileArgs.AppService = "root"
		profileArgs.ProfileEventType = args.ProfileEventType
		var maxKernelStackDepth = common.MAX_KERNEL_STACK_DEPTH_DEFAULT
		profileArgs.MaxKernelStackDepth = &maxKernelStackDepth

		result, debug, err := service.GrafanaProfile(profileArgs, cfg, args.Sql)
		if err == nil && !profileArgs.Debug {
			debug = nil
		}
		router.JsonResponse(c, result, debug, err)
	})
}
