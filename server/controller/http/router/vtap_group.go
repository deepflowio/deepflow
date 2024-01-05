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

	"github.com/deepflowio/deepflow/server/controller/config"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	. "github.com/deepflowio/deepflow/server/controller/http/router/common"
	"github.com/deepflowio/deepflow/server/controller/http/service"
	"github.com/deepflowio/deepflow/server/controller/model"
)

type VtapGroup struct {
	cfg *config.ControllerConfig
}

func NewVtapGroup(cfg *config.ControllerConfig) *VtapGroup {
	return &VtapGroup{cfg: cfg}
}

func (v *VtapGroup) RegisterTo(e *gin.Engine) {
	e.GET("/v1/vtap-groups/:lcuuid/", getVtapGroup)
	e.GET("/v1/vtap-groups/", getVtapGroups)
	e.POST("/v1/vtap-groups/", createVtapGroup(v.cfg))
	e.PATCH("/v1/vtap-groups/:lcuuid/", updateVtapGroup(v.cfg))
	e.DELETE("/v1/vtap-groups/:lcuuid/", deleteVtapGroup)
}

func getVtapGroup(c *gin.Context) {
	args := make(map[string]interface{})
	args["lcuuid"] = c.Param("lcuuid")
	data, err := service.GetVtapGroups(args)
	JsonResponse(c, data, err)
}

func getVtapGroups(c *gin.Context) {
	args := make(map[string]interface{})
	if value, ok := c.GetQuery("name"); ok {
		args["name"] = value
	}
	if value, ok := c.GetQuery("short_uuid"); ok {
		args["short_uuid"] = value
	}
	data, err := service.GetVtapGroups(args)
	JsonResponse(c, data, err)
}

func createVtapGroup(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error
		var vtapGroupCreate model.VtapGroupCreate

		// 参数校验
		err = c.ShouldBindBodyWith(&vtapGroupCreate, binding.JSON)
		if err != nil {
			BadRequestResponse(c, httpcommon.INVALID_POST_DATA, err.Error())
			return
		}

		data, err := service.CreateVtapGroup(vtapGroupCreate, cfg)
		JsonResponse(c, data, err)
	})
}

func updateVtapGroup(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error
		var vtapGroupUpdate model.VtapGroupUpdate

		// 参数校验
		err = c.ShouldBindBodyWith(&vtapGroupUpdate, binding.JSON)
		if err != nil {
			BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
			return
		}

		// 接收参数
		// 避免struct会有默认值，这里转为map作为函数入参
		patchMap := map[string]interface{}{}
		c.ShouldBindBodyWith(&patchMap, binding.JSON)

		lcuuid := c.Param("lcuuid")
		data, err := service.UpdateVtapGroup(lcuuid, patchMap, cfg)
		JsonResponse(c, data, err)
	})
}

func deleteVtapGroup(c *gin.Context) {
	var err error

	lcuuid := c.Param("lcuuid")
	data, err := service.DeleteVtapGroup(lcuuid)
	JsonResponse(c, data, err)
}
