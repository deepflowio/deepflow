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
	"github.com/deepflowio/deepflow/server/controller/db/metadb/common"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
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
	e.GET("/v1/vtap-groups/:lcuuid/", v.getVtapGroup())
	e.GET("/v1/vtap-groups/", v.getVtapGroups())
	e.POST("/v1/vtap-groups/", v.createVtapGroup())
	e.PATCH("/v1/vtap-groups/:lcuuid/", v.updateVtapGroup())
	e.DELETE("/v1/vtap-groups/:lcuuid/", v.deleteVtapGroup())
}

func (v *VtapGroup) getVtapGroup() gin.HandlerFunc {
	return func(c *gin.Context) {
		args := make(map[string]interface{})
		args["lcuuid"] = c.Param("lcuuid")
		agentGroupService := service.NewAgentGroup(httpcommon.GetUserInfo(c), v.cfg)
		data, err := agentGroupService.Get(args)
		response.JSON(c, response.SetData(data), response.SetError(err))
	}
}

func (v *VtapGroup) getVtapGroups() gin.HandlerFunc {
	return func(c *gin.Context) {
		args := make(map[string]interface{})
		if value, ok := c.GetQuery("name"); ok {
			args["name"] = value
		}
		if value, ok := c.GetQuery("short_uuid"); ok {
			args["short_uuid"] = value
		}
		if value, ok := c.GetQuery("team_id"); ok {
			args["team_id"] = value
		}
		if value, ok := c.GetQuery("user_id"); ok {
			args["user_id"] = value
		}
		if value, ok := c.GetQuery("can_deleted"); ok {
			args["can_deleted"] = value
		}
		agentGroupService := service.NewAgentGroup(httpcommon.GetUserInfo(c), v.cfg)
		data, err := agentGroupService.Get(args)
		response.JSON(c, response.SetData(data), response.SetError(err))
	}
}

func (v *VtapGroup) createVtapGroup() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error
		var vtapGroupCreate model.VtapGroupCreate

		// 参数校验
		err = c.ShouldBindBodyWith(&vtapGroupCreate, binding.JSON)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.INVALID_PARAMETERS), response.SetError(err))
			return
		}
		if vtapGroupCreate.TeamID == 0 {
			vtapGroupCreate.TeamID = common.DEFAULT_TEAM_ID
		}

		agentGroupService := service.NewAgentGroup(httpcommon.GetUserInfo(c), v.cfg)
		data, err := agentGroupService.Create(vtapGroupCreate)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func (v *VtapGroup) updateVtapGroup() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error
		var vtapGroupUpdate model.VtapGroupUpdate

		err = c.ShouldBindBodyWith(&vtapGroupUpdate, binding.JSON)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.INVALID_PARAMETERS), response.SetError(err))
			return
		}

		// 接收参数
		// 避免struct会有默认值，这里转为map作为函数入参
		patchMap := map[string]interface{}{}
		if err := c.ShouldBindBodyWith(&patchMap, binding.JSON); err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.SERVER_ERROR), response.SetError(err))
			return
		}

		agentGroupService := service.NewAgentGroup(httpcommon.GetUserInfo(c), v.cfg)
		data, err := agentGroupService.Update(c.Param("lcuuid"), patchMap, v.cfg)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func (v *VtapGroup) deleteVtapGroup() gin.HandlerFunc {
	return func(c *gin.Context) {
		var err error

		lcuuid := c.Param("lcuuid")
		agentGroupService := service.NewAgentGroup(httpcommon.GetUserInfo(c), v.cfg)
		data, err := agentGroupService.Delete(lcuuid)
		response.JSON(c, response.SetData(data), response.SetError(err))
	}
}
