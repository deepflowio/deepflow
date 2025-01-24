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
	"io"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"github.com/deepflowio/deepflow/server/agent_config"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
	"github.com/deepflowio/deepflow/server/controller/http/service"
)

type VTapGroupConfig struct {
	cfg *config.ControllerConfig
}

func NewVTapGroupConfig(cfg *config.ControllerConfig) *VTapGroupConfig {
	return &VTapGroupConfig{
		cfg: cfg,
	}
}

func (cgc *VTapGroupConfig) RegisterTo(e *gin.Engine) {
	e.POST("/v1/vtap-group-configuration/", createVTapGroupConfig(cgc.cfg))
	e.DELETE("/v1/vtap-group-configuration/:lcuuid/", deleteVTapGroupConfig(cgc.cfg))
	e.PATCH("/v1/vtap-group-configuration/:lcuuid/", updateVTapGroupConfig(cgc.cfg))
	e.GET("/v1/vtap-group-configuration/", getVTapGroupConfigs(cgc.cfg))
	e.GET("/v1/vtap-group-configuration/detailed/:lcuuid/", getVTapGroupDetailedConfig)
	e.POST("/v1/vtap-group-configuration/advanced/", createVTapGroupAdvancedConfig)
	e.GET("/v1/vtap-group-configuration/advanced/:lcuuid/", getVTapGroupAdvancedConfig)
	e.GET("/v1/vtap-group-configuration/advanced/", getVTapGroupAdvancedConfigs)
	e.PATCH("/v1/vtap-group-configuration/advanced/:lcuuid/", updateVTapGroupAdvancedConfig)
	e.GET("/v1/vtap-group-configuration/example/", getVTapGroupExampleConfig)

	e.GET("/v1/vtap-group-configuration/filter/", getVTapGroupConfigByFilter)
	e.DELETE("/v1/vtap-group-configuration/filter/", deleteVTapGroupConfigByFilter)
}

func createVTapGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		vTapGroupConfig := &agent_config.AgentGroupConfig{}
		err := c.ShouldBindBodyWith(&vTapGroupConfig, binding.JSON)
		if err == nil {

			data, err := service.NewVTapGroupConfig(common.GetUserInfo(c), cfg).CreateVTapGroupConfig(common.GetUserInfo(c).ORGID, vTapGroupConfig)
			response.JSON(c, response.SetData(data), response.SetError(err))
		} else {
			response.JSON(c, response.SetError(err))
		}
	}
}

func deleteVTapGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		lcuuid := c.Param("lcuuid")
		data, err := service.NewVTapGroupConfig(common.GetUserInfo(c), cfg).DeleteVTapGroupConfig(common.GetUserInfo(c).ORGID, lcuuid)
		response.JSON(c, response.SetData(data), response.SetError(err))
	}
}

func updateVTapGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		vTapGroupConfig := &agent_config.AgentGroupConfig{}
		if err := c.ShouldBindBodyWith(&vTapGroupConfig, binding.JSON); err != nil {
			response.JSON(c, response.SetStatus(common.INVALID_PARAMETERS), response.SetDescription(err.Error()))
			return
		}
		data, err := service.NewVTapGroupConfig(common.GetUserInfo(c), cfg).
			UpdateVTapGroupConfig(common.GetUserInfo(c).ORGID, c.Param("lcuuid"), vTapGroupConfig)
		response.JSON(c, response.SetData(data), response.SetError(err))
	}
}

func getVTapGroupConfigs(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		args := make(map[string]interface{})
		if value, ok := c.GetQuery("vtap_group_id"); ok {
			args["vtap_group_id"] = value
		}
		userInfo := common.GetUserInfo(c)
		data, err := service.GetVTapGroupConfigs(userInfo, &cfg.FPermit, args)
		response.JSON(c, response.SetData(data), response.SetError(err))
	}
}

func getVTapGroupDetailedConfig(c *gin.Context) {
	lcuuid := c.Param("lcuuid")

	data, err := service.GetVTapGroupDetailedConfig(common.GetUserInfo(c).ORGID, lcuuid)
	response.JSON(c, response.SetData(data), response.SetError(err))
}

func getVTapGroupAdvancedConfig(c *gin.Context) {
	lcuuid := c.Param("lcuuid")
	data, err := service.GetVTapGroupAdvancedConfig(common.GetUserInfo(c).ORGID, lcuuid)
	response.JSON(c, response.SetData(data), response.SetError(err))
}

func updateVTapGroupAdvancedConfig(c *gin.Context) {
	lcuuid := c.Param("lcuuid")
	vTapGroupConfig := &agent_config.AgentGroupConfig{}
	err := c.ShouldBindBodyWith(&vTapGroupConfig, binding.YAML)
	if err == nil || err == io.EOF {
		data, err := service.UpdateVTapGroupAdvancedConfig(common.GetUserInfo(c).ORGID, lcuuid, vTapGroupConfig)
		response.JSON(c, response.SetData(data), response.SetError(err))
	} else {
		response.JSON(c, response.SetError(err))
	}
}

func createVTapGroupAdvancedConfig(c *gin.Context) {
	vTapGroupConfig := &agent_config.AgentGroupConfig{}
	err := c.ShouldBindBodyWith(&vTapGroupConfig, binding.YAML)
	if err == nil {
		data, err := service.CreateVTapGroupAdvancedConfig(common.GetUserInfo(c).ORGID, vTapGroupConfig)
		response.JSON(c, response.SetData(data), response.SetError(err))
	} else {
		response.JSON(c, response.SetError(err))
	}
}

func getVTapGroupConfigByFilter(c *gin.Context) {
	args := make(map[string]string)
	if value, ok := c.GetQuery("vtap_group_id"); ok {
		args["vtap_group_id"] = value
	}
	data, err := service.GetVTapGroupConfigByFilter(common.GetUserInfo(c).ORGID, args)
	response.JSON(c, response.SetData(data), response.SetError(err))
}

func deleteVTapGroupConfigByFilter(c *gin.Context) {
	args := make(map[string]string)
	if value, ok := c.GetQuery("vtap_group_id"); ok {
		args["vtap_group_id"] = value
	}
	data, err := service.DeleteVTapGroupConfigByFilter(common.GetUserInfo(c).ORGID, args)
	response.JSON(c, response.SetData(data), response.SetError(err))
}

func getVTapGroupExampleConfig(c *gin.Context) {
	data, err := service.GetVTapGroupExampleConfig()
	response.JSON(c, response.SetData(data), response.SetError(err))
}

func getVTapGroupAdvancedConfigs(c *gin.Context) {
	data, err := service.GetVTapGroupAdvancedConfigs(common.GetUserInfo(c).ORGID)
	response.JSON(c, response.SetData(data), response.SetError(err))
}
