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
	. "github.com/deepflowio/deepflow/server/controller/http/router/common"
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

			data, err := service.NewAgentGroupConfig(service.GetUserInfo(c), cfg).CreateVTapGroupConfig(service.GetUserInfo(c).ORGID, vTapGroupConfig)
			JsonResponse(c, data, err)
		} else {
			JsonResponse(c, nil, err)
		}
	}
}

func deleteVTapGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		lcuuid := c.Param("lcuuid")
		data, err := service.NewAgentGroupConfig(service.GetUserInfo(c), cfg).DeleteVTapGroupConfig(service.GetUserInfo(c).ORGID, lcuuid)
		JsonResponse(c, data, err)
	}
}

func updateVTapGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		lcuuid := c.Param("lcuuid")
		vTapGroupConfig := &agent_config.AgentGroupConfig{}
		err := c.ShouldBindBodyWith(&vTapGroupConfig, binding.JSON)
		if err == nil {
			data, err := service.NewAgentGroupConfig(service.GetUserInfo(c), cfg).UpdateVTapGroupConfig(service.GetUserInfo(c).ORGID, lcuuid, vTapGroupConfig)
			JsonResponse(c, data, err)
		} else {
			JsonResponse(c, nil, err)
		}
	}
}

func getVTapGroupConfigs(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		args := make(map[string]interface{})
		if value, ok := c.GetQuery("vtap_group_id"); ok {
			args["vtap_group_id"] = value
		}
		userInfo := service.GetUserInfo(c)
		data, err := service.GetVTapGroupConfigs(userInfo, &cfg.FPermit, args)
		JsonResponse(c, data, err)
	}
}

func getVTapGroupDetailedConfig(c *gin.Context) {
	lcuuid := c.Param("lcuuid")

	data, err := service.GetVTapGroupDetailedConfig(service.GetUserInfo(c).ORGID, lcuuid)
	JsonResponse(c, data, err)
}

func getVTapGroupAdvancedConfig(c *gin.Context) {
	lcuuid := c.Param("lcuuid")
	data, err := service.GetVTapGroupAdvancedConfig(service.GetUserInfo(c).ORGID, lcuuid)
	JsonResponse(c, data, err)
}

func updateVTapGroupAdvancedConfig(c *gin.Context) {
	lcuuid := c.Param("lcuuid")
	vTapGroupConfig := &agent_config.AgentGroupConfig{}
	err := c.ShouldBindBodyWith(&vTapGroupConfig, binding.YAML)
	if err == nil || err == io.EOF {
		data, err := service.UpdateVTapGroupAdvancedConfig(service.GetUserInfo(c).ORGID, lcuuid, vTapGroupConfig)
		JsonResponse(c, data, err)
	} else {
		JsonResponse(c, nil, err)
	}
}

func createVTapGroupAdvancedConfig(c *gin.Context) {
	vTapGroupConfig := &agent_config.AgentGroupConfig{}
	err := c.ShouldBindBodyWith(&vTapGroupConfig, binding.YAML)
	if err == nil {
		data, err := service.CreateVTapGroupAdvancedConfig(service.GetUserInfo(c).ORGID, vTapGroupConfig)
		JsonResponse(c, data, err)
	} else {
		JsonResponse(c, nil, err)
	}
}

func getVTapGroupConfigByFilter(c *gin.Context) {
	args := make(map[string]string)
	if value, ok := c.GetQuery("vtap_group_id"); ok {
		args["vtap_group_id"] = value
	}
	data, err := service.GetVTapGroupConfigByFilter(service.GetUserInfo(c).ORGID, args)
	JsonResponse(c, data, err)
}

func deleteVTapGroupConfigByFilter(c *gin.Context) {
	args := make(map[string]string)
	if value, ok := c.GetQuery("vtap_group_id"); ok {
		args["vtap_group_id"] = value
	}
	data, err := service.DeleteVTapGroupConfigByFilter(service.GetUserInfo(c).ORGID, args)
	JsonResponse(c, data, err)
}

func getVTapGroupExampleConfig(c *gin.Context) {
	data, err := service.GetVTapGroupExampleConfig()
	JsonResponse(c, data, err)
}

func getVTapGroupAdvancedConfigs(c *gin.Context) {
	data, err := service.GetVTapGroupAdvancedConfigs(service.GetUserInfo(c).ORGID)
	JsonResponse(c, data, err)
}
