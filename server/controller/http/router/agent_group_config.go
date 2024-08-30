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

	"github.com/deepflowio/deepflow/server/agent_config"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/http/common"
	routercommon "github.com/deepflowio/deepflow/server/controller/http/router/common"
	"github.com/deepflowio/deepflow/server/controller/http/service"
)

type AgentGroupConfig struct {
	cfg *config.ControllerConfig
}

func NewAgentGroupConfig(cfg *config.ControllerConfig) *AgentGroupConfig {
	return &AgentGroupConfig{
		cfg: cfg,
	}
}

func (cgc *AgentGroupConfig) RegisterTo(e *gin.Engine) {
	e.GET("/v1/agent-group-configuration/template/yaml", getYAMLAgentGroupConfigTmpl)
	e.GET("/v1/agent-group-configuration/template/json", getJsonAgentGroupConfigTmpl(cgc.cfg))

	e.GET("/v1/agent-group-configuration/json", getJsonAgentGroupConfigs(cgc.cfg))
	e.GET("/v1/agent-group-configuration/:group-lcuuid/json", getJsonAgentGroupConfig(cgc.cfg))
	e.POST("/v1/agent-group-configuration/:group-lcuuid/json", postJsonAgentGroupConfig(cgc.cfg))
	e.PUT("/v1/agent-group-configuration/:group-lcuuid/json", putJsonAgentGroupConfig(cgc.cfg))

	e.GET("/v1/agent-group-configuration/:group-lcuuid/yaml", getYAMLAgentGroupConfig(cgc.cfg))
	e.POST("/v1/agent-group-configuration/:group-lcuuid/yaml", postYAMLAgentGroupConfig(cgc.cfg))
	e.PUT("/v1/agent-group-configuration/:group-lcuuid/yaml", putYAMLAgentGroupConfig(cgc.cfg))

	e.DELETE("/v1/agent-group-configuration/:group-lcuuid", deleteAgentGroupConfig(cgc.cfg))

}

func getYAMLAgentGroupConfigTmpl(c *gin.Context) {
	routercommon.JsonResponse(c, string(agent_config.YamlAgentGroupConfigTemplate), nil)
}

func getJsonAgentGroupConfigTmpl(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		data, err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).GetAgentGroupConfigTemplateJson()
		routercommon.JsonResponse(c, data, err)
	}
}

func getJsonAgentGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		groupLcuuid := c.Param("group-lcuuid")
		data, err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).GetAgentGroupConfig(groupLcuuid, service.DataTypeJSON)
		routercommon.JsonResponse(c, data, err)
	}
}

func getJsonAgentGroupConfigs(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		data, err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).GetAgentGroupConfigs()
		routercommon.JsonResponse(c, data, err)
	}
}

func postJsonAgentGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		var postData map[string]interface{}
		if err := c.ShouldBindJSON(&postData); err != nil {
			routercommon.JsonResponse(c, nil, err)
			return
		}
		groupLcuuid := c.Param("group-lcuuid")
		data, err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).CreateAgentGroupConfig(groupLcuuid, postData, service.DataTypeJSON)
		routercommon.JsonResponse(c, data, err)
	}
}

func putJsonAgentGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		var postData map[string]interface{}
		if err := c.ShouldBindJSON(&postData); err != nil {
			routercommon.JsonResponse(c, nil, err)
			return
		}
		groupLcuuid := c.Param("group-lcuuid")
		data, err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).UpdateAgentGroupConfig(groupLcuuid, postData, service.DataTypeJSON)
		routercommon.JsonResponse(c, data, err)
	}
}

func getYAMLAgentGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		groupLcuuid := c.Param("group-lcuuid")
		data, err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).GetAgentGroupConfig(groupLcuuid, service.DataTypeYAML)
		routercommon.JsonResponse(c, string(data), err)
	}
}

func postYAMLAgentGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		bytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			routercommon.JsonResponse(c, nil, err)
			return
		}
		groupLcuuid := c.Param("group-lcuuid")
		body := map[string]interface{}{"data": string(bytes)}
		data, err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).CreateAgentGroupConfig(groupLcuuid, body, service.DataTypeYAML)
		routercommon.JsonResponse(c, string(data), err)
	}
}

func putYAMLAgentGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		bytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			routercommon.JsonResponse(c, nil, err)
			return
		}
		groupLcuuid := c.Param("group-lcuuid")
		body := map[string]interface{}{"data": string(bytes)}
		data, err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).UpdateAgentGroupConfig(groupLcuuid, body, service.DataTypeYAML)
		routercommon.JsonResponse(c, string(data), err)
	}
}

func deleteAgentGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		groupLcuuid := c.Param("group-lcuuid")
		err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).DeleteAgentGroupConfig(groupLcuuid)
		routercommon.JsonResponse(c, nil, err)
	}
}
