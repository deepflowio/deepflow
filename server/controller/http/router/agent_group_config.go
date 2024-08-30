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
	e.GET("/v1/agent-group-configuration/template/yaml", getAgentGroupConfigTemplate)
	e.GET("/v1/agent-group-configuration/template/json", getAgentGroupConfig(cgc.cfg))
	e.PUT("/v1/agent-group-configuration/:group-lcuuid", getAgentGroupConfig(cgc.cfg))
	e.GET("/v1/agent-group-configuration/value/:group-lcuuid", getAgentGroupConfigValue(cgc.cfg))
	e.GET("/v1/agent-group-configuration/value", getAgentGroupConfigValues(cgc.cfg))
	e.POST("/v1/agent-group-configuration/value/:group-lcuuid", createAgentGroupConfig(cgc.cfg))
	e.PUT("/v1/agent-group-configuration/value/:group-lcuuid", updateAgentGroupConfig(cgc.cfg))
	e.DELETE("/v1/agent-group-configuration/:group-lcuuid", deleteAgentGroupConfig(cgc.cfg))

}

func getAgentGroupConfigTemplate(c *gin.Context) {
	routercommon.JsonResponse(c, string(agent_config.YamlAgentGroupConfigTemplate), nil)
}

func getAgentGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// args := make(map[string]interface{})
		// if value, ok := c.GetQuery("agent_group_id"); ok {
		// 	args["agent_group_id"] = value
		// }
		data, err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).GetAgentGroupConfigTemplateJson() // FIXME args 参数实际没有使用？
		routercommon.JsonResponse(c, data, err)
	}
}

func getAgentGroupConfigValue(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		groupLcuuid := c.Param("group-lcuuid")
		data, err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).GetAgentGroupConfigValue(groupLcuuid)
		routercommon.JsonResponse(c, data, err)
	}
}

func getAgentGroupConfigValues(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		data, err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).GetAgentGroupConfigValues()
		routercommon.JsonResponse(c, data, err)
	}
}

func createAgentGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		var postData map[string]interface{}
		if err := c.ShouldBindJSON(&postData); err != nil {
			routercommon.JsonResponse(c, nil, err)
			return
		}
		groupLcuuid := c.Param("group-lcuuid")
		data, err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).CreateAgentGroupConfig(groupLcuuid, postData)
		routercommon.JsonResponse(c, data, err)
	}
}

func updateAgentGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		var postData map[string]interface{}
		if err := c.ShouldBindJSON(&postData); err != nil {
			routercommon.JsonResponse(c, nil, err)
			return
		}
		groupLcuuid := c.Param("group-lcuuid")
		data, err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).UpdateAgentGroupConfig(groupLcuuid, postData)
		routercommon.JsonResponse(c, data, err)
	}
}

func deleteAgentGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		groupLcuuid := c.Param("group-lcuuid")
		err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).DeleteAgentGroupConfig(groupLcuuid)
		routercommon.JsonResponse(c, nil, err)
	}
}
