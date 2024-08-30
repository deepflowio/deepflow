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
	. "github.com/deepflowio/deepflow/server/controller/http/router/common"
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
	e.GET("/v1/agent-group-configuration/value/:lcuuid/", getAgentGroupConfigValue(cgc.cfg))

}

func getAgentGroupConfigTemplate(c *gin.Context) {
	JsonResponse(c, string(agent_config.YamlAgentGroupConfigTemplate), nil)
}

func getAgentGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		args := make(map[string]interface{})
		if value, ok := c.GetQuery("agent_group_id"); ok {
			args["agent_group_id"] = value
		}
		data, err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).GetAgentGroupConfigTemplateJson(args)
		JsonResponse(c, data, err)
	}
}

func getAgentGroupConfigValue(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {

		lcuuid := c.Param("lcuuid")
		data, err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).GetAgentGroupConfigValue(lcuuid)
		JsonResponse(c, data, err)
	}
}

func createAgentGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		var data map[string]interface{}
		if err := c.ShouldBindJSON(&data); err != nil {
			JsonResponse(c, nil, err)
			return
		}
		// TODO(weiqiang): create
		JsonResponse(c, data, nil)
	}
}
