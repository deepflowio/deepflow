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

package agent

import (
	"io"

	"github.com/gin-gonic/gin"

	"github.com/deepflowio/deepflow/server/agent_config"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	routercommon "github.com/deepflowio/deepflow/server/controller/http/router/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/agent"
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

	e.GET("/v1/agent-group-configurations", getAgentGroupConfigs(cgc.cfg))
}

func getYAMLAgentGroupConfigTmpl(c *gin.Context) {
	agent_group_config := agent_config.YamlSubTemplateRegex.ReplaceAllStringFunc(string(agent_config.YamlAgentGroupConfigTemplate), agent_config.ReplaceTemplateSyntax(false))
	response.JSON(c, response.SetData(string(agent_group_config)))
}

func getJsonAgentGroupConfigTmpl(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		data, err := agent.NewAgentGroupConfig(common.GetUserInfo(c), cfg).GetAgentGroupConfigTemplateJson()
		response.JSON(c, response.SetData(data), response.SetError(err))
	}
}

func getJsonAgentGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		groupLcuuid := c.Param("group-lcuuid")
		data, err := agent.NewAgentGroupConfig(common.GetUserInfo(c), cfg).GetAgentGroupConfig(groupLcuuid, agent.DataTypeJSON)
		response.JSON(c, response.SetData(data), response.SetError(err))
	}
}

func getJsonAgentGroupConfigs(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		data, err := agent.NewAgentGroupConfig(common.GetUserInfo(c), cfg).GetAgentGroupConfigs(agent.DataTypeJSON)
		response.JSON(c, response.SetData(data.([]byte)), response.SetError(err)) // TODO 不需要转换类型
	}
}

func postJsonAgentGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		var postData map[string]interface{}
		if err := c.ShouldBindJSON(&postData); err != nil {
			response.JSON(c, response.SetError(err))
			return
		}
		groupLcuuid := c.Param("group-lcuuid")
		data, err := agent.NewAgentGroupConfig(common.GetUserInfo(c), cfg).CreateAgentGroupConfig(groupLcuuid, postData, agent.DataTypeJSON)
		response.JSON(c, response.SetData(data), response.SetError(err))
	}
}

func putJsonAgentGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		var postData map[string]interface{}
		if err := c.ShouldBindJSON(&postData); err != nil {
			response.JSON(c, response.SetError(err))
			return
		}
		groupLcuuid := c.Param("group-lcuuid")
		data, err := agent.NewAgentGroupConfig(common.GetUserInfo(c), cfg).UpdateAgentGroupConfig(groupLcuuid, postData, agent.DataTypeJSON)
		response.JSON(c, response.SetData(data), response.SetError(err))
	}
}

func getYAMLAgentGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		groupLcuuid := c.Param("group-lcuuid")
		data, err := agent.NewAgentGroupConfig(common.GetUserInfo(c), cfg).GetAgentGroupConfig(groupLcuuid, agent.DataTypeYAML)
		response.JSON(c, response.SetData(string(data)), response.SetError(err)) // TODO 不需要转换类型
	}
}

func postYAMLAgentGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		bytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			response.JSON(c, response.SetError(err))
			return
		}
		groupLcuuid := c.Param("group-lcuuid")
		data, err := agent.NewAgentGroupConfig(common.GetUserInfo(c), cfg).CreateAgentGroupConfig(groupLcuuid, bytes, agent.DataTypeYAML)
		response.JSON(c, response.SetData(string(data)), response.SetError(err)) // TODO 不需要转换类型
	}
}

func putYAMLAgentGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		bytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			response.JSON(c, response.SetError(err))
			return
		}
		groupLcuuid := c.Param("group-lcuuid")
		data, err := agent.NewAgentGroupConfig(common.GetUserInfo(c), cfg).UpdateAgentGroupConfig(groupLcuuid, bytes, agent.DataTypeYAML)
		response.JSON(c, response.SetData(string(data)), response.SetError(err)) // TODO 不需要转换类型
	}
}

func deleteAgentGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		groupLcuuid := c.Param("group-lcuuid")
		err := agent.NewAgentGroupConfig(common.GetUserInfo(c), cfg).DeleteAgentGroupConfig(groupLcuuid)
		response.JSON(c, response.SetError(err))
	}
}

// Get 获取采集器配置变更记录
// @Summary 获取采集器配置变更记录
// @Tags AgentGroupConfig
// @Accept json
// @Produce json
// @Param X-User-Id header string true "用户 ID"
// @Param X-User-Type header string true "用户类型"
// @Param X-Org-Id header string true "组织 ID"
// @Param query query model.AgentGroupConfigQuery true "参数"
// @Success 200 {object} model.AgentGroupConfigResponse "获取成功"
// @Failure 400 {object} response.Response "请求参数错误"
// @Failure 403 "权限不足"
// @Failure 404 "页面不存在"
// @Failure 500 "服务器内部错误"
// @Router /v1/agent-group-configurations [get]
func getAgentGroupConfigs(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := routercommon.NewHeaderValidator(c.Request.Header, cfg.FPermit)
		query := routercommon.NewQueryValidator[model.AgentGroupConfigQuery](c.Request.URL.Query())
		if err := routercommon.NewValidators(header, query).Validate(); err != nil {
			response.JSON(c, response.SetOptStatus(common.INVALID_PARAMETERS), response.SetError(err))
		} else {
			data, err := agent.NewAgentGroupConfig(common.GetUserInfo(c), cfg).Get(query.GetStructData())
			response.JSON(c, response.SetData(data), response.SetError(err))
		}
	}
}
