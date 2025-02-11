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
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
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

	e.GET("/v1/agent-group-configuration/yaml", getYAMLAgentGroupConfigs(cgc.cfg))
	e.GET("/v1/agent-group-configuration/:group-lcuuid/yaml", getYAMLAgentGroupConfig(cgc.cfg))
	e.POST("/v1/agent-group-configuration/:group-lcuuid/yaml", postYAMLAgentGroupConfig(cgc.cfg))
	e.PUT("/v1/agent-group-configuration/:group-lcuuid/yaml", putYAMLAgentGroupConfig(cgc.cfg))

	e.DELETE("/v1/agent-group-configuration/:group-lcuuid", deleteAgentGroupConfig(cgc.cfg))

}

func getYAMLAgentGroupConfigTmpl(c *gin.Context) {
	agent_group_config := agent_config.YamlSubTemplateRegex.ReplaceAllStringFunc(string(agent_config.YamlAgentGroupConfigTemplate), agent_config.ReplaceTemplateSyntax(false))
	response.JSON(c, response.SetData(string(agent_group_config)))
}

func getJsonAgentGroupConfigTmpl(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		data, err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).GetAgentGroupConfigTemplateJson()
		response.JSON(c, response.SetData(data), response.SetError(err))
	}
}

func getJsonAgentGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		groupLcuuid := c.Param("group-lcuuid")
		data, err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).GetAgentGroupConfig(groupLcuuid, service.DataTypeJSON)
		response.JSON(c, response.SetData(data), response.SetError(err))
	}
}

func getJsonAgentGroupConfigs(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		data, err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).GetAgentGroupConfigs(service.DataTypeJSON)
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
		data, err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).CreateAgentGroupConfig(groupLcuuid, postData, service.DataTypeJSON)
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
		data, err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).UpdateAgentGroupConfig(groupLcuuid, postData, service.DataTypeJSON)
		response.JSON(c, response.SetData(data), response.SetError(err))
	}
}

func getYAMLAgentGroupConfigs(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		data, err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).GetAgentGroupConfigs(service.DataTypeYAML)
		response.JSON(c, response.SetData(data), response.SetError(err))
	}
}

func getYAMLAgentGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		groupLcuuid := c.Param("group-lcuuid")
		data, err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).GetAgentGroupConfig(groupLcuuid, service.DataTypeYAML)
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
		data, err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).CreateAgentGroupConfig(groupLcuuid, bytes, service.DataTypeYAML)
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
		data, err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).UpdateAgentGroupConfig(groupLcuuid, bytes, service.DataTypeYAML)
		response.JSON(c, response.SetData(string(data)), response.SetError(err)) // TODO 不需要转换类型
	}
}

func deleteAgentGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		groupLcuuid := c.Param("group-lcuuid")
		err := service.NewAgentGroupConfig(common.GetUserInfo(c), cfg).DeleteAgentGroupConfig(groupLcuuid)
		response.JSON(c, response.SetError(err))
	}
}
