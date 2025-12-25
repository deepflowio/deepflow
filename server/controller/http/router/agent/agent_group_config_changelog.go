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
	"fmt"

	"github.com/gin-gonic/gin"

	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	routercommon "github.com/deepflowio/deepflow/server/controller/http/router/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/agent"
)

type AgentGroupConfigChangelog struct {
	cfg *config.ControllerConfig
}

func NewAgentGroupConfigChangelog(cfg *config.ControllerConfig) *AgentGroupConfigChangelog {
	return &AgentGroupConfigChangelog{
		cfg: cfg,
	}
}

func (cgc *AgentGroupConfigChangelog) RegisterTo(e *gin.Engine) {
	e.GET("/v1/agent-group-configurations/:config-lcuuid/changelogs", cgc.get)
	e.POST("/v1/agent-group-configurations/:config-lcuuid/changelogs", cgc.post)
	e.PATCH("/v1/agent-group-configurations/:config-lcuuid/changelogs/:changelog-lcuuid", cgc.patch)
}

// Get 获取采集器配置变更记录
// @Summary 获取采集器配置变更记录
// @Tags AgentGroupConfigChangelog
// @Accept json
// @Produce json
// @Param X-User-Id header string true "用户 ID"
// @Param X-User-Type header string true "用户类型"
// @Param X-Org-Id header string true "组织 ID"
// @Param config-lcuuid path string true "采集器组 LCUUID"
// @Param query query model.AgentGroupConfigChangelogQuery true "参数"
// @Success 200 {object} model.AgentGroupConfigChangelogTrendResponse "获取成功"
// @Failure 400 {object} response.Response "请求参数错误"
// @Failure 403 "权限不足"
// @Failure 404 "页面不存在"
// @Failure 500 "服务器内部错误"
// @Router /v1/agent-group-configurations/{config-lcuuid}/changelogs [get]
func (cgc *AgentGroupConfigChangelog) get(c *gin.Context) {
	header := routercommon.NewHeaderValidator(c.Request.Header, cgc.cfg.FPermit)
	query := routercommon.NewQueryValidator[model.AgentGroupConfigChangelogQuery](c.Request.URL.Query())
	if err := routercommon.NewValidators(header, query).Validate(); err != nil {
		response.JSON(c, response.SetOptStatus(common.INVALID_PARAMETERS), response.SetError(err))
	}
	service := agent.NewAgentGroupConfigChangelogService(header.GetUserInfo(), cgc.cfg.FPermit)
	if service == nil {
		response.JSON(c, response.SetOptStatus(common.SERVER_ERROR), response.SetError(fmt.Errorf("failed to create agent group config changelog service")))
		return
	}
	configLcuuid := c.Param("config-lcuuid")
	data, err := service.Get(configLcuuid, query.GetStructData())
	if err != nil {
		response.JSON(c, response.SetOptStatus(common.SERVER_ERROR), response.SetError(err))
		return
	}
	response.JSON(c, response.SetOptStatus(common.SUCCESS), response.SetData(data))
}

// Create 创建采集器配置变更记录
// @Summary 创建采集器配置变更记录
// @Tags AgentGroupConfigChangelog
// @Accept json
// @Produce json
// @Param X-User-Id header string true "用户 ID"
// @Param X-User-Type header string true "用户类型"
// @Param X-Org-Id header string true "组织 ID"
// @Param config-lcuuid path string true "采集器组配置 LCUUID"
// @Param payload body model.AgentGroupConfigChangelogCreate true "参数"
// @Success 200 {object} model.AgentGroupConfigChangelogResponse "创建成功"
// @Failure 400 {object} response.Response "请求参数错误"
// @Failure 403 "权限不足"
// @Failure 404 "页面不存在"
// @Failure 500 "服务器内部错误"
// @Router /v1/agent-group-configurations/{config-lcuuid}/changelogs [post]
func (cgc *AgentGroupConfigChangelog) post(c *gin.Context) {
	header := routercommon.NewHeaderValidator(c.Request.Header, cgc.cfg.FPermit)
	if err := routercommon.NewValidators(header).Validate(); err != nil {
		response.JSON(c, response.SetOptStatus(common.INVALID_PARAMETERS), response.SetError(err))
	}
	service := agent.NewAgentGroupConfigChangelogService(header.GetUserInfo(), cgc.cfg.FPermit)
	if service == nil {
		response.JSON(c, response.SetOptStatus(common.SERVER_ERROR), response.SetError(fmt.Errorf("failed to create agent group config changelog service")))
		return
	}
	var payload model.AgentGroupConfigChangelogCreate
	if err := c.BindJSON(&payload); err != nil {
		response.JSON(c, response.SetOptStatus(common.INVALID_PARAMETERS), response.SetError(err))
		return
	}
	configLcuuid := c.Param("config-lcuuid")
	data, err := service.Create(configLcuuid, &payload)
	if err != nil {
		response.JSON(c, response.SetOptStatus(common.SERVER_ERROR), response.SetError(err))
		return
	}
	response.JSON(c, response.SetOptStatus(common.SUCCESS), response.SetData(data))
}

// Update 更新采集器配置变更记录
// @Summary 更新采集器配置变更记录
// @Tags AgentGroupConfigChangelog
// @Accept json
// @Produce json
// @Param X-User-Id header string true "用户 ID"
// @Param X-User-Type header string true "用户类型"
// @Param X-Org-Id header string true "组织 ID"
// @Param config-lcuuid path string true "采集器组配置 LCUUID"
// @Param changelog-lcuuid path string true "采集器配置变更记录 LCUUID"
// @Param payload body model.AgentGroupConfigChangelogUpdate true "参数"
// @Success 200 {object} model.AgentGroupConfigChangelogResponse "更新成功"
// @Failure 400 {object} response.Response "请求参数错误"
// @Failure 403 "权限不足"
// @Failure 404 "页面不存在"
// @Failure 500 "服务器内部错误"
// @Router /v1/agent-group-configurations/{config-lcuuid}/changelogs/{changelog-lcuuid} [patch]
func (cgc *AgentGroupConfigChangelog) patch(c *gin.Context) {
	header := routercommon.NewHeaderValidator(c.Request.Header, cgc.cfg.FPermit)
	if err := routercommon.NewValidators(header).Validate(); err != nil {
		response.JSON(c, response.SetOptStatus(common.INVALID_PARAMETERS), response.SetError(err))
		return
	}
	service := agent.NewAgentGroupConfigChangelogService(header.GetUserInfo(), cgc.cfg.FPermit)
	if service == nil {
		response.JSON(c, response.SetOptStatus(common.SERVER_ERROR), response.SetError(fmt.Errorf("failed to create agent group config changelog service")))
		return
	}
	var payload model.AgentGroupConfigChangelogUpdate
	if err := c.BindJSON(&payload); err != nil {
		response.JSON(c, response.SetOptStatus(common.INVALID_PARAMETERS), response.SetError(err))
		return
	}
	changelogLcuuid := c.Param("changelog-lcuuid")
	data, err := service.Update(changelogLcuuid, &payload)
	if err != nil {
		response.JSON(c, response.SetOptStatus(common.SERVER_ERROR), response.SetError(err))
		return
	}
	response.JSON(c, response.SetOptStatus(common.SUCCESS), response.SetData(data))
}
