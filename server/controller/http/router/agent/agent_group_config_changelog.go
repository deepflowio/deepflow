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
	e.GET("/v1/agent-group-configurations/:config-lcuuid/changelogs", getChangelogs(cgc.cfg))
	e.POST("/v1/agent-group-configurations/:config-lcuuid/changelogs", postJsonAgentGroupConfig(cgc.cfg))
	e.PATCH("/v1/agent-group-configurations/:config-lcuuid/changelogs/:changelog-lcuuid", patchJsonAgentGroupConfig(cgc.cfg))
}

func getJsonAgentGroupConfig(cfg *config.ControllerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		groupLcuuid := c.Param("group-lcuuid")
		data, err := agent.NewAgentGroupConfig(common.GetUserInfo(c), cfg).GetAgentGroupConfig(groupLcuuid, agent.DataTypeJSON)
		response.JSON(c, response.SetData(data), response.SetError(err))
	}
}
