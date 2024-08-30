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

package service

import (
	agentconf "github.com/deepflowio/deepflow/server/agent_config"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/google/uuid"
)

type AgentGroupConfig struct {
	cfg *config.ControllerConfig

	resourceAccess *ResourceAccess
}

func NewAgentGroupConfig(userInfo *httpcommon.UserInfo, cfg *config.ControllerConfig) *AgentGroupConfig {
	return &AgentGroupConfig{
		cfg:            cfg,
		resourceAccess: &ResourceAccess{Fpermit: cfg.FPermit, UserInfo: userInfo},
	}
}

func (a *AgentGroupConfig) GetAgentGroupConfigTemplateJson(filter map[string]interface{}) ([]byte, error) {
	return agentconf.ParseTemplateYAMLToJson(agentconf.YamlAgentGroupConfig)
}

func (a *AgentGroupConfig) GetAgentGroupConfigValue(lcuuid string) ([]byte, error) {
	return nil, nil
}

func (a *AgentGroupConfig) CreateAgentGroupConfig(data map[string]interface{}) ([]byte, error) {
	dbInfo, err := mysql.GetDB(a.resourceAccess.UserInfo.ORGID)
	if err != nil {
		return nil, err
	}
	// TODO(weiqiang): validate data, convert data to yaml
	lcuuid := uuid.New().String()
	yamlData := agentconf.AgentGroupConfigYaml{
		Lcuuid: lcuuid,
		// TODO(weiqiang): add yaml data
		Yaml: "",
	}
	if err := dbInfo.Create(&yamlData).Error; err != nil {
		return nil, err
	}

	return a.GetAgentGroupConfigValue(lcuuid)
}
