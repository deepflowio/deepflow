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
	"errors"

	"gorm.io/gorm"

	agentconf "github.com/deepflowio/deepflow/server/agent_config"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/model"
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
	return agentconf.ParseYAMLToJson(agentconf.YamlAgentGroupConfigTemplate)
}

func (a *AgentGroupConfig) GetAgentGroupConfigValue(groupLcuuid string) ([]byte, error) {
	dbInfo, err := mysql.GetDB(a.resourceAccess.UserInfo.ORGID)
	if err != nil {
		return nil, err
	}
	var data agentconf.AgentGroupConfigYaml
	if err := dbInfo.Where("agent_group_lcuuid = ?", groupLcuuid).First(&data).Error; err != nil {
		return nil, err
	}

	return agentconf.ParseYAMLToJson([]byte(data.Yaml))
}

func (a *AgentGroupConfig) CreateAgentGroupConfig(groupLcuuid string, data map[string]interface{}) ([]byte, error) {
	dbInfo, err := mysql.GetDB(a.resourceAccess.UserInfo.ORGID)
	if err != nil {
		return nil, err
	}
	var agentGroup model.VTapGroup
	if err := dbInfo.Where("lcuuid = ?", groupLcuuid).First(&agentGroup).Error; err != nil {
		return nil, err
	}

	yamlData, err := agentconf.ParseJsonToYAMLAndValidate(data)
	if err != nil {
		return nil, err
	}

	var agentGroupConfig agentconf.AgentGroupConfigYaml
	if err := dbInfo.Where("agent_group_lcuuid = ?", groupLcuuid).First(&agentGroupConfig).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			newConfig := &agentconf.AgentGroupConfigYaml{
				Lcuuid:           uuid.New().String(),
				AgentGroupLcuuid: groupLcuuid,
				Yaml:             string(yamlData),
			}
			if err := dbInfo.Create(newConfig).Error; err != nil {
				return nil, err
			}

			return a.GetAgentGroupConfigValue(groupLcuuid)
		}
		return nil, err
	}

	// TODO(weiqiang): duplicate and verify
	agentGroupConfig.Yaml = string(yamlData)
	if err := dbInfo.Save(&agentGroupConfig).Error; err != nil {
		return nil, err
	}
	return a.GetAgentGroupConfigValue(groupLcuuid)
}

func (a *AgentGroupConfig) UpdateAgentGroupConfig(groupLcuuid string, data map[string]interface{}) ([]byte, error) {
	dbInfo, err := mysql.GetDB(a.resourceAccess.UserInfo.ORGID)
	if err != nil {
		return nil, err
	}
	var agentGroup model.VTapGroup
	if err := dbInfo.Where("lcuuid = ?", groupLcuuid).First(&agentGroup).Error; err != nil {
		return nil, err
	}

	yamlData, err := agentconf.ParseJsonToYAMLAndValidate(data)
	if err != nil {
		return nil, err
	}

	var agentGroupConfig agentconf.AgentGroupConfigYaml
	if err := dbInfo.Where("agent_group_lcuuid = ?", groupLcuuid).First(&agentGroupConfig).Error; err != nil {
		return nil, err
	}
	agentGroupConfig.Yaml = string(yamlData)
	if err := dbInfo.Save(&agentGroupConfig).Error; err != nil {
		return nil, err
	}
	return a.GetAgentGroupConfigValue(groupLcuuid)
}

func (a *AgentGroupConfig) DeleteAgentGroupConfig(groupLcuuid string) error {
	dbInfo, err := mysql.GetDB(a.resourceAccess.UserInfo.ORGID)
	if err != nil {
		return err
	}

	var agentGroup model.VTapGroup
	if err := dbInfo.Where("lcuuid = ?", groupLcuuid).First(&agentGroup).Error; err != nil {
		return err
	}

	return dbInfo.Where("agent_group_lcuuid = ?", groupLcuuid).Delete(&agentconf.AgentGroupConfigYaml{}).Error
}
