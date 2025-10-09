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

package script

import (
	"fmt"

	"gorm.io/gorm"

	agentconf "github.com/deepflowio/deepflow/server/agent_config"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

const SCRIPT_UPGRADE_VTAP_GROUP_CONFIG = "6.6.1.16"

func UpgradeVTapAgentConfig(db *gorm.DB) error {
	log.Infof("execute script (%s)", SCRIPT_UPGRADE_VTAP_GROUP_CONFIG)
	var configs []agentconf.AgentGroupConfigModel
	if err := db.Find(&configs).Error; err != nil {
		return fmt.Errorf("failed to get from vtap_group_configuration: %s", err.Error())
	}
	if len(configs) == 0 {
		log.Infof("no vtap_group_configuration data to upgrade")
		return nil
	}

	var domains []model.Domain
	if err := db.Find(&domains).Error; err != nil {
		return fmt.Errorf("failed to get from domain: %s", err.Error())
	}
	domainLcuuidToID := make(map[string]int)
	for _, domain := range domains {
		domainLcuuidToID[domain.Lcuuid] = domain.ID
	}

	var existedNewConfigs []agentconf.MySQLAgentGroupConfiguration
	if err := db.Find(&existedNewConfigs).Error; err != nil {
		return fmt.Errorf("failed to get from agent_group_configuration: %s", err.Error())
	}
	existedNewConfigInfo := make(map[string]bool)
	for _, existedNewConfig := range existedNewConfigs {
		existedNewConfigInfo[existedNewConfig.AgentGroupLcuuid] = true
	}
	newConfigs := make([]agentconf.MySQLAgentGroupConfiguration, 0)
	for _, config := range configs {
		if config.VTapGroupLcuuid == nil {
			log.Infof("agent_group_configuration (lcuuid: %s) has no vtap_group_lcuuid", *config.Lcuuid)
			continue
		}
		if _, ok := existedNewConfigInfo[*config.VTapGroupLcuuid]; ok {
			log.Infof("agent_group_configuration (agent_group_lcuuid: %s) already exists", *config.VTapGroupLcuuid)
			continue
		}

		if config.YamlConfig != nil {
			log.Infof("upgrade vtap_group_configuration (agent_group_lcuuid: %s): %s", *config.VTapGroupLcuuid, *config.YamlConfig)
		}
		upgradedYaml := " "
		bytes, err := agentconf.Upgrade(&config, &agentconf.DomainData{LcuuidToID: domainLcuuidToID})
		if err != nil {
			return fmt.Errorf("failed to get (agent_group_lcuuid: %s) upgraded yaml: %s", *config.VTapGroupLcuuid, err.Error())
		}
		upgradedYaml = string(bytes)
		log.Infof("(agent_group_lcuuid: %s) upgraded yaml: %s", *config.VTapGroupLcuuid, upgradedYaml)
		newConfig := agentconf.MySQLAgentGroupConfiguration{
			Lcuuid:           *config.Lcuuid,
			AgentGroupLcuuid: *config.VTapGroupLcuuid,
			Yaml:             upgradedYaml,
		}
		newConfigs = append(newConfigs, newConfig)
	}
	if len(newConfigs) == 0 {
		log.Infof("no agent_group_configuration data to insert")
		return nil
	}
	if err := db.Create(&newConfigs).Error; err != nil {
		return fmt.Errorf("failed to insert into agent_group_configuration : %s", err.Error())
	}
	return nil
}
