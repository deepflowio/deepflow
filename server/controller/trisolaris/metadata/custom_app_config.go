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

package metadata

import (
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	kyaml "github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/knadh/koanf/v2"

	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

type CustomAppConfig struct {
	orgID                    int
	version                  atomic.Uint64
	teamIDToProtocolPolicies sync.Map
	teamIDToDictionaries     sync.Map
	agentGroupIDToPolicies   sync.Map
	metaData                 *MetaData
}

func newCustomAppConfig(orgID int, metaData *MetaData) *CustomAppConfig {
	config := CustomAppConfig{
		orgID:                    orgID,
		teamIDToProtocolPolicies: sync.Map{},
		teamIDToDictionaries:     sync.Map{},
		agentGroupIDToPolicies:   sync.Map{},
		metaData:                 metaData,
	}
	config.version.Store(uint64(time.Now().Unix()))
	return &config
}

func (c *CustomAppConfig) generateCache() {
	var changeVersion bool

	metaDataCache := c.metaData.GetDBDataCache()
	// protocol policy
	bizDecodeCustomProtocol := metaDataCache.GetBizBizDecodeCustomProtocol()
	protocolPolicies := map[int][]string{}
	for _, p := range bizDecodeCustomProtocol {
		protocolPolicies[p.TeamID] = append(protocolPolicies[p.TeamID], p.Yaml)
	}
	for k, v := range protocolPolicies {
		if !changeVersion {
			value, ok := c.teamIDToProtocolPolicies.Load(k)
			if !ok {
				changeVersion = true
			} else {
				changeVersion = !slices.Equal(value.([]string), v)
			}
		}
		c.teamIDToProtocolPolicies.Store(k, v)
	}

	// dictionary
	bizDecodeDictionaries := metaDataCache.GetBizDecodeDictionaries()
	dictionaries := map[int][]string{}
	for _, d := range bizDecodeDictionaries {
		dictionaries[d.TeamID] = append(dictionaries[d.TeamID], d.Yaml)
	}
	for k, v := range dictionaries {
		if !changeVersion {
			value, ok := c.teamIDToDictionaries.Load(k)
			if !ok {
				changeVersion = true
			} else {
				changeVersion = !slices.Equal(value.([]string), v)
			}
		}
		c.teamIDToDictionaries.Store(k, v)
	}

	// policy
	bizDecodePolicies := metaDataCache.GetBizDecodePolicies()
	policIDToPolicy := map[int]metadbmodel.BizDecodePolicy{}
	for _, p := range bizDecodePolicies {
		policIDToPolicy[p.ID] = *p
	}
	bizDecodePolicyAgentGroupConnections := metaDataCache.GetBizDecodePolicyAgentGroupConnections()
	policies := map[int][]metadbmodel.BizDecodePolicy{}
	for _, conn := range bizDecodePolicyAgentGroupConnections {
		policy, ok := policIDToPolicy[conn.PolicyID]
		if !ok {
			continue
		}
		policies[conn.AgentGroupID] = append(policies[conn.AgentGroupID], policy)
	}
	for k, v := range policies {
		if !changeVersion {
			value, ok := c.agentGroupIDToPolicies.Load(k)
			if !ok {
				changeVersion = true
			} else {
				changeVersion = !slices.Equal(value.([]metadbmodel.BizDecodePolicy), v)
			}
		}
		c.agentGroupIDToPolicies.Store(k, v)
	}

	if changeVersion {
		c.version.Add(1)
	}
}

func (c *CustomAppConfig) GetVersion() uint64 {
	return c.version.Load()
}

func (c *CustomAppConfig) GetCustomAppConfigByte(teamID, agentGroupID int) []byte {
	k := koanf.New(".")

	// protocol policy
	protocolPolicies, ok := c.teamIDToProtocolPolicies.Load(teamID)
	if ok {
		protocolPolicyYamls := []map[string]interface{}{}
		for _, p := range protocolPolicies.([]string) {
			protocolPolicyYaml := koanf.New(".")
			err := protocolPolicyYaml.Load(rawbytes.Provider([]byte(p)), kyaml.Parser())
			if err != nil {
				errMessage := fmt.Sprintf("load protocol policy yaml (%s) failed: %s", p, err.Error())
				log.Error(errMessage, logger.NewORGPrefix(c.orgID))
				return []byte("# " + errMessage)
			}
			protocolPolicyYamls = append(protocolPolicyYamls, protocolPolicyYaml.Raw())
		}
		err := k.Set(common.CONFIG_KEY_CUSTOM_PROTOCOL_POLICIES, protocolPolicyYamls)
		if err != nil {
			errMessage := fmt.Sprintf("set protocol policy yamls failed: %s", err.Error())
			log.Error(errMessage, logger.NewORGPrefix(c.orgID))
			return []byte("# " + errMessage)
		}
	}

	// dictionary
	dictionaries, ok := c.teamIDToDictionaries.Load(teamID)
	if ok {
		dictYamls := []map[string]interface{}{}
		for _, d := range dictionaries.([]string) {
			dictYaml := koanf.New(".")
			err := dictYaml.Load(rawbytes.Provider([]byte(d)), kyaml.Parser())
			if err != nil {
				errMessage := fmt.Sprintf("load dictionary yaml (%s) failed: %s", d, err.Error())
				log.Error(errMessage, logger.NewORGPrefix(c.orgID))
				return []byte("# " + errMessage)
			}
			dictYamls = append(dictYamls, dictYaml.Raw())
		}
		err := k.Set(common.CONFIG_KEY_CUSTOM_FIELD_DICTIONARIES, dictYamls)
		if err != nil {
			errMessage := fmt.Sprintf("set dictionary yamls failed: %s", err.Error())
			log.Error(errMessage, logger.NewORGPrefix(c.orgID))
			return []byte("# " + errMessage)
		}
	}

	// policy
	policies, ok := c.agentGroupIDToPolicies.Load(agentGroupID)
	if ok {
		policyYamls := []map[string]interface{}{}
		for _, p := range policies.([]metadbmodel.BizDecodePolicy) {
			policyYaml := koanf.New(".")
			err := policyYaml.Load(rawbytes.Provider([]byte(p.Yaml)), kyaml.Parser())
			if err != nil {
				errMessage := fmt.Sprintf("load policy (%s) yaml failed: %s", p.Name, err.Error())
				log.Error(errMessage, logger.NewORGPrefix(c.orgID))
				return []byte("# " + errMessage)
			}
			policyYamls = append(policyYamls, policyYaml.Raw())
		}
		err := k.Set(common.CONFIG_KEY_CUSTOM_FIELD_POLICIES, policyYamls)
		if err != nil {
			errMessage := fmt.Sprintf("set policy yamls failed: %s", err.Error())
			log.Error(errMessage, logger.NewORGPrefix(c.orgID))
			return []byte("# " + errMessage)
		}
	}

	yaml, err := k.Marshal(kyaml.Parser())
	if err != nil {
		errMessage := fmt.Sprintf("marshal custom app config failed: %s", err.Error())
		log.Error(errMessage, logger.NewORGPrefix(c.orgID))
		return []byte(errMessage)
	}
	return yaml
}
