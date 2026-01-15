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
	protocolPolicyMutex      sync.RWMutex
	dictionaryMutex          sync.RWMutex
	policyMutex              sync.RWMutex
	teamIDToProtocolPolicies map[int][]string
	teamIDToDictionaries     map[int][]string
	agentGroupIDToPolicies   map[int][]metadbmodel.BizDecodePolicy
	metaData                 *MetaData
}

func newCustomAppConfig(orgID int, metaData *MetaData) *CustomAppConfig {
	config := CustomAppConfig{
		orgID:                    orgID,
		teamIDToProtocolPolicies: map[int][]string{},
		teamIDToDictionaries:     map[int][]string{},
		agentGroupIDToPolicies:   map[int][]metadbmodel.BizDecodePolicy{},
		metaData:                 metaData,
	}
	config.version.Store(uint64(time.Now().Unix()))
	return &config
}

func (c *CustomAppConfig) generateCache() {
	var changeVersion atomic.Bool
	var wg sync.WaitGroup
	wg.Add(3)

	metaDataCache := c.metaData.GetDBDataCache()

	go func() {
		defer wg.Done()

		// protocol policy
		var change bool
		bizDecodeCustomProtocol := metaDataCache.GetBizBizDecodeCustomProtocol()
		protocolPolicies := map[int][]string{}
		for _, p := range bizDecodeCustomProtocol {
			protocolPolicies[p.TeamID] = append(protocolPolicies[p.TeamID], p.Yaml)
		}
		change = len(protocolPolicies) != len(c.teamIDToProtocolPolicies)

		if !change {
			c.protocolPolicyMutex.RLock()
			for k, v := range c.teamIDToProtocolPolicies {
				value, ok := protocolPolicies[k]
				if !ok {
					change = true
					break
				} else {
					if !slices.Equal(value, v) {
						change = true
						break
					}
				}
			}
			c.protocolPolicyMutex.RUnlock()
		}

		if !change {
			return
		}

		changeVersion.Store(true)
		c.protocolPolicyMutex.Lock()
		c.teamIDToProtocolPolicies = protocolPolicies
		c.protocolPolicyMutex.Unlock()
	}()

	go func() {
		defer wg.Done()

		// dictionary
		var change bool
		bizDecodeDictionaries := metaDataCache.GetBizDecodeDictionaries()
		dictionaries := map[int][]string{}
		for _, d := range bizDecodeDictionaries {
			dictionaries[d.TeamID] = append(dictionaries[d.TeamID], d.Yaml)
		}
		change = len(dictionaries) != len(c.teamIDToDictionaries)

		if !change {
			c.dictionaryMutex.RLock()
			for k, v := range c.teamIDToDictionaries {
				value, ok := dictionaries[k]
				if !ok {
					change = true
					break
				} else {
					if !slices.Equal(value, v) {
						change = true
						break
					}
				}
			}
			c.dictionaryMutex.RUnlock()
		}

		if !change {
			return
		}

		changeVersion.Store(true)
		c.dictionaryMutex.Lock()
		c.teamIDToDictionaries = dictionaries
		c.dictionaryMutex.Unlock()
	}()

	go func() {
		defer wg.Done()

		// policy
		var change bool
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
		change = len(policies) != len(c.agentGroupIDToPolicies)

		if !change {
			c.policyMutex.RLock()
			for k, v := range c.agentGroupIDToPolicies {
				value, ok := policies[k]
				if !ok {
					change = true
					break
				} else {
					if !slices.Equal(value, v) {
						change = true
						break
					}
				}
			}
			c.policyMutex.RUnlock()
		}

		if !change {
			return
		}

		changeVersion.Store(true)
		c.policyMutex.Lock()
		c.agentGroupIDToPolicies = policies
		c.policyMutex.Unlock()
	}()

	wg.Wait()

	if changeVersion.Load() {
		c.version.Add(1)
	}
}

func (c *CustomAppConfig) GetVersion() uint64 {
	return c.version.Load()
}

func (c *CustomAppConfig) GetCustomAppConfigByte(teamID, agentGroupID int) []byte {
	k := koanf.New(".")

	// protocol policy
	c.protocolPolicyMutex.RLock()
	protocolPolicies, ok := c.teamIDToProtocolPolicies[teamID]
	c.protocolPolicyMutex.RUnlock()
	if ok {
		protocolPolicyYamls := []map[string]interface{}{}
		for _, p := range protocolPolicies {
			protocolPolicyYaml := koanf.New(".")
			err := protocolPolicyYaml.Load(rawbytes.Provider([]byte(p)), kyaml.Parser())
			if err != nil {
				errMessage := fmt.Sprintf("load protocol policy yaml (%s) failed: %s", p, err.Error())
				log.Error(errMessage, logger.NewORGPrefix(c.orgID))
				return []byte("# " + errMessage)
			}
			protocolPolicyYamls = append(protocolPolicyYamls, protocolPolicyYaml.Raw())
		}
		err := k.Set(common.CONFIG_KEY_BIZ_PROTOCOL_POLICIES, protocolPolicyYamls)
		if err != nil {
			errMessage := fmt.Sprintf("set protocol policy yamls failed: %s", err.Error())
			log.Error(errMessage, logger.NewORGPrefix(c.orgID))
			return []byte("# " + errMessage)
		}
	}

	// dictionary
	c.dictionaryMutex.RLock()
	dictionaries, ok := c.teamIDToDictionaries[teamID]
	c.dictionaryMutex.RUnlock()
	if ok {
		dictYamls := []map[string]interface{}{}
		for _, d := range dictionaries {
			dictYaml := koanf.New(".")
			err := dictYaml.Load(rawbytes.Provider([]byte(d)), kyaml.Parser())
			if err != nil {
				errMessage := fmt.Sprintf("load dictionary yaml (%s) failed: %s", d, err.Error())
				log.Error(errMessage, logger.NewORGPrefix(c.orgID))
				return []byte("# " + errMessage)
			}
			dictYamls = append(dictYamls, dictYaml.Raw())
		}
		err := k.Set(common.CONFIG_KEY_BIZ_FIELD_DICTIONARIES, dictYamls)
		if err != nil {
			errMessage := fmt.Sprintf("set dictionary yamls failed: %s", err.Error())
			log.Error(errMessage, logger.NewORGPrefix(c.orgID))
			return []byte("# " + errMessage)
		}
	}

	// policy
	c.policyMutex.RLock()
	policies, ok := c.agentGroupIDToPolicies[agentGroupID]
	c.policyMutex.RUnlock()
	if ok {
		policyYamls := []map[string]interface{}{}
		for _, p := range policies {
			policyYaml := koanf.New(".")
			err := policyYaml.Load(rawbytes.Provider([]byte(p.Yaml)), kyaml.Parser())
			if err != nil {
				errMessage := fmt.Sprintf("load policy (%s) yaml failed: %s", p.Name, err.Error())
				log.Error(errMessage, logger.NewORGPrefix(c.orgID))
				return []byte("# " + errMessage)
			}
			policyYamls = append(policyYamls, policyYaml.Raw())
		}
		err := k.Set(common.CONFIG_KEY_BIZ_FIELD_POLICIES, policyYamls)
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
