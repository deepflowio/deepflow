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
	"bytes"
	"errors"
	"strconv"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"

	agentconf "github.com/deepflowio/deepflow/server/agent_config"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
)

var (
	DataTypeYAML = 1
	DataTypeJSON = 2
)

type AgentGroupConfig struct {
	cfg *config.ControllerConfig

	resourceAccess *ResourceAccess // FIXME 实际没有使用此数据做权限控制，重构 UserInfo 传递方式

	dataType int
}

func NewAgentGroupConfig(userInfo *httpcommon.UserInfo, cfg *config.ControllerConfig) *AgentGroupConfig {
	return &AgentGroupConfig{
		cfg:            cfg,
		resourceAccess: &ResourceAccess{Fpermit: cfg.FPermit, UserInfo: userInfo},
	}
}

func (a *AgentGroupConfig) GetAgentGroupConfigTemplateJson() ([]byte, error) {
	dbInfo, err := mysql.GetDB(a.resourceAccess.UserInfo.ORGID)
	if err != nil {
		return nil, err
	}
	var tapTypes []model.TapType
	if err := dbInfo.Select("id", "name").Find(&tapTypes).Error; err != nil {
		return nil, err
	}
	tapTypInfos := make([]map[string]interface{}, len(tapTypes))
	for i, tapType := range tapTypes {
		tapTypInfos[i] = map[string]interface{}{
			strconv.Itoa(tapType.ID): map[string]interface{}{
				"ch": tapType.Name,
				"en": tapType.Name,
			},
		}
	}
	tapTypeInfosYamlBytes, err := yaml.Marshal(tapTypInfos)
	if err != nil {
		return nil, err
	}
	var tapTypeInfosNode yaml.Node
	if err := yaml.Unmarshal(tapTypeInfosYamlBytes, &tapTypeInfosNode); err != nil {
		return nil, err
	}
	var plugins []model.Plugin
	if err := dbInfo.Select("type", "id", "name").Find(&plugins).Error; err != nil {
		return nil, err
	}
	wasmPluginInfos := make([]map[string]interface{}, 0)
	soPluginInfos := make([]map[string]interface{}, 0)
	for _, plugin := range plugins {
		if plugin.Type == 1 {
			wasmPluginInfos = append(wasmPluginInfos, map[string]interface{}{
				strconv.Itoa(plugin.ID): map[string]interface{}{
					"ch": plugin.Name,
					"en": plugin.Name,
				},
			})
		} else if plugin.Type == 2 {
			soPluginInfos = append(soPluginInfos, map[string]interface{}{
				strconv.Itoa(plugin.ID): map[string]interface{}{
					"ch": plugin.Name,
					"en": plugin.Name,
				},
			})
		}
	}
	wasmPluginInfosYamlBytes, err := yaml.Marshal(wasmPluginInfos)
	if err != nil {
		return nil, err
	}
	soPluginInfosYamlBytes, err := yaml.Marshal(soPluginInfos)
	if err != nil {
		return nil, err
	}
	var wasmPluginInfosNode yaml.Node
	if err := yaml.Unmarshal(wasmPluginInfosYamlBytes, &wasmPluginInfosNode); err != nil {
		return nil, err
	}
	var soPluginInfosNode yaml.Node
	if err := yaml.Unmarshal(soPluginInfosYamlBytes, &soPluginInfosNode); err != nil {
		return nil, err
	}
	var domains []model.Domain
	if err := dbInfo.Select("id", "name").Find(&domains).Error; err != nil {
		return nil, err
	}
	domainInfos := make([]map[string]interface{}, len(domains))
	for i, domain := range domains {
		domainInfos[i] = map[string]interface{}{
			strconv.Itoa(domain.ID): map[string]interface{}{
				"ch": domain.Name,
				"en": domain.Name,
			},
		}
	}
	domainKeyToInfoYamlBytes, err := yaml.Marshal(domainInfos)
	if err != nil {
		return nil, err
	}
	var domainKeyToInfoNode yaml.Node
	if err := yaml.Unmarshal(domainKeyToInfoYamlBytes, &domainKeyToInfoNode); err != nil {
		return nil, err
	}
	// TODO get from ck
	l7Protocols := []string{
		"HTTP", "HTTP2", "Dubbo", "gRPC", "SOFARPC", "FastCGI", "bRPC", "Tars", "Some/IP", "MySQL", "PostgreSQL",
		"Oracle", "Redis", "MongoDB", "Kafka", "MQTT", "AMQP", "OpenWire", "NATS", "Pulsar", "ZMTP", "DNS", "TLS", "Custom"}
	l7ProtocolsYamlBytes, err := yaml.Marshal(l7Protocols)
	if err != nil {
		return nil, err
	}
	var l7ProtocolsNode yaml.Node
	if err := yaml.Unmarshal(l7ProtocolsYamlBytes, &l7ProtocolsNode); err != nil {
		return nil, err
	}
	dynamicOptions := agentconf.DynamicOptions{
		"inputs.cbpf.physical_mirror.default_capture_network_type_comment.enum_options":                tapTypeInfosNode.Content[0],
		"outputs.flow_log.filters.l4_capture_network_types_comment.enum_options":                       tapTypeInfosNode.Content[0],
		"outputs.flow_log.filters.l7_capture_network_types_comment.enum_options":                       tapTypeInfosNode.Content[0],
		"inputs.resources.pull_resource_from_controller.domain_filter_comment.enum_options":            domainKeyToInfoNode.Content[0],
		"plugins.wasm_plugins_comment.enum_options":                                                    wasmPluginInfosNode.Content[0],
		"plugins.so_plugins_comment.enum_options":                                                      soPluginInfosNode.Content[0],
		"inputs.ebpf.socket.preprocess.out_of_order_reassembly_protocols_comment.enum_options":         l7ProtocolsNode.Content[0],
		"inputs.ebpf.socket.preprocess.segmentation_reassembly_protocols_comment.enum_options":         l7ProtocolsNode.Content[0],
		"processors.request_log.application_protocol_inference.enabled_protocols_comment.enum_options": l7ProtocolsNode.Content[0],
		"processors.request_log.filters.port_number_prefilters_comment.enum_options":                   l7ProtocolsNode.Content[0],
		"processors.request_log.filters.tag_filters_comment.enum_options":                              l7ProtocolsNode.Content[0],
	}
	return agentconf.ParseYAMLToJson(agentconf.YamlAgentGroupConfigTemplate, dynamicOptions)
}

func (a *AgentGroupConfig) GetAgentGroupConfig(groupLcuuid string, dataType int) ([]byte, error) {
	dbInfo, err := mysql.GetDB(a.resourceAccess.UserInfo.ORGID)
	if err != nil {
		return nil, err
	}
	var data agentconf.MySQLAgentGroupConfiguration
	if err := dbInfo.Where("agent_group_lcuuid = ?", groupLcuuid).First(&data).Error; err != nil {
		return nil, err
	}

	if dataType == DataTypeJSON {
		if data.Yaml == "" {
			return []byte("{}"), nil
		}
		return agentconf.ParseYAMLToJson([]byte(data.Yaml), nil)
	} else {
		return []byte(data.Yaml), nil
	}
}

func (a *AgentGroupConfig) GetAgentGroupConfigs() ([]byte, error) {
	dbInfo, err := mysql.GetDB(a.resourceAccess.UserInfo.ORGID)
	if err != nil {
		return nil, err
	}
	var data []agentconf.MySQLAgentGroupConfiguration
	if err := dbInfo.Find(&data).Error; err != nil {
		return nil, err
	}
	var jsonArray bytes.Buffer
	jsonArray.WriteByte('{')
	for i, d := range data {
		if i > 0 {
			jsonArray.WriteByte(',')
		}
		var bs []byte
		if d.Yaml == "" {
			bs = []byte("{}")
		} else {
			bs, err = agentconf.ParseYAMLToJson([]byte(d.Yaml), nil)
			if err != nil {
				return nil, err
			}
		}
		jsonArray.WriteString(`"` + d.AgentGroupLcuuid + `":`)
		jsonArray.Write(bs)
	}
	jsonArray.WriteByte('}')
	return jsonArray.Bytes(), nil
}

func (a *AgentGroupConfig) CreateAgentGroupConfig(groupLcuuid string, data map[string]interface{}, dataType int) ([]byte, error) {
	dbInfo, err := mysql.GetDB(a.resourceAccess.UserInfo.ORGID)
	if err != nil {
		return nil, err
	}
	var agentGroup model.VTapGroup
	if err := dbInfo.Where("lcuuid = ?", groupLcuuid).First(&agentGroup).Error; err != nil {
		return nil, err
	}

	var strYaml string
	if dataType == DataTypeJSON {
		yamlData, err := agentconf.ParseJsonToYAMLAndValidate(data)
		if err != nil {
			return nil, err
		}
		strYaml = string(yamlData)
	} else {
		strYaml = data["data"].(string)
	}

	var agentGroupConfig agentconf.MySQLAgentGroupConfiguration
	if err := dbInfo.Where("agent_group_lcuuid = ?", groupLcuuid).First(&agentGroupConfig).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			newConfig := &agentconf.MySQLAgentGroupConfiguration{
				Lcuuid:           uuid.New().String(),
				AgentGroupLcuuid: groupLcuuid,
				Yaml:             strYaml,
			}
			if err := dbInfo.Create(newConfig).Error; err != nil {
				return nil, err
			}

			return a.GetAgentGroupConfig(groupLcuuid, dataType)
		}
		return nil, err
	}

	// TODO(weiqiang): duplicate and verify
	agentGroupConfig.Yaml = strYaml
	if err := dbInfo.Save(&agentGroupConfig).Error; err != nil {
		return nil, err
	}
	return a.GetAgentGroupConfig(groupLcuuid, dataType)
}

func (a *AgentGroupConfig) UpdateAgentGroupConfig(groupLcuuid string, data map[string]interface{}, dataType int) ([]byte, error) {
	dbInfo, err := mysql.GetDB(a.resourceAccess.UserInfo.ORGID)
	if err != nil {
		return nil, err
	}
	var agentGroup model.VTapGroup
	if err := dbInfo.Where("lcuuid = ?", groupLcuuid).First(&agentGroup).Error; err != nil {
		return nil, err
	}

	var strYaml string
	if dataType == DataTypeJSON {
		yamlData, err := agentconf.ParseJsonToYAMLAndValidate(data)
		if err != nil {
			return nil, err
		}
		strYaml = string(yamlData)
	} else {
		strYaml = data["data"].(string)
	}

	var agentGroupConfig agentconf.MySQLAgentGroupConfiguration
	if err := dbInfo.Where("agent_group_lcuuid = ?", groupLcuuid).First(&agentGroupConfig).Error; err != nil {
		return nil, err
	}
	agentGroupConfig.Yaml = strYaml
	if err := dbInfo.Save(&agentGroupConfig).Error; err != nil {
		return nil, err
	}
	return a.GetAgentGroupConfig(groupLcuuid, dataType)
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

	return dbInfo.Where("agent_group_lcuuid = ?", groupLcuuid).Delete(&agentconf.MySQLAgentGroupConfiguration{}).Error
}
