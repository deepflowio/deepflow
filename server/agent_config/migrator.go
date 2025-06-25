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

package agent_config

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/baidubce/bce-sdk-go/util/log"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"
)

type DomainData struct {
	LcuuidToID map[string]int
	IDToLcuuid map[int]string
}

func Upgrade(lowerVersionDBData *AgentGroupConfigModel, domainData *DomainData) ([]byte, error) {
	lowerVersionYAMLBytes, err := convertDBToYAML(lowerVersionDBData)
	if err != nil {
		return []byte{}, err
	}
	toolData, err := NewMigrationToolData(domainData)
	if err != nil {
		return []byte{}, err
	}
	upgrader := newUpgrader(toolData)
	return upgrader.Upgrade(lowerVersionYAMLBytes)
}

func Downgrade(lowerVersionDBData *AgentGroupConfigModel, higherVersionYAMLBytes []byte, domainData *DomainData) error {
	toolData, err := NewMigrationToolData(domainData)
	if err != nil {
		return fmt.Errorf("failed to init migration tool data: %s", err.Error())
	}
	downgrader := &Downgrader{
		MigrationToolData: toolData,
	}
	lowerVersionYAMLBytes, err := downgrader.Downgrade(higherVersionYAMLBytes)
	if err != nil {
		return fmt.Errorf("failed to downgrade: %s, yaml: %s", err.Error(), string(higherVersionYAMLBytes))
	}
	return convertYAMLToDB(lowerVersionYAMLBytes, lowerVersionDBData)
}

type Upgrader struct {
	dictDataConv

	MigrationToolData

	spacialLowerVersionKeyToValue map[string]interface{}
}

func newUpgrader(toolData MigrationToolData) *Upgrader {
	return &Upgrader{
		MigrationToolData:             toolData,
		spacialLowerVersionKeyToValue: make(map[string]interface{}),
	}
}

func (m *Upgrader) Upgrade(bytes []byte) ([]byte, error) {
	lowerVerData := make(map[string]interface{})
	err := yaml.Unmarshal(bytes, &lowerVerData)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to unmarshal yaml: %v to map", err)
	}
	result := make(map[string]interface{})
	m.lowerToHigher(lowerVerData, "", result)
	m.appendSpecialLowerVersionKeyToValue(result)
	return mapToYaml(result)
}

func (m *Upgrader) appendSpecialLowerVersionKeyToValue(result map[string]interface{}) {
	hasProcessMatcher := false
	if inputs, ok := result["inputs"]; ok {
		if proc, ok := inputs.(map[string]interface{})["proc"]; ok {
			if _, ok := proc.(map[string]interface{})["process_matcher"]; ok {
				hasProcessMatcher = true
				if lowerVal, ok := m.spacialLowerVersionKeyToValue["static_config.ebpf.uprobe-process-name-regexs.golang-symbol"]; ok {
					switch value := proc.(map[string]interface{})["process_matcher"].(type) {
					case []interface{}:
						value = append(value, interface{}(map[string]interface{}{"match_regex": lowerVal}))
						proc.(map[string]interface{})["process_matcher"] = value
					case []map[string]interface{}:
						value = append(value, map[string]interface{}{"match_regex": lowerVal})
						proc.(map[string]interface{})["process_matcher"] = value
					default:
					}
				}

				if lowerVal, ok := m.spacialLowerVersionKeyToValue["static_config.ebpf.on-cpu-profile.regex"]; ok {
					switch value := proc.(map[string]interface{})["process_matcher"].(type) {
					case []interface{}:
						value = append(value, interface{}(map[string]interface{}{"match_regex": lowerVal}))
						proc.(map[string]interface{})["process_matcher"] = value
					case []map[string]interface{}:
						value = append(value, map[string]interface{}{"match_regex": lowerVal})
						proc.(map[string]interface{})["process_matcher"] = value
					default:
					}
				}
				if lowerVal, ok := m.spacialLowerVersionKeyToValue["static_config.ebpf.off-cpu-profile.regex"]; ok {
					switch value := proc.(map[string]interface{})["process_matcher"].(type) {
					case []interface{}:
						value = append(value, interface{}(map[string]interface{}{"match_regex": lowerVal}))
						proc.(map[string]interface{})["process_matcher"] = value
					case []map[string]interface{}:
						value = append(value, map[string]interface{}{"match_regex": lowerVal})
						proc.(map[string]interface{})["process_matcher"] = value
					default:
					}
				}

				if lowerVal, ok := m.spacialLowerVersionKeyToValue["os-proc-sync-tagged-only"]; ok {
					switch value := proc.(map[string]interface{})["process_matcher"].(type) {
					case []interface{}:
						for i := range value {
							value[i].(map[string]interface{})["only_with_tag"] = lowerVal
						}
					case []map[string]interface{}:
						for i := range value {
							value[i]["only_with_tag"] = lowerVal
						}
					default:
					}
				}
			}
		}
	}
	if !hasProcessMatcher {
		onlyWithTag, onlyWithTagOK := m.spacialLowerVersionKeyToValue["os-proc-sync-tagged-only"]
		var processMatchers []interface{}
		if lowerVal, ok := m.spacialLowerVersionKeyToValue["static_config.ebpf.uprobe-process-name-regexs.golang-symbol"]; ok {
			value := make(map[string]interface{})
			value["match_regex"] = lowerVal
			if onlyWithTagOK {
				value["only_with_tag"] = onlyWithTag
			}
			processMatchers = append(processMatchers, value)
		}
		if lowerVal, ok := m.spacialLowerVersionKeyToValue["static_config.ebpf.on-cpu-profile.regex"]; ok {
			value := make(map[string]interface{})
			value["match_regex"] = lowerVal
			if onlyWithTagOK {
				value["only_with_tag"] = onlyWithTag
			}
			value["enabled_features"] = []string{"ebpf.profile.on_cpu"}
			processMatchers = append(processMatchers, value)
		}
		if lowerVal, ok := m.spacialLowerVersionKeyToValue["static_config.ebpf.off-cpu-profile.regex"]; ok {
			value := make(map[string]interface{})
			value["match_regex"] = lowerVal
			if onlyWithTagOK {
				value["only_with_tag"] = onlyWithTag
			}
			value["enabled_features"] = []string{"ebpf.profile.off_cpu"}
			processMatchers = append(processMatchers, value)
		}

		if len(processMatchers) > 0 {
			m.setNestedValue(result, "inputs.proc.process_matcher", processMatchers)
		}
	}
}

func (m *Upgrader) lowerToHigher(lowerVerData interface{}, ancestor string, higherVerData map[string]interface{}) {
	switch data := lowerVerData.(type) {
	case map[string]interface{}:
		for key, value := range data {
			newAncestor := m.appendAncestor(ancestor, key)
			if higher, ok := m.lowerVerToHigherVerKey[newAncestor]; ok {
				lowers := m.higherVerToLowerVerKeys[higher]
				if len(lowers) > 1 {
					for _, lower := range lowers {
						log.Warnf("%s has been upgraded to %s, please configure it manually", lower, higher)
					}
				} else {
					m.setNestedValue(higherVerData, higher, m.fmtLowerVersionValue(newAncestor, value))
				}
			} else if slices.Contains(m.lowerVersionKeysNeedHandleManually, newAncestor) {
				m.setSpecialLowerVersionKeyToValue(newAncestor, value)
			}
			m.lowerToHigher(value, newAncestor, higherVerData)
		}
	default:
		return
	}
}

func (m *Upgrader) fmtLowerVersionValue(longKey string, value interface{}) interface{} {
	if longKey == "max_collect_pps" {
		switch value := value.(type) {
		case int:
			return value * 1000
		default:
			return 1048576
		}
	} else if longKey == "static_config.cpu-affinity" {
		switch value := value.(type) {
		case string:
			list, err := convertStrToIntList(value)
			if err != nil {
				log.Warnf("failed to convert %s to list: %v", longKey, err)
			}
			return list
		default:
			return []int{}
		}
	} else if longKey == "domains" {
		switch value := value.(type) {
		case []interface{}:
			if len(value) == 0 {
				return []int{}
			}
			switch item := value[0].(type) {
			case string:
				result := make([]int, 0)
				if len(value) == 1 && item == "0" {
					return []int{0}
				}
				for i := range value {
					if id, ok := m.domainData.LcuuidToID[value[i].(string)]; ok {
						result = append(result, id)
					}
				}
				return result
			default:
				log.Warnf("failed to convert %s to list: %v", longKey, value)
				return []int{}
			}
		case []string:
			result := make([]int, 0)
			if len(value) == 1 && value[0] == "0" {
				return []int{0}
			}
			for i := range value {
				if id, ok := m.domainData.LcuuidToID[value[i]]; ok {
					result = append(result, id)
				}
			}
			return result
		default:
		}
		return []int{}
	} else if slices.Contains(m.lowerVersionIntToBoolKeys, longKey) {
		switch value := value.(type) {
		case int:
			if value == 1 {
				return true
			} else {
				return false
			}
		default:
			return false
		}
	} else if slices.Contains(m.lowerVersionIntToSecondKeys, longKey) {
		switch value := value.(type) {
		case int:
			return fmt.Sprintf("%ds", value)
		default:
			return "60s"
		}
	} else if slices.Contains(m.lowerVersionIntToDayKeys, longKey) {
		switch value := value.(type) {
		case int:
			return fmt.Sprintf("%dd", value)
		default:
			return "7d"
		}
	} else if slices.Contains(m.lowerVersionStrToListKeys, longKey) {
		switch value := value.(type) {
		case string:
			return strings.Split(strings.ReplaceAll(value, " ", ""), ",")
		default:
			return []string{}
		}
	} else if slices.Contains(m.lowerVersionReverseKeys, longKey) {
		switch value := value.(type) {
		case bool:
			return !value
		default:
			return value
		}
	} else if longKey == "static_config.ebpf.uprobe-process-name-regexs.golang-symbol" {
		// 升级 static_config.ebpf.uprobe-process-name-regexs.golang-symbol 时，需要：
		//  1. 将 inputs.proc.symbol_table.golang_specific.enabled 设置为 true
		//  2. 新增一条 inputs.proc.process_matcher
		switch value := value.(type) {
		case string:
			if value == "" {
				return false
			}
			m.setSpecialLowerVersionKeyToValue(longKey, value)
			return true
		default:
			return false
		}
	}

	return m.convDictData(longKey, value)
}

func (m *Upgrader) setSpecialLowerVersionKeyToValue(key string, value interface{}) {
	m.spacialLowerVersionKeyToValue[key] = value
}

func (m *Upgrader) convDictData(longKey string, value interface{}) interface{} {
	convMap, ok := m.dictValLowerKeyToHigher[longKey]
	if !ok {
		return value
	}
	return m.convDictDataValue(value, convMap, longKey)
}

type Downgrader struct {
	dictDataConv
	MigrationToolData
}

func (m *Downgrader) Downgrade(bytes []byte) ([]byte, error) {
	data := make(map[string]interface{})
	err := yaml.Unmarshal(bytes, &data)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to unmarshal yaml: %v to map", err)
	}
	m.copyMaxMillicpusToMaxCpus()
	result := make(map[string]interface{})
	m.higherToLower(data, "", result)
	return mapToYaml(result)
}

func (m *Downgrader) copyMaxMillicpusToMaxCpus() {
	newKey := "global.limits.max_millicpus"
	if _, ok := m.higherVerToLowerVerKeys[newKey]; ok {
		m.higherVerToLowerVerKeys[newKey] = append(m.higherVerToLowerVerKeys[newKey], "max_cpus")
	}
}

func (m *Downgrader) higherToLower(higherVerData interface{}, ancestor string, lowerVerData map[string]interface{}) {
	switch data := higherVerData.(type) {
	case map[string]interface{}:
		for key, value := range data {
			newAncestor := m.appendAncestor(ancestor, key)
			if lowers, ok := m.higherVerToLowerVerKeys[newAncestor]; ok {
				for _, lower := range lowers {
					m.setNestedValue(lowerVerData, lower, m.fmtHigherVersionValue(newAncestor, value))
				}
			}
			m.higherToLower(value, newAncestor, lowerVerData)
		}
	default:
		return
	}
}

func (m *Downgrader) fmtHigherVersionValue(longKey string, value interface{}) interface{} {
	if longKey == "inputs.cbpf.tunning.max_capture_pps" {
		switch value := value.(type) {
		case int:
			return value / 1000
		default:
			return 1048576 / 1000
		}
	} else if longKey == "global.tunning.cpu_affinity" {
		switch value := value.(type) {
		case []interface{}:
			if len(value) == 0 {
				return ""
			}
			switch value[0].(type) {
			case int:
				var result string
				for i := range value {
					result += fmt.Sprintf("%d,", value[i].(int))
				}
				return result[:len(result)-1]
			default:
				return ""
			}
		case []int:
			return convertIntSliceToString(value)
		default:
			return ""
		}
	} else if longKey == "inputs.resources.pull_resource_from_controller.domain_filter" {
		switch value := value.(type) {
		case []interface{}:
			if len(value) == 0 {
				return ""
			}
			switch value[0].(type) {
			case int:
				if len(value) == 1 && value[0].(int) == 0 {
					return []string{"0"}
				}
				result := make([]string, 0)
				for i := range value {
					if lcuuid, ok := m.domainData.IDToLcuuid[value[i].(int)]; ok {
						result = append(result, lcuuid)
					}
				}
				return result
			default:
				return []string{}
			}
		case []int:
			if len(value) == 1 && value[0] == 0 {
				return []string{"0"}
			}
			result := make([]string, 0)
			for i := range value {
				if lcuuid, ok := m.domainData.IDToLcuuid[value[i]]; ok {
					result = append(result, lcuuid)
				}
			}
			return result
		default:
			return []string{}
		}
	} else if slices.Contains(m.higherVersionBoolToIntKeys, longKey) {
		switch value := value.(type) {
		case bool:
			if value {
				return 1
			} else {
				return 0
			}
		default:
			return 0
		}
	} else if slices.Contains(m.higherVersionSecondToIntKeys, longKey) {
		switch value := value.(type) {
		case string:
			v, err := strconv.Atoi(strings.TrimSuffix(value, "s"))
			if err != nil {
				log.Errorf("failed to convert %s value %s to int: %s ", longKey, value, err.Error())
				return 60
			}
			return v
		default:
			return 60
		}
	} else if slices.Contains(m.higherVersionDayToIntKeys, longKey) {
		switch value := value.(type) {
		case string:
			v, err := strconv.Atoi(strings.TrimSuffix(value, "d"))
			if err != nil {
				log.Errorf("failed to convert %s value %s to int: %s ", longKey, value, err.Error())
				return 7
			}
			return v
		default:
			return 7
		}
	} else if slices.Contains(m.higherVersionListToStrKeys, longKey) {
		switch value := value.(type) {
		case []interface{}:
			if len(value) == 0 {
				return ""
			}
			switch value[0].(type) {
			case string:
				var result string
				for i := range value {
					result += fmt.Sprintf("%s,", value[i].(string))
				}
				return result[:len(result)-1]
			default:
				return ""
			}
		case []string:
			return strings.Join(value, ",")
		default:
			return ""
		}
	} else if slices.Contains(m.higherVersionReverseKeys, longKey) {
		switch value := value.(type) {
		case bool:
			return !value
		default:
			return value
		}
	}
	return m.convDictData(longKey, value)
}

func (m *Downgrader) convDictData(longKey string, value interface{}) interface{} {
	convMap, ok := m.dictValHigherKeyToLower[longKey]
	if !ok {
		return value
	}
	return m.convDictDataValue(value, convMap, longKey)
}

type dictDataConv struct{}

func (m *dictDataConv) convDictDataValue(data interface{}, convMap map[string]interface{}, longKey string) interface{} {
	switch data := data.(type) {
	case []interface{}:
		result := make([]map[string]interface{}, 0)
		for i := range data {
			result = append(
				result,
				m.convDictDataKey(data[i].(map[string]interface{}), convMap, longKey))
		}
		return result
	case map[string]interface{}:
		result := make(map[string]interface{})
		for k, v := range data {
			tmpV := make([]map[string]interface{}, 0)
			switch v := v.(type) {
			case []map[string]interface{}:
				for i := range v {
					tmpV = append(
						tmpV,
						m.convDictDataKey(v[i], convMap, longKey+"."+k))
				}
			case []interface{}:
				for i := range v {
					tmpV = append(
						tmpV,
						m.convDictDataKey(v[i].(map[string]interface{}), convMap, longKey+"."+k))
				}
			default:
				continue
			}
			result[k] = tmpV
		}
		return result
	}
	return data
}

// convDictDataKey 将 dict 类型数据列表里 value 的 key 根据新旧版本的映射关系进行转换
func (m *dictDataConv) convDictDataKey(data map[string]interface{}, convMap map[string]interface{}, longKey string) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range data {
		if newK, ok := convMap[k]; ok {
			if longKey == "static_config.os-proc-regex" {
				if newK.(string) == "ignore" {
					newV := true
					if v == "accept" {
						newV = false
					}
					result[newK.(string)] = newV
					continue
				}
			} else if longKey == "inputs.proc.process_matcher" {
				if newK.(string) == "action" {
					newV := "accept"
					if v == true {
						newV = "drop"
					}
					result[newK.(string)] = newV
					continue
				}
			}
			result[newK.(string)] = v
		} else {
			log.Warnf("key %s.%s is not supportted", longKey, v)
		}
	}
	return result
}

func (m *dictDataConv) setNestedValue(data map[string]interface{}, longKey string, value interface{}) {
	keys := strings.Split(longKey, ".")
	for i := 0; i < len(keys)-1; i++ {
		if _, ok := data[keys[i]]; !ok {
			data[keys[i]] = make(map[string]interface{})
		}
		data = data[keys[i]].(map[string]interface{})
	}
	data[keys[len(keys)-1]] = value
}

type MigrationToolData struct {
	higherVerToLowerVerKeys map[string][]string
	lowerVerToHigherVerKey  map[string]string

	dictValHigherKeyToLower map[string]map[string]interface{}
	dictValLowerKeyToHigher map[string]map[string]interface{}

	lowerVersionIntToBoolKeys    []string
	higherVersionBoolToIntKeys   []string
	lowerVersionIntToSecondKeys  []string
	higherVersionSecondToIntKeys []string
	lowerVersionIntToDayKeys     []string
	higherVersionDayToIntKeys    []string
	lowerVersionStrToListKeys    []string
	higherVersionListToStrKeys   []string
	lowerVersionReverseKeys      []string
	higherVersionReverseKeys     []string

	lowerVersionKeysNeedHandleManually []string

	domainData *DomainData

	DataFormatter
}

func NewMigrationToolData(domainData *DomainData) (MigrationToolData, error) {
	lineFmt := NewLineFormatter(YamlAgentGroupConfigTemplate)
	formattedLines, err := lineFmt.Format()
	if err != nil {
		return MigrationToolData{}, err
	}
	p := MigrationToolData{
		higherVerToLowerVerKeys: make(map[string][]string),
		lowerVerToHigherVerKey:  make(map[string]string),

		dictValHigherKeyToLower: make(map[string]map[string]interface{}),
		dictValLowerKeyToHigher: make(map[string]map[string]interface{}),

		domainData: domainData,
	}
	err = p.DataFormatter.LoadYAMLData(formattedLines)
	if err != nil {
		return p, err
	}
	p.Format()
	return p, err
}

func (p *MigrationToolData) SetDomainData(domainData *DomainData) {
	p.domainData = domainData
}

func (p *MigrationToolData) Format() {
	p.generateHigherKeyToLowerKeys(p.DataFormatter.mapData, "")
	for higher, lowers := range p.higherVerToLowerVerKeys {
		for _, lower := range lowers {
			p.lowerVerToHigherVerKey[lower] = higher
		}
	}
	p.fmtDictValKeyMap()
}

func (p *MigrationToolData) generateHigherKeyToLowerKeys(data interface{}, ancestors string) {
	switch data := data.(type) {
	case map[string]interface{}:
		for key, value := range data {
			newAncestors := p.appendAncestor(ancestors, key)
			if p.isKeyComment(key) {
				commentValue := value.(map[string]interface{})
				if upgradeFrom, ok := commentValue["upgrade_from"]; ok {
					switch upgradeFrom := upgradeFrom.(type) {
					case string:
						if strings.HasSuffix(upgradeFrom, ".$protocol") {
							continue
						}
						upgradeFroms := strings.Split(upgradeFrom, ", ")
						p.higherVerToLowerVerKeys[newAncestors] = upgradeFroms
					default:
					}
				}
			}
			p.generateHigherKeyToLowerKeys(value, newAncestors)
		}
	default:
		return
	}
}

func (p *MigrationToolData) fmtDictValKeyMap() {
	p.dictValHigherKeyToLower = map[string]map[string]interface{}{
		// process handly
		"inputs.proc.process_matcher": {
			"match_regex": "match-regex",
			"match_type":  "match-type",
			// "only_with_tag":    "static_config.os-proc-sync-tagged-only", // TODO
			"ignore":       "action",
			"rewrite_name": "rewrite-name",
			// "enabled_features": []string{"static_config.ebpf.on-cpu-profile.regex", "static_config.ebpf.off-cpu-profile.regex"}, // 无法升降级
		},

		"inputs.cbpf.af_packet.bond_interfaces": {
			"slave_interfaces": "tap-interfaces",
		},
		"inputs.resources.kubernetes.api_resources": {
			"name":           "name",
			"group":          "group",
			"version":        "version",
			"disabled":       "disabled",
			"field_selector": "field-selector",
		},
		"processors.request_log.tag_extraction.http_endpoint.match_rules": {
			"url_prefix":    "prefix",
			"keep_segments": "keep-segments",
		},
		// next level list dict
		"processors.request_log.filters.tag_filters": {
			"field_name":  "field-name",
			"operator":    "operator",
			"field_value": "value",
		},
		"processors.request_log.tag_extraction.custom_fields": {
			"field_name": "field-name",
		},
	}
	p.dictValLowerKeyToHigher = map[string]map[string]interface{}{
		// process handly
		"static_config.os-proc-regex": {
			"match-regex":  "match_regex",
			"match-type":   "match_type",
			"action":       "ignore",
			"rewrite-name": "rewrite_name",
		},
		// "static_config.os-proc-sync-tagged-only": {},
		"static_config.tap-interface-bond-groups": {
			"tap-interfaces": "slave_interfaces",
		},
		"static_config.kubernetes-resources": {
			"name":           "name",
			"group":          "group",
			"version":        "version",
			"disabled":       "disabled",
			"field-selector": "field_selector",
		},
		"static_config.l7-protocol-advanced-features.http-endpoint-extraction.match-rules": {
			"prefix":        "url_prefix",
			"keep-segments": "keep_segments",
		},
		// next level list dict
		"static_config.l7-log-blacklist": {
			"field-name": "field_name",
			"operator":   "operator",
			"value":      "field_value",
		},
		"static_config.l7-protocol-advanced-features.extra-log-fields": {
			"field-name": "field_name",
		},
	}
	p.lowerVersionIntToBoolKeys = []string{
		"vtap_flow_1s_enabled",
		"npb_dedup_enabled",
		"ntp_enabled",
		"nat_ip_enabled",
		"rsyslog_enabled",
		"platform_enabled",
		"external_agent_http_proxy_enabled",
		"collector_enabled",
		"inactive_server_port_enabled",
		"inactive_ip_enabled",
		"l4_performance_enabled",
		"l7_metrics_enabled",
		"pod_cluster_internal_ip",

		"static_config.ebpf.on-cpu-profile.cpu",
		"static_config.ebpf.off-cpu-profile.cpu",
	}
	p.higherVersionBoolToIntKeys = []string{
		"global.ntp.enabled",
		"global.communication.request_via_nat_ip",
		"global.self_monitoring.log.log_backhaul_enabled",
		"inputs.resources.private_cloud.hypervisor_resource_enabled",
		"inputs.resources.pull_resource_from_controller.only_kubernetes_pod_ip_in_local_cluster",
		"inputs.integration.enabled",
		"outputs.flow_metrics.enabled",
		"outputs.flow_metrics.filters.inactive_server_port_aggregation",
		"outputs.flow_metrics.filters.inactive_ip_aggregation",
		"outputs.flow_metrics.filters.npm_metrics",
		"outputs.flow_metrics.filters.apm_metrics",
		"outputs.flow_metrics.filters.second_metrics",
		"outputs.npb.traffic_global_dedup",

		"inputs.ebpf.profile.on_cpu.aggregate_by_cpu",
		"inputs.ebpf.profile.off_cpu.aggregate_by_cpu",
	}
	p.lowerVersionIntToSecondKeys = []string{
		"bandwidth_probe_interval",
		"sync_interval",
		"max_escape_seconds",
		"platform_sync_interval",
		"static_config.os-proc-socket-sync-interval",
		"static_config.os-proc-socket-min-lifetime",
		"static_config.ebpf.go-tracing-timeout",
		"static_config.l7-protocol-inference-ttl",
	}
	p.higherVersionSecondToIntKeys = []string{
		"global.circuit_breakers.tx_throughput.throughput_monitoring_interval",
		"global.communication.proactive_request_interval",
		"global.communication.max_escape_duration",
		"inputs.resources.push_interval",
		"inputs.proc.sync_interval",
		"inputs.proc.min_lifetime",
		"inputs.ebpf.socket.uprobe.golang.tracing_timeout",
		"processors.request_log.application_protocol_inference.inference_result_ttl",
	}
	p.lowerVersionIntToDayKeys = []string{
		"log_retention",
	}
	p.higherVersionDayToIntKeys = []string{
		"global.limits.local_log_retention",
	}
	p.lowerVersionStrToListKeys = []string{
		"http_log_proxy_client",
		"http_log_x_request_id",
		"http_log_trace_id",
		"http_log_span_id",
	}
	p.higherVersionListToStrKeys = []string{
		"processors.request_log.tag_extraction.tracing_tag.http_real_client",
		"processors.request_log.tag_extraction.tracing_tag.x_request_id",
		"processors.request_log.tag_extraction.tracing_tag.apm_trace_id",
		"processors.request_log.tag_extraction.tracing_tag.apm_span_id",
	}
	p.lowerVersionReverseKeys = []string{
		"static_config.memory-trim-disabled",
	}
	p.higherVersionReverseKeys = []string{
		"global.tunning.idle_memory_trimming",
	}

	p.lowerVersionKeysNeedHandleManually = []string{
		// 升级 static_config.os-proc-sync-tagged-only 时，需要：
		//  1. 将 inputs.proc.process_matcher 里所有的 only_with_tag 设置为 static_config.os-proc-sync-tagged-only
		"os-proc-sync-tagged-only",
		// 升级 static_config.ebpf.uprobe-process-name-regexs.golang-symbol 时，需要：
		//  1. 将 inputs.proc.symbol_table.golang_specific.enabled 设置为 true
		//  2. 新增一条 inputs.proc.process_matcher
		"static_config.ebpf.uprobe-process-name-regexs.golang-symbol",
		// 升级 static_config.ebpf.on-cpu-profile.regex 时，需要：
		//  1. 新增一条 inputs.proc.process_matcher
		"static_config.ebpf.on-cpu-profile.regex",
		// 升级 static_config.ebpf.off-cpu-profile.regex 时，需要：
		//  1. 新增一条 inputs.proc.process_matcher
		"static_config.ebpf.off-cpu-profile.regex",
	}
}

func mapToYaml(data map[string]interface{}) ([]byte, error) {
	var buf strings.Builder
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	err := enc.Encode(data)
	if err != nil {
		return nil, fmt.Errorf("failed to encode map to yaml: %v", err)
	}
	return []byte(buf.String()), nil
}
