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
	"strings"

	"gopkg.in/yaml.v3"
	k8syaml "sigs.k8s.io/yaml"
)

func ParseTemplateYAMLToJson(yamlData []byte) ([]byte, error) {
	formatedTemplate, err := formatTemplateYAML(yamlData)
	if err != nil {
		return nil, err
	}
	return k8syaml.YAMLToJSON(formatedTemplate)
}

func formatTemplateYAML(yamlData []byte) ([]byte, error) {
	indentedLines, err := IndentTemplate(yamlData)
	if err != nil {
		return nil, err
	}
	return UncommentTemplate(indentedLines)
}

func IndentTemplate(yamlData []byte) ([]string, error) {
	yamlStr := string(YamlAgentGroupConfigTemplate)
	lines := strings.Split(yamlStr, "\n")

	var indentedLines []string
	var tempLines []string
	for i := 0; i < len(lines); i++ {
		if strings.Contains(lines[i], "---") {
			j := i + 1
			for ; j < len(lines); j++ {
				if strings.Contains(lines[j], "---") {
					break
				}
			}
			i = j + 1
			continue
		}

		if strings.Contains(lines[i], "#") {
			if !strings.HasPrefix(strings.TrimSpace(lines[i]), "#") {
				tempLines = append(tempLines, lines[i])
			} else {
				// add indent to config
				tempLines = append(tempLines, "  "+lines[i])
			}
			continue
		}

		configNames := strings.Split(lines[i], ":")
		if len(configNames) == 0 {
			return nil, fmt.Errorf("line(index: %d, value: %s) split by \":\" failed", i, lines[i])
		}
		if len(tempLines) > 0 {
			indentedLines = append(indentedLines, configNames[0]+"_comment:")
			indentedLines = append(indentedLines, tempLines...)
		}
		indentedLines = append(indentedLines, lines[i])
		tempLines = []string{}
	}

	return indentedLines, nil
}

// UncommentTemplate removes all lines containing "TODO" and uncomments all lines
// by removing the "#" prefix. It is used to convert the agent configuration
// template file to json format.
func UncommentTemplate(indentedLines []string) ([]byte, error) {
	var uncommentedLines []string
	for i := 0; i < len(indentedLines); i++ {
		line := indentedLines[i]
		if strings.Contains(line, "TODO") {
			continue
		}
		if !strings.HasPrefix(strings.TrimSpace(line), "#") && strings.Contains(line, "#") {
			uncommentedLines = append(uncommentedLines, line)
			continue
		}

		line = strings.ReplaceAll(line, "# ", "")
		line = strings.ReplaceAll(line, "#", "")
		uncommentedLines = append(uncommentedLines, line)
	}
	return []byte(strings.Join(uncommentedLines, "\n")), nil
}

func ParseJsonToYAMLAndValidate(jsonData map[string]interface{}) ([]byte, error) {
	b, err := yaml.Marshal(jsonData)
	if err != nil {
		return nil, err
	}
	yamlData, err := k8syaml.JSONToYAML(b)
	if err != nil {
		return nil, err
	}
	var node yaml.Node
	err = yaml.Unmarshal(yamlData, &node)
	if err != nil {
		return nil, fmt.Errorf("unmarshal data to yaml node error: %v", err)
	}

	formatedTemplate, err := formatTemplateYAML(YamlAgentGroupConfigTemplate)
	if err != nil {
		return nil, err
	}
	var nodeTemplate yaml.Node
	err = yaml.Unmarshal(formatedTemplate, &nodeTemplate)
	if err != nil {
		return nil, fmt.Errorf("unmarshal template data to yaml node error: %v", err)
	}

	// 检查 node 中的每一项是否包含在 nodeTemplate 中
	err = validateNodeAgainstTemplate(&node, &nodeTemplate)
	if err != nil {
		return nil, fmt.Errorf("验证配置失败: %v", err)
	}

	return yamlData, nil
}

func validateNodeAgainstTemplate(node, nodeTemplate *yaml.Node) error {
	if node.Kind != nodeTemplate.Kind {
		return fmt.Errorf("node kind mismatch: expected %v, got %v", nodeTemplate.Kind, node.Kind)
	}

	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) != len(nodeTemplate.Content) {
			return fmt.Errorf("document node content length mismatch")
		}
		for i := range node.Content {
			if err := validateNodeAgainstTemplate(node.Content[i], nodeTemplate.Content[i]); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		nodeMap := make(map[string]*yaml.Node)
		for i := 0; i < len(node.Content); i += 2 {
			nodeMap[node.Content[i].Value] = node.Content[i+1]
		}

		templateMap := make(map[string]*yaml.Node)
		for i := 0; i < len(nodeTemplate.Content); i += 2 {
			templateMap[nodeTemplate.Content[i].Value] = nodeTemplate.Content[i+1]
		}

		for key, value := range nodeMap {
			if templateValue, exists := templateMap[key]; exists {
				if err := validateNodeAgainstTemplate(value, templateValue); err != nil {
					return fmt.Errorf("invalid value for key '%s': %v", key, err)
				}
			} else {
				return fmt.Errorf("unexpected key in configuration: %s", key)
			}
		}
	case yaml.SequenceNode:
		if len(node.Content) > 0 && len(nodeTemplate.Content) > 0 {
			for _, item := range node.Content {
				if err := validateNodeAgainstTemplate(item, nodeTemplate.Content[0]); err != nil {
					return fmt.Errorf("invalid sequence item: %v", err)
				}
			}
		} else if len(node.Content) > 0 && len(nodeTemplate.Content) == 0 {
			return fmt.Errorf("unexpected sequence in configuration")
		}
	case yaml.ScalarNode:
		if node.Tag != nodeTemplate.Tag {
			return fmt.Errorf("scalar type mismatch: expected %s, got %s", nodeTemplate.Tag, node.Tag)
		}
	case yaml.AliasNode:
		if nodeTemplate.Kind != yaml.AliasNode {
			return fmt.Errorf("unexpected alias node")
		}
		// For alias nodes, we should validate the actual content they refer to
		if err := validateNodeAgainstTemplate(node.Alias, nodeTemplate.Alias); err != nil {
			return fmt.Errorf("invalid alias node: %v", err)
		}
	default:
		return fmt.Errorf("unsupported node kind: %v", node.Kind)
	}

	return nil
}
