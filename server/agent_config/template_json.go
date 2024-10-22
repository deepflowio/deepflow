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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/baidubce/bce-sdk-go/util/log"
	"gopkg.in/yaml.v3"
)

type DynamicOptions map[string]*yaml.Node

const keyCommentSuffix = "_comment"

func ParseYAMLToJson(yamlData []byte, d DynamicOptions) ([]byte, error) { // TODO refactor d
	formatedTemplate, err := formatTemplateYAML(yamlData)
	// lineParser := NewLineParser(yamlData)
	// formatedTemplate, err := lineParser.StripLines()
	if err != nil {
		return nil, fmt.Errorf("format template yaml error: %v", err)
	}

	var node yaml.Node
	err = yaml.Unmarshal(formatedTemplate, &node)
	if err != nil {
		return nil, fmt.Errorf("unmarshal data to yaml node error: %v", err)
	}

	formattedNode, err := convTypeDictValToString(&node)
	if err != nil {
		return nil, fmt.Errorf("convert type dict value to string error: %v", err)
	}

	formattedNode, err = fillingEnumOptions("", formattedNode, d)
	if err != nil {
		return nil, fmt.Errorf("filling enum options error: %v", err)
	}

	jsonData, err := fillingOrder(formattedNode)
	// jsonData, err := fillingOrder(&node)
	if err != nil {
		return nil, fmt.Errorf("yaml node to map with order error: %v", err)
	}

	jsonBytes, err := json.MarshalIndent(jsonData, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal data to json error: %v", err)
	}
	jsonStr := string(jsonBytes)
	jsonStr = strings.ReplaceAll(jsonStr, ": null", ": []") // TODO 为什么要替换 null 为 []？

	return []byte(jsonStr), nil
}

func formatTemplateYAML(yamlData []byte) ([]byte, error) {
	indentedLines, err := IndentTemplate(yamlData)
	if err != nil {
		return nil, err
	}
	return UncommentTemplate(indentedLines)
}

func IndentTemplate(yamlData []byte) ([]string, error) {
	yamlStr := string(yamlData)
	lines := strings.Split(yamlStr, "\n")

	var indentedLines []string
	var tempLines []string
	for i := 0; i < len(lines); i++ {
		// 以 --- 开头结尾的注释，需要忽略
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

		//  --- 包含以外的注释，需要提取出来，作为配置的注解
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

func fillingEnumOptions(ancetors string, node *yaml.Node, d DynamicOptions) (*yaml.Node, error) {
	switch node.Kind {
	case yaml.DocumentNode:
		return fillingEnumOptions(ancetors, node.Content[0], d)
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			newAncetors := node.Content[i].Value
			if ancetors != "" {
				newAncetors = ancetors + "." + newAncetors
			}
			value, err := fillingEnumOptions(newAncetors, node.Content[i+1], d)
			if err != nil {
				return nil, err
			}
			node.Content[i+1] = value
		}
		return node, nil
	case yaml.SequenceNode:
		value := make([]*yaml.Node, 0)
		if dynamicValue, ok := d[ancetors]; ok {
			for _, contentNode := range node.Content {
				if contentNode.Kind == yaml.MappingNode {
					for i := 0; i < len(contentNode.Content); i += 2 {
						key := contentNode.Content[i].Value
						if key != "_DYNAMIC_OPTIONS_" {
							value = append(value, contentNode)
						}
					}
				}
			}
			value = append(value, dynamicValue.Content...)
		} else {
			for _, contentNode := range node.Content {
				valueNode, err := fillingEnumOptions(ancetors, contentNode, d)
				if err != nil {
					return nil, err
				}
				value = append(value, valueNode)
			}
		}
		node.Content = value
		return node, nil
	case yaml.ScalarNode:
		return node, nil
	default:
		return nil, fmt.Errorf("unsupported YAML node kind: %v", node.Kind)
	}
}

func convTypeDictValToString(node *yaml.Node) (*yaml.Node, error) {
	switch node.Kind {
	case yaml.DocumentNode:
		return convTypeDictValToString(node.Content[0])
	case yaml.MappingNode:
		var dictKey string
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i].Value
			valueNode := node.Content[i+1]
			if strings.HasSuffix(key, keyCommentSuffix) {
				for j := 0; j < len(valueNode.Content); j += 2 {
					if valueNode.Content[j].Value == "type" && valueNode.Content[j+1].Value == "dict" {
						dictKey = strings.TrimSuffix(key, keyCommentSuffix)
						break
					}
				}
				value, err := convTypeDictValToString(valueNode)
				if err != nil {
					return nil, err
				}
				node.Content[i+1] = value
			} else if key == dictKey {
				bytes, err := yaml.Marshal(valueNode)
				if err != nil {
					return nil, err
				}
				strValNode := &yaml.Node{
					Kind:  yaml.ScalarNode,
					Tag:   "!!str",
					Value: string(bytes),
				}
				node.Content[i+1] = strValNode
				dictKey = ""
			} else {
				value, err := convTypeDictValToString(valueNode)
				if err != nil {
					return nil, err
				}
				node.Content[i+1] = value
			}
		}
		return node, nil
	case yaml.SequenceNode:
		value := make([]*yaml.Node, 0)
		for i := 0; i < len(node.Content); i++ {
			valueNode, err := convTypeDictValToString(node.Content[i])
			if err != nil {
				return nil, err
			}
			value = append(value, valueNode)
		}
		node.Content = value
		return node, nil
	case yaml.ScalarNode:
		return node, nil
	default:
		return nil, fmt.Errorf("unsupported YAML node kind: %v", node.Kind)
	}
}

func fillingOrder(node *yaml.Node) (interface{}, error) {
	switch node.Kind {
	case yaml.DocumentNode:
		return fillingOrder(node.Content[0])
	case yaml.MappingNode:
		values := make(map[string]interface{})
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]

			key := keyNode.Value
			value, err := fillingOrder(valueNode)
			if err != nil {
				return nil, err
			}

			if strings.HasSuffix(key, keyCommentSuffix) {
				if valueMap, ok := value.(map[string]interface{}); ok {
					valueMap["order"] = i/2 + 1
					value = valueMap
				}
			}

			values[key] = value
		}
		return values, nil
	case yaml.SequenceNode:
		var seq []interface{}
		for i, contentNode := range node.Content {
			value, err := fillingOrder(contentNode)
			if err != nil {
				return nil, err
			}
			if valueMap, ok := value.(map[string]interface{}); ok {
				valueMap["order"] = i + 1
				value = valueMap
			}
			seq = append(seq, value)
		}
		return seq, nil
	case yaml.ScalarNode:
		if node.Tag == "!!int" {
			var err error
			if intValue, err := strconv.Atoi(node.Value); err == nil {
				return intValue, nil
			}
			if intValue, err := strconv.ParseInt(node.Value, 0, 64); err == nil {
				return intValue, nil
			}
			return nil, err
		} else if node.Tag == "!!bool" {
			boolValue, err := strconv.ParseBool(node.Value)
			if err != nil {
				return nil, err
			}
			return boolValue, nil
		} else if node.Tag == "!!float" {
			floatValue, err := strconv.ParseFloat(node.Value, 64)
			if err != nil {
				return nil, err
			}
			return floatValue, nil
		}
		return node.Value, nil
	default:
		return nil, fmt.Errorf("unsupported YAML node kind: %v", node.Kind)
	}
}

func ParseJsonToYAMLAndValidate(jsonData map[string]interface{}) ([]byte, error) {
	// FIXME
	var buf strings.Builder
	enc := yaml.NewEncoder(&buf)
	var node yaml.Node
	enc.SetIndent(2)
	err := enc.Encode(jsonData)
	if err != nil {
		return nil, err
	}
	yamlData := []byte(buf.String())

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

	nodeTemplate.Content[0], err = convTypeDictValToString(nodeTemplate.Content[0])
	if err != nil {
		log.Infof("weiqiang convTypeDictValToString error: %v", err)
		return nil, err
	}

	// Check if each item in node is included in nodeTemplate
	if err = validateNodeAgainstTemplate(&node, &nodeTemplate); err != nil {
		// if err = validateNodeAgainstTemplate(&node, &nodeTemplate); err != nil {
		return nil, fmt.Errorf("validate config error: %v", err)
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
		}
		// TODO validate sequence content by comment
	case yaml.ScalarNode:
		if nodeTemplate.Tag == "!!float" && node.Tag == "!!int" {
			return nil
		}
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
