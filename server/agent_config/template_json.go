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

	"gopkg.in/yaml.v3"
)

const (
	keyCommentSuffix = "_comment"

	commentFlag           = "#"
	subelementCommentFlag = "# ---"
	todoFlag              = "TODO"

	templateIndent = "  "
)

func ConvertYAMLToJSON(yamlData []byte) ([]byte, error) {
	keyToComment, err := NewTemplateFormatter(YamlAgentGroupConfigTemplate).GenerateKeyToComment()
	if err != nil {
		return nil, fmt.Errorf("generate key to comment error: %v", err)
	}
	dataFmt := NewDataFommatter()
	err = dataFmt.LoadYAMLData(yamlData)
	if err != nil {
		return nil, fmt.Errorf("new data formatter error: %v", err)
	}
	return dataFmt.mapToJSON(keyToComment)
}

func ValidateYAML(yamlData []byte) error {
	tmplFmt := NewTemplateFormatter(YamlAgentGroupConfigTemplate)
	KeyToComment, err := tmplFmt.GenerateKeyToComment()
	if err != nil {
		return fmt.Errorf("generate key to comment error: %v", err)
	}
	tmplFmt.DataFomatter.fmtMapValAndRefresh(KeyToComment, true)

	dataFmt := NewDataFommatter()
	err = dataFmt.LoadYAMLData(yamlData)
	if err != nil {
		return fmt.Errorf("new data formatter error: %v", err)
	}
	err = dataFmt.fmtMapValAndRefresh(KeyToComment, true)
	if err != nil {
		return fmt.Errorf("convert value and refresh error: %v", err)
	}

	return validateNodeAgainstTemplate(dataFmt.yamlNode, tmplFmt.DataFomatter.yamlNode)
}

func ConvertJSONToYAMLAndValidate(jsonData map[string]interface{}) ([]byte, error) {
	tmplFmt := NewTemplateFormatter(YamlAgentGroupConfigTemplate)
	KeyToComment, err := tmplFmt.GenerateKeyToComment()
	if err != nil {
		return nil, fmt.Errorf("generate key to comment error: %v", err)
	}
	tmplFmt.DataFomatter.fmtMapValAndRefresh(KeyToComment, true)

	dataFmt := NewDataFommatter()
	dataFmt.setKeyToComment(KeyToComment)
	err = dataFmt.LoadMapData(jsonData)
	if err != nil {
		return nil, fmt.Errorf("new data formatter error: %v", err)
	}
	err = dataFmt.fmtMapValAndRefresh(KeyToComment, true)
	if err != nil {
		return nil, fmt.Errorf("convert value and refresh error: %v", err)
	}

	if err := validateNodeAgainstTemplate(dataFmt.yamlNode, tmplFmt.DataFomatter.yamlNode); err != nil {
		return nil, err
	}

	return dataFmt.formattedYAMLData, nil
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
		if nodeTemplate.Tag == "!!null" { // TODO more strict validation
			return nil
		}
		if (nodeTemplate.Tag == "!!float" && node.Tag == "!!int") || (nodeTemplate.Tag == "!!int" && node.Tag == "!!float") {
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

func ConvertTemplateYAMLToJSON(d DynamicOptions) ([]byte, error) {
	return NewTemplateFormatter(YamlAgentGroupConfigTemplate).mapToJSON(d)
}

type KeyToComment map[string]map[string]interface{}

type TemplateFormatter struct {
	lineFmt *LineFomatter
	DataFomatter
}

func NewTemplateFormatter(data []byte) *TemplateFormatter {
	return &TemplateFormatter{
		lineFmt: NewLineFommatter(data),
	}
}

func (f *TemplateFormatter) mapToJSON(d DynamicOptions) ([]byte, error) {
	formattedLines, err := f.lineFmt.Format()
	if err != nil {
		return nil, fmt.Errorf("format template yaml lines error: %v", err)
	}

	err = f.DataFomatter.LoadYAMLData(formattedLines)
	if err != nil {
		return nil, fmt.Errorf("LoadYAMLData data formatter error: %v", err)
	}
	keyToComment := make(KeyToComment)
	f.generateKeyComment(f.mapData, "", keyToComment)
	err = f.DataFomatter.fmtMapValAndRefresh(keyToComment, true)
	if err != nil {
		return nil, fmt.Errorf("convert dict value to string error: %v", err)
	}

	formattedNode, err := f.fillingEnumOptions(f.DataFomatter.yamlNode, "", d)
	if err != nil {
		return nil, fmt.Errorf("filling enum options error: %v", err)
	}
	formattedMap, err := f.fillingOrder(formattedNode)
	if err != nil {
		return nil, fmt.Errorf("filling order error: %v", err)
	}
	return f.formatJson(formattedMap)
}

func (f *TemplateFormatter) fillingEnumOptions(node *yaml.Node, ancetors string, d DynamicOptions) (*yaml.Node, error) {
	switch node.Kind {
	case yaml.DocumentNode:
		return f.fillingEnumOptions(node.Content[0], ancetors, d)
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			newAncetors := node.Content[i].Value
			if ancetors != "" {
				newAncetors = ancetors + "." + newAncetors
			}
			value, err := f.fillingEnumOptions(node.Content[i+1], newAncetors, d)
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
				valueNode, err := f.fillingEnumOptions(contentNode, ancetors, d)
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

func (f *TemplateFormatter) fillingOrder(node *yaml.Node) (interface{}, error) {
	switch node.Kind {
	case yaml.DocumentNode:
		return f.fillingOrder(node.Content[0])
	case yaml.MappingNode:
		values := make(map[string]interface{})
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]

			key := keyNode.Value
			value, err := f.fillingOrder(valueNode)
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
			value, err := f.fillingOrder(contentNode)
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

func (f *TemplateFormatter) GenerateKeyToComment() (KeyToComment, error) {
	formattedLines, err := f.lineFmt.Format()
	if err != nil {
		return nil, fmt.Errorf("format template yaml lines error: %v", err)
	}
	err = f.DataFomatter.LoadYAMLData(formattedLines)
	if err != nil {
		return nil, fmt.Errorf("LoadYAMLData data formatter error: %v", err)
	}

	keyToComment := make(KeyToComment)
	f.generateKeyComment(f.mapData, "", keyToComment)
	return keyToComment, nil
}

func (f *TemplateFormatter) generateKeyComment(data interface{}, ancestors string, result KeyToComment) interface{} {
	switch data := data.(type) {
	case map[string]interface{}:
		for key, value := range data {
			newAncestors := f.appendAncestor(ancestors, key)
			if f.isKeyComment(key) {
				result[newAncestors] = f.generateKeyComment(value, newAncestors, result).(map[string]interface{})
			}
			f.generateKeyComment(value, newAncestors, result)
		}
	default:
		return data
	}
	return data
}

// LineFomatter 将 template.yaml 文件中的注释转换为 yaml section。
// 文件中的多行注释每一行以 # 开头，是多行注释结束后数据字段 key 的说明：
// 1. 添加与数据字段 key 同缩进的说明字段 key_comment。
// 2. 将说明反注释后增加缩进，作为说明字段的值。
//
// 例如：
//
//	# type: section
//	# name:
//	#   en: Global
//	#   ch: 全局配置
//	# description:
//	global:
//
// 其中，# type: section 及至 # description: 行是 section 的说明，global 是 section 的 key，转换后的 yaml 为：
//
//	global_comment:
//	  type: section
//	  name:
//	    en: Global
//	    ch: 全局配置
//	  description:
//	global:
type LineFomatter struct {
	lines []string
}

func NewLineFommatter(bytes []byte) *LineFomatter {
	return &LineFomatter{
		lines: strings.Split(string(bytes), "\n"),
	}
}

func (f *LineFomatter) Format() ([]byte, error) {
	strippedLines := make([]string, 0)
	for i := 0; i < len(f.lines); i++ {
		if f.isCommentLine(f.lines[i]) {
			end, lines, err := f.convCommentToSection(i)
			if err != nil {
				return []byte{}, err
			}
			strippedLines = append(strippedLines, lines...)
			i = end
			continue
		}
		strippedLines = append(strippedLines, f.lines[i])
	}
	return []byte(strings.Join(strippedLines, "\n")), nil
}

func (f *LineFomatter) convCommentToSection(start int) (end int, commentlines []string, err error) {
	i := start
	for ; i < len(f.lines); i++ {
		if !f.isCommentLine(f.lines[i]) {
			break
		}
		if f.isTodoCommentLine(f.lines[i]) {
			i = f.ignoreTodoComments(i)
			continue
		}
		if f.isSubelementCommentLine(f.lines[i]) {
			i = f.ignoreSubelementComments(i)
			continue
		}
		commentlines = append(commentlines, f.indentLine(f.uncommentLine(f.lines[i]), 1))
	}

	keyCommentLine, err := f.keyLineToKeyCommentLine(f.lines[i])
	if err != nil {
		return 0, nil, fmt.Errorf(err.Error()+" at line: %d", i)
	}
	return i - 1, append([]string{keyCommentLine}, commentlines...), nil
}

func (f *LineFomatter) indentLine(line string, indentCount int) string {
	for i := 0; i < indentCount; i++ {
		line = templateIndent + line
	}
	return line
}

func (f *LineFomatter) uncommentLine(line string) string {
	line = strings.Replace(line, commentFlag+" ", "", 1)
	if f.isCommentLine(line) {
		line = strings.Replace(line, commentFlag, "", 1)
	}
	return line
}

func (f *LineFomatter) isCommentLine(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), commentFlag)
}

func (f *LineFomatter) isSubelementCommentLine(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), subelementCommentFlag)
}

func (f *LineFomatter) isTodoCommentLine(line string) bool {
	return (f.isCommentLine(line) && strings.Contains(line, todoFlag))
}

func (f *LineFomatter) keyLineToKeyCommentLine(line string) (string, error) {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("failed to split key line: %s by \":\"", line)
	}
	key := parts[0]
	keyCommentLine := key + keyCommentSuffix + ":"
	return keyCommentLine, nil
}

// TODO remove
func (f *LineFomatter) ignoreSubelementComments(start int) (end int) {
	j := start + 1
	for ; j < len(f.lines); j++ {
		if !f.isCommentLine(f.lines[j]) {
			break
		}
	}
	return j - 1
}

func (f *LineFomatter) convSubelementCommentToSection(start int, result []string) (end int, lines []string, err error) {
	i := start
	subeleCommentFlagLineNum := i
	subeleCommentLines := make([]string, 0)
	var subeleLineNum int
	for ; i < len(f.lines); i++ {
		if !f.isCommentLine(f.lines[i]) {
			return i - 1, result, nil
		}
		if f.isSubelementCommentLine(f.lines[i]) {
			if i == subeleCommentFlagLineNum {
				continue
			} else {
				subeleLineNum = i + 1
				break
			}
		}
		if f.isTodoCommentLine(f.lines[i]) {
			i = f.ignoreTodoComments(i)
			continue
		}
		subeleCommentLines = append(subeleCommentLines, f.indentLine(f.uncommentLine(f.lines[i]), 2))
	}

	subeleKeyCommentLine, err := f.keyLineToKeyCommentLine(f.indentLine(f.uncommentLine(f.lines[subeleLineNum]), 1))
	if err != nil {
		return 0, nil, fmt.Errorf(err.Error()+" at line: %d", i)
	}
	subeleCommentSection := append([]string{subeleKeyCommentLine}, subeleCommentLines...)

	result = append(result, subeleCommentSection...)
	return f.convSubelementCommentToSection(subeleLineNum+1, result)
}

func (f *LineFomatter) ignoreTodoComments(start int) (end int) {
	j := start + 1
	for ; j < len(f.lines); j++ {
		if !f.isTodoCommentLine(f.lines[j]) {
			break
		}
	}
	return j - 1
}

type DynamicOptions map[string]*yaml.Node

type DataFomatter struct {
	keyToComment KeyToComment

	formattedYAMLData []byte // 与 template.yaml 文件格式一致的 yaml 数据
	mapData           map[string]interface{}
	yamlNode          *yaml.Node
}

func NewDataFommatter() *DataFomatter {
	return &DataFomatter{}
}

func (f *DataFomatter) setKeyToComment(keyToComment KeyToComment) {
	f.keyToComment = keyToComment
}

func (f *DataFomatter) LoadMapData(data map[string]interface{}) error {
	f.mapData = data
	yamlData, err := f.mapToYAML()
	if err != nil {
		return fmt.Errorf("convert json to yaml error: %v", err)
	}

	var yamlNode yaml.Node
	err = yaml.Unmarshal(yamlData, &yamlNode)
	if err != nil {
		return fmt.Errorf("unmarshal yaml to node error: %v", err)
	}

	err = f.stringToDictValue(f.mapData, "", f.keyToComment)
	if err != nil {
		return fmt.Errorf("convert dict value to string error: %v", err)
	}
	f.formattedYAMLData, err = f.mapToYAML()
	if err != nil {
		return fmt.Errorf("convert json to yaml error: %v", err)
	}

	return nil
}

func (f *DataFomatter) mapToYAML() ([]byte, error) {
	var buf strings.Builder
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	err := enc.Encode(f.mapData)
	if err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

func (f *DataFomatter) LoadYAMLData(yamlData []byte) error {
	var mapData map[string]interface{}
	err := yaml.Unmarshal(yamlData, &mapData)
	if err != nil {
		return fmt.Errorf("unmarshal data to map error: %v", err)
	}
	var yamlNode yaml.Node
	err = yaml.Unmarshal(yamlData, &yamlNode)
	if err != nil {
		return fmt.Errorf("unmarshal data to yaml node error: %v", err)
	}
	f.mapData = mapData
	f.yamlNode = &yamlNode
	return nil
}

func (f *DataFomatter) mapToJSON(keyToComment KeyToComment) ([]byte, error) {
	err := f.fmtMapValAndRefresh(keyToComment, true)
	if err != nil {
		return nil, fmt.Errorf("convert value and refresh error: %v", err)
	}
	bytes, err := f.formatJson(f.mapData)
	if err != nil {
		return nil, fmt.Errorf("format json error: %v", err)
	}
	return bytes, nil
}

func (f *DataFomatter) fmtMapValAndRefresh(keyToComment KeyToComment, dictValToStr bool) error {
	var err error
	if dictValToStr {
		err = f.dictValueToString(f.mapData, "", keyToComment)
	} else {
		err = f.stringToDictValue(f.mapData, "", keyToComment)
	}
	if err != nil {
		return fmt.Errorf("convert dict value to string error: %v", err)
	}
	// refresh yamlNode if changes dict value
	if _, ok := keyToComment["changesDictValue"]; ok {
		yamlBytes, err := yaml.Marshal(f.mapData)
		if err != nil {
			return fmt.Errorf("marshal map to yaml error: %v", err)
		}
		var yamlNode yaml.Node
		err = yaml.Unmarshal(yamlBytes, &yamlNode)
		if err != nil {
			return fmt.Errorf("unmarshal yaml to node error: %v", err)
		}
		f.yamlNode = &yamlNode
	}
	return nil
}

func (f *DataFomatter) dictValueToString(data interface{}, ancestors string, keyToComment KeyToComment) error {
	switch data := data.(type) {
	case map[string]interface{}:
		for key, value := range data {
			newAncestors := f.appendAncestor(ancestors, key)
			if !f.isKeyComment(key) {
				if f.isDictValue(keyToComment[newAncestors]) {
					valueStr, err := f.dictToString(value)
					if err != nil {
						return fmt.Errorf("convert dict value to string error: %v, key: %s", err, newAncestors)
					}
					data[key] = valueStr
					keyToComment["changesDictValue"] = make(map[string]interface{})
				}
				f.dictValueToString(value, newAncestors, keyToComment)
			}
		}
	default:
		return nil
	}
	return nil
}

func (f *DataFomatter) stringToDictValue(data interface{}, ancestors string, keyToComment KeyToComment) error {
	switch data := data.(type) {
	case map[string]interface{}:
		for key, value := range data {
			newAncestors := f.appendAncestor(ancestors, key)
			if !f.isKeyComment(key) {
				if f.isDictValue(keyToComment[newAncestors]) {
					var valueMap map[string]interface{}
					err := yaml.Unmarshal([]byte(key+":\n"+value.(string)), &valueMap)
					if err != nil {
						return fmt.Errorf("unmarshal string to map error: %v, key: %s", err, newAncestors)
					}
					data[key] = valueMap[key]
					keyToComment["changesDictValue"] = make(map[string]interface{})
				}
				f.stringToDictValue(value, newAncestors, keyToComment)
			}
		}
	default:
		return nil
	}
	return nil
}

func (f *DataFomatter) formatJson(data interface{}) ([]byte, error) {
	indenttedJson, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal json error: %v", err)
	}
	jsonStr := strings.ReplaceAll(string(indenttedJson), ": null", ": []")
	return []byte(jsonStr), nil
}

func (f *DataFomatter) dictToString(data interface{}) (string, error) {
	bytes, err := yaml.Marshal(data)
	return string(bytes), err
}

func (f *DataFomatter) isKeyComment(key string) bool {
	return strings.HasSuffix(key, keyCommentSuffix)
}

func (f *DataFomatter) appendAncestor(ancestor, key string) string {
	key = strings.TrimSuffix(key, keyCommentSuffix)
	if ancestor == "" {
		return key
	}
	return ancestor + "." + key
}

func (f *DataFomatter) isDictValue(comment map[string]interface{}) bool {
	if _, ok := comment["type"]; ok {
		return comment["type"] == "dict"
	}
	return false
}
