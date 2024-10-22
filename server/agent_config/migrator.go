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

	"github.com/baidubce/bce-sdk-go/util/log"
	"gopkg.in/yaml.v3"
)

const (
	commentFlag           = "#"
	subelementCommentFlag = "# ---"
	todoFlag              = "TODO"

	templateIndent = "  "
)

type Migrator struct {
	lineParser          *LineParser
	migrationDataParser *MigrationDataParser
}

func NewMigrator(bytes []byte) (*Migrator, error) {
	lineParser := NewLineParser(bytes)
	strippedBytes, err := lineParser.StripLines()
	if err != nil {
		return nil, err
	}
	migrationDataParser, err := NewMigrationDataParser(strippedBytes)
	if err != nil {
		return nil, err
	}
	migrationDataParser.Parse()
	return &Migrator{
		lineParser:          lineParser,
		migrationDataParser: migrationDataParser,
	}, nil
}

func (m *Migrator) Upgrade(bytes []byte) ([]byte, error) {
	data := make(map[string]interface{})
	err := yaml.Unmarshal(bytes, &data)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to unmarshal yaml: %v to map", err)
	}
	result := make(map[string]interface{})
	m.sourceToTarget("", data, result)
	upgradedBytes, err := yaml.Marshal(result)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to marshal map: %v to yaml", err)
	}
	return upgradedBytes, nil
}

func (m *Migrator) sourceToTarget(ancestor string, data interface{}, result map[string]interface{}) {
	switch data := data.(type) {
	case map[string]interface{}:
		for key, value := range data {
			newAncestor := key
			if ancestor != "" {
				newAncestor = ancestor + "." + key
			}
			if target, ok := m.migrationDataParser.sourceToTarget[newAncestor]; ok {
				sources := m.migrationDataParser.targetToSource[target]
				if len(sources) > 1 {
					for _, source := range sources {
						log.Warnf("%s has been upgraded to %s", source, target) // TODO return?
					}
				} else {
					m.setNestedValue(result, target, value)
				}
			}
			m.sourceToTarget(newAncestor, value, result)
		}
	default:
		return
	}
}

func (m *Migrator) targetToSource(ancestor string, data interface{}, result map[string]interface{}) {
	switch data := data.(type) {
	case map[string]interface{}:
		for key, value := range data {
			newAncestor := key
			if ancestor != "" {
				newAncestor = ancestor + "." + key
			}
			if sources, ok := m.migrationDataParser.targetToSource[newAncestor]; ok {
				for _, source := range sources {
					m.setNestedValue(result, source, value)
				}
			}
			m.targetToSource(newAncestor, value, result)
		}
	default:
		return
	}
}

func (m *Migrator) setNestedValue(data map[string]interface{}, key string, value interface{}) {
	keys := strings.Split(key, ".")
	for i := 0; i < len(keys)-1; i++ {
		if _, ok := data[keys[i]]; !ok {
			data[keys[i]] = make(map[string]interface{})
		}
		data = data[keys[i]].(map[string]interface{})
	}
	data[keys[len(keys)-1]] = value
}

type MigrationDataParser struct {
	templJsonData  map[string]interface{}
	targetToSource map[string][]string
	sourceToTarget map[string]string

	// dictTargets []string
}

func NewMigrationDataParser(bytes []byte) (*MigrationDataParser, error) {
	p := &MigrationDataParser{
		targetToSource: make(map[string][]string),
		sourceToTarget: make(map[string]string),
	}
	err := yaml.Unmarshal(bytes, &p.templJsonData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal json: %v to map", err)
	}
	return p, nil
}

func (p *MigrationDataParser) Parse() {
	p.generateTargetToSource("", p.templJsonData)
	for target, sources := range p.targetToSource {
		for _, source := range sources {
			p.sourceToTarget[source] = target
		}
	}
}

func (p *MigrationDataParser) generateTargetToSource(ansenstor string, data interface{}) {
	switch data := data.(type) {
	case map[string]interface{}:
		for key, value := range data {
			if strings.HasSuffix(key, keyCommentSuffix) {
				rawKey := strings.TrimSuffix(key, keyCommentSuffix)
				newAncetor := rawKey
				if ansenstor != "" {
					newAncetor = ansenstor + "." + rawKey
				}
				commentValue := value.(map[string]interface{})
				if upgradeFrom, ok := commentValue["upgrade_from"]; ok {
					upgradeFroms := strings.Split(upgradeFrom.(string), ", ")
					p.targetToSource[newAncetor] = upgradeFroms
				}
			} else {
				newAncetor := key
				if ansenstor != "" {
					newAncetor = ansenstor + "." + key
				}
				p.generateTargetToSource(newAncetor, value)
			}
		}
	default:
		return
	}
}

type LineParser struct {
	lines []string
}

func NewLineParser(bytes []byte) *LineParser {
	return &LineParser{
		lines: strings.Split(string(bytes), "\n"),
	}
}

func (p *LineParser) StripLines() ([]byte, error) {
	strippedLines := make([]string, 0)
	for i := 0; i < len(p.lines); i++ {
		if p.isCommentLine(p.lines[i]) {
			end, lines, err := p.convCommentToSection(i)
			if err != nil {
				return []byte{}, err
			}
			strippedLines = append(strippedLines, lines...)
			i = end
			continue
		}
		strippedLines = append(strippedLines, p.lines[i])
	}
	return []byte(strings.Join(strippedLines, "\n")), nil
}

func (p *LineParser) convCommentToSection(start int) (end int, commentlines []string, err error) {
	i := start
	for ; i < len(p.lines); i++ {
		if !p.isCommentLine(p.lines[i]) {
			break
		}
		if p.isSubelementCommentLine(p.lines[i]) {
			i = p.ignoreSubelementComments(i)
			continue
		}
		if p.isTodoCommentLine(p.lines[i]) {
			i = p.ignoreTodoComments(i)
			continue
		}
		commentlines = append(commentlines, p.indentLine(p.uncommentLine(p.lines[i])))
	}

	keyCommentLine, err := p.keyLineToKeyCommentLine(p.lines[i])
	if err != nil {
		return 0, nil, fmt.Errorf(err.Error()+" at line: %d", i)
	}
	return i - 1, append([]string{keyCommentLine}, commentlines...), nil
}

func (p *LineParser) indentLine(line string) string {
	return templateIndent + line
}

func (p *LineParser) uncommentLine(line string) string {
	line = strings.Replace(line, commentFlag+" ", "", 1)
	if p.isCommentLine(line) {
		line = strings.Replace(line, commentFlag, "", 1)
	}
	return line
}

func (p *LineParser) isCommentLine(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), commentFlag)
}

func (p *LineParser) isSubelementCommentLine(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), subelementCommentFlag)
}

func (p *LineParser) isTodoCommentLine(line string) bool {
	return (p.isCommentLine(line) && strings.Contains(line, todoFlag))
}

func (p *LineParser) keyLineToKeyCommentLine(line string) (string, error) {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("failed to split key line: %s by \":\"", line)
	}
	key := parts[0]
	keyCommentLine := key + keyCommentSuffix + ":"
	return keyCommentLine, nil
}

func (p *LineParser) ignoreSubelementComments(start int) (end int) {
	j := start + 1
	for ; j < len(p.lines); j++ {
		if !p.isCommentLine(p.lines[j]) {
			break
		}
	}
	return j - 1
}

func (p *LineParser) ignoreTodoComments(start int) (end int) {
	j := start + 1
	for ; j < len(p.lines); j++ {
		if !p.isTodoCommentLine(p.lines[j]) {
			break
		}
	}
	return j - 1
}
