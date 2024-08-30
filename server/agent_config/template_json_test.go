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
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseTemplateYAMLToJson(t *testing.T) {
	type args struct {
		yamlData []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "case01",
			args: args{
				yamlData: YamlAgentGroupConfigTemplate,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTemplateYAMLToJson(tt.args.yamlData)
			if (err != nil) != tt.wantErr {
				t.Errorf("err: %v", err)
				t.Errorf("ParseTemplateYAMLToJson() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			fmt.Println(got)
			if err = os.WriteFile("template_2.json", got, os.ModePerm); err != nil {
				t.Fatalf("Failed to write to file: %v", err)
			}
		})
	}
}

func TestIndentAndUncommentTemplate(t *testing.T) {
	type args struct {
		yamlData []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "case01",
			args: args{
				yamlData: YamlAgentGroupConfigTemplate,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indentedLines, err := IndentTemplate(tt.args.yamlData)
			if (err != nil) != tt.wantErr {
				t.Errorf("IndentTemplate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			uncommentedLines, err := UncommentTemplate(indentedLines)
			if (err != nil) != tt.wantErr {
				t.Errorf("UncommentTemplate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err := os.WriteFile("template_formated.yaml", []byte(strings.Join(indentedLines, "\n")), os.ModePerm); err != nil {
				t.Fatalf("Failed to write to file: %v", err)
			}
			if err := os.WriteFile("template_uncommented.yaml", uncommentedLines, os.ModePerm); err != nil {
				t.Fatalf("Failed to write to file: %v", err)
			}
		})
	}
}

func TestParseJsonToYAMLAndValidate(t *testing.T) {
	type args struct {
		jsonData map[string]interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "case01",
			args: args{
				jsonData: map[string]interface{}{
					"global": map[string]interface{}{
						"alerts": map[string]interface{}{
							"check_core_file_disabled": true,
						},
					},
				},
			},
			want: []byte(`global:
  alerts:
    check_core_file_disabled: true
`),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseJsonToYAMLAndValidate(tt.args.jsonData)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseJsonToYAMLAndValidate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.EqualValues(t, string(tt.want), string(got))
			if err = os.WriteFile("template_3.yaml", got, os.ModePerm); err != nil {
				t.Fatalf("Failed to write to file: %v", err)
			}
		})
	}
}
