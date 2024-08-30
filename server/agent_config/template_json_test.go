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
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestParseYAMLToJson(t *testing.T) {
	l7Protocols := []string{
		"HTTP", "HTTP2", "Dubbo", "gRPC", "SOFARPC", "FastCGI", "bRPC", "Tars", "Some/IP", "MySQL", "PostgreSQL",
		"Oracle", "Redis", "MongoDB", "Kafka", "MQTT", "AMQP", "OpenWire", "NATS", "Pulsar", "ZMTP", "DNS", "TLS", "Custom"}
	l7ProtocolsYamlBytes, err := yaml.Marshal(l7Protocols)
	if err != nil {
		t.Fatalf("Failed to marshal l7Protocols: %v", err)
	}
	var l7ProtocolsNode yaml.Node
	if err := yaml.Unmarshal(l7ProtocolsYamlBytes, &l7ProtocolsNode); err != nil {
		t.Fatalf("Failed to unmarshal l7Protocols: %v", err)
	}
	domainKeyToInfo := []map[string]interface{}{
		{
			"1": map[string]interface{}{
				"ch": "aliyun",
				"en": "aliyun",
			},
		},
		{
			"2": map[string]interface{}{
				"ch": "openstack",
				"en": "openstack",
			},
		},
	}
	domainKeyToInfoYamlBytes, err := yaml.Marshal(domainKeyToInfo)
	if err != nil {
		t.Fatalf("Failed to marshal domainKeyToInfo: %v", err)
	}
	var domainInfoNode yaml.Node
	if err := yaml.Unmarshal(domainKeyToInfoYamlBytes, &domainInfoNode); err != nil {
		t.Fatalf("Failed to unmarshal domainKeyToInfo: %v", err)
	}
	tapTypeInfo := []map[string]interface{}{
		{
			"1": map[string]interface{}{
				"ch": "test1",
				"en": "test1",
			},
		},
		{
			"2": map[string]interface{}{
				"ch": "test2",
				"en": "test2",
			},
		},
	}
	tapTypeInfoYamlBytes, err := yaml.Marshal(tapTypeInfo)
	if err != nil {
		t.Fatalf("Failed to marshal tapTypeInfo: %v", err)
	}
	var tapTypeInfoNode yaml.Node
	if err := yaml.Unmarshal(tapTypeInfoYamlBytes, &tapTypeInfoNode); err != nil {
		t.Fatalf("Failed to unmarshal tapTypeInfo: %v", err)
	}
	// fmt.Printf("tapTypeInfoNode: %#v\n", tapTypeInfoNode.Content[0])

	dynamicOptions := DynamicOptions{
		"inputs.cbpf.physical_mirror.default_capture_network_type_comment.enum_options":        tapTypeInfoNode.Content[0],
		"inputs.resources.pull_resource_from_controller.domain_filter_comment.enum_options":    domainInfoNode.Content[0],
		"inputs.ebpf.socket.preprocess.out_of_order_reassembly_protocols_comment.enum_options": l7ProtocolsNode.Content[0],
	}
	type args struct {
		yamlData    []byte
		dynamicOpts DynamicOptions
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "case01",
			args: args{
				yamlData:    YamlAgentGroupConfigTemplate,
				dynamicOpts: dynamicOptions,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseYAMLToJson(tt.args.yamlData, tt.args.dynamicOpts)
			if (err != nil) != tt.wantErr {
				t.Errorf("err: %v", err)
				t.Errorf("ParseYAMLToJson() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err = os.WriteFile("json_tmpl.json", got, os.ModePerm); err != nil {
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
						"common": map[string]interface{}{
							"enabled": false,
						},
						"alerts": map[string]interface{}{
							"check_core_file_disabled": true,
						},
					},
				},
			},
			want: []byte(`global:
  common:
    enabled: false
  alerts:
    check_core_file_disabled: true
`),
			wantErr: false,
		},
		{
			name: "case02",
			args: args{
				jsonData: map[string]interface{}{
					"inputs": map[string]interface{}{
						"resources": map[string]interface{}{
							"kubernetes": map[string]interface{}{
								"api_resources": "- name: namespaces\n- name: nodes\n",
							},
						},
					},
				},
			},
			want: []byte(`inputs:
  resources:
    kubernetes:
	  api_resources: 
	  - name: namespaces
	  - name: nodes
`),
			wantErr: false,
		},
		{
			name: "case03",
			args: args{
				jsonData: map[string]interface{}{
					"inputs": map[string]interface{}{
						"ebpf": map[string]interface{}{
							"socket": map[string]interface{}{
								"preprocess": map[string]interface{}{
									"out_of_order_reassembly_protocols": []string{
										"HTTP",
										"Dubbo",
										"SOFARPC",
									},
								},
							},
						},
					},
				},
			},
			want: []byte(`inputs:
  ebpf:
    socket:
	  preprocess:
	    out_of_order_reassembly_protocols:
		- HTTP
		- Dubbo
		- SOFARPC
`),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		// if tt.name != "case03" {
		// 	continue
		// }
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
