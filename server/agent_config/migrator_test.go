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
	"reflect"

	"testing"
)

func TestIgnoreSubelementComments(t *testing.T) {
	type args struct {
		yamlData []byte
		start    int
	}
	tests := []struct {
		name    string
		args    args
		want    int
		wantErr bool
	}{
		{
			name: "case01",
			args: args{
				yamlData: []byte(`# type: section
global:
  # type: section
  # ---
  # name:
  #   en: Global
  limits:`),
				start: 3,
			},
			want:    5,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewLineParser(tt.args.yamlData)
			i := parser.ignoreSubelementComments(tt.args.start)
			if i != tt.want {
				t.Errorf("ignoreSubelementComments() = %v, want %v", i, tt.want)
			}
		})
	}
}

func TestIgnoreTodoComments(t *testing.T) {
	type args struct {
		yamlData []byte
		start    int
	}
	tests := []struct {
		name    string
		args    args
		want    int
		wantErr bool
	}{
		{
			name: "case01",
			args: args{
				yamlData: []byte(`# type: section
# TODO: add more fields
global:`),
				start: 0,
			},
			want:    1,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewLineParser(tt.args.yamlData)
			i := parser.ignoreTodoComments(tt.args.start)
			if i != tt.want {
				t.Errorf("ignoreTodoComments() = %v, want %v", i, tt.want)
			}
		})
	}
}

func TestConvCommentToSection(t *testing.T) {
	type args struct {
		yamlData []byte
		start    int
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
				yamlData: []byte(`# type: section
# name:
#   en: Global
# ----
# TODO: add more fields
global:
  # type: section
  # --
  #
  limits:`),
				start: 0,
			},
			want: []string{
				"global_comment:",
				"  type: section",
				"  name:",
				"    en: Global",
			},
			wantErr: false,
		},
		{
			name: "case02",
			args: args{
				yamlData: []byte(`# type: section
# name:
#   en: Global
# ----
# TODO: add more fields
global:
  # type: section
  # ---
  #
  limits:`),
				start: 6,
			},
			want: []string{
				"  limits_comment:",
				"    type: section",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewLineParser(tt.args.yamlData)
			_, detailCommentlines, err := parser.convCommentToSection(tt.args.start)
			if (err != nil) != tt.wantErr {
				t.Errorf("convCommentToSection() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(detailCommentlines) != len(tt.want) {
				t.Errorf("convCommentToSection() = \"%v\", want \"%v\"", detailCommentlines, tt.want)
			}
			for i := 0; i < len(detailCommentlines); i++ {
				if detailCommentlines[i] != tt.want[i] {
					t.Errorf("line %d convCommentToSection() = \"%v\", want \"%v\"", i, detailCommentlines[i], tt.want[i])
				}
			}
		})
	}
}

func TestKeyLineToKeyCommentLine(t *testing.T) {
	type args struct {
		line string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "case01",
			args: args{
				line: "global:",
			},
			want:    "global_comment:",
			wantErr: false,
		},
		{
			name: "case02",
			args: args{
				line: "  limits:",
			},
			want:    "  limits_comment:",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewLineParser([]byte{})
			got, err := parser.keyLineToKeyCommentLine(tt.args.line)
			if (err != nil) != tt.wantErr {
				t.Errorf("keyLineToKeyCommentLine() error = \"%v\", wantErr \"%v\"", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("keyLineToKeyCommentLine() = \"%v\", want \"%v\"", got, tt.want)
			}
		})
	}
}

func TestStripLines(t *testing.T) {
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
				yamlData: []byte(`# type: section
# name:
#   en: Global
# ----
# TODO
global:
  # type: section
  # description: |-
  #
  #   The global section contains global settings.
  limits:`),
			},
			want: []string{
				"global_comment:",
				"  type: section",
				"  name:",
				"    en: Global",
				"gloabl:",
				"  limits_comment:",
				"    type: section",
				"    description: |-",
				"      ",
				"      The global section contains global settings.",
				"  limits:",
			},
		},
		{
			name: "case02",
			args: args{
				yamlData: YamlAgentGroupConfigTemplate,
			},
			want: []string{},
		},
	}
	for _, tt := range tests {
		if tt.name != "case02" {
			continue
		}
		t.Run(tt.name, func(t *testing.T) {
			parser := NewLineParser(tt.args.yamlData)
			lines, err := parser.StripLines()
			if (err != nil) != tt.wantErr {
				t.Errorf("stripLines() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			os.Mkdir("test_tmp", 0755)
			if err := os.WriteFile("test_tmp/stripped_lines.yaml", lines, os.ModePerm); err != nil {
				t.Fatalf("Failed to write to file: %v", err)
			}
		})
	}
}

func TestGenerateUpgradeTargetToSource(t *testing.T) {
	type args struct {
		yamlData []byte
	}
	tests := []struct {
		name    string
		args    args
		want    map[string][]string
		wantErr bool
	}{
		{
			name: "case01",
			args: args{
				yamlData: []byte(`global_comment:
  type: section
global:
  limits_comment:
    type: section
  limits:
    max_millicpus_comment:
      type: int
      upgrade_from: max_millicpus
    max_millicpus: 1000
  alerts_comment:
    type: section
  alerts:
    thread_threshold_comment:
      type: int
      upgrade_from: thread_threshold, static_config.os-proc-sync-thread-threshold
    thread_threshold: 500

inputs_comment:
  type: section
inputs:
  proc_comment:
    type: section
  proc:
    enabled_comment:
      type: bool
      upgrade_from: static_config.os-proc-sync-enabled
    enabled: false`),
			},
			want: map[string][]string{
				"global.limits.max_millicpus":    {"max_millicpus"},
				"global.alerts.thread_threshold": {"thread_threshold", "static_config.os-proc-sync-thread-threshold"},
				"inputs.proc.enabled":            {"static_config.os-proc-sync-enabled"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser, err := NewMigrationDataParser(tt.args.yamlData)
			if err != nil {
				t.Fatalf("Failed to create parser: %v", err)
			}
			parser.Parse()
			if (err != nil) != tt.wantErr {
				t.Errorf("getUpgradeTargetToSource() error = \"%v\", wantErr \"%v\"", err, tt.wantErr)
				return
			}
			if len(parser.targetToSource) != len(tt.want) {
				t.Errorf("getUpgradeTargetToSource() = \"%v\", want \"%v\"", parser.targetToSource, tt.want)
			}
			for k, v := range parser.targetToSource {
				if len(v) != len(tt.want[k]) {
					t.Errorf("field %s getUpgradeTargetToSource() = \"%v\", want \"%v\"", k, v, tt.want[k])
				}
				for i := 0; i < len(v); i++ {
					if v[i] != tt.want[k][i] {
						t.Errorf("field %s %d getUpgradeTargetToSource() = \"%v\", want \"%v\"", k, i, v[i], tt.want[k][i])
					}
				}
			}
		})
	}
}

func TestSetNestedValue(t *testing.T) {
	type args struct {
		data  map[string]interface{}
		key   string
		value interface{}
	}
	tests := []struct {
		name string
		args args
		want map[string]interface{}
	}{
		{
			name: "case01",
			args: args{
				data:  map[string]interface{}{},
				key:   "global.limits.max_millicpus",
				value: 1000,
			},
			want: map[string]interface{}{
				"global": map[string]interface{}{
					"limits": map[string]interface{}{
						"max_millicpus": 1000,
					},
				},
			},
		},
		{
			name: "case02",
			args: args{
				data: map[string]interface{}{
					"global": map[string]interface{}{
						"limits": map[string]interface{}{
							"max_millicpus": 1000,
						},
					},
				},
				key:   "global.alerts.thread_threshold",
				value: 500,
			},
			want: map[string]interface{}{
				"global": map[string]interface{}{
					"limits": map[string]interface{}{
						"max_millicpus": 1000,
					},
					"alerts": map[string]interface{}{
						"thread_threshold": 500,
					},
				},
			},
		},
		{
			name: "case03",
			args: args{
				data: map[string]interface{}{
					"global": map[string]interface{}{
						"limits": map[string]interface{}{
							"max_millicpus": 1000,
						},
						"alerts": map[string]interface{}{
							"thread_threshold": 500,
						},
					},
				},
				key:   "inputs.proc.enabled",
				value: false,
			},
			want: map[string]interface{}{
				"global": map[string]interface{}{
					"limits": map[string]interface{}{
						"max_millicpus": 1000,
					},
					"alerts": map[string]interface{}{
						"thread_threshold": 500,
					},
				},
				"inputs": map[string]interface{}{
					"proc": map[string]interface{}{
						"enabled": false,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			migrator := &Migrator{
				migrationDataParser: &MigrationDataParser{
					sourceToTarget: map[string]string{},
				},
			}
			migrator.setNestedValue(tt.args.data, tt.args.key, tt.args.value)
			if !reflect.DeepEqual(tt.args.data, tt.want) {
				t.Errorf("setNestedValue() = %v, want %v", tt.args.data, tt.want)
			}
		})
	}
}

func TestSourceToTarget(t *testing.T) {
	type args struct {
		sourceToTarget map[string]string
		ancestor       string
		data           interface{}
		result         map[string]interface{}
	}
	tests := []struct {
		name string
		args args
		want map[string]interface{}
	}{
		{
			name: "case01",
			args: args{
				sourceToTarget: map[string]string{
					"max_millicpus":    "global.limits.max_millicpus",
					"thread_threshold": "global.alerts.thread_threshold",
					"static_config.os-proc-sync-thread-threshold": "global.alerts.thread_threshold",
					"static_config.os-proc-sync-enabled":          "inputs.proc.enabled",
				},
				ancestor: "",
				data: map[string]interface{}{
					"max_millicpus":    1000,
					"thread_threshold": 500,
					"static_config": map[string]interface{}{
						"os-proc-sync-thread-threshold": 500,
						"os-proc-sync-enabled":          false,
					},
				},
				result: map[string]interface{}{},
			},
			want: map[string]interface{}{
				"global": map[string]interface{}{
					"limits": map[string]interface{}{
						"max_millicpus": 1000,
					},
					"alerts": map[string]interface{}{
						"thread_threshold": 500,
					},
				},
				"inputs": map[string]interface{}{
					"proc": map[string]interface{}{
						"enabled": false,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			migrator := &Migrator{
				migrationDataParser: &MigrationDataParser{
					sourceToTarget: tt.args.sourceToTarget,
				},
			}
			migrator.sourceToTarget(tt.args.ancestor, tt.args.data, tt.args.result)
			if !reflect.DeepEqual(tt.args.result, tt.want) {
				t.Errorf("sourceToTarget() = %v, want %v", tt.args.result, tt.want)
			}
		})
	}
}

func TestTargetToSource(t *testing.T) {
	type args struct {
		targetToSource map[string][]string
		ancestor       string
		data           interface{}
		result         map[string]interface{}
	}
	tests := []struct {
		name string
		args args
		want map[string]interface{}
	}{
		{
			name: "case01",
			args: args{
				targetToSource: map[string][]string{
					"global.limits.max_millicpus":    {"max_millicpus"},
					"global.alerts.thread_threshold": {"thread_threshold", "static_config.os-proc-sync-thread-threshold"},
					"inputs.proc.enabled":            {"static_config.os-proc-sync-enabled"},
					"inputs.proc.process_matcher":    {"static_config.os-proc-regex"},
				},
				ancestor: "",
				data: map[string]interface{}{
					"global": map[string]interface{}{
						"limits": map[string]interface{}{
							"max_millicpus": 1000,
						},
						"alerts": map[string]interface{}{
							"thread_threshold": 500,
						},
					},
					"inputs": map[string]interface{}{
						"proc": map[string]interface{}{
							"enabled": false,
							"process_matcher": []interface{}{
								map[string]interface{}{
									"match_regex":       "deepflow-*",
									"only_in_container": false,
									"enabled_features": []interface{}{
										"ebpf.profile.on_cpu",
										"ebpf.profile.off_cpu",
										"proc.gprocess_info",
									},
								},
							},
						},
					},
				},
				result: map[string]interface{}{},
			},
			want: map[string]interface{}{
				"max_millicpus":    1000,
				"thread_threshold": 500,
				"static_config": map[string]interface{}{
					"os-proc-sync-thread-threshold": 500,
					"os-proc-sync-enabled":          false,
					"os-proc-regex": []interface{}{
						map[string]interface{}{
							"match_regex":       "deepflow-*",
							"only_in_container": false,
							"enabled_features": []interface{}{
								"ebpf.profile.on_cpu",
								"ebpf.profile.off_cpu",
								"proc.gprocess_info",
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			migrator := &Migrator{
				migrationDataParser: &MigrationDataParser{
					targetToSource: tt.args.targetToSource,
				},
			}
			migrator.targetToSource(tt.args.ancestor, tt.args.data, tt.args.result)
			if !reflect.DeepEqual(tt.args.result, tt.want) {
				t.Errorf("targetToSource() = %v, want %v", tt.args.result, tt.want)
			}
		})
	}
}
