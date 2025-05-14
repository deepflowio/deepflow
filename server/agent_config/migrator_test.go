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
	"reflect"
	"strings"

	"testing"
)

func TestUpgrade(t *testing.T) {
	type args struct {
		bytes []byte
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
				bytes: []byte(`max_millicpus: 1000
static_config:
  os-proc-regex:
    - match-regex: deepflow-.*
    - match-regex: deepflow-server.*
      action: drop
  l7-log-blacklist:
    HTTP:
        - field-name: HTTP
          value: HTTP
    HTTP2:
        - field-name: HTTP2-1
`),
			},
			want: []byte(`global:
  limits:
    max_millicpus: 1000
inputs:
  proc:
    process_matcher:
      - match_regex: deepflow-.*
      - ignore: true
        match_regex: deepflow-server.*
processors:
  request_log:
    filters:
      tag_filters:
        HTTP:
          - field_name: HTTP
            field_value: HTTP
        HTTP2:
          - field_name: HTTP2-1
`),
			wantErr: false,
		},
		{
			name: "case02",
			args: args{
				bytes: []byte(`max_collectpps: 10000
max_cpus: 50
max_memory: 500000
tap_interface_regex: enp26s0f1|enp95s0f0
npp_dedup_enabled: 1
l4_log_collect_nps_threshold: 1000000
l7_log_collect_nps_threshold: 1000000
capture_socket_type: 0
tap_mode: 2
decap_type: 0
external_agent_http_proxy_enabled: 0

static_config:
  afpacket-blocks-enabled: true
  afpacket-blocks: 128
  analyzer-dedup-disabled: true
  src-interfaces:
    - tap-bid-0
    - tap-bid-1
    - tap-bid-2
    - tap-bid-3
    - tap-bid-4
    - tap-bid-5
    - tap-bid-6
    - tap-bid-7
  cloud-gateway-traffic: true
  flow:
    flow-slots-size: 500000
    flow-count-limit: 20000000
    flow-queue-size: 256000
    quadruple-queue-size: 512000
    analyzer-queue-size: 256000
  xflow-collector:
    slow-ports:
      - "6343"
    netflow-ports:
      - "2056"
  collector-sender-queue-size: 512000
  collector-sender-queue-count: 8
  total-sender-queue-size: 256000
  flow-sender-queue-size: 512000
  flow-sender-queue-count: 8
  packet-sequence-flag: 128
  l7-protocol-enabled:
    - HTTP
    - DNS
    - MySQL
  forward-capacity: 300000`),
			},
		},
		{
			name: "case03_1",
			args: args{
				bytes: []byte(`os-proc-sync-tagged-only: true

static_config:
  ebpf:
    uprobe-process-name-regexs:
      golang-symbol: deepflow-.*`),
			},
			want: []byte(`inputs:
  proc:
    process_matcher:
      - match_regex: deepflow-.*
        only_with_tag: true
    symbol_table:
      golang_specific:
        enabled: true
`),
		},
		{
			name: "case03_2",
			args: args{
				bytes: []byte(`os-proc-sync-tagged-only: true`),
			},
			want: []byte(`{}
`),
		},
		{
			name: "case03_3",
			args: args{
				bytes: []byte(`os-proc-sync-tagged-only: true

static_config:
  os-proc-regex:
    - match-regex: test-.*
  ebpf:
    uprobe-process-name-regexs:
      golang-symbol: deepflow-.*`),
			},
			want: []byte(`inputs:
  proc:
    process_matcher:
      - match_regex: test-.*
        only_with_tag: true
      - match_regex: deepflow-.*
        only_with_tag: true
    symbol_table:
      golang_specific:
        enabled: true
`),
		},
		{
			name: "case03_4",
			args: args{
				bytes: []byte(`os-proc-sync-tagged-only: false

static_config:
  os-proc-regex:
    - match-regex: test-.*`),
			},
			want: []byte(`inputs:
  proc:
    process_matcher:
      - match_regex: test-.*
        only_with_tag: false
`),
		},
		{
			name: "case03_5",
			args: args{
				bytes: []byte(`static_config:
  os-proc-regex:
    - match-regex: test-.*`),
			},
			want: []byte(`inputs:
  proc:
    process_matcher:
      - match_regex: test-.*
`),
		},
		{
			name: "case03_6",
			args: args{
				bytes: []byte(`static_config:
  ebpf:
    uprobe-process-name-regexs:
      golang-symbol: deepflow-.*`),
			},
			want: []byte(`inputs:
  proc:
    process_matcher:
      - match_regex: deepflow-.*
    symbol_table:
      golang_specific:
        enabled: true
`),
		},
		{
			name: "case03_7",
			args: args{
				bytes: []byte(`static_config:
  ebpf:
    on-cpu-profile:
      regex: on-cpu-profile-.*`),
			},
			want: []byte(`inputs:
  proc:
    process_matcher:
      - enabled_features:
          - ebpf.profile.on_cpu
        match_regex: on-cpu-profile-.*
`),
		},
		{
			name: "case03_8",
			args: args{
				bytes: []byte(`os-proc-sync-tagged-only: true
static_config:
  ebpf:
    on-cpu-profile:
      regex: on-cpu-profile-.*
    off-cpu-profile:
      regex: off-cpu-profile-.*`),
			},
			want: []byte(`inputs:
  proc:
    process_matcher:
      - enabled_features:
          - ebpf.profile.on_cpu
        match_regex: on-cpu-profile-.*      
        only_with_tag: true
      - enabled_features:
          - ebpf.profile.off_cpu
        match_regex: off-cpu-profile-.*
        only_with_tag: true
`),
		},
	}
	for _, tt := range tests {
		if !strings.HasPrefix(tt.name, "case03") {
			continue
		}
		t.Run(tt.name, func(t *testing.T) {
			toolData, err := NewMigrationToolData(nil)
			if err != nil {
				t.Fatalf("Failed to create toolData: %v", err)
				return
			}
			migrator := newUpgrader(toolData)
			got, err := migrator.Upgrade(tt.args.bytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("Upgrade() error = \"%v\", wantErr \"%v\"", err, tt.wantErr)
				return
			}
			os.Mkdir("test_tmp", 0755)
			if err := os.WriteFile(fmt.Sprintf("test_tmp/upgrade_%s.yaml", tt.name), got, os.ModePerm); err != nil {
				t.Fatalf("Failed to write to file: %v", err)
			}
			if err := os.WriteFile(fmt.Sprintf("test_tmp/upgrade_%s_want.yaml", tt.name), tt.want, os.ModePerm); err != nil {
				t.Fatalf("Failed to write to file: %v", err)
			}
			if string(got) != string(tt.want) {
				t.Errorf("Upgrade() = \"%v\", want \"%v\"", string(got), string(tt.want))
			}
		})
	}
}

func TestDowngrade(t *testing.T) {
	type args struct {
		bytes []byte
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
				bytes: []byte(`global:
  limits:
    max_millicpus: 1000
inputs:
  proc:
    process_matcher:
      - match_regex: deepflow-.*
      - ignore: true
        match_regex: deepflow-server.*
processors:
  request_log:
    filters:
      tag_filters:
        HTTP:
          - field_name: HTTP
            field_value: HTTP
        HTTP2:
          - field_name: HTTP2-1
`),
			},
			want: []byte(`max_millicpus: 1000
static_config:
  os-proc-regex:
    - match-regex: deepflow-.*
    - match-regex: deepflow-server.*
      action: drop
  l7-log-blacklist:
    HTTP:
      - field-name: HTTP
        value: HTTP
    HTTP2:
      - field-name: HTTP2-1
`),
			wantErr: false,
		},
		{
			name: "case02",
			args: args{
				bytes: []byte(`inputs:
  cbpf:
    af_packet:
      bond_interfaces:
        - slave_interfaces:
            - eth0
            - eth1
`),
			},
			want: []byte(`static_config:
  tap-interface-bond-groups:
    - tap-interfaces:
        - eth0
        - eth1
`),
			wantErr: false,
		},
		{
			name: "case03",
			args: args{
				bytes: []byte(`processors:
  request_log:
    tag_extraction:
      tracing_tag:
        x_request_id:
        - X-Request-Id
        - X-Request-ID
`),
			},
			want: []byte(`http_log_x_request_id: X-Request-Id, X-Request-ID
`),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		if tt.name != "case03" {
			continue
		}
		t.Run(tt.name, func(t *testing.T) {
			toolData, err := NewMigrationToolData(nil)
			if err != nil {
				t.Fatalf("Failed to create toolData: %v", err)
				return
			}
			migrator := &Downgrader{
				MigrationToolData: toolData,
			}
			got, err := migrator.Downgrade(tt.args.bytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("Upgrade() error = \"%v\", wantErr \"%v\"", err, tt.wantErr)
				return
			}
			os.Mkdir("test_tmp", 0755)
			if err := os.WriteFile(fmt.Sprintf("test_tmp/downgrade_%s.yaml", tt.name), got, os.ModePerm); err != nil {
				t.Fatalf("Failed to write to file: %v", err)
			}
			if err := os.WriteFile(fmt.Sprintf("test_tmp/downgrade_%s_want.yaml", tt.name), tt.want, os.ModePerm); err != nil {
				t.Fatalf("Failed to write to file: %v", err)
			}
			if string(got) != string(tt.want) {
				t.Errorf("Upgrade() = \"%v\", want \"%v\"", string(got), string(tt.want))
			}
		})
	}
}

func TestFmtHigherVersionValue(t *testing.T) {
	type args struct {
		longKey    string
		value      interface{}
		domainData *DomainData
	}
	tests := []struct {
		name string
		args args
		want interface{}
	}{
		{
			name: "case01",
			args: args{
				longKey:    "global.tunning.cpu_affinity",
				value:      []interface{}{1, 2, 3},
				domainData: &DomainData{},
			},
			want: "1,2,3",
		},
		{
			name: "case02",
			args: args{
				longKey: "inputs.resources.pull_resource_from_controller.domain_filter",
				value:   []interface{}{1, 2},
				domainData: &DomainData{
					IDToLcuuid: map[int]string{
						1: "lcuuid1",
						2: "lcuuid2",
					},
				},
			},
			want: []string{"lcuuid1", "lcuuid2"},
		},
		{
			name: "case03",
			args: args{
				longKey:    "global.tunning.cpu_affinity",
				value:      []int{1, 2, 3},
				domainData: &DomainData{},
			},
			want: "1,2,3",
		},
		{
			name: "case04",
			args: args{
				longKey: "inputs.resources.pull_resource_from_controller.domain_filter",
				value:   []int{1, 2},
				domainData: &DomainData{
					IDToLcuuid: map[int]string{
						1: "lcuuid1",
						2: "lcuuid2",
					},
				},
			},
			want: []string{"lcuuid1", "lcuuid2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			migrator := &Downgrader{}
			migrator.domainData = tt.args.domainData
			got := migrator.fmtHigherVersionValue(tt.args.longKey, tt.args.value)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fmtHigherVersionValue() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFmtLowerVersionValue(t *testing.T) {
	type args struct {
		longKey    string
		value      interface{}
		domainData *DomainData
	}
	tests := []struct {
		name string
		args args
		want interface{}
	}{
		{
			name: "case01",
			args: args{
				longKey:    "static_config.cpu-affinity",
				value:      "1,2,3",
				domainData: &DomainData{},
			},
			want: []int{1, 2, 3},
		},
		{
			name: "case02",
			args: args{
				longKey: "domains",
				value:   []string{"lcuuid1", "lcuuid2"},
				domainData: &DomainData{
					LcuuidToID: map[string]int{
						"lcuuid1": 1,
						"lcuuid2": 2,
					},
				},
			},
			want: []int{1, 2},
		},
		{
			name: "case04",
			args: args{
				longKey: "domains",
				value:   []interface{}{"lcuuid1", "lcuuid2"},
				domainData: &DomainData{
					LcuuidToID: map[string]int{
						"lcuuid1": 1,
						"lcuuid2": 2,
					},
				},
			},
			want: []int{1, 2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			migrator := &Upgrader{}
			migrator.domainData = tt.args.domainData
			got := migrator.fmtLowerVersionValue(tt.args.longKey, tt.args.value)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fmtLowerVersionValue() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateUpgradeHigherToLower(t *testing.T) {
	type args struct {
	}
	tests := []struct {
		name    string
		args    args
		want    map[string][]string
		wantErr bool
	}{
		{
			name: "case01",
			args: args{},
			want: map[string][]string{
				"global.limits.max_millicpus":              {"max_millicpus"},
				"global.alerts.thread_threshold":           {"thread_threshold"},
				"inputs.proc.enabled":                      {"static_config.os-proc-sync-enabled"},
				"inputs.ebpf.socket.uprobe.golang.enabled": {"static_config.ebpf.uprobe-golang-trace-enabled", "static_config.ebpf.uprobe-process-name-regexs.golang"},
			},
			wantErr: false,
		},
		{
			name: "case02",
			args: args{},
			want: map[string][]string{
				"inputs.proc.process_matcher":           {"static_config.os-proc-regex"},
				"inputs.cbpf.af_packet.bond_interfaces": {"static_config.tap-interface-bond-groups"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		if tt.name != "case02" {
			continue
		}
		t.Run(tt.name, func(t *testing.T) {
			fmtt, err := NewMigrationToolData(nil)
			if err != nil {
				t.Fatalf("Failed to create parser: %v", err)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("getHigherToLowers() error = \"%v\", wantErr \"%v\"", err, tt.wantErr)
				return
			}
			for k, v := range tt.want {
				if len(v) != len(fmtt.higherVerToLowerVerKeys[k]) {
					t.Errorf("field %s getHigherToLowers() = \"%v\", want \"%v\"", k, v, tt.want[k])
				}
				for i := 0; i < len(v); i++ {
					if v[i] != fmtt.higherVerToLowerVerKeys[k][i] {
						t.Errorf("field %s %d getHigherToLowers() = \"%v\", want \"%v\"", k, i, v[i], tt.want[k][i])
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
			dictConv := &dictDataConv{}
			dictConv.setNestedValue(tt.args.data, tt.args.key, tt.args.value)
			if !reflect.DeepEqual(tt.args.data, tt.want) {
				t.Errorf("setNestedValue() = %v, want %v", tt.args.data, tt.want)
			}
		})
	}
}

func TestLowerToHigher(t *testing.T) {
	type args struct {
		lowerToHigher           map[string]string
		dictValLowerKeyToHigher map[string]map[string]interface{}
		ancestor                string
		data                    interface{}
		result                  map[string]interface{}
	}
	tests := []struct {
		name string
		args args
		want map[string]interface{}
	}{
		{
			name: "case01",
			args: args{
				lowerToHigher: map[string]string{
					"max_millicpus":    "global.limits.max_millicpus",
					"thread_threshold": "global.alerts.thread_threshold",
					"static_config.os-proc-sync-thread-threshold": "global.alerts.thread_threshold",
					"static_config.os-proc-sync-enabled":          "inputs.proc.enabled",
				},
				dictValLowerKeyToHigher: map[string]map[string]interface{}{},
				ancestor:                "",
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
		{
			name: "case02",
			args: args{
				lowerToHigher: map[string]string{
					"static_config.tap-interface-bond-groups": "inputs.cbpf.af_packet.bond_interfaces",
				},
				dictValLowerKeyToHigher: map[string]map[string]interface{}{
					"static_config.tap-interface-bond-groups": {
						"tap-interfaces": "slave_interfaces",
					},
				},
				ancestor: "",
				data: map[string]interface{}{
					"static_config": map[string]interface{}{
						"tap-interface-bond-groups": []interface{}{
							map[string]interface{}{
								"tap-interfaces": []string{"eth0", "eth1"},
							},
							map[string]interface{}{
								"tap-interfaces": []string{"eth2", "eth3"},
							},
						},
					},
				},
				result: map[string]interface{}{},
			},
			want: map[string]interface{}{
				"inputs": map[string]interface{}{
					"cbpf": map[string]interface{}{
						"af_packet": map[string]interface{}{
							"bond_interfaces": []map[string]interface{}{
								{
									"slave_interfaces": []string{"eth0", "eth1"},
								},
								{
									"slave_interfaces": []string{"eth2", "eth3"},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		// if tt.name != "case02" {
		// 	continue
		// }
		t.Run(tt.name, func(t *testing.T) {
			migrator := &Upgrader{
				MigrationToolData: MigrationToolData{
					lowerVerToHigherVerKey:  tt.args.lowerToHigher,
					dictValLowerKeyToHigher: tt.args.dictValLowerKeyToHigher,
				},
			}
			migrator.lowerToHigher(tt.args.data, tt.args.ancestor, tt.args.result)
			if !reflect.DeepEqual(tt.args.result, tt.want) {
				t.Errorf("sourceToTarget() = %#v, want %#v", tt.args.result, tt.want)
			}
		})
	}
}

func TestHigherToLower(t *testing.T) {
	type args struct {
		higherToLower           map[string][]string
		dictValHigherKeyToLower map[string]map[string]interface{}
		ancestor                string
		data                    interface{}
		result                  map[string]interface{}
	}
	tests := []struct {
		name string
		args args
		want map[string]interface{}
	}{
		{
			name: "case01",
			args: args{
				higherToLower: map[string][]string{
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
		{
			name: "case02",
			args: args{
				higherToLower: map[string][]string{
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
									"match-regex":       "deepflow-*",
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
							"match-regex":       "deepflow-*",
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
		{
			name: "case03",
			args: args{
				higherToLower: map[string][]string{
					"processors.request_log.tag_extraction.custom_fields": {"static_config.l7-protocol-advanced-features.extra-log-fields"},
				},
				dictValHigherKeyToLower: map[string]map[string]interface{}{
					"processors.request_log.tag_extraction.custom_fields": {
						"field_name": "field-name",
					},
				},
				ancestor: "",
				data: map[string]interface{}{
					"processors": map[string]interface{}{
						"request_log": map[string]interface{}{
							"tag_extraction": map[string]interface{}{
								"custom_fields": map[string]interface{}{
									"HTTP": []map[string]interface{}{
										{
											"field_name": "HTTP",
										},
									},
								},
							},
						},
					},
				},
				result: map[string]interface{}{},
			},
			want: map[string]interface{}{
				"static_config": map[string]interface{}{
					"l7-protocol-advanced-features": map[string]interface{}{
						"extra-log-fields": map[string]interface{}{
							"HTTP": []map[string]interface{}{
								{
									"field-name": "HTTP",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "case04",
			args: args{
				higherToLower: map[string][]string{
					"inputs.cbpf.af_packet.bond_interfaces": {"static_config.tap-interface-bond-groups"},
				},
				dictValHigherKeyToLower: map[string]map[string]interface{}{
					"inputs.cbpf.af_packet.bond_interfaces": {
						"slave_interfaces": "tap-interfaces",
					},
				},
				ancestor: "",
				data: map[string]interface{}{
					"inputs": map[string]interface{}{
						"cbpf": map[string]interface{}{
							"af_packet": map[string]interface{}{
								"bond_interfaces": []map[string]interface{}{
									{
										"slave_interfaces": []string{"eth0", "eth1"},
									},
									{
										"slave_interfaces": []string{"eth2", "eth3"},
									},
								},
							},
						},
					},
				},
				result: map[string]interface{}{},
			},
			want: map[string]interface{}{
				"static_config": map[string]interface{}{
					"tap-interface-bond-groups": []map[string]interface{}{
						{
							"tap-interfaces": []string{"eth0", "eth1"},
						},
						{
							"tap-interfaces": []string{"eth2", "eth3"},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		if tt.name != "case04" {
			continue
		}
		t.Run(tt.name, func(t *testing.T) {
			migrator := &Downgrader{
				MigrationToolData: MigrationToolData{
					higherVerToLowerVerKeys: tt.args.higherToLower,
					dictValHigherKeyToLower: tt.args.dictValHigherKeyToLower,
				},
			}
			migrator.higherToLower(tt.args.data, tt.args.ancestor, tt.args.result)
			if !reflect.DeepEqual(tt.args.result, tt.want) {
				t.Errorf("targetToSource() = %v, want %v", tt.args.result, tt.want)
			}
		})
	}
}

func TestConvDictDataKey(t *testing.T) {
	type args struct {
		data    map[string]interface{}
		convMap map[string]interface{}
		longKey string
	}
	tests := []struct {
		name string
		args args
		want map[string]interface{}
	}{
		{
			name: "case01",
			args: args{
				data: map[string]interface{}{
					"match_regex": "deepflow-*",
					"ignore":      false,
				},
				convMap: map[string]interface{}{
					"match_regex":  "match-regex",
					"match_type":   "match-type",
					"ignore":       "action",
					"rewrite_name": "rewrite-name",
				},
				longKey: "inputs.proc.process_matcher",
			},
			want: map[string]interface{}{
				"match-regex": "deepflow-*",
				"action":      "accept",
			},
		},
		{
			name: "case02",
			args: args{
				data: map[string]interface{}{
					"field-name": "test",
					"value":      "test",
				},
				convMap: map[string]interface{}{
					"field-name": "field_name",
					"operator":   "operator",
					"value":      "field_value",
				},
				longKey: "static_config.l7-log-blacklist",
			},
			want: map[string]interface{}{
				"field_name":  "test",
				"field_value": "test",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			migrator := &dictDataConv{}
			got := migrator.convDictDataKey(tt.args.data, tt.args.convMap, tt.args.longKey)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("convDictDataKey() = %v, want %v", tt.args.data, tt.want)
			}
		})
	}
}

func TestConvDictDataValue(t *testing.T) {
	type args struct {
		data    interface{}
		convMap map[string]interface{}
		longKey string
	}
	tests := []struct {
		name string
		args args
		want interface{}
	}{
		{
			name: "case01",
			args: args{
				data: []interface{}{
					map[string]interface{}{
						"match-regex": "deepflow-*",
						"action":      "drop",
					},
					map[string]interface{}{
						"match-regex":  "deepflow-*",
						"rewrite-name": "deepflow",
					},
				},
				convMap: map[string]interface{}{
					"match-regex":  "match_regex",
					"match-type":   "match_type",
					"action":       "ignore",
					"rewrite-name": "rewrite_name",
				},
				longKey: "static_config.os-proc-regex",
			},
			want: []map[string]interface{}{
				{
					"match_regex": "deepflow-*",
					"ignore":      true,
				},
				{
					"match_regex":  "deepflow-*",
					"rewrite_name": "deepflow",
				},
			},
		},
		{
			name: "case02",
			args: args{
				data: map[string]interface{}{
					"HTTP": []interface{}{
						map[string]interface{}{
							"field_name":  "HTTP",
							"field_value": "HTTP",
						},
					},
					"HTTP2": []interface{}{
						map[string]interface{}{
							"field_name":  "HTTP2-1",
							"field_value": "HTTP2-1",
						},
						map[string]interface{}{
							"field_name":  "HTTP2-2",
							"field_value": "HTTP2-2",
						},
					},
					"gRPC": []map[string]interface{}{},
				},
				convMap: map[string]interface{}{
					"field_name":  "field-name",
					"operator":    "operator",
					"field_value": "value",
				},
				longKey: "processors.request_log.filters.tag_filters",
			},
			want: map[string]interface{}{
				"HTTP": []map[string]interface{}{
					{
						"field-name": "HTTP",
						"value":      "HTTP",
					},
				},
				"HTTP2": []map[string]interface{}{
					{
						"field-name": "HTTP2-1",
						"value":      "HTTP2-1",
					},
					{
						"field-name": "HTTP2-2",
						"value":      "HTTP2-2",
					},
				},
				"gRPC": []map[string]interface{}{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dictConv := &dictDataConv{}
			got := dictConv.convDictDataValue(tt.args.data, tt.args.convMap, tt.args.longKey)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("convDictDataValue() = %v, want %v", got, tt.want)
			}
		})
	}
}
