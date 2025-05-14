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
	"testing"
)

func TestConvertDBToYAML(t *testing.T) {
	type args struct {
		dbData *AgentGroupConfigModel
	}
	L4LogTapTypes := "1,2,3"
	MaxCollectPps := 10000
	YamlConfig := string([]byte(`ebpf:
  on-cpu-profile:
    disabled: true
os-proc-sync-enabled: true`))
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "TestConvertDBToYAML_01",
			args: args{
				dbData: &AgentGroupConfigModel{
					ID:            1,
					YamlConfig:    &YamlConfig,
					L4LogTapTypes: &L4LogTapTypes,
					MaxCollectPps: &MaxCollectPps,
				},
			},
			want: []byte(`max_npb_bps: 10
l4_log_tap_types:
  - 1
  - 2
  - 3
static_config:
  ebpf:
    on-cpu-profile:
	  disabled: true
os-proc-sync-enabled: true`),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertDBToYAML(tt.args.dbData)
			if (err != nil) != tt.wantErr {
				t.Errorf("convertDBToYAML() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if string(got) != string(tt.want) {
				t.Errorf("convertDBToYAML() = %v, want %v", string(got), string(tt.want))
			}
		})
	}
}

func TestYAMLToDB(t *testing.T) {
	type args struct {
		yamlData []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *AgentGroupConfigModel
		wantErr bool
	}{
		{
			name: "TestYAMLToDB_01",
			args: args{
				yamlData: []byte(`max_collectpps: 10000
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
			want: &AgentGroupConfigModel{},
		},
		{
			name: "TestYAMLToDB_02",
			args: args{
				yamlData: []byte(`http_log_x_request_id: X-Request-Id, X-Request-ID`),
			},
			want: &AgentGroupConfigModel{},
		},
		{
			name: "TestYAMLToDB_03",
			args: args{
				yamlData: []byte(`http_log_proxy_client: X-Forwarded-For`),
			},
			want: &AgentGroupConfigModel{},
		},
	}
	for _, tt := range tests {
		if tt.name == "TestYAMLToDB_01" {
			continue
		}
		t.Run(tt.name, func(t *testing.T) {
			if err := convertYAMLToDB(tt.args.yamlData, tt.want); (err != nil) != tt.wantErr {
				t.Errorf("YAMLToDB() error = %v, wantErr %v", err, tt.wantErr)
			}
			fmt.Printf("got: %#v\n", tt.want)
		})
	}
}
