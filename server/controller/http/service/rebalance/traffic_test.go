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

package rebalance

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/stretchr/testify/assert"
)

func TestAZInfo_rebalanceAnalyzer(t *testing.T) {
	type arg struct {
		ifCheck bool
	}
	type fields struct {
		vTapIDToTraffic map[int]int64
		vtaps           map[int]*mysql.VTap
		analyzers       []*mysql.Analyzer
	}
	tests := []struct {
		name          string
		arg           arg
		fields        fields
		isAllNewVTaps bool
		want          map[int]*ChangeInfo
		want1         *model.AZVTapRebalanceResult
	}{
		{
			name: "stable balance",
			arg:  arg{ifCheck: true},
			fields: fields{
				vTapIDToTraffic: map[int]int64{1: 100, 2: 100, 3: 100},
				vtaps: map[int]*mysql.VTap{
					1: {ID: 1, AnalyzerIP: "192.168.0.1"},
					2: {ID: 2, AnalyzerIP: "192.168.0.2"},
					3: {ID: 3, AnalyzerIP: "192.168.0.3"},
				},
				analyzers: []*mysql.Analyzer{
					{IP: "192.168.0.1", State: common.HOST_STATE_COMPLETE},
					{IP: "192.168.0.2", State: common.HOST_STATE_COMPLETE},
					{IP: "192.168.0.3", State: common.HOST_STATE_COMPLETE},
				},
			},
			want: map[int]*ChangeInfo{
				1: {OldIP: "192.168.0.1", NewIP: "192.168.0.1"},
				2: {OldIP: "192.168.0.2", NewIP: "192.168.0.2"},
				3: {OldIP: "192.168.0.3", NewIP: "192.168.0.3"},
			},
			want1: &model.AZVTapRebalanceResult{
				TotalSwitchVTapNum: 0,
				Details: []*model.HostVTapRebalanceResult{
					{IP: "192.168.0.1", BeforeVTapNum: 1, AfterVTapNum: 1, SwitchVTapNum: 0,
						BeforeVTapWeights: 1, AfterVTapWeights: 1, State: common.HOST_STATE_COMPLETE},
					{IP: "192.168.0.2", BeforeVTapNum: 1, AfterVTapNum: 1, SwitchVTapNum: 0,
						BeforeVTapWeights: 1, AfterVTapWeights: 1, State: common.HOST_STATE_COMPLETE},
					{IP: "192.168.0.3", BeforeVTapNum: 1, AfterVTapNum: 1, SwitchVTapNum: 0,
						BeforeVTapWeights: 1, AfterVTapWeights: 1, State: common.HOST_STATE_COMPLETE},
				},
			},
		},
		{
			name: "a new vtap, an analyzer with weight 0",
			arg:  arg{ifCheck: true},
			fields: fields{
				vTapIDToTraffic: map[int]int64{1: 100, 2: 200, 3: 0},
				vtaps: map[int]*mysql.VTap{
					1: {ID: 1, AnalyzerIP: "192.168.0.1"},
					2: {ID: 2, AnalyzerIP: "192.168.0.2"},
					3: {ID: 3, AnalyzerIP: ""},
				},
				analyzers: []*mysql.Analyzer{
					{IP: "192.168.0.1", State: common.HOST_STATE_COMPLETE},
					{IP: "192.168.0.2", State: common.HOST_STATE_COMPLETE},
					{IP: "192.168.0.3", State: common.HOST_STATE_COMPLETE},
				},
			},
			want: map[int]*ChangeInfo{
				1: {OldIP: "192.168.0.1", NewIP: "192.168.0.1"},
				2: {OldIP: "192.168.0.2", NewIP: "192.168.0.2"},
				3: {OldIP: "", NewIP: "192.168.0.3"},
			},
			want1: &model.AZVTapRebalanceResult{
				TotalSwitchVTapNum: 1,
				Details: []*model.HostVTapRebalanceResult{
					{IP: "192.168.0.1", BeforeVTapNum: 1, AfterVTapNum: 1, SwitchVTapNum: 0,
						BeforeVTapWeights: 0.99, AfterVTapWeights: 0.67, State: common.HOST_STATE_COMPLETE},
					{IP: "192.168.0.2", BeforeVTapNum: 1, AfterVTapNum: 1, SwitchVTapNum: 0,
						BeforeVTapWeights: 2.01, AfterVTapWeights: 1.33, State: common.HOST_STATE_COMPLETE},
					{IP: "192.168.0.3", BeforeVTapNum: 0, AfterVTapNum: 1, SwitchVTapNum: 1,
						BeforeVTapWeights: 0, AfterVTapWeights: 1, State: common.HOST_STATE_COMPLETE},
				},
			},
		},
		{
			name: "an analyzer exception",
			arg:  arg{ifCheck: true},
			fields: fields{
				vTapIDToTraffic: map[int]int64{1: 100, 2: 200, 3: 300},
				vtaps: map[int]*mysql.VTap{
					1: {ID: 1, AnalyzerIP: "192.168.0.1"},
					2: {ID: 2, AnalyzerIP: "192.168.0.2"},
					3: {ID: 3, AnalyzerIP: "192.168.0.3"},
				},
				analyzers: []*mysql.Analyzer{
					{IP: "192.168.0.1", State: common.HOST_STATE_COMPLETE},
					{IP: "192.168.0.2", State: common.HOST_STATE_EXCEPTION},
					{IP: "192.168.0.3", State: common.HOST_STATE_COMPLETE},
				},
			},
			want: map[int]*ChangeInfo{
				1: {OldIP: "192.168.0.1", NewIP: "192.168.0.1"},
				2: {OldIP: "192.168.0.2", NewIP: "192.168.0.1"},
				3: {OldIP: "192.168.0.3", NewIP: "192.168.0.3"},
			},
			want1: &model.AZVTapRebalanceResult{
				TotalSwitchVTapNum: 2,
				Details: []*model.HostVTapRebalanceResult{
					{IP: "192.168.0.1", BeforeVTapNum: 1, AfterVTapNum: 2, SwitchVTapNum: 1,
						BeforeVTapWeights: 0.34, AfterVTapWeights: 1, State: common.HOST_STATE_COMPLETE},
					{IP: "192.168.0.2", BeforeVTapNum: 1, AfterVTapNum: 0, SwitchVTapNum: 1,
						BeforeVTapWeights: 0.66, AfterVTapWeights: 0, State: common.HOST_STATE_EXCEPTION},
					{IP: "192.168.0.3", BeforeVTapNum: 1, AfterVTapNum: 1, SwitchVTapNum: 0,
						BeforeVTapWeights: 1, AfterVTapWeights: 1, State: common.HOST_STATE_COMPLETE},
				},
			},
		},
		{
			name: "two new vtaps, normal analyzer has a vtap, an exception analyzer",
			arg:  arg{ifCheck: true},
			fields: fields{
				vTapIDToTraffic: map[int]int64{1: 100, 2: 200, 3: 300, 4: 0, 5: 0},
				vtaps: map[int]*mysql.VTap{
					1: {ID: 1, AnalyzerIP: "192.168.0.1"},
					2: {ID: 2, AnalyzerIP: "192.168.0.2"},
					3: {ID: 3, AnalyzerIP: "192.168.0.3"},
					4: {ID: 4, AnalyzerIP: ""},
					5: {ID: 5, AnalyzerIP: ""},
				},
				analyzers: []*mysql.Analyzer{
					{IP: "192.168.0.1", State: common.HOST_STATE_COMPLETE},
					{IP: "192.168.0.2", State: common.HOST_STATE_COMPLETE},
					{IP: "192.168.0.3", State: common.HOST_STATE_EXCEPTION},
					{IP: "192.168.0.4", State: common.HOST_STATE_COMPLETE},
				},
			},
			want: map[int]*ChangeInfo{
				1: {OldIP: "192.168.0.1", NewIP: "192.168.0.1"},
				2: {OldIP: "192.168.0.2", NewIP: "192.168.0.2"},
				3: {OldIP: "192.168.0.3", NewIP: "192.168.0.4"},
				4: {OldIP: "", NewIP: "192.168.0.1"},
				5: {OldIP: "", NewIP: "192.168.0.2"},
			},
			want1: &model.AZVTapRebalanceResult{
				TotalSwitchVTapNum: 4,
				Details: []*model.HostVTapRebalanceResult{
					{IP: "192.168.0.1", BeforeVTapNum: 1, AfterVTapNum: 2, SwitchVTapNum: 1,
						BeforeVTapWeights: 0.51, AfterVTapWeights: 0.9, State: common.HOST_STATE_COMPLETE},
					{IP: "192.168.0.2", BeforeVTapNum: 1, AfterVTapNum: 2, SwitchVTapNum: 1,
						BeforeVTapWeights: 0.99, AfterVTapWeights: 1.2, State: common.HOST_STATE_COMPLETE},
					{IP: "192.168.0.3", BeforeVTapNum: 1, AfterVTapNum: 0, SwitchVTapNum: 1,
						BeforeVTapWeights: 1.5, AfterVTapWeights: 0, State: common.HOST_STATE_EXCEPTION},
					{IP: "192.168.0.4", BeforeVTapNum: 0, AfterVTapNum: 1, SwitchVTapNum: 1,
						BeforeVTapWeights: 0, AfterVTapWeights: 0.9, State: common.HOST_STATE_COMPLETE},
				},
			},
		},
		{
			name: "a vtap traffic decreases",
			arg:  arg{ifCheck: true},
			fields: fields{
				vTapIDToTraffic: map[int]int64{1: 100, 2: 200, 3: 10, 4: 200, 5: 600, 6: 800},
				vtaps: map[int]*mysql.VTap{
					1: {ID: 1, AnalyzerIP: "192.168.0.1"},
					2: {ID: 2, AnalyzerIP: "192.168.0.2"},
					3: {ID: 3, AnalyzerIP: "192.168.0.3"},
					4: {ID: 4, AnalyzerIP: "192.168.0.1"},
					5: {ID: 5, AnalyzerIP: "192.168.0.3"},
					6: {ID: 6, AnalyzerIP: "192.168.0.2"},
				},
				analyzers: []*mysql.Analyzer{
					{IP: "192.168.0.1", State: common.HOST_STATE_COMPLETE}, // traffic: 300
					{IP: "192.168.0.2", State: common.HOST_STATE_COMPLETE}, // traffic: 1000
					{IP: "192.168.0.3", State: common.HOST_STATE_COMPLETE}, // traffic: 610
				},
			},
			want: map[int]*ChangeInfo{
				1: {OldIP: "192.168.0.1", NewIP: "192.168.0.1"},
				2: {OldIP: "192.168.0.2", NewIP: "192.168.0.1"}, // changed
				3: {OldIP: "192.168.0.3", NewIP: "192.168.0.3"},
				4: {OldIP: "192.168.0.1", NewIP: "192.168.0.1"},
				5: {OldIP: "192.168.0.3", NewIP: "192.168.0.3"},
				6: {OldIP: "192.168.0.2", NewIP: "192.168.0.2"},
			},
			want1: &model.AZVTapRebalanceResult{
				TotalSwitchVTapNum: 2,
				Details: []*model.HostVTapRebalanceResult{
					{IP: "192.168.0.1", BeforeVTapNum: 2, AfterVTapNum: 3, SwitchVTapNum: 1,
						BeforeVTapWeights: 0.45, AfterVTapWeights: 0.78, State: common.HOST_STATE_COMPLETE},
					{IP: "192.168.0.2", BeforeVTapNum: 2, AfterVTapNum: 1, SwitchVTapNum: 1,
						BeforeVTapWeights: 1.58, AfterVTapWeights: 1.26, State: common.HOST_STATE_COMPLETE},
					{IP: "192.168.0.3", BeforeVTapNum: 2, AfterVTapNum: 2, SwitchVTapNum: 0,
						BeforeVTapWeights: 0.97, AfterVTapWeights: 0.96, State: common.HOST_STATE_COMPLETE},
				},
			},
		},
		{
			name: "two vtap traffic increases",
			arg:  arg{ifCheck: true},
			fields: fields{
				vTapIDToTraffic: map[int]int64{1: 100, 2: 100, 3: 900, 4: 100, 5: 100, 6: 900},
				vtaps: map[int]*mysql.VTap{
					1: {ID: 1, AnalyzerIP: "192.168.0.1"},
					2: {ID: 2, AnalyzerIP: "192.168.0.1"},
					3: {ID: 3, AnalyzerIP: "192.168.0.2"},
					4: {ID: 4, AnalyzerIP: "192.168.0.2"},
					5: {ID: 5, AnalyzerIP: "192.168.0.3"},
					6: {ID: 6, AnalyzerIP: "192.168.0.3"},
				},
				analyzers: []*mysql.Analyzer{
					{IP: "192.168.0.1", State: common.HOST_STATE_COMPLETE}, // traffic: 200
					{IP: "192.168.0.2", State: common.HOST_STATE_COMPLETE}, // traffic: 1000
					{IP: "192.168.0.3", State: common.HOST_STATE_COMPLETE}, // traffic: 1000
				},
			},
			want: map[int]*ChangeInfo{
				1: {OldIP: "192.168.0.1", NewIP: "192.168.0.1"},
				2: {OldIP: "192.168.0.1", NewIP: "192.168.0.1"},
				3: {OldIP: "192.168.0.2", NewIP: "192.168.0.2"},
				4: {OldIP: "192.168.0.2", NewIP: "192.168.0.1"}, // changed
				5: {OldIP: "192.168.0.3", NewIP: "192.168.0.1"}, // changed
				6: {OldIP: "192.168.0.3", NewIP: "192.168.0.3"},
			},
			want1: &model.AZVTapRebalanceResult{
				TotalSwitchVTapNum: 4,
				Details: []*model.HostVTapRebalanceResult{
					{IP: "192.168.0.1", BeforeVTapNum: 2, AfterVTapNum: 4, SwitchVTapNum: 2,
						BeforeVTapWeights: 0.29, AfterVTapWeights: 0.54, State: common.HOST_STATE_COMPLETE},
					{IP: "192.168.0.2", BeforeVTapNum: 2, AfterVTapNum: 1, SwitchVTapNum: 1,
						BeforeVTapWeights: 1.35, AfterVTapWeights: 1.23, State: common.HOST_STATE_COMPLETE},
					{IP: "192.168.0.3", BeforeVTapNum: 2, AfterVTapNum: 1, SwitchVTapNum: 1,
						BeforeVTapWeights: 1.35, AfterVTapWeights: 1.23, State: common.HOST_STATE_COMPLETE},
				},
			},
		},
		{
			name:          "all vtap news",
			arg:           arg{ifCheck: true},
			isAllNewVTaps: true,
			fields: fields{
				vTapIDToTraffic: map[int]int64{1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0},
				vtaps: map[int]*mysql.VTap{
					1: {ID: 1, AnalyzerIP: ""},
					2: {ID: 2, AnalyzerIP: ""},
					3: {ID: 3, AnalyzerIP: ""},
					4: {ID: 4, AnalyzerIP: ""},
					5: {ID: 5, AnalyzerIP: ""},
					6: {ID: 6, AnalyzerIP: ""},
				},
				analyzers: []*mysql.Analyzer{
					{IP: "192.168.0.1", State: common.HOST_STATE_COMPLETE},
					{IP: "192.168.0.2", State: common.HOST_STATE_COMPLETE},
					{IP: "192.168.0.3", State: common.HOST_STATE_COMPLETE},
				},
			},
			want: map[int]*ChangeInfo{
				1: {OldIP: "", NewIP: "192.168.0.1"},
				2: {OldIP: "", NewIP: "192.168.0.1"},
				3: {OldIP: "", NewIP: "192.168.0.2"},
				4: {OldIP: "", NewIP: "192.168.0.2"},
				5: {OldIP: "", NewIP: "192.168.0.3"},
				6: {OldIP: "", NewIP: "192.168.0.3"},
			},
			want1: &model.AZVTapRebalanceResult{
				TotalSwitchVTapNum: 6,
				Details: []*model.HostVTapRebalanceResult{
					{IP: "192.168.0.1", BeforeVTapNum: 0, AfterVTapNum: 2, SwitchVTapNum: 2,
						BeforeVTapWeights: 0, AfterVTapWeights: 1, State: common.HOST_STATE_COMPLETE},
					{IP: "192.168.0.2", BeforeVTapNum: 0, AfterVTapNum: 2, SwitchVTapNum: 2,
						BeforeVTapWeights: 0, AfterVTapWeights: 1, State: common.HOST_STATE_COMPLETE},
					{IP: "192.168.0.3", BeforeVTapNum: 0, AfterVTapNum: 2, SwitchVTapNum: 2,
						BeforeVTapWeights: 0, AfterVTapWeights: 1, State: common.HOST_STATE_COMPLETE},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &AZInfo{
				vTapIDToTraffic: tt.fields.vTapIDToTraffic,
				vtapIDToVTap:    tt.fields.vtaps,
				analyzers:       tt.fields.analyzers,
			}
			got, got1 := p.rebalanceAnalyzer(nil, tt.arg.ifCheck)
			if !tt.isAllNewVTaps {
				assert.EqualValues(t, tt.want, got)
			}
			assert.EqualValues(t, tt.want1.Details, got1.Details)
			assert.EqualValues(t, tt.want1.TotalSwitchVTapNum, got1.TotalSwitchVTapNum)
		})
	}
}

var (
	parseBodyDataCase1 = `{
    "OPT_STATUS": "SUCCESS",
    "DESCRIPTION": "",
    "result": {
        "columns": [
            "tag.host",
            "Sum(metrics.rx_bytes)"
        ],
        "schemas": [
            {
                "label_type": "",
                "pre_as": "",
                "type": 0,
                "unit": "",
                "value_type": "String"
            },
            {
                "label_type": "",
                "pre_as": "Sum(metrics.rx_bytes)",
                "type": 1,
                "unit": "",
                "value_type": "Float64"
            }
        ],
        "values": [
            [
                "node1-V1",
                286801565230
            ],
            [
                "node2-V2",
                331792689200
            ]
        ]
    },
    "debug": null
}`

	parseBodyDataCase2 = `{
    "OPT_STATUS": "SUCCESS",
    "DESCRIPTION": "",
    "result": {
        "columns": [
            "Sum(metrics.rx_bytes)",
			"tag.host"
        ],
        "schemas": [
            {
                "label_type": "",
                "pre_as": "",
                "type": 0,
                "unit": "",
                "value_type": "String"
            },
            {
                "label_type": "",
                "pre_as": "Sum(metrics.rx_bytes)",
                "type": 1,
                "unit": "",
                "value_type": "Float64"
            }
        ],
        "values": [
            [
				286801565230,
                "node1-V1"
            ],
            [
				331792689200,
                "node2-V2"
            ]
        ]
    },
    "debug": null
}`

	parseBodyDataCase3 = `{
		"OPT_STATUS": "SUCCESS",
		"DESCRIPTION": "",
		"result": {
			"columns": [
				"tag.host",
				"Sum(metrics.rx_bytes)"
			],
			"schemas": [
				{
					"label_type": "",
					"pre_as": "",
					"type": 0,
					"unit": "",
					"value_type": "String"
				},
				{
					"label_type": "",
					"pre_as": "Sum(metrics.rx_bytes)",
					"type": 1,
					"unit": "",
					"value_type": "Float64"
				}
			],
			"values": [
				[
					"analyzer23-V80",
					107816643268
				],
				[
					"node25-V98",
					54493557306
				],
				[
					"controller21-V81",
					351335927386
				],
				[
					"master24-V99",
					27266894795
				],
				[
					"tomato-V100",
					600983768
				],
				[
					"analyzer22-V82",
					114210549428
				],
				[
					"Automation-Public-Debug-W2523",
					0
				],
				[
					"ydx-H12",
					467756308
				],
				[
					"deepflow-agent-gnzz6",
					0
				]
			]
		},
		"debug": null
	}`
)

func Test_parseBody(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    map[string]int64
		wantErr bool
	}{
		{
			name: "two vtaps in region",
			args: args{
				data: []byte(parseBodyDataCase1),
			},
			want: map[string]int64{
				"node1-V1": 286801565230,
				"node2-V2": 331792689200,
			},
			wantErr: false,
		},
		{
			name: "swap cloumn order",
			args: args{
				data: []byte(parseBodyDataCase1),
			},
			want: map[string]int64{
				"node1-V1": 286801565230,
				"node2-V2": 331792689200,
			},
			wantErr: false,
		},
		{
			name: "lots of vtaps in region",
			args: args{
				data: []byte(parseBodyDataCase3),
			},
			want: map[string]int64{
				"analyzer23-V80":                107816643268,
				"node25-V98":                    54493557306,
				"controller21-V81":              351335927386,
				"master24-V99":                  27266894795,
				"tomato-V100":                   600983768,
				"analyzer22-V82":                114210549428,
				"Automation-Public-Debug-W2523": 0,
				"ydx-H12":                       467756308,
				"deepflow-agent-gnzz6":          0,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseBody(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseBody() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseBody() = %v, want %v", got, tt.want)
			}
		})
	}
}

func getRebalanceData(data string) (*RebalanceData, error) {
	temp := make(map[string]interface{})
	if err := json.Unmarshal([]byte(data), &temp); err != nil {
		return nil, err
	}
	b, err := json.Marshal(temp["TRAFFIC_DATA"])
	if err != nil {
		return nil, err
	}
	result := &RebalanceData{}
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func TestAnalyzerInfo_RebalanceAnalyzerByTraffic(t *testing.T) {
	data1 := `{"TRAFFIC_ANALYZER":[{"AGENT_COUNT":1,"ANALYZER_IP":"10.1.4.2","ANALYZER_STATE":2,"ANALYZER_TRAFFIC":7609796230,"AZ":"41476579-ebcf-58bf-8f60-09d5ff4745ff(earth), f01b7189-4335-50e3-8e9a-5deab1833833(cn-bj-a)","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff(系统默认)"},{"AGENT_COUNT":2,"ANALYZER_IP":"10.1.4.1","ANALYZER_STATE":2,"ANALYZER_TRAFFIC":5290868681,"AZ":"ALL","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff(系统默认)"}],"TRAFFIC_AZ":[{"AGENT_COUNT":0,"ANALYZER_IP":"10.1.4.1","ANALYZER_STATE":2,"ANALYZER_TRAFFIC":0,"AZ":"41476579-ebcf-58bf-8f60-09d5ff4745ff(earth)","AZ_TRAFFIC":7609796230,"REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff(系统默认)"},{"AGENT_COUNT":1,"ANALYZER_IP":"10.1.4.2","ANALYZER_STATE":2,"ANALYZER_TRAFFIC":7609796230,"AZ":"41476579-ebcf-58bf-8f60-09d5ff4745ff(earth)","AZ_TRAFFIC":7609796230,"REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff(系统默认)"},{"AGENT_COUNT":1,"ANALYZER_IP":"10.1.4.1","ANALYZER_STATE":2,"ANALYZER_TRAFFIC":4683073700,"AZ":"339832f3-3ee7-54a7-ad9d-01ca925872b6(华北 2 可用区 A)","AZ_TRAFFIC":4683073700,"REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff(系统默认)"},{"AGENT_COUNT":1,"ANALYZER_IP":"10.1.4.1","ANALYZER_STATE":2,"ANALYZER_TRAFFIC":607794981,"AZ":"0b218e93-564d-5287-ae8b-635e1c0b5eff(huanchao)","AZ_TRAFFIC":607794981,"REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff(系统默认)"}],"TRAFFIC_DATA":{"AZToAnalyzers":{"0b218e93-564d-5287-ae8b-635e1c0b5eff":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"0cb9b690-956b-53a0-b5fc-bfcebd5d548b":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"0ed61353-307a-5f2c-b177-40bf56d5748a":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"1d01f8ed-83f7-5a5b-b7ed-105c5d4faef5":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"27c232ee-54ed-52dc-81e1-0ccf5f1ea96f":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"2c4f39f9-386b-54be-8eb2-00e2845b0c4d":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"303a7b13-e891-5ebe-892f-33e1ad6e5c43":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"316d8d52-b1d9-5e01-9a28-2312a5563576":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"339832f3-3ee7-54a7-ad9d-01ca925872b6":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"3d1d386b-d223-5f5b-9d78-fc57d60de99f":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"3fd8d232-d796-5eeb-9437-e907ebeb07ea":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"41476579-ebcf-58bf-8f60-09d5ff4745ff":[{"IP":"10.1.4.1","NAME":"node1","STATE":2},{"IP":"10.1.4.2","NAME":"node2","STATE":2}],"415d0617-8a6c-5bfe-9b21-2c7d93e4dde2":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"4a73a758-89b3-57b3-938d-4a5141788388":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"5538781a-9e8d-55e7-bb34-d35f2d601aff":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"66e5b6ee-6fa7-54db-badd-0cb5597490fa":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"67f52294-3ee0-561d-8862-a440c68b1fb9":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"7506b859-e150-59ab-9d7c-21d9cd40c7ad":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"77c816dc-01a7-5633-87de-4a689867c950":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"8183638f-77e3-5ea6-8eef-88f1a0788847":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"84e429a6-7e61-591d-9c47-ded6a5016a83":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"881eff33-19d3-5a45-8984-9f63fd4fdbc1":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"89de379a-d00e-5c0b-b268-bbb02ef81c28":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"90b10c24-40da-586f-8fb1-629e4c5078d5":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"9ba9914d-261e-5c45-948d-bef0dd6ec6a9":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"9dc0a2a0-695d-5bdc-94f1-4853f20346ff":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"a931078c-c7b2-5190-ba57-8cc435502713":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"b4014a33-3741-5c8c-9d83-c2468ea8805e":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"b6a772a4-54d4-5169-8f70-2eaebd2d42bd":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"bd4af43e-6f23-5925-b60d-6249c3ba5ff5":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"be8419be-074d-5907-b9f0-e01864578250":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"cf20ce18-a2be-5abf-8a2c-66c68267983e":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"d15d062c-b05f-5696-be7b-98dc2d9b41f4":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"de1dbf59-48b5-5a97-a03c-f21be41fdecc":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"e3c16fd3-1892-56e7-a2f8-6e1b0fb2ae61":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"e9241dca-bf08-567d-88d2-fa5cbc6c7cff":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"f01b7189-4335-50e3-8e9a-5deab1833833":[{"IP":"10.1.4.1","NAME":"node1","STATE":2},{"IP":"10.1.4.2","NAME":"node2","STATE":2}],"f60a0a09-771a-5c58-8a9e-7b0bc30a4d71":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"fcef0fd3-7c50-567d-9703-57674c6461e1":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}],"ffffffff-ffff-ffff-ffff-ffffffffffff":[{"IP":"10.1.4.1","NAME":"node1","STATE":2}]},"AZToRegion":{"0b218e93-564d-5287-ae8b-635e1c0b5eff":"ffffffff-ffff-ffff-ffff-ffffffffffff","0cb9b690-956b-53a0-b5fc-bfcebd5d548b":"ffffffff-ffff-ffff-ffff-ffffffffffff","0ed61353-307a-5f2c-b177-40bf56d5748a":"ffffffff-ffff-ffff-ffff-ffffffffffff","1d01f8ed-83f7-5a5b-b7ed-105c5d4faef5":"ffffffff-ffff-ffff-ffff-ffffffffffff","27c232ee-54ed-52dc-81e1-0ccf5f1ea96f":"ffffffff-ffff-ffff-ffff-ffffffffffff","2c4f39f9-386b-54be-8eb2-00e2845b0c4d":"ffffffff-ffff-ffff-ffff-ffffffffffff","303a7b13-e891-5ebe-892f-33e1ad6e5c43":"ffffffff-ffff-ffff-ffff-ffffffffffff","316d8d52-b1d9-5e01-9a28-2312a5563576":"ffffffff-ffff-ffff-ffff-ffffffffffff","339832f3-3ee7-54a7-ad9d-01ca925872b6":"ffffffff-ffff-ffff-ffff-ffffffffffff","3d1d386b-d223-5f5b-9d78-fc57d60de99f":"ffffffff-ffff-ffff-ffff-ffffffffffff","3fd8d232-d796-5eeb-9437-e907ebeb07ea":"ffffffff-ffff-ffff-ffff-ffffffffffff","41476579-ebcf-58bf-8f60-09d5ff4745ff":"ffffffff-ffff-ffff-ffff-ffffffffffff","415d0617-8a6c-5bfe-9b21-2c7d93e4dde2":"ffffffff-ffff-ffff-ffff-ffffffffffff","4a73a758-89b3-57b3-938d-4a5141788388":"ffffffff-ffff-ffff-ffff-ffffffffffff","5538781a-9e8d-55e7-bb34-d35f2d601aff":"ffffffff-ffff-ffff-ffff-ffffffffffff","66e5b6ee-6fa7-54db-badd-0cb5597490fa":"ffffffff-ffff-ffff-ffff-ffffffffffff","67f52294-3ee0-561d-8862-a440c68b1fb9":"ffffffff-ffff-ffff-ffff-ffffffffffff","7506b859-e150-59ab-9d7c-21d9cd40c7ad":"ffffffff-ffff-ffff-ffff-ffffffffffff","77c816dc-01a7-5633-87de-4a689867c950":"ffffffff-ffff-ffff-ffff-ffffffffffff","8183638f-77e3-5ea6-8eef-88f1a0788847":"ffffffff-ffff-ffff-ffff-ffffffffffff","84e429a6-7e61-591d-9c47-ded6a5016a83":"ffffffff-ffff-ffff-ffff-ffffffffffff","881eff33-19d3-5a45-8984-9f63fd4fdbc1":"ffffffff-ffff-ffff-ffff-ffffffffffff","89de379a-d00e-5c0b-b268-bbb02ef81c28":"ffffffff-ffff-ffff-ffff-ffffffffffff","90b10c24-40da-586f-8fb1-629e4c5078d5":"ffffffff-ffff-ffff-ffff-ffffffffffff","9ba9914d-261e-5c45-948d-bef0dd6ec6a9":"ffffffff-ffff-ffff-ffff-ffffffffffff","9dc0a2a0-695d-5bdc-94f1-4853f20346ff":"ffffffff-ffff-ffff-ffff-ffffffffffff","a931078c-c7b2-5190-ba57-8cc435502713":"ffffffff-ffff-ffff-ffff-ffffffffffff","b4014a33-3741-5c8c-9d83-c2468ea8805e":"ffffffff-ffff-ffff-ffff-ffffffffffff","b6a772a4-54d4-5169-8f70-2eaebd2d42bd":"ffffffff-ffff-ffff-ffff-ffffffffffff","bd4af43e-6f23-5925-b60d-6249c3ba5ff5":"ffffffff-ffff-ffff-ffff-ffffffffffff","be8419be-074d-5907-b9f0-e01864578250":"ffffffff-ffff-ffff-ffff-ffffffffffff","cf20ce18-a2be-5abf-8a2c-66c68267983e":"ffffffff-ffff-ffff-ffff-ffffffffffff","d15d062c-b05f-5696-be7b-98dc2d9b41f4":"ffffffff-ffff-ffff-ffff-ffffffffffff","de1dbf59-48b5-5a97-a03c-f21be41fdecc":"ffffffff-ffff-ffff-ffff-ffffffffffff","e3c16fd3-1892-56e7-a2f8-6e1b0fb2ae61":"ffffffff-ffff-ffff-ffff-ffffffffffff","e9241dca-bf08-567d-88d2-fa5cbc6c7cff":"ffffffff-ffff-ffff-ffff-ffffffffffff","f01b7189-4335-50e3-8e9a-5deab1833833":"ffffffff-ffff-ffff-ffff-ffffffffffff","f60a0a09-771a-5c58-8a9e-7b0bc30a4d71":"ffffffff-ffff-ffff-ffff-ffffffffffff","fcef0fd3-7c50-567d-9703-57674c6461e1":"ffffffff-ffff-ffff-ffff-ffffffffffff","ffffffff-ffff-ffff-ffff-ffffffffffff":"ffffffff-ffff-ffff-ffff-ffffffffffff"},"AZToVTaps":{"0b218e93-564d-5287-ae8b-635e1c0b5eff":[{"ANALYZER_IP":"10.1.4.1","AZ":"0b218e93-564d-5287-ae8b-635e1c0b5eff","ID":17,"NAME":"tomato-V3"}],"339832f3-3ee7-54a7-ad9d-01ca925872b6":[{"ANALYZER_IP":"10.1.4.1","AZ":"339832f3-3ee7-54a7-ad9d-01ca925872b6","ID":13,"NAME":"DF-DAILY-R0-C1-W4202"}],"41476579-ebcf-58bf-8f60-09d5ff4745ff":[{"ANALYZER_IP":"10.1.4.2","AZ":"41476579-ebcf-58bf-8f60-09d5ff4745ff","ID":16,"NAME":"node2-V2"}]},"AZs":[{"DOMAIN":"ffffffff-ffff-ffff-ffff-ffffffffffff","LCUUID":"ffffffff-ffff-ffff-ffff-ffffffffffff","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"41476579-ebcf-58bf-8f60-09d5ff474561","LCUUID":"41476579-ebcf-58bf-8f60-09d5ff4745ff","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"849484e6-8c2d-5e5a-b39d-b3cdbf90788d","LCUUID":"f01b7189-4335-50e3-8e9a-5deab1833833","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"849484e6-8c2d-5e5a-b39d-b3cdbf90788d","LCUUID":"89de379a-d00e-5c0b-b268-bbb02ef81c28","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"849484e6-8c2d-5e5a-b39d-b3cdbf90788d","LCUUID":"84e429a6-7e61-591d-9c47-ded6a5016a83","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"849484e6-8c2d-5e5a-b39d-b3cdbf90788d","LCUUID":"67f52294-3ee0-561d-8862-a440c68b1fb9","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"849484e6-8c2d-5e5a-b39d-b3cdbf90788d","LCUUID":"d15d062c-b05f-5696-be7b-98dc2d9b41f4","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"849484e6-8c2d-5e5a-b39d-b3cdbf90788d","LCUUID":"9ba9914d-261e-5c45-948d-bef0dd6ec6a9","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"2623681a-9cce-5edb-b393-9c1a703b9955","LCUUID":"f60a0a09-771a-5c58-8a9e-7b0bc30a4d71","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"2623681a-9cce-5edb-b393-9c1a703b9955","LCUUID":"4a73a758-89b3-57b3-938d-4a5141788388","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"2623681a-9cce-5edb-b393-9c1a703b9955","LCUUID":"8183638f-77e3-5ea6-8eef-88f1a0788847","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"2623681a-9cce-5edb-b393-9c1a703b9955","LCUUID":"3d1d386b-d223-5f5b-9d78-fc57d60de99f","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"2623681a-9cce-5edb-b393-9c1a703b9955","LCUUID":"e3c16fd3-1892-56e7-a2f8-6e1b0fb2ae61","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"c0763048-38ad-591b-aa49-7f9f73434f1f","LCUUID":"fcef0fd3-7c50-567d-9703-57674c6461e1","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"c0763048-38ad-591b-aa49-7f9f73434f1f","LCUUID":"2c4f39f9-386b-54be-8eb2-00e2845b0c4d","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"c0763048-38ad-591b-aa49-7f9f73434f1f","LCUUID":"27c232ee-54ed-52dc-81e1-0ccf5f1ea96f","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"c0763048-38ad-591b-aa49-7f9f73434f1f","LCUUID":"1d01f8ed-83f7-5a5b-b7ed-105c5d4faef5","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"c0763048-38ad-591b-aa49-7f9f73434f1f","LCUUID":"b4014a33-3741-5c8c-9d83-c2468ea8805e","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"c0763048-38ad-591b-aa49-7f9f73434f1f","LCUUID":"bd4af43e-6f23-5925-b60d-6249c3ba5ff5","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"9dc0a2a0-695d-5bdc-94f1-4853f20346b3","LCUUID":"9dc0a2a0-695d-5bdc-94f1-4853f20346ff","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"0a7d140e-123d-5a50-b0a8-2f34a68902b5","LCUUID":"a931078c-c7b2-5190-ba57-8cc435502713","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"0a7d140e-123d-5a50-b0a8-2f34a68902b5","LCUUID":"0ed61353-307a-5f2c-b177-40bf56d5748a","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"0a7d140e-123d-5a50-b0a8-2f34a68902b5","LCUUID":"7506b859-e150-59ab-9d7c-21d9cd40c7ad","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"0a7d140e-123d-5a50-b0a8-2f34a68902b5","LCUUID":"90b10c24-40da-586f-8fb1-629e4c5078d5","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"5538781a-9e8d-55e7-bb34-d35f2d601afa","LCUUID":"5538781a-9e8d-55e7-bb34-d35f2d601aff","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"e9241dca-bf08-567d-88d2-fa5cbc6c7c21","LCUUID":"e9241dca-bf08-567d-88d2-fa5cbc6c7cff","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"2623681a-9cce-5edb-b393-9c1a703b9955","LCUUID":"316d8d52-b1d9-5e01-9a28-2312a5563576","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"74895509-1ff5-5744-be4f-b8af40e63da2","LCUUID":"339832f3-3ee7-54a7-ad9d-01ca925872b6","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"74895509-1ff5-5744-be4f-b8af40e63da2","LCUUID":"be8419be-074d-5907-b9f0-e01864578250","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"74895509-1ff5-5744-be4f-b8af40e63da2","LCUUID":"cf20ce18-a2be-5abf-8a2c-66c68267983e","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"74895509-1ff5-5744-be4f-b8af40e63da2","LCUUID":"415d0617-8a6c-5bfe-9b21-2c7d93e4dde2","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"74895509-1ff5-5744-be4f-b8af40e63da2","LCUUID":"303a7b13-e891-5ebe-892f-33e1ad6e5c43","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"74895509-1ff5-5744-be4f-b8af40e63da2","LCUUID":"b6a772a4-54d4-5169-8f70-2eaebd2d42bd","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"74895509-1ff5-5744-be4f-b8af40e63da2","LCUUID":"de1dbf59-48b5-5a97-a03c-f21be41fdecc","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"74895509-1ff5-5744-be4f-b8af40e63da2","LCUUID":"3fd8d232-d796-5eeb-9437-e907ebeb07ea","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"74895509-1ff5-5744-be4f-b8af40e63da2","LCUUID":"0cb9b690-956b-53a0-b5fc-bfcebd5d548b","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"0b218e93-564d-5287-ae8b-635e1c0b5ee9","LCUUID":"0b218e93-564d-5287-ae8b-635e1c0b5eff","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"626016d9-e9fb-563f-842e-db8c15239eb4","LCUUID":"77c816dc-01a7-5633-87de-4a689867c950","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"626016d9-e9fb-563f-842e-db8c15239eb4","LCUUID":"66e5b6ee-6fa7-54db-badd-0cb5597490fa","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"},{"DOMAIN":"626016d9-e9fb-563f-842e-db8c15239eb4","LCUUID":"881eff33-19d3-5a45-8984-9f63fd4fdbc1","REGION":"ffffffff-ffff-ffff-ffff-ffffffffffff"}],"RegionToAZLcuuids":{"ffffffff-ffff-ffff-ffff-ffffffffffff":["ffffffff-ffff-ffff-ffff-ffffffffffff","41476579-ebcf-58bf-8f60-09d5ff4745ff","f01b7189-4335-50e3-8e9a-5deab1833833","89de379a-d00e-5c0b-b268-bbb02ef81c28","84e429a6-7e61-591d-9c47-ded6a5016a83","67f52294-3ee0-561d-8862-a440c68b1fb9","d15d062c-b05f-5696-be7b-98dc2d9b41f4","9ba9914d-261e-5c45-948d-bef0dd6ec6a9","f60a0a09-771a-5c58-8a9e-7b0bc30a4d71","4a73a758-89b3-57b3-938d-4a5141788388","8183638f-77e3-5ea6-8eef-88f1a0788847","3d1d386b-d223-5f5b-9d78-fc57d60de99f","e3c16fd3-1892-56e7-a2f8-6e1b0fb2ae61","fcef0fd3-7c50-567d-9703-57674c6461e1","2c4f39f9-386b-54be-8eb2-00e2845b0c4d","27c232ee-54ed-52dc-81e1-0ccf5f1ea96f","1d01f8ed-83f7-5a5b-b7ed-105c5d4faef5","b4014a33-3741-5c8c-9d83-c2468ea8805e","bd4af43e-6f23-5925-b60d-6249c3ba5ff5","9dc0a2a0-695d-5bdc-94f1-4853f20346ff","a931078c-c7b2-5190-ba57-8cc435502713","0ed61353-307a-5f2c-b177-40bf56d5748a","7506b859-e150-59ab-9d7c-21d9cd40c7ad","90b10c24-40da-586f-8fb1-629e4c5078d5","5538781a-9e8d-55e7-bb34-d35f2d601aff","e9241dca-bf08-567d-88d2-fa5cbc6c7cff","316d8d52-b1d9-5e01-9a28-2312a5563576","339832f3-3ee7-54a7-ad9d-01ca925872b6","be8419be-074d-5907-b9f0-e01864578250","cf20ce18-a2be-5abf-8a2c-66c68267983e","415d0617-8a6c-5bfe-9b21-2c7d93e4dde2","303a7b13-e891-5ebe-892f-33e1ad6e5c43","b6a772a4-54d4-5169-8f70-2eaebd2d42bd","de1dbf59-48b5-5a97-a03c-f21be41fdecc","3fd8d232-d796-5eeb-9437-e907ebeb07ea","0cb9b690-956b-53a0-b5fc-bfcebd5d548b","0b218e93-564d-5287-ae8b-635e1c0b5eff","77c816dc-01a7-5633-87de-4a689867c950","66e5b6ee-6fa7-54db-badd-0cb5597490fa","881eff33-19d3-5a45-8984-9f63fd4fdbc1"]},"RegionToVTapNameToTraffic":{"ffffffff-ffff-ffff-ffff-ffffffffffff":{"DF-DAILY-R0-C1":183033,"DF-DAILY-R0-C1-W4202":4683073700,"node2-V2":7609796230,"tomato":144182,"tomato-V3":607794981}}}}`
	field1, err := getRebalanceData(data1)
	if err != nil {
		t.Error(err)
		return
	}

	type fields struct {
		onlyWeight    bool
		dbInfo        *DBInfo
		db            DB
		query         Querier
		RebalanceData RebalanceData
	}
	type args struct {
		db           *mysql.DB
		ifCheckout   bool
		dataDuration int
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *model.VTapRebalanceResult
		wantErr bool
	}{
		{
			name:   "three agents",
			fields: fields{RebalanceData: *field1},
			args:   args{ifCheckout: true},
			want: &model.VTapRebalanceResult{
				Details: []*model.HostVTapRebalanceResult{
					{
						IP:               "10.1.4.1",
						AZ:               "41476579-ebcf-58bf-8f60-09d5ff4745ff",
						State:            2,
						NewVTapToTraffic: map[string]int64{},
						DelVTapToTraffic: map[string]int64{},
					},
					{
						IP:                "10.1.4.2",
						AZ:                "41476579-ebcf-58bf-8f60-09d5ff4745ff",
						State:             2,
						BeforeVTapNum:     1,
						AfterVTapNum:      1,
						BeforeVTapWeights: 2,
						AfterVTapWeights:  2,
						BeforeVTapTraffic: 7609796230,
						AfterVTapTraffic:  7609796230,
						NewVTapToTraffic:  map[string]int64{},
						DelVTapToTraffic:  map[string]int64{},
					},
					{
						IP:                "10.1.4.1",
						AZ:                "339832f3-3ee7-54a7-ad9d-01ca925872b6",
						State:             2,
						BeforeVTapNum:     1,
						AfterVTapNum:      1,
						BeforeVTapWeights: 1,
						AfterVTapWeights:  1,
						BeforeVTapTraffic: 4683073700,
						AfterVTapTraffic:  4683073700,
						NewVTapToTraffic:  map[string]int64{},
						DelVTapToTraffic:  map[string]int64{},
					},
					{
						IP:                "10.1.4.1",
						AZ:                "0b218e93-564d-5287-ae8b-635e1c0b5eff",
						State:             2,
						BeforeVTapNum:     1,
						AfterVTapNum:      1,
						BeforeVTapWeights: 1,
						AfterVTapWeights:  1,
						BeforeVTapTraffic: 607794981,
						AfterVTapTraffic:  607794981,
						NewVTapToTraffic:  map[string]int64{},
						DelVTapToTraffic:  map[string]int64{},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &AnalyzerInfo{
				onlyWeight:    tt.fields.onlyWeight,
				dbInfo:        tt.fields.dbInfo,
				db:            tt.fields.db,
				query:         tt.fields.query,
				RebalanceData: tt.fields.RebalanceData,
			}
			got, err := r.RebalanceAnalyzerByTraffic(tt.args.db, tt.args.ifCheckout, tt.args.dataDuration)
			if (err != nil) != tt.wantErr {
				t.Errorf("AnalyzerInfo.RebalanceAnalyzerByTraffic() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.EqualValues(t, tt.want, got)
		})
	}
}
