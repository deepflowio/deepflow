/*
 * Copyright (c) 2023 Yunshan Networks
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
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/rebalance/mocks"
	"github.com/deepflowio/deepflow/server/controller/model"
)

func TestAZInfo_rebalanceAnalyzer(t *testing.T) {
	type arg struct {
		ifCheck bool
	}
	type fields struct {
		vTapIDToTraffic map[int]int64
		vtaps           []*mysql.VTap
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
				vtaps: []*mysql.VTap{
					{ID: 1, AnalyzerIP: "192.168.0.1"},
					{ID: 2, AnalyzerIP: "192.168.0.2"},
					{ID: 3, AnalyzerIP: "192.168.0.3"},
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
				vtaps: []*mysql.VTap{
					{ID: 1, AnalyzerIP: "192.168.0.1"},
					{ID: 2, AnalyzerIP: "192.168.0.2"},
					{ID: 3, AnalyzerIP: ""},
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
				vtaps: []*mysql.VTap{
					{ID: 1, AnalyzerIP: "192.168.0.1"},
					{ID: 2, AnalyzerIP: "192.168.0.2"},
					{ID: 3, AnalyzerIP: "192.168.0.3"},
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
				vtaps: []*mysql.VTap{
					{ID: 1, AnalyzerIP: "192.168.0.1"},
					{ID: 2, AnalyzerIP: "192.168.0.2"},
					{ID: 3, AnalyzerIP: "192.168.0.3"},
					{ID: 4, AnalyzerIP: ""},
					{ID: 5, AnalyzerIP: ""},
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
				vtaps: []*mysql.VTap{
					{ID: 1, AnalyzerIP: "192.168.0.1"},
					{ID: 2, AnalyzerIP: "192.168.0.2"},
					{ID: 3, AnalyzerIP: "192.168.0.3"},
					{ID: 4, AnalyzerIP: "192.168.0.1"},
					{ID: 5, AnalyzerIP: "192.168.0.3"},
					{ID: 6, AnalyzerIP: "192.168.0.2"},
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
				vtaps: []*mysql.VTap{
					{ID: 1, AnalyzerIP: "192.168.0.1"},
					{ID: 2, AnalyzerIP: "192.168.0.1"},
					{ID: 3, AnalyzerIP: "192.168.0.2"},
					{ID: 4, AnalyzerIP: "192.168.0.2"},
					{ID: 5, AnalyzerIP: "192.168.0.3"},
					{ID: 6, AnalyzerIP: "192.168.0.3"},
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
				vtaps: []*mysql.VTap{
					{ID: 1, AnalyzerIP: ""},
					{ID: 2, AnalyzerIP: ""},
					{ID: 3, AnalyzerIP: ""},
					{ID: 4, AnalyzerIP: ""},
					{ID: 5, AnalyzerIP: ""},
					{ID: 6, AnalyzerIP: ""},
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
				vtaps:           tt.fields.vtaps,
				analyzers:       tt.fields.analyzers,
			}
			got, got1 := p.rebalanceAnalyzer(tt.arg.ifCheck)
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

func Test_AnalyzerInfo_RebalanceAnalyzerByTraffic(t *testing.T) {
	type args struct {
		ifCheckout   bool
		dataDuration int
	}
	tests := []struct {
		name        string
		args        args
		prepareMock func(*testing.T, *AnalyzerInfo)
		want        *model.VTapRebalanceResult
		wantErr     bool
	}{
		{
			name: "normal",
			args: args{ifCheckout: true},
			prepareMock: func(t *testing.T, analyzerInfo *AnalyzerInfo) {
				ctl := gomock.NewController(t)
				defer ctl.Finish()

				mockDB := mocks.NewMockDB(ctl)
				mockDB.EXPECT().Get().Return(nil).AnyTimes()
				mockQuerier := mocks.NewMockQuerier(ctl)
				vtapNameToTraffic1 := map[string]int64{
					"deepflow-agent-kvdfq":          0,
					"analyzer23-V80":                1143803380205,
					"node25-V98":                    257133899165,
					"controller21-V81":              2003650739777,
					"master24-V99":                  159003985827,
					"tomato-V100":                   2624832689,
					"analyzer22-V82":                822718331962,
					"Automation-Public-Debug-W2523": 0,
				}
				mockQuerier.EXPECT().GetAgentDispatcher("master-", 0).Return(vtapNameToTraffic1, nil).AnyTimes()
				vtapNameToTraffic2 := map[string]int64{
					"master65-V96":                            6695427268,
					"zqy-k8s-test2-V95":                       5510451019,
					"test-suncy-2-V33":                        439735190,
					"controller20-V89":                        782390468225,
					"vsphere252-win2019-10.50.1.70-W2212":     44634783020,
					"test-suncy-1-V32":                        2604616196,
					"zx-test1-10.50.100.71-W2748":             14622179,
					"lh-1-zqytest10.50.100.81-W2746":          112457139,
					"vsphere252-hyperv-10.50.1.73-W2215":      44629063242,
					"maste10.50.1.160-W2736":                  108315921,
					"openstack14-ubuntu1404-10.50.1.61-W2710": 19216200,
					"ubuntu-22.04-node-V21":                   7776242323,
					"a7":                                      83797875970,
					"zqy-k8s-test1-V94":                       10563563877,
					"ubuntu16.04-10.50.100.126-W2738":         6753916,
					"analyzer8-V88":                           788528100245,
					"node66-V97":                              1903900750,
					"ubuntu-22.04-master-V22":                 37401081294,
					"10.50.1.153-H42":                         763009540,
				}
				mockQuerier.EXPECT().GetAgentDispatcher("slave1-", 0).Return(vtapNameToTraffic2, nil).AnyTimes()
				analyzerInfo.db = mockDB
				analyzerInfo.query = mockQuerier
				analyzerInfo.dbInfo = &DBInfo{
					AZAnalyzerConns: []mysql.AZAnalyzerConnection{
						{AZ: "ALL", Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", AnalyzerIP: "10.1.23.23"},
						{AZ: "ALL", Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", AnalyzerIP: "10.1.23.21"},
						{AZ: "ALL", Region: "396531b8-6297-4515-91e6-2969b601c104", AnalyzerIP: "10.50.1.20"},
						{AZ: "ALL", Region: "396531b8-6297-4515-91e6-2969b601c104", AnalyzerIP: "10.50.1.8"},
						{AZ: "ALL", Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", AnalyzerIP: "10.1.23.22"},
					},
					Analyzers: []mysql.Analyzer{
						{IP: "10.1.23.23", State: 2},
						{IP: "10.1.23.21", State: 2},
						{IP: "10.50.1.20", State: 2},
						{IP: "10.50.1.8", State: 2},
						{IP: "10.1.23.22", State: 2},
					},
					AZs: []mysql.AZ{
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "ffffffff-ffff-ffff-ffff-ffffffffffff"}},
						{Region: "396531b8-6297-4515-91e6-2969b601c104", Base: mysql.Base{Lcuuid: "9b77b708-03c5-56e1-928d-de48be830aff"}},
						{Region: "396531b8-6297-4515-91e6-2969b601c104", Base: mysql.Base{Lcuuid: "22bade47-1a47-52c0-902e-243deb44c3ff"}},
						{Region: "396531b8-6297-4515-91e6-2969b601c104", Base: mysql.Base{Lcuuid: "be348a51-1685-5b11-9aff-778dd6b828ff"}},
						{Region: "396531b8-6297-4515-91e6-2969b601c104", Base: mysql.Base{Lcuuid: "9e33ce09-0bf9-502c-afe6-eba39ca204ff"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "4cf87ac9-fc52-5ea2-a91d-4fd1812042ff"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "379f4280-7049-5766-8749-5ddbc90c5cff"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "3ca4bbe6-1d81-51d5-a967-31e9739c86f8"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "706f1d74-6443-596a-9c9b-1e63d8f6c748"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "99372578-5c18-5ffb-9c3d-92e44f8f5d50"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "efa76df4-f6e7-55a2-ac91-a17a348f8945"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "2b901916-4fdc-5cad-809b-0ea6823775e8"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "bb887c7d-7207-584e-b001-3bff78514729"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "52316a67-55a3-50b3-8224-63e80e3b3f97"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "d00cf304-ceb4-5714-bacf-1ec184748d25"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "eac86c11-71c3-5db0-a591-a6b7fb64d1f4"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "63e6357e-5973-5e89-9647-62ad8da3443a"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "04d0cfd6-8cf0-596e-acb4-88d42e469588"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "cd9ada09-11a6-5d5a-99ca-5545ddfafce4"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "ec845427-14aa-5f93-8cc1-533dd2be8e2f"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "06772ec3-17fb-59c5-a536-3fe9958ae32d"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "44ef678c-e8ca-57c8-9592-a6e23c9ac669"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "149fb842-f6a6-5b43-95cb-dd4c16ff9bcd"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "627b6a37-b2bb-5ee2-a288-fa50f10b4346"}},
						{Region: "396531b8-6297-4515-91e6-2969b601c104", Base: mysql.Base{Lcuuid: "4ae44912-600f-52d2-93a4-5a5d028dfdff"}},
						{Region: "396531b8-6297-4515-91e6-2969b601c104", Base: mysql.Base{Lcuuid: "c477b669-f325-57e1-8cd8-5074e0d54cff"}},
						{Region: "396531b8-6297-4515-91e6-2969b601c104", Base: mysql.Base{Lcuuid: "f33fdd6d-d027-5f79-ba99-a40b46c5f9ff"}},
						{Region: "396531b8-6297-4515-91e6-2969b601c104", Base: mysql.Base{Lcuuid: "4c351ce9-b6fb-55cb-bdd5-c2c9ae1cb6ff"}},
						{Region: "396531b8-6297-4515-91e6-2969b601c104", Base: mysql.Base{Lcuuid: "0552bacf-5927-5a8d-a02e-c13b601039ff"}},
						{Region: "396531b8-6297-4515-91e6-2969b601c104", Base: mysql.Base{Lcuuid: "97f2edd9-e10e-516d-834e-74bf2e43c7ff"}},
						{Region: "396531b8-6297-4515-91e6-2969b601c104", Base: mysql.Base{Lcuuid: "237d83da-d6a3-58bd-8605-4f75dfb3a8ff"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "a931078c-c7b2-5190-ba57-8cc435502713"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "0ed61353-307a-5f2c-b177-40bf56d5748a"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "7506b859-e150-59ab-9d7c-21d9cd40c7ad"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "90b10c24-40da-586f-8fb1-629e4c5078d5"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "31e06c8b-459f-5b49-a7bc-c4b23612258a"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "0d418a66-20c4-54f7-a107-fdd6fb486522"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "71061f5e-d19a-5b95-926a-3d47cc9476ff"}},
						{Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", Base: mysql.Base{Lcuuid: "4899614d-58e5-5619-9a5e-85afdd4232ff"}},
					},
					VTaps: []mysql.VTap{
						{ID: 456, AZ: "be348a51-1685-5b11-9aff-778dd6b828ff", Name: "vsphere252-hyperv-10.50.1.73-W2215", AnalyzerIP: "10.50.1.8"},
						{ID: 545, AZ: "4cf87ac9-fc52-5ea2-a91d-4fd1812042ff", Name: "controller21-V81", AnalyzerIP: "10.1.23.22"},
						{ID: 546, AZ: "4cf87ac9-fc52-5ea2-a91d-4fd1812042ff", Name: "analyzer23-V80", AnalyzerIP: "10.1.23.21"},
						{ID: 565, AZ: "4c351ce9-b6fb-55cb-bdd5-c2c9ae1cb6ff", Name: "controller20-V89", AnalyzerIP: "10.50.1.8"},
						{ID: 571, AZ: "c477b669-f325-57e1-8cd8-5074e0d54cff", Name: "ubuntu-22.04-node-V21", AnalyzerIP: "10.50.1.8"},
						{ID: 580, AZ: "237d83da-d6a3-58bd-8605-4f75dfb3a8ff", Name: "10.50.1.153-H42", AnalyzerIP: "10.50.1.8"},
						{ID: 581, AZ: "237d83da-d6a3-58bd-8605-4f75dfb3a8ff", Name: "zx-test1-10.50.100.71-W2748", AnalyzerIP: "10.50.1.8"},
						{ID: 585, AZ: "237d83da-d6a3-58bd-8605-4f75dfb3a8ff", Name: "lh-1-zqytest10.50.100.81-W2746", AnalyzerIP: "10.50.1.8"},
						{ID: 610, AZ: "4c351ce9-b6fb-55cb-bdd5-c2c9ae1cb6ff", Name: "analyzer8-V88", AnalyzerIP: "10.50.1.20"},
						{ID: 612, AZ: "71061f5e-d19a-5b95-926a-3d47cc9476ff", Name: "node25-V98", AnalyzerIP: "10.1.23.21"},
						{ID: 613, AZ: "71061f5e-d19a-5b95-926a-3d47cc9476ff", Name: "master24-V99", AnalyzerIP: "10.1.23.22"},
						{ID: 615, AZ: "237d83da-d6a3-58bd-8605-4f75dfb3a8ff", Name: "a7", AnalyzerIP: "10.50.1.20"},
						{ID: 622, AZ: "237d83da-d6a3-58bd-8605-4f75dfb3a8ff", Name: "ubuntu16.04-10.50.100.126-W2738", AnalyzerIP: "10.50.1.20"},
						{ID: 623, AZ: "237d83da-d6a3-58bd-8605-4f75dfb3a8ff", Name: "maste10.50.1.160-W2736", AnalyzerIP: "10.50.1.20"},
						{ID: 625, AZ: "c477b669-f325-57e1-8cd8-5074e0d54cff", Name: "ubuntu-22.04-master-V22", AnalyzerIP: "10.50.1.20"},
						{ID: 627, AZ: "be348a51-1685-5b11-9aff-778dd6b828ff", Name: "vsphere252-win2019-10.50.1.70-W2212", AnalyzerIP: "10.50.1.20"},
						{ID: 630, AZ: "f33fdd6d-d027-5f79-ba99-a40b46c5f9ff", Name: "zqy-k8s-test2-V95", AnalyzerIP: "10.50.1.20"},
						{ID: 632, AZ: "be348a51-1685-5b11-9aff-778dd6b828ff", Name: "master65-V96", AnalyzerIP: "10.50.1.20"},
						{ID: 633, AZ: "be348a51-1685-5b11-9aff-778dd6b828ff", Name: "node66-V97", AnalyzerIP: "10.50.1.8"},
						{ID: 634, AZ: "4899614d-58e5-5619-9a5e-85afdd4232ff", Name: "tomato-V100", AnalyzerIP: "10.1.23.22"},
						{ID: 638, AZ: "f33fdd6d-d027-5f79-ba99-a40b46c5f9ff", Name: "zqy-k8s-test1-V94", AnalyzerIP: "10.50.1.8"},
						{ID: 641, AZ: "4cf87ac9-fc52-5ea2-a91d-4fd1812042ff", Name: "analyzer22-V82", AnalyzerIP: "10.1.23.23"},
					},
					AZControllerConns: []mysql.AZControllerConnection{
						{AZ: "ALL", Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", ControllerIP: "10.1.23.23"},
						{AZ: "ALL", Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", ControllerIP: "10.1.23.21"},
						{AZ: "ALL", Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", ControllerIP: "10.1.23.22"},
						{AZ: "ALL", Region: "396531b8-6297-4515-91e6-2969b601c104", ControllerIP: "10.50.1.20"},
						{AZ: "ALL", Region: "396531b8-6297-4515-91e6-2969b601c104", ControllerIP: "10.50.1.8"},
						{AZ: "ALL", Region: "ffffffff-ffff-ffff-ffff-ffffffffffff", ControllerIP: "10.1.4.3"},
					},
					Controllers: []mysql.Controller{
						{RegionDomainPrefix: "master-", IP: "10.1.23.23"},
						{RegionDomainPrefix: "master-", IP: "10.1.23.21"},
						{RegionDomainPrefix: "master-", IP: "10.1.23.22"},
						{RegionDomainPrefix: "slave1-", IP: "10.50.1.20"},
						{RegionDomainPrefix: "slave1-", IP: "10.50.1.8"},
					},
				}
			},
			want: &model.VTapRebalanceResult{
				TotalSwitchVTapNum: 4,
				Details: []*model.HostVTapRebalanceResult{
					{IP: "10.50.1.20", BeforeVTapNum: 2, AfterVTapNum: 2, SwitchVTapNum: 0, State: 2,
						BeforeVTapWeights: 0.53, AfterVTapWeights: 0.52, AZ: "be348a51-1685-5b11-9aff-778dd6b828ff"},
					{IP: "10.50.1.8", BeforeVTapNum: 2, AfterVTapNum: 2, SwitchVTapNum: 0, State: 2,
						BeforeVTapWeights: 0.48, AfterVTapWeights: 0.48, AZ: "be348a51-1685-5b11-9aff-778dd6b828ff"},
					// the other az
					{IP: "10.1.23.23", BeforeVTapNum: 1, AfterVTapNum: 1, SwitchVTapNum: 0, State: 2,
						BeforeVTapWeights: 0.21, AfterVTapWeights: 0.21, AZ: "4cf87ac9-fc52-5ea2-a91d-4fd1812042ff"},
					{IP: "10.1.23.21", BeforeVTapNum: 1, AfterVTapNum: 1, SwitchVTapNum: 0, State: 2,
						BeforeVTapWeights: 0.29, AfterVTapWeights: 0.29, AZ: "4cf87ac9-fc52-5ea2-a91d-4fd1812042ff"},
					{IP: "10.1.23.22", BeforeVTapNum: 1, AfterVTapNum: 1, SwitchVTapNum: 0, State: 2,
						BeforeVTapWeights: 0.5, AfterVTapWeights: 0.5, AZ: "4cf87ac9-fc52-5ea2-a91d-4fd1812042ff"},
					// the other az
					{IP: "10.50.1.20", BeforeVTapNum: 1, AfterVTapNum: 1, SwitchVTapNum: 0, State: 2,
						BeforeVTapWeights: 0.83, AfterVTapWeights: 0.83, AZ: "c477b669-f325-57e1-8cd8-5074e0d54cff"},
					{IP: "10.50.1.8", BeforeVTapNum: 1, AfterVTapNum: 1, SwitchVTapNum: 0, State: 2,
						BeforeVTapWeights: 0.17, AfterVTapWeights: 0.17, AZ: "c477b669-f325-57e1-8cd8-5074e0d54cff"},
					// the other az
					{IP: "10.50.1.20", BeforeVTapNum: 1, AfterVTapNum: 1, SwitchVTapNum: 0, State: 2,
						BeforeVTapWeights: 0.34, AfterVTapWeights: 0.34, AZ: "f33fdd6d-d027-5f79-ba99-a40b46c5f9ff"},
					{IP: "10.50.1.8", BeforeVTapNum: 1, AfterVTapNum: 1, SwitchVTapNum: 0, State: 2,
						BeforeVTapWeights: 0.66, AfterVTapWeights: 0.66, AZ: "f33fdd6d-d027-5f79-ba99-a40b46c5f9ff"},
					// the other az
					{IP: "10.50.1.20", BeforeVTapNum: 1, AfterVTapNum: 1, SwitchVTapNum: 0, State: 2,
						BeforeVTapWeights: 0.5, AfterVTapWeights: 0.5, AZ: "4c351ce9-b6fb-55cb-bdd5-c2c9ae1cb6ff"},
					{IP: "10.50.1.8", BeforeVTapNum: 1, AfterVTapNum: 1, SwitchVTapNum: 0, State: 2,
						BeforeVTapWeights: 0.5, AfterVTapWeights: 0.5, AZ: "4c351ce9-b6fb-55cb-bdd5-c2c9ae1cb6ff"},
					// the other az
					{IP: "10.50.1.20", BeforeVTapNum: 3, AfterVTapNum: 1, SwitchVTapNum: 2, State: 2,
						BeforeVTapWeights: 0.99, AfterVTapWeights: 0.99, AZ: "237d83da-d6a3-58bd-8605-4f75dfb3a8ff"},
					{IP: "10.50.1.8", BeforeVTapNum: 3, AfterVTapNum: 5, SwitchVTapNum: 2, State: 2,
						BeforeVTapWeights: 0.01, AfterVTapWeights: 0.01, AZ: "237d83da-d6a3-58bd-8605-4f75dfb3a8ff"},
					// the other az
					{IP: "10.1.23.23", BeforeVTapNum: 0, AfterVTapNum: 0, SwitchVTapNum: 0, State: 2,
						BeforeVTapWeights: 0, AfterVTapWeights: 0, AZ: "71061f5e-d19a-5b95-926a-3d47cc9476ff"},
					{IP: "10.1.23.21", BeforeVTapNum: 1, AfterVTapNum: 1, SwitchVTapNum: 0, State: 2,
						BeforeVTapWeights: 0.62, AfterVTapWeights: 0.62, AZ: "71061f5e-d19a-5b95-926a-3d47cc9476ff"},
					{IP: "10.1.23.22", BeforeVTapNum: 1, AfterVTapNum: 1, SwitchVTapNum: 0, State: 2,
						BeforeVTapWeights: 0.38, AfterVTapWeights: 0.38, AZ: "71061f5e-d19a-5b95-926a-3d47cc9476ff"},
					// the other az
					{IP: "10.1.23.23", BeforeVTapNum: 0, AfterVTapNum: 0, SwitchVTapNum: 0, State: 2,
						BeforeVTapWeights: 0, AfterVTapWeights: 0, AZ: "4899614d-58e5-5619-9a5e-85afdd4232ff"},
					{IP: "10.1.23.21", BeforeVTapNum: 0, AfterVTapNum: 0, SwitchVTapNum: 0, State: 2,
						BeforeVTapWeights: 0, AfterVTapWeights: 0, AZ: "4899614d-58e5-5619-9a5e-85afdd4232ff"},
					{IP: "10.1.23.22", BeforeVTapNum: 1, AfterVTapNum: 1, SwitchVTapNum: 0, State: 2,
						BeforeVTapWeights: 1, AfterVTapWeights: 1, AZ: "4899614d-58e5-5619-9a5e-85afdd4232ff"},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewAnalyzerInfo()
			tt.prepareMock(t, r)
			got, err := r.RebalanceAnalyzerByTraffic(tt.args.ifCheckout, tt.args.dataDuration)
			if (err != nil) != tt.wantErr {
				t.Errorf("analyzerInfo.RebalanceAnalyzerByTraffic() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.EqualValues(t, tt.want, got)
		})
	}
}
