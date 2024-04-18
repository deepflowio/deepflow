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

package service

import (
	"testing"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/model"
)

func Test_copyStruct(t *testing.T) {
	ignoreName := []string{"ID", "YamlConfig", "L4LogTapTypes", "L4LogIgnoreTapSides",
		"L7LogIgnoreTapSides", "L7LogStoreTapTypes", "DecapType", "Domains", "MaxCollectPps",
		"MaxNpbBps", "MaxTxBandwidth", "WasmPlugins", "SoPlugins"}
	type args struct {
		from       interface{}
		to         interface{}
		ignoreName []string
	}
	tests := []struct {
		name       string
		args       args
		assertFunc func(t *testing.T, data *model.VTapGroupConfigurationResponse)
	}{
		{
			name: "ignore name test",
			args: args{
				ignoreName: ignoreName,
				from:       &agent_config.VTapGroupConfigurationModel{},
				to:         &model.VTapGroupConfigurationResponse{},
			},
			assertFunc: func(t *testing.T, data *model.VTapGroupConfigurationResponse) {
				if data.WasmPlugins == nil {
					t.Errorf("WasmPlugins is nil, wanted: []string")
				}
				if data.DecapType == nil {
					t.Errorf("DecapType is nil, wanted: []*TypeInfo")
				}
				if data.Domains == nil {
					t.Errorf("Domains is nil, wanted: []*TapSideInfo")
				}
				if data.L4LogIgnoreTapSides == nil {
					t.Errorf("L4LogIgnoreTapSides is nil, wanted: []*TapSideInfo")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			copyStruct(tt.args.from, tt.args.to, tt.args.ignoreName)
			tt.assertFunc(t, tt.args.to.(*model.VTapGroupConfigurationResponse))
		})
	}
}
