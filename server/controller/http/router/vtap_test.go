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

package router

import (
	"reflect"
	"testing"

	"github.com/deepflowio/deepflow/server/controller/model"
)

func Test_getVtapCSVData(t *testing.T) {
	type args struct {
		headerMap map[string]int
		vtap      *model.Vtap
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "two headers",
			args: args{
				headerMap: map[string]int{
					"NAME":        0,
					"REGION_NAME": 1,
				},
				vtap: &model.Vtap{Name: "name", RegionName: "region name"},
			},
			want: []string{"name", "region name"},
		},
		{
			name: "special headers",
			args: args{
				headerMap: map[string]int{
					"TYPE":       0,
					"TAP_MODE":   1,
					"STATE":      2,
					"BOOT_TIME":  3,
					"EXCEPTIONS": 4,
				},
				vtap: &model.Vtap{
					Type:       1,
					TapMode:    1,
					State:      1,
					BootTime:   1676022891,
					Exceptions: []int64{268435456, 1073741824},
				},
			},
			want: []string{"KVM", "镜像", "运行", "2023-02-10 17:54:51", "采集器授权个数不足、分配数据节点失败"},
		},
		{
			name: "boot time header",
			args: args{
				headerMap: map[string]int{
					"BOOT_TIME":  0,
					"EXCEPTIONS": 0,
				},
				vtap: &model.Vtap{BootTime: 0, Exceptions: []int64{}},
			},
			want: []string{"", ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getVtapCSVData(tt.args.headerMap, tt.args.vtap); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getVtapCSVData() = %v, want %v", got, tt.want)
			}
		})
	}
}
