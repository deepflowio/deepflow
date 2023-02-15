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

func Test_vtapToCSVData(t *testing.T) {
	type args struct {
		headers []model.CSVHeader
		vtap    *model.Vtap
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "two headers",
			args: args{
				headers: []model.CSVHeader{
					{DisplayName: "名称", FieldName: "NAME"},
					{DisplayName: "区域", FieldName: "REGION_NAME"},
				},
				vtap: &model.Vtap{Name: "name", RegionName: "region name"},
			},
			want: []string{"name", "region name"},
		},
		{
			name: "special headers",
			args: args{
				headers: []model.CSVHeader{
					{DisplayName: "类型", FieldName: "TYPE"},
					{DisplayName: "采集模式", FieldName: "TAP_MODE"},
					{DisplayName: "状态", FieldName: "STATE"},
					{DisplayName: "启动时间", FieldName: "BOOT_TIME"},
					{DisplayName: "异常", FieldName: "EXCEPTIONS"},
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
				headers: []model.CSVHeader{
					{DisplayName: "启动时间", FieldName: "BOOT_TIME"},
					{DisplayName: "异常", FieldName: "EXCEPTIONS"},
				},
				vtap: &model.Vtap{BootTime: 0, Exceptions: []int64{}},
			},
			want: []string{"", ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := vtapToCSVData(tt.args.headers, tt.args.vtap); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("vtapToCSVData() = %v, want %v", got, tt.want)
			}
		})
	}
}
