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
)

func Test_getTableName(t *testing.T) {
	type args struct {
		collection string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "network",
			args: args{
				collection: "flow_metrics.network*",
			},
			want: "network",
		},
		{
			name: "application",
			args: args{
				collection: "flow_metrics.application*",
			},
			want: "application",
		},
		{
			name: "flow_log.l4_flow_log",
			args: args{
				collection: "flow_log.l4_flow_log",
			},
			want: "flow_log.l4_flow_log",
		},
		{
			name: "deepflow_system",
			args: args{
				collection: "deepflow_system.*",
			},
			want: "deepflow_system",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getTableName(tt.args.collection); got != tt.want {
				t.Errorf("getTableName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getName(t *testing.T) {
	type args struct {
		interval   int
		collection string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "1s",
			args: args{
				interval:   1,
				collection: "flow_metrics.network*",
			},
			want:    "1s",
			wantErr: false,
		},
		{
			name: "1m",
			args: args{
				interval:   60 * 1,
				collection: "flow_metrics.application*",
			},
			want:    "1m",
			wantErr: false,
		},
		{
			name: "1h",
			args: args{
				interval:   60 * 60 * 1,
				collection: "flow_metrics.application*",
			},
			want:    "1h",
			wantErr: false,
		},
		{
			name: "1d",
			args: args{
				interval:   60 * 60 * 24 * 1,
				collection: "flow_metrics.application*",
			},
			want:    "1d",
			wantErr: false,
		},
		{
			name: "flow_log.l4_flow_log",
			args: args{
				interval:   0,
				collection: "flow_log.l4_flow_log",
			},
			want:    "flow_log.l4_flow_log",
			wantErr: false,
		},
		{
			name: "deepflow_system",
			args: args{
				interval:   0,
				collection: "deepflow_system.*",
			},
			want:    "deepflow_system",
			wantErr: false,
		},
		{
			name: "prometheus",
			args: args{
				interval:   0,
				collection: "prometheus.*",
			},
			want:    "prometheus",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getName(tt.args.interval, tt.args.collection)
			if (err != nil) != tt.wantErr {
				t.Errorf("getName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getName() = %v, want %v", got, tt.want)
			}
		})
	}
}
