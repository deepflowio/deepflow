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

package common

import "testing"

func TestDiffMap(t *testing.T) {
	type args struct {
		base    map[string]string
		newTags map[string]string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "empty cloud tags",
			args: args{
				base:    map[string]string{"key1": "value1"},
				newTags: map[string]string{},
			},
			want: true,
		},
		{
			name: "add cloud tags",
			args: args{
				base:    map[string]string{},
				newTags: map[string]string{"key1": "value1"},
			},
			want: true,
		},
		{
			name: "do nothing",
			args: args{
				base:    map[string]string{},
				newTags: map[string]string{},
			},
			want: false,
		},
		{
			name: "update cloud tags",
			args: args{
				base:    map[string]string{"key1": "value1"},
				newTags: map[string]string{"key1": "value1", "key2": "value2"},
			},
			want: true,
		},
		{
			name: "update cloud tags",
			args: args{
				base:    map[string]string{"key1": "value1", "key2": "value2"},
				newTags: map[string]string{"key1": "value1"},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DiffMap(tt.args.base, tt.args.newTags); got != tt.want {
				t.Errorf("DiffMap() = %v, want %v", got, tt.want)
			}
		})
	}
}
