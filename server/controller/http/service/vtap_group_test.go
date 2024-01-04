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

import "testing"

func TestIsVtapGroupShortUUID(t *testing.T) {
	type args struct {
		uuid string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "successful match",
			args: args{
				uuid: "g-1yhIguXFQH",
			},
			want: true,
		},
		{
			name: "contains ','",
			args: args{
				uuid: "g-yh,guXFQH",
			},
			want: false,
		},
		{
			name: "contains '#'",
			args: args{
				uuid: "g-yhguX#FQH",
			},
			want: false,
		},
		{
			name: "mismatched length",
			args: args{
				uuid: "g-1yhIguXFa",
			},
			want: false,
		},
		{
			name: "mismatched length",
			args: args{
				uuid: "g-1yhIguXFabbbbb",
			},
			want: false,
		},
		{
			name: "does not contain the g- prefix",
			args: args{
				uuid: "1yhIguXFa",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsVtapGroupShortUUID(tt.args.uuid); got != tt.want {
				t.Errorf("IsShortUUID() = %v, want %v", got, tt.want)
			}
		})
	}
}
