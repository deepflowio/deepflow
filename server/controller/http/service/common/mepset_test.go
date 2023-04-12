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

import (
	"testing"

	mapset "github.com/deckarep/golang-set"
)

func TestCompareSets(t *testing.T) {
	type args struct {
		set1 mapset.Set
		set2 mapset.Set
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test case EQUAL",
			args: args{
				set1: mapset.NewSetFromSlice([]interface{}{"a", "b", "c"}),
				set2: mapset.NewSetFromSlice([]interface{}{"a", "b", "c"}),
			},
			want: EQUAL,
		},
		{
			name: "Test case DISJOINT",
			args: args{
				set1: mapset.NewSetFromSlice([]interface{}{"a", "b"}),
				set2: mapset.NewSetFromSlice([]interface{}{"c", "d"}),
			},
			want: DISJOINT,
		},
		{
			name: "Test case CONTAINED_BY",
			args: args{
				set1: mapset.NewSetFromSlice([]interface{}{"a", "b"}),
				set2: mapset.NewSetFromSlice([]interface{}{"a", "b", "c"}),
			},
			want: CONTAINED_BY,
		},
		{
			name: "Test case CONTAINS",
			args: args{
				set1: mapset.NewSetFromSlice([]interface{}{"a", "b", "c"}),
				set2: mapset.NewSetFromSlice([]interface{}{"a", "b"}),
			},
			want: CONTAINS,
		},
		{
			name: "Test case INTERSECTING",
			args: args{
				set1: mapset.NewSetFromSlice([]interface{}{"a", "b"}),
				set2: mapset.NewSetFromSlice([]interface{}{"b", "c"}),
			},
			want: INTERSECTING,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CompareSets(tt.args.set1, tt.args.set2); got != tt.want {
				t.Errorf("CompareSets() = %v, want %v", got, tt.want)
			}
		})
	}
}
