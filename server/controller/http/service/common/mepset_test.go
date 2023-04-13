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
	"reflect"
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

func TestGetAddAndDelAZs(t *testing.T) {
	type args struct {
		oldSet mapset.Set
		newSet mapset.Set
	}
	tests := []struct {
		name       string
		args       args
		wantAddAZs mapset.Set
		wantDelAZs mapset.Set
	}{
		{
			name: "Test case EQUAL",
			args: args{
				oldSet: mapset.NewSetFromSlice([]interface{}{"a", "b"}),
				newSet: mapset.NewSetFromSlice([]interface{}{"a", "b"}),
			},
			wantAddAZs: mapset.NewSet(),
			wantDelAZs: mapset.NewSet(),
		},
		{
			name: "Test case DISJOINT",
			args: args{
				oldSet: mapset.NewSetFromSlice([]interface{}{"a", "b"}),
				newSet: mapset.NewSetFromSlice([]interface{}{"c", "d"}),
			},
			wantAddAZs: mapset.NewSetFromSlice([]interface{}{"c", "d"}),
			wantDelAZs: mapset.NewSetFromSlice([]interface{}{"a", "b"}),
		},
		{
			name: "Test case CONTAINED_BY",
			args: args{
				oldSet: mapset.NewSetFromSlice([]interface{}{"a", "b"}),
				newSet: mapset.NewSetFromSlice([]interface{}{"a", "b", "c"}),
			},
			wantAddAZs: mapset.NewSetFromSlice([]interface{}{"c"}),
			wantDelAZs: mapset.NewSet(),
		},
		{
			name: "Test case CONTAINS",
			args: args{
				oldSet: mapset.NewSetFromSlice([]interface{}{"a", "b", "c"}),
				newSet: mapset.NewSetFromSlice([]interface{}{"a", "b"}),
			},
			wantAddAZs: mapset.NewSet(),
			wantDelAZs: mapset.NewSetFromSlice([]interface{}{"c"}),
		},
		{
			name: "Test case INTERSECTING",
			args: args{
				oldSet: mapset.NewSetFromSlice([]interface{}{"a", "b", "c"}),
				newSet: mapset.NewSetFromSlice([]interface{}{"b", "c", "d"}),
			},
			wantAddAZs: mapset.NewSetFromSlice([]interface{}{"d"}),
			wantDelAZs: mapset.NewSetFromSlice([]interface{}{"a"}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAddAZs, gotDelAZs := GetAddAndDelAZs(tt.args.oldSet, tt.args.newSet)
			if !reflect.DeepEqual(gotAddAZs, tt.wantAddAZs) {
				t.Errorf("GetAddAndDelAZs() gotAddAZs = %v, want %v", gotAddAZs, tt.wantAddAZs)
			}
			if !reflect.DeepEqual(gotDelAZs, tt.wantDelAZs) {
				t.Errorf("GetAddAndDelAZs() gotDelAZs = %v, want %v", gotDelAZs, tt.wantDelAZs)
			}
		})
	}
}
