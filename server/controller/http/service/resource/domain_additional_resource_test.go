/*
 * Copyright (c) 2022 Yunshan Networks
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

package resource

import (
	"testing"

	"github.com/deepflowio/deepflow/server/controller/model"
)

func Test_convertTagsToString(t *testing.T) {
	type args struct {
		tags []model.AdditionalResourceTag
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "one tag",
			args: args{
				tags: []model.AdditionalResourceTag{
					{Key: "key-1", Value: "value-1"},
				},
			},
			want:    "key-1:value-1",
			wantErr: false,
		},
		{
			name: "more than one tags",
			args: args{
				tags: []model.AdditionalResourceTag{
					{Key: "key-1", Value: "value-1"},
					{Key: "key-2", Value: "value-2"},
				},
			},
			want:    "key-1:value-1, key-2:value-2",
			wantErr: false,
		},
		{
			name: "one of tags with null",
			args: args{
				tags: []model.AdditionalResourceTag{
					{Key: "", Value: ""},
					{Key: "key", Value: "value"},
				},
			},
			wantErr: true,
		},
		{
			name: "one tag with null",
			args: args{
				tags: []model.AdditionalResourceTag{
					{Key: "", Value: ""},
				},
			},
			wantErr: true,
		},
		{
			name: "without tags",
			args: args{
				tags: []model.AdditionalResourceTag{},
			},
			want:    "",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertTagsToString(tt.args.tags)
			if (err != nil) != tt.wantErr {
				t.Errorf("convertTagsToString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("convertTagsToString() = %v, want %v", got, tt.want)
			}
		})
	}
}
