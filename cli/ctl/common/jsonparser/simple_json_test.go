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

package jsonparser

import (
	"testing"

	"github.com/bitly/go-simplejson"
)

func TestGetTheMaxSizeOfAttr(t *testing.T) {
	case1Str := `{"DATA":[{"NAME":"tencent"},{"NAME":"legacy-host"},{"NAME":"mars"}]}`
	case1Json, err := simplejson.NewJson([]byte(case1Str))
	if err != nil {
		t.Error(err)
	}
	case2Str := `{"DATA":[{"ID":"1"},{"ID":"2"},{"ID":"3"}]}`
	case2Json, err := simplejson.NewJson([]byte(case2Str))
	if err != nil {
		t.Error(err)
	}
	case3Str := `{"DATA":{"ID":"1"}}`
	case3Json, err := simplejson.NewJson([]byte(case3Str))
	if err != nil {
		t.Error(err)
	}

	type args struct {
		data *simplejson.Json
		attr string
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "success",
			args: args{
				data: case1Json,
				attr: "NAME",
			},
			want: 11,
		},
		{
			name: "data has no NAME attribute",
			args: args{
				data: case2Json,
				attr: "NAME",
			},
			want: 4,
		},
		{
			name: "DATA is not an array",
			args: args{
				data: case3Json,
				attr: "NAME",
			},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetTheMaxSizeOfAttr(tt.args.data.Get("DATA"), tt.args.attr)
			if got != tt.want {
				t.Errorf("GetTheMaxSizeOfName() got = %v, want %v", got, tt.want)
			}
		})
	}
}
