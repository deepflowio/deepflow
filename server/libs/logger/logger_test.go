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

package logger

import (
	"testing"
)

func TestGetRemoteAddress(t *testing.T) {
	for _, tc := range []struct {
		input  string
		output string
	}{
		{"172.16.1.128", "172.16.1.128:20033"},
		{"172.16.1.128:20033", "172.16.1.128:20033"},
		{"2009::123", "[2009::123]:20033"},
		{"[2009::123]:20033", "[2009::123]:20033"},
		{"localhost", "localhost:20033"},
		{"localhost:20033", "localhost:20033"},
		{"github.com", "github.com:20033"},
		{"github.com:20033", "github.com:20033"},
	} {
		if result := getRemoteAddress(tc.input, 20033); result != tc.output {
			t.Errorf("应为%s, 实为%s", tc.output, result)
		}
	}
}
