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

package log_data

import (
	"testing"
)

func TestParseUrlPath(t *testing.T) {
	testCases := []struct {
		url      string
		expected string
		err      bool
	}{
		{"http://nacos:8848/nacos/v1/ns/instance/list", "/nacos/v1/ns/instance/list", false},
		{"http://example.com/", "/", false},
		{"http://example.com", "/", false},
		{"https://example.com/path/to/resource", "/path/to/resource", false},
		{"ftp://example.com/path/to/resource", "/path/to/resource", false},
		{"example.com/path/to/resource", "", true},
		{"", "", true},
		{"http://", "", true},
	}

	for _, testCase := range testCases {
		result, err := ParseUrlPath(testCase.url)
		if (err != nil) != testCase.err {
			t.Errorf("URL: %s\nExpected error: %v\nGot error: %v\n", testCase.url, testCase.err, err != nil)
		}
		if result != testCase.expected {
			t.Errorf("URL: %s\nExpected: %s\nGot: %s\n", testCase.url, testCase.expected, result)
		}
	}
}
