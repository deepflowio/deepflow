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

package hmap

import (
	"testing"
)

func TestDumpHexBytes(t *testing.T) {
	for _, tc := range []struct {
		input  []byte
		output string
	}{
		{
			[]byte{}, "0x0",
		},
		{
			[]byte{0, 0, 0, 0, 1}, "0x1",
		},
		{
			[]byte{0, 0, 1, 0, 1}, "0x10001",
		},
		{
			[]byte{0xff, 0, 0, 0, 0}, "0xff00000000",
		},
	} {
		if result := dumpHexBytes(tc.input); result != tc.output {
			t.Errorf("结果不正确, 应为%s, 实为%s", tc.output, result)
		}
	}
}
