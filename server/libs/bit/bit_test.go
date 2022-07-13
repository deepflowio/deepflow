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

package bit

import (
	"testing"
)

func TestCountTrailingZeros32(t *testing.T) {
	for exp := 0; exp < 32; exp++ {
		x := (uint32(1) << uint32(exp)) | (1 << 31)
		if exp != CountTrailingZeros32(x) {
			t.Errorf("Expected %v found %v", exp, CountTrailingZeros32(x))
		}
	}
}

func TestCountTrailingZeros64(t *testing.T) {
	for exp := 0; exp < 64; exp++ {
		x := (uint64(1) << uint64(exp)) | (1 << 63)
		if exp != CountTrailingZeros64(x) {
			t.Errorf("Expected %v found %v", exp, CountTrailingZeros64(x))
		}
	}
}

func TestCountLeadingZeros32(t *testing.T) {
	for exp := 0; exp < 32; exp++ {
		x := (uint32(1) << uint32(exp)) | 0x1
		if exp != CountLeadingZeros32(x) {
			t.Errorf("Expected %v found %v", exp, CountLeadingZeros32(x))
		}
	}
}

func TestCountLeadingZeros64(t *testing.T) {
	for exp := 0; exp < 64; exp++ {
		x := (uint64(1) << uint64(exp)) | 0x1
		if exp != CountLeadingZeros64(x) {
			t.Errorf("Expected %v found %v", exp, CountLeadingZeros64(x))
		}
	}
}
