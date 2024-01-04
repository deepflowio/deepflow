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

package datatype

import (
	"reflect"
	"testing"
)

func TestPortRange(t *testing.T) {
	expect := []PortRange{NewPortRange(1, 1), NewPortRange(2, 2), NewPortRange(3, 3)}
	result := GetPortRanges([]PortRange{NewPortRange(1, 2), NewPortRange(2, 3)})
	if !reflect.DeepEqual(expect, result) {
		t.Errorf("TestPortRange expect: %+v  return: %+v ", expect, result)
	}

	result = GetPortRanges([]PortRange{NewPortRange(6666, 6666), NewPortRange(6667, 6667), NewPortRange(6666, 6667), NewPortRange(8000, 8003), NewPortRange(8002, 8005), NewPortRange(8001, 8001), NewPortRange(8005, 8005)})
	expect = []PortRange{NewPortRange(6666, 6666), NewPortRange(6667, 6667), NewPortRange(8000, 8000), NewPortRange(8001, 8001), NewPortRange(8002, 8003), NewPortRange(8004, 8004), NewPortRange(8005, 8005)}
	if !reflect.DeepEqual(expect, result) {
		t.Errorf("TestPortRange expect: %+v  return: %+v ", expect, result)
	}

	expect = []PortRange{NewPortRange(1, 1), NewPortRange(2, 2)}
	result = GetPortRanges([]PortRange{NewPortRange(1, 2), NewPortRange(2, 2)})
	if !reflect.DeepEqual(expect, result) {
		t.Errorf("TestPortRange expect: %+v  return: %+v ", expect, result)
	}

	expect = []PortRange{NewPortRange(1, 1), NewPortRange(2, 2)}
	result = GetPortRanges([]PortRange{NewPortRange(1, 1), NewPortRange(1, 2)})
	if !reflect.DeepEqual(expect, result) {
		t.Errorf("TestPortRange expect: %+v  return: %+v ", expect, result)
	}

	expect = []PortRange{NewPortRange(1, 1), NewPortRange(2, 2)}
	result = GetPortRanges([]PortRange{NewPortRange(1, 1), NewPortRange(2, 2)})
	if !reflect.DeepEqual(expect, result) {
		t.Errorf("TestPortRange expect: %+v  return: %+v ", expect, result)
	}

	expect = []PortRange{NewPortRange(1, 4), NewPortRange(5, 8), NewPortRange(9, 10)}
	result = GetPortRanges([]PortRange{NewPortRange(1, 10), NewPortRange(5, 8)})
	if !reflect.DeepEqual(expect, result) {
		t.Errorf("TestPortRange expect: %+v  return: %+v ", expect, result)
	}

	expect = []PortRange{NewPortRange(1, 8), NewPortRange(9, 9), NewPortRange(10, 10), NewPortRange(11, 15), NewPortRange(16, 20)}
	result = GetPortRanges([]PortRange{NewPortRange(1, 10), NewPortRange(9, 15), NewPortRange(10, 20)})
	if !reflect.DeepEqual(expect, result) {
		t.Errorf("TestPortRange expect: %+v  return: %+v ", expect, result)
	}

	expect = []PortRange{NewPortRange(1, 8), NewPortRange(9, 9), NewPortRange(10, 10), NewPortRange(11, 15), NewPortRange(16, 18), NewPortRange(19, 20)}
	result = GetPortRanges([]PortRange{NewPortRange(1, 10), NewPortRange(9, 15), NewPortRange(10, 20), NewPortRange(11, 18)})
	if !reflect.DeepEqual(expect, result) {
		t.Errorf("TestPortRange expect: %+v  return: %+v ", expect, result)
	}

	expect = []PortRange{NewPortRange(1, 9), NewPortRange(10, 19), NewPortRange(20, 29), NewPortRange(30, 39), NewPortRange(40, 60), NewPortRange(61, 70), NewPortRange(71, 80), NewPortRange(81, 90), NewPortRange(91, 100)}
	result = GetPortRanges([]PortRange{NewPortRange(1, 100), NewPortRange(10, 90), NewPortRange(20, 80), NewPortRange(30, 70), NewPortRange(40, 60)})
	if !reflect.DeepEqual(expect, result) {
		t.Errorf("TestPortRange expect: %+v  return: %+v ", expect, result)
	}

	expect = []PortRange{NewPortRange(1, 1), NewPortRange(2, 2), NewPortRange(3, 3), NewPortRange(4, 79), NewPortRange(80, 80), NewPortRange(81, 100), NewPortRange(200, 300)}
	result = GetPortRanges([]PortRange{NewPortRange(1, 1), NewPortRange(2, 2), NewPortRange(3, 3), NewPortRange(3, 100), NewPortRange(80, 80), NewPortRange(200, 300)})
	if !reflect.DeepEqual(expect, result) {
		t.Errorf("TestPortRange expect: %+v  return: %+v ", expect, result)
	}

	expect = []PortRange{NewPortRange(0, 999), NewPortRange(1000, 1000), NewPortRange(1001, 65535)}
	result = GetPortRanges([]PortRange{NewPortRange(1000, 1000), NewPortRange(0, 65535)})
	if !reflect.DeepEqual(expect, result) {
		t.Errorf("TestPortRange expect: %+v  return: %+v ", expect, result)
	}
}
