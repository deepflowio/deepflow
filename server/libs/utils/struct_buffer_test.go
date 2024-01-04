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

package utils

import (
	"testing"
)

type testStruct struct {
	v int
}

func TestGetStructBuffer(t *testing.T) {
	b := &StructBuffer{New: func() interface{} { return &testStruct{} }}
	v := b.Get()
	if v.(*testStruct) == nil || len(b.Slice()) != 1 {
		t.Errorf("Get操作处理不正确")
	}

	v = b.Get()
	if v.(*testStruct) == nil || len(b.Slice()) != 2 {
		t.Errorf("Get操作处理不正确")
	}
}

func TestResetStructBuffer(t *testing.T) {
	b := &StructBuffer{New: func() interface{} { return &testStruct{} }}
	b.Get()
	b.Reset()
	v := b.Get()
	if v.(*testStruct) == nil || len(b.Slice()) != 1 {
		t.Errorf("Reset操作处理不正确")
	}
}
