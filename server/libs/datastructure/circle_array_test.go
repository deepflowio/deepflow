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

package datastructure

import (
	"testing"
)

func TestAppendPop(t *testing.T) {
	array := CircleArray{}
	array.Init(10)
	array.Append(10086)
	if actual := array.Pop(); actual != 10086 {
		t.Errorf("Expected 10086 found %v", actual)
	}
}

func TestPutGet(t *testing.T) {
	array := CircleArray{}
	array.Init(10)
	array.Append(10010)
	array.Put(0, 10086)
	if actual := array.Get(0); actual != 10086 {
		t.Errorf("Expected 10086 found %v", actual)
	}
}

func TestOverWrite(t *testing.T) {
	array := CircleArray{}
	array.Init(10)
	for i := 0; i < 10; i++ {
		array.Append(i + 1)
	}
	array.Push(10086)
	if actual := array.Pop(); actual != 2 {
		t.Errorf("Expected 2 found %v", actual)
	}
}

func TestOutOfCapacity(t *testing.T) {
	array := CircleArray{}
	array.Init(10)
	for i := 0; i < 10; i++ {
		array.Append(i + 1)
	}
	if actual := array.Append(11); actual != OutOfCapacity {
		t.Errorf("Expected OutOfCapacity found %v", actual)
	}
}
