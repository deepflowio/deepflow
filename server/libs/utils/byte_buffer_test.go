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

func TestByteBufferUse(t *testing.T) {
	bytes := &ByteBuffer{quota: 10}
	buf := bytes.Use(10)
	if len(buf) != 10 || len(bytes.Bytes()) != 10 {
		t.Error("Use函数处理不正确")
	}
}

func TestByteBufferUseTwice(t *testing.T) {
	bytes := &ByteBuffer{quota: 10}
	buf := bytes.Use(10)
	if len(buf) != 10 || len(bytes.Bytes()) != 10 {
		t.Error("第一次调用Use函数处理不正确")
	}
	bytes.SetQuota(30)
	buf = bytes.Use(20)
	if len(buf) != 20 || len(bytes.Bytes()) != 30 {
		t.Error("第二次调用Use函数处理不正确")
	}
}

func TestByteBufferReset(t *testing.T) {
	bytes := &ByteBuffer{quota: 10}
	buf := bytes.Use(10)
	if len(buf) != 10 || len(bytes.Bytes()) != 10 {
		t.Error("Use函数处理不正确")
	}
	bytes.Reset()
	if len(bytes.Bytes()) != 0 {
		t.Error("Reset函数处理不正确")
	}
}
