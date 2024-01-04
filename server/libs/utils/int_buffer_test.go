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

func TestWriteU8(t *testing.T) {
	b := &IntBuffer{}
	b.WriteU8(0x2)
	exp := []byte{0x2}
	if len(b.String()) != len(exp) {
		t.Errorf("Expected %v found %v", len(exp), len(b.String()))
	}
	for i := 0; i < len(exp); i++ {
		if b.buf[i] != exp[i] {
			t.Errorf("Expected %v found %v", exp[i], b.buf[i])
		}
	}
}

func TestWriteU16(t *testing.T) {
	b := &IntBuffer{}
	b.WriteU16(0x1234)
	exp := []byte{0x34, 0x12}
	if len(b.String()) != len(exp) {
		t.Errorf("Expected %v found %v", len(exp), len(b.String()))
	}
	for i := 0; i < len(exp); i++ {
		if b.buf[i] != exp[i] {
			t.Errorf("Expected %v found %v", exp[i], b.buf[i])
		}
	}
}

func TestWriteU24(t *testing.T) {
	b := &IntBuffer{}
	b.WriteU24(0x12345678)
	exp := []byte{0x78, 0x56, 0x34}
	if len(b.String()) != len(exp) {
		t.Errorf("Expected %v found %v", len(exp), len(b.String()))
	}
	for i := 0; i < len(exp); i++ {
		if b.buf[i] != exp[i] {
			t.Errorf("Expected %v found %v", exp[i], b.buf[i])
		}
	}
}

func TestWriteU32(t *testing.T) {
	b := &IntBuffer{}
	b.WriteU32(0x12345678)
	exp := []byte{0x78, 0x56, 0x34, 0x12}
	if len(b.String()) != len(exp) {
		t.Errorf("Expected %v found %v", len(exp), len(b.String()))
	}
	for i := 0; i < len(exp); i++ {
		if b.buf[i] != exp[i] {
			t.Errorf("Expected %v found %v", exp[i], b.buf[i])
		}
	}
}

func TestWriteU48(t *testing.T) {
	b := &IntBuffer{}
	b.WriteU48(0x123456789abcdef0)
	exp := []byte{0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56}
	if len(b.String()) != len(exp) {
		t.Errorf("Expected %v found %v", len(exp), len(b.String()))
	}
	for i := 0; i < len(exp); i++ {
		if b.buf[i] != exp[i] {
			t.Errorf("Expected %v found %v", exp[i], b.buf[i])
		}
	}
}

func TestWriteU64(t *testing.T) {
	b := &IntBuffer{}
	b.WriteU64(0x123456789abcdef0)
	exp := []byte{0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12}
	if len(b.String()) != len(exp) {
		t.Errorf("Expected %v found %v", len(exp), len(b.String()))
	}
	for i := 0; i < len(exp); i++ {
		if b.buf[i] != exp[i] {
			t.Errorf("Expected %v found %v", exp[i], b.buf[i])
		}
	}
}

func TestWriteString(t *testing.T) {
	b := &IntBuffer{}
	exp := "Hello, world! Hello, Yunshan Networks!"
	b.WriteString(exp)
	if b.String() != exp {
		t.Errorf("Expected %v found %v", exp, b.String())
	}
}

func TestReset(t *testing.T) {
	b := &IntBuffer{}
	exp := "Hello, world! Hello, Yunshan Networks!"
	b.WriteString(exp)
	if b.String() != exp {
		t.Errorf("Expected %v found %v", exp, b.String())
	}

	b.Reset()
	if b.String() != "" {
		t.Errorf("Expected %v found %v", "", b.String())
	}

	exp = "Bye, world! Bye, Yunshan Networks!"
	b.WriteString(exp)
	if b.String() != exp {
		t.Errorf("Expected %v found %v", exp, b.String())
	}
}
