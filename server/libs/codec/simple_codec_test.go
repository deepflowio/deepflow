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

package codec

import (
	"math/rand"
	"net"
	"testing"
)

func TestWriteU8(t *testing.T) {
	e := &SimpleEncoder{}
	e.WriteU8(0x2)
	exp := []byte{0x2}
	if len(e.String()) != len(exp) {
		t.Errorf("Expected %v found %v", len(exp), len(e.String()))
	}
	for i := 0; i < len(exp); i++ {
		if e.buf[i] != exp[i] {
			t.Errorf("Expected %v found %v", exp[i], e.buf[i])
		}
	}
}

func TestWriteU16(t *testing.T) {
	e := &SimpleEncoder{}
	e.WriteU16(0x1234)
	exp := []byte{0x34, 0x12}
	if len(e.String()) != len(exp) {
		t.Errorf("Expected %v found %v", len(exp), len(e.String()))
	}
	for i := 0; i < len(exp); i++ {
		if e.buf[i] != exp[i] {
			t.Errorf("Expected %v found %v", exp[i], e.buf[i])
		}
	}
}

func TestWriteU32(t *testing.T) {
	e := &SimpleEncoder{}
	e.WriteU32(0x12345678)
	exp := []byte{0x78, 0x56, 0x34, 0x12}
	if len(e.String()) != len(exp) {
		t.Errorf("Expected %v found %v", len(exp), len(e.String()))
	}
	for i := 0; i < len(exp); i++ {
		if e.buf[i] != exp[i] {
			t.Errorf("Expected %v found %v", exp[i], e.buf[i])
		}
	}
}

func TestWriteU64(t *testing.T) {
	e := &SimpleEncoder{}
	d := &SimpleDecoder{}
	e.WriteU64(0x123456789abcdef0)
	expU8 := []byte{0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12}
	d.Init(e.Bytes())
	for i := 0; i < len(expU8); i++ {
		v := d.ReadU8()
		if v != expU8[i] {
			t.Errorf("Expected %v found %v", expU8[i], v)
		}
	}

	expU16 := []uint16{0xdef0, 0x9abc, 0x5678, 0x1234}
	d.Init(e.Bytes())
	for i := 0; i < len(expU16); i++ {
		v := d.ReadU16()
		if v != expU16[i] {
			t.Errorf("Expected %v found %v", expU16[i], v)
		}
	}

	expU32 := []uint32{0x9abcdef0, 0x12345678}
	d.Init(e.Bytes())
	for i := 0; i < len(expU32); i++ {
		v := d.ReadU32()
		if v != expU32[i] {
			t.Errorf("Expected %v found %v", expU32[i], v)
		}
	}

	expU64 := []uint64{0x123456789abcdef0}
	d.Init(e.Bytes())
	for i := 0; i < len(expU64); i++ {
		v := d.ReadU64()
		if v != expU64[i] {
			t.Errorf("Expected %v found %v", expU64[i], v)
		}
	}
}

func TestWriteIPv6(t *testing.T) {
	e := &SimpleEncoder{}
	d := &SimpleDecoder{}
	ip := net.ParseIP("1:23:456:789a:0::1")
	e.WriteIPv6(ip)
	expU8 := []byte{0x0, 0x1, 0x0, 0x23, 0x4, 0x56, 0x78, 0x9a, 0, 0, 0, 0, 0, 0, 0, 0x1}
	d.Init(e.Bytes())
	for i := 0; i < len(expU8); i++ {
		v := d.ReadU8()
		if v != expU8[i] {
			t.Errorf("Expected %v found %v", expU8[i], v)
		}
	}

	d.Init(e.Bytes())
	var v net.IP
	v = make([]byte, 16)
	d.ReadIPv6(v)
	if !v.Equal(ip) {
		t.Errorf("Expected %v found %v", ip, v)
	}
}

func TestWriteString255(t *testing.T) {
	e := &SimpleEncoder{}
	d := &SimpleDecoder{}
	exp := "Hello, world! Hello, Yunshan Networks!"
	e.WriteString255(exp)
	d.Init(e.Bytes())
	s := d.ReadString255()
	if s != exp {
		t.Errorf("Expected %v found %v", exp, s)
	}
}

func TestWriteRawString(t *testing.T) {
	e := &SimpleEncoder{}
	exp := "Hello, world! Hello, Yunshan Networks!"
	e.WriteRawString(exp)
	if e.String() != exp {
		t.Errorf("Expected %v found %v", exp, e.String())
	}
}

func TestWriteBytes(t *testing.T) {
	e := &SimpleEncoder{}
	d := &SimpleDecoder{}
	exp := []byte{90, 91, 92, 93, 94, 95}
	e.WriteBytes(exp)
	d.Init(e.Bytes())
	bytes := d.ReadBytes()
	for i, v := range bytes {
		if v != exp[i] {
			t.Errorf("Expected %v found %v", exp[i], v)
		}
	}
}

func TestWriteBytesWithVarintLen(t *testing.T) {
	e := &SimpleEncoder{}
	d := &SimpleDecoder{}
	exp := []byte{90, 91, 92, 93, 94, 95}
	e.WriteBytesWithVarintLen(exp)
	d.Init(e.Bytes())
	bytes := d.ReadBytesWithVarintLen()
	for i, v := range bytes {
		if v != exp[i] {
			t.Errorf("Expected %v found %v", exp[i], v)
		}
	}
}

func TestRefOfString(t *testing.T) {
	e := &SimpleEncoder{}
	exp := ""
	if e.RefOfString() != exp {
		t.Errorf("Expected %v found %v", exp, e.RefOfString())
	}

	exp = "A"
	e.WriteRawString(exp)
	if e.RefOfString() != exp {
		t.Errorf("Expected %v found %v", exp, e.RefOfString())
	}

	e.Reset()
	exp = ""
	if e.RefOfString() != exp {
		t.Errorf("Expected %v found %v", exp, e.RefOfString())
	}

	exp = "AB"
	e.WriteRawString(exp)
	if e.RefOfString() != exp {
		t.Errorf("Expected %v found %v", exp, e.RefOfString())
	}
}

func TestReset(t *testing.T) {
	e := &SimpleEncoder{}
	exp := "Hello, world! Hello, Yunshan Networks!"
	e.WriteRawString(exp)
	if e.String() != exp {
		t.Errorf("Expected %v found %v", exp, e.String())
	}

	e.Reset()
	if e.String() == exp {
		t.Errorf("Expected %v found %v", "", e.String())
	}

	exp = "Bye, world! Bye, Yunshan Networks!"
	e.WriteRawString(exp)
	if e.String() != exp {
		t.Errorf("Expected %v found %v", exp, e.String())
	}
}

func TestWriteBool(t *testing.T) {
	e := &SimpleEncoder{}
	e.WriteBool(true)
	exp := uint8(1)

	if e.buf[0] != exp {
		t.Errorf("Expected %T found %T", e.buf[0], exp)
	}
}

func BenchmarkEncodeU32(b *testing.B) {
	u32s := []uint32{}
	for i := 0; i < b.N; i++ {
		u32s = append(u32s, rand.Uint32())
	}
	e := &SimpleEncoder{buf: make([]byte, 0, b.N*4)}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.WriteU32(u32s[i])
	}
}

func BenchmarkDecodeU32(b *testing.B) {
	e := &SimpleEncoder{}
	for i := 0; i < b.N; i++ {
		e.WriteU32(rand.Uint32())
	}

	d := &SimpleDecoder{}
	d.Init(e.Bytes())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.ReadU32()
	}
}

func BenchmarkEncodeU64(b *testing.B) {
	u64s := []uint64{}
	for i := 0; i < b.N; i++ {
		u64s = append(u64s, rand.Uint64())
	}
	e := &SimpleEncoder{buf: make([]byte, 0, b.N*8)}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.WriteU64(u64s[i])
	}
}

func BenchmarkDecodeU64(b *testing.B) {
	e := &SimpleEncoder{}
	for i := 0; i < b.N; i++ {
		e.WriteU64(rand.Uint64())
	}

	d := &SimpleDecoder{}
	d.Init(e.Bytes())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.ReadU64()
	}
}
