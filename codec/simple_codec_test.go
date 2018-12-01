package codec

import (
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
