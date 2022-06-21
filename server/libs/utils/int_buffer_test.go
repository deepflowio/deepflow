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
