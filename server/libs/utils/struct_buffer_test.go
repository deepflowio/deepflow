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
