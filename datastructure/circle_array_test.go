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
