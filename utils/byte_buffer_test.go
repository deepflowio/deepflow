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
