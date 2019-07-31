package zerodoc

import (
	"testing"
)

func TestSequence(t *testing.T) {
	chunk := make([]byte, 10)
	SetSequence(1234, chunk)

	if GetSequence(chunk) != 1234 {
		t.Error("squence处理不正确")
	}
}
