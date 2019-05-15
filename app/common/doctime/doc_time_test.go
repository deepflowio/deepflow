package doctime

import (
	"testing"
)

func TestRoundToSecond(t *testing.T) {
	if RoundToSecond(123123123123) != 123 {
		t.Error("RoundToSecond错误")
	}
}

func TestRoundToMinute(t *testing.T) {
	if RoundToMinute(123123123123) != 120 {
		t.Error("RoundToMinute错误")
	}
}
