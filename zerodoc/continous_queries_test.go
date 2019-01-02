package zerodoc

import (
	"strings"
	"testing"
)

func TestSumPacket(t *testing.T) {
	query := GetContinousQueryString(&UsageMeter{})
	if !strings.Contains(query, "sum(sum_bit) AS sum_bit") {
		t.Error("缺少sum_bit字段")
	}
	if !strings.Contains(query, "sum(sum_packet) AS sum_packet") {
		t.Error("缺少sum_packet字段")
	}
}
