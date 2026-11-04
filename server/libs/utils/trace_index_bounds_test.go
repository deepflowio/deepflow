package utils

import "testing"

func TestTraceIndexInvalidBounds(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	for _, bounds := range [][2]int{{0, -1}, {1, maxInt}, {maxInt, 2}, {-4, 1}} {
		if _, err := GetTraceIdIndex("123", true, false, bounds[0], bounds[1]); err == nil {
			t.Fatalf("bounds %v accepted", bounds)
		}
	}
	for _, bounds := range [][2]int{{0, 3}, {-2, 2}} {
		if _, err := GetTraceIdIndex("123", true, false, bounds[0], bounds[1]); err != nil {
			t.Fatalf("valid bounds %v: %v", bounds, err)
		}
	}
}
