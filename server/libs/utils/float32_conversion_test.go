package utils

import "testing"

func TestConvertFloat32ToFloat64(t *testing.T) {
	for _, tc := range []struct {
		value float32
		text  string
	}{
		{0, "0"},
		{1.5, "1.5"},
		{-2.25, "-2.25"},
		{0.1, "0.1"},
	} {
		got, text, ok := ConvertToFloat64(tc.value)
		if !ok || got != float64(tc.value) || text != tc.text {
			t.Errorf("ConvertToFloat64(%v) = (%v, %q, %v)", tc.value, got, text, ok)
		}
	}
	if _, _, ok := ConvertToFloat64("1.5"); ok {
		t.Fatal("string unexpectedly accepted as a numeric value")
	}
}
