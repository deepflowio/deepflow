package hmap

import (
	"testing"
)

func TestDumpHexBytes(t *testing.T) {
	for _, tc := range []struct {
		input  []byte
		output string
	}{
		{
			[]byte{}, "0x0",
		},
		{
			[]byte{0, 0, 0, 0, 1}, "0x1",
		},
		{
			[]byte{0, 0, 1, 0, 1}, "0x10001",
		},
		{
			[]byte{0xff, 0, 0, 0, 0}, "0xff00000000",
		},
	} {
		if result := dumpHexBytes(tc.input); result != tc.output {
			t.Errorf("结果不正确, 应为%s, 实为%s", tc.output, result)
		}
	}
}
