package hmap

import (
	"testing"

	"gitlab.x.lan/yunshan/droplet-libs/hmap/idmap"
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

func TestDumpCollisionChain(t *testing.T) {
	m := idmap.NewU128IDMap("test", 1).NoStats()
	m.SetCollisionChainDebugThreshold(5)

	for i := 0; i < 10; i++ {
		m.AddOrGet(0, uint64(i), 0, false)
	}
	if DumpCollisionChain(m) != "0x6-0x5-0x2-0x1-0x0" {
		t.Error("冲突链打印不正确")
	}
}
