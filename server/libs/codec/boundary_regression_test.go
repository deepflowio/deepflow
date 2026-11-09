package codec

import "testing"

func TestPrefixTruncatedInput(t *testing.T) {
	for _, value := range []uint64{0, 128, 1 << 20, 1 << 35, 1 << 50, ^uint64(0)} {
		var e SimpleEncoder
		e.Init(nil)
		e.WritePrefixU64(value)
		for size := 0; size < len(e.Bytes()); size++ {
			var d SimpleDecoder
			d.Init(e.Bytes()[:size])
			if got := d.ReadPrefixU64(); got != 0 || !d.Failed() || d.Offset() != 0 {
				t.Fatalf("value %d size %d got %d", value, size, got)
			}
		}
		var d SimpleDecoder
		d.Init(e.Bytes())
		if got := d.ReadPrefixU64(); got != value || d.Failed() {
			t.Fatalf("valid value %d got %d", value, got)
		}
	}
}
