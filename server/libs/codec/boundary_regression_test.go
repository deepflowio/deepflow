package codec

import "testing"

func TestReadBytesNInvalidLength(t *testing.T) {
	for _, n := range []int{-1, int(^uint(0) >> 1)} {
		var d SimpleDecoder
		d.Init([]byte{1, 2})
		d.ReadU8()
		if got := d.ReadBytesN(n); got != nil || !d.Failed() || d.Offset() != 1 {
			t.Fatalf("n %d: got %v failed %v offset %d", n, got, d.Failed(), d.Offset())
		}
	}
	var d SimpleDecoder
	d.Init([]byte{1, 2})
	if len(d.ReadBytesN(2)) != 2 || d.Failed() {
		t.Fatal("valid exact-boundary read failed")
	}
}
