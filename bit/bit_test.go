package bit

import (
	"testing"
)

func TestCountTrailingZeros32(t *testing.T) {
	for exp := 0; exp <= 32; exp++ {
		x := uint32(1) << uint32(exp)
		if exp != CountTrailingZeros32(x) {
			t.Errorf("Expected %v found %v", exp, CountTrailingZeros32(x))
		}
	}
}

func TestCountTrailingZeros64(t *testing.T) {
	for exp := 0; exp <= 64; exp++ {
		x := uint64(1) << uint64(exp)
		if exp != CountTrailingZeros64(x) {
			t.Errorf("Expected %v found %v", exp, CountTrailingZeros64(x))
		}
	}
}
