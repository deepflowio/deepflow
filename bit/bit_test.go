package bit

import (
	"testing"
)

func TestCountTrailingZeros32(t *testing.T) {
	for exp := 0; exp < 32; exp++ {
		x := (uint32(1) << uint32(exp)) | (1 << 31)
		if exp != CountTrailingZeros32(x) {
			t.Errorf("Expected %v found %v", exp, CountTrailingZeros32(x))
		}
	}
}

func TestCountTrailingZeros64(t *testing.T) {
	for exp := 0; exp < 64; exp++ {
		x := (uint64(1) << uint64(exp)) | (1 << 63)
		if exp != CountTrailingZeros64(x) {
			t.Errorf("Expected %v found %v", exp, CountTrailingZeros64(x))
		}
	}
}

func TestCountLeadingZeros32(t *testing.T) {
	for exp := 0; exp < 32; exp++ {
		x := (uint32(1) << uint32(exp)) | 0x1
		if exp != CountLeadingZeros32(x) {
			t.Errorf("Expected %v found %v", exp, CountLeadingZeros32(x))
		}
	}
}

func TestCountLeadingZeros64(t *testing.T) {
	for exp := 0; exp < 64; exp++ {
		x := (uint64(1) << uint64(exp)) | 0x1
		if exp != CountLeadingZeros64(x) {
			t.Errorf("Expected %v found %v", exp, CountLeadingZeros64(x))
		}
	}
}
