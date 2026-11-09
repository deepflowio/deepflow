package codec

import (
	"encoding/binary"
	"testing"
)

func TestReplaceAtBoundary(t *testing.T) {
	for _, width := range []int{2, 4, 8} {
		for _, offset := range []int{0, 1} {
			var e SimpleEncoder
			e.Init(make([]byte, width+offset))
			switch width {
			case 2:
				e.ReplaceU16At(offset, 0x1234)
			case 4:
				e.ReplaceU32At(offset, 0x12345678)
			case 8:
				e.ReplaceU64At(offset, 0x123456789abcdef0)
			}
			b := e.Bytes()[offset:]
			var got uint64
			switch width {
			case 2:
				got = uint64(binary.LittleEndian.Uint16(b))
			case 4:
				got = uint64(binary.LittleEndian.Uint32(b))
			case 8:
				got = binary.LittleEndian.Uint64(b)
			}
			if got == 0 {
				t.Fatalf("width %d offset %d: replacement skipped", width, offset)
			}
		}
	}
	var e SimpleEncoder
	e.Init(make([]byte, 8))
	for _, offset := range []int{-1, 9, int(^uint(0) >> 1)} {
		e.ReplaceU16At(offset, 1)
		e.ReplaceU32At(offset, 1)
		e.ReplaceU64At(offset, 1)
	}
}
