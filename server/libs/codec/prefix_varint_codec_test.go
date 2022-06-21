package codec

import (
	"math/rand"
	"testing"
)

func TestWritePrefixU64(t *testing.T) {
	expU64 := []uint64{1, 1<<7 + 10, 1<<14 + 10, 1<<21 + 10, 1<<28 + 10, 1<<35 + 10, 1<<42 + 10, 1<<49 + 10, 1<<56 + 10, 1 << 63, 0, 0xffffffffffffffff}

	e := &SimpleEncoder{}
	d := &SimpleDecoder{}

	for _, v := range expU64 {
		e.WritePrefixU64(v)
	}

	d.Init(e.Bytes())
	for i := 0; i < len(expU64); i++ {
		v := d.ReadPrefixU64()
		if v != expU64[i] {
			t.Errorf("Expected %v found %v", expU64[i], v)
		}
	}
}

func BenchmarkEncodePrefixU64(b *testing.B) {
	u64s := []uint64{}
	for i := 0; i < b.N; i++ {
		mod := i % 10
		if mod >= 0 && mod < 3 {
			u64s = append(u64s, uint64(rand.Uint32()>>16))
		} else if mod >= 3 && mod < 8 {
			u64s = append(u64s, uint64(rand.Uint32()))
		} else {
			u64s = append(u64s, uint64(rand.Uint64()))
		}

	}
	e := &SimpleEncoder{buf: make([]byte, 0, b.N*8)}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.WritePrefixU64(u64s[i])
	}
}

func BenchmarkDecodePrefixU64(b *testing.B) {
	e := &SimpleEncoder{}
	for i := 0; i < b.N; i++ {
		mod := i % 10
		if mod >= 0 && mod < 3 {
			e.WritePrefixU64(uint64(rand.Uint32() >> 16))
		} else if mod >= 3 && mod < 8 {
			e.WritePrefixU64(uint64(rand.Uint32()))
		} else {
			e.WritePrefixU64(uint64(rand.Uint64()))
		}
	}
	e.WritePrefixU64(uint64(rand.Uint64()))
	e.WritePrefixU64(uint64(rand.Uint64()))
	if b.N > 10000000 {
		b.Logf("PrefixU64 origin_len=%-9d encode_len=%-9d compressRate=%d%%\n",
			b.N*8, len(e.Bytes()), len(e.Bytes())*100/(b.N*8))
	}

	d := &SimpleDecoder{}
	d.Init(e.Bytes())
	b.ResetTimer()
	for i := 0; i < b.N-1; i++ {
		d.ReadPrefixU64()
	}
}
