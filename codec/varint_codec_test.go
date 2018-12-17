/*
BenchmarkEncodeU32-20          	200000000	         8.92 ns/op
BenchmarkEncodeU64-20          	100000000	        12.3 ns/op
BenchmarkDecodeU32-20          	1000000000	         2.06 ns/op
BenchmarkDecodeU64-20          	500000000	         3.84 ns/op
BenchmarkEncodeVarintU32-20    	100000000	        18.9 ns/op
BenchmarkEncodeVarintU64-20    	50000000	        32.3 ns/op
BenchmarkEncodeZigzagU32-20    	50000000	        20.5 ns/op
BenchmarkEncodeZigzagU64-20    	30000000	        35.5 ns/op
BenchmarkDecodeVarintU32-20    	100000000	        11.2 ns/op
BenchmarkDecodeVarintU64-20    	100000000	        18.8 ns/op
BenchmarkDecodeZigzagU32-20    	200000000	        12.2 ns/op
BenchmarkDecodeZigzagU64-20    	100000000	        22.1 ns/op
*/

package codec

import (
	"math/rand"
	"testing"
)

func TestWriteZigzagU32(t *testing.T) {
	e := &SimpleEncoder{}
	d := &SimpleDecoder{}

	expU32 := []uint32{1, 1<<7 + 10, 1<<14 + 10, 1<<21 + 10, 1<<28 + 10, 1 << 31, 0, 0xffffffff}

	for _, v := range expU32 {
		e.WriteZigzagU32(v)
	}

	d.Init(e.Bytes())
	for i := 0; i < len(expU32); i++ {
		v := d.ReadZigzagU32()
		if v != expU32[i] {
			t.Errorf("Expected %v found %v", expU32[i], v)
		}
	}
}

func TestWriteZigzagU64(t *testing.T) {
	e := &SimpleEncoder{}
	d := &SimpleDecoder{}

	expU64 := []uint64{1, 1<<7 + 10, 1<<14 + 10, 1<<21 + 10, 1<<28 + 10, 1<<35 + 10, 1<<42 + 10, 1<<49 + 10, 1<<56 + 10, 1 << 63, 0, 0xffffffffffffffff}

	for _, v := range expU64 {
		e.WriteZigzagU64(v)
	}

	d.Init(e.Bytes())
	for i := 0; i < len(expU64); i++ {
		v := d.ReadZigzagU64()
		if v != expU64[i] {
			t.Errorf("Expected %v found %v", expU64[i], v)
		}
	}
}

func TestWriteVarintU32(t *testing.T) {
	e := &SimpleEncoder{}
	d := &SimpleDecoder{}

	expU32 := []uint32{1, 1<<7 + 10, 1<<14 + 10, 1<<21 + 10, 1<<28 + 10, 1 << 31, 0, 0xffffffff}

	for _, v := range expU32 {
		e.WriteVarintU32(v)
	}

	d.Init(e.Bytes())
	for i := 0; i < len(expU32); i++ {
		v := d.ReadVarintU32()
		if v != expU32[i] {
			t.Errorf("Expected %v found %v", expU32[i], v)
		}
	}
}

func TestWriteVarintU64(t *testing.T) {
	e := &SimpleEncoder{}
	d := &SimpleDecoder{}

	expU64 := []uint64{1, 1<<7 + 10, 1<<14 + 10, 1<<21 + 10, 1<<28 + 10, 1<<35 + 10, 1<<42 + 10, 1<<49 + 10, 1<<56 + 10, 1 << 63, 0, 0xffffffffffffffff}

	for _, v := range expU64 {
		e.WriteVarintU64(v)
	}

	d.Init(e.Bytes())
	for i := 0; i < len(expU64); i++ {
		v := d.ReadVarintU64()
		if v != expU64[i] {
			t.Errorf("Expected %v found %v", expU64[i], v)
		}
	}
}

func BenchmarkEncodeVarintU32(b *testing.B) {
	u32s := []uint32{}
	for i := 0; i < b.N; i++ {
		u32s = append(u32s, rand.Uint32())
	}
	e := &SimpleEncoder{buf: make([]byte, b.N*4, b.N*4)}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.WriteVarintU32(u32s[i])
	}
}

func BenchmarkEncodeVarintU64(b *testing.B) {
	u64s := []uint64{}
	for i := 0; i < b.N; i++ {
		u64s = append(u64s, rand.Uint64())
	}
	e := &SimpleEncoder{buf: make([]byte, b.N*8, b.N*8)}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.WriteVarintU64(u64s[i])
	}
}

func BenchmarkEncodeZigzagU32(b *testing.B) {
	u32s := []uint32{}
	for i := 0; i < b.N; i++ {
		u32s = append(u32s, rand.Uint32())
	}
	e := &SimpleEncoder{buf: make([]byte, b.N*4, b.N*4)}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.WriteZigzagU32(u32s[i])
	}
}

func BenchmarkEncodeZigzagU64(b *testing.B) {
	u64s := []uint64{}
	for i := 0; i < b.N; i++ {
		u64s = append(u64s, rand.Uint64())
	}
	e := &SimpleEncoder{buf: make([]byte, b.N*8, b.N*8)}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.WriteZigzagU64(u64s[i])
	}
}

func BenchmarkDecodeVarintU32(b *testing.B) {
	e := &SimpleEncoder{}
	for i := 0; i < b.N; i++ {
		e.WriteVarintU32(rand.Uint32())
	}

	d := &SimpleDecoder{}
	d.Init(e.Bytes())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.ReadVarintU32()
	}
}

func BenchmarkDecodeVarintU64(b *testing.B) {
	e := &SimpleEncoder{}
	for i := 0; i < b.N; i++ {
		e.WriteVarintU64(rand.Uint64())
	}

	d := &SimpleDecoder{}
	d.Init(e.Bytes())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.ReadVarintU64()
	}
}

func BenchmarkDecodeZigzagU32(b *testing.B) {
	e := &SimpleEncoder{}
	for i := 0; i < b.N; i++ {
		e.WriteZigzagU32(rand.Uint32())
	}

	d := &SimpleDecoder{}
	d.Init(e.Bytes())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.ReadZigzagU32()
	}
}

func BenchmarkDecodeZigzagU64(b *testing.B) {
	e := &SimpleEncoder{}
	for i := 0; i < b.N; i++ {
		e.WriteZigzagU64(rand.Uint64())
	}

	d := &SimpleDecoder{}
	d.Init(e.Bytes())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.ReadZigzagU64()
	}
}
