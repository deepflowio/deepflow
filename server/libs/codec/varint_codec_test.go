/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
BenchmarkEncodePrefixU64-20    	50000000	        22.5 ns/op
BenchmarkDecodePrefixU64-20    	100000000	        10.3 ns/op
--- BENCH: BenchmarkDecodePrefixU64-20
    prefixvarint_codec_test.go:77: PrefixU64 origin_len=800000000 encode_len=509220501 compressRate=63%
BenchmarkEncodeU32-20          	1000000000	         2.68 ns/op
BenchmarkDecodeU32-20          	1000000000	         2.25 ns/op
BenchmarkEncodeU64-20          	300000000	         5.17 ns/op
BenchmarkDecodeU64-20          	500000000	         3.95 ns/op
BenchmarkEncodeVarintU32-20    	100000000	        13.3 ns/op
BenchmarkDecodeVarintU32-20    	100000000	        12.0 ns/op
--- BENCH: BenchmarkDecodeVarintU32-20
    varint_codec_test.go:117: VarintU32 origin_len=400000000 encode_len=281140395 compressRate=70%
BenchmarkEncodeZigzagU32-20    	100000000	        12.8 ns/op
BenchmarkDecodeZigzagU32-20    	100000000	        11.3 ns/op
--- BENCH: BenchmarkDecodeZigzagU32-20
    varint_codec_test.go:162: ZigzagU32 origin_len=400000000 encode_len=294935670 compressRate=73%
BenchmarkEncodeVarintU64-20    	100000000	        16.1 ns/op
BenchmarkDecodeVarintU64-20    	100000000	        12.9 ns/op
--- BENCH: BenchmarkDecodeVarintU64-20
    varint_codec_test.go:208: VarintU64 origin_len=800000000 encode_len=519212756 compressRate=64%
BenchmarkEncodeZigzagU64-20    	100000000	        16.3 ns/op
BenchmarkDecodeZigzagU64-20    	100000000	        13.7 ns/op
--- BENCH: BenchmarkDecodeZigzagU64-20
    varint_codec_test.go:253: ZigzagU64 origin_len=800000000 encode_len=524573662 compressRate=65%
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
		mod := i % 10
		if mod >= 0 && mod < 3 {
			u32s = append(u32s, rand.Uint32()>>24)
		} else if mod >= 3 && mod < 8 {
			u32s = append(u32s, rand.Uint32()>>16)
		} else {
			u32s = append(u32s, rand.Uint32())
		}
	}
	e := &SimpleEncoder{buf: make([]byte, 0, b.N*4)}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.WriteVarintU32(u32s[i])
	}
}

func BenchmarkDecodeVarintU32(b *testing.B) {
	e := &SimpleEncoder{}
	for i := 0; i < b.N; i++ {
		mod := i % 10
		if mod >= 0 && mod < 3 {
			e.WriteVarintU32(rand.Uint32() >> 24)
		} else if mod >= 3 && mod < 8 {
			e.WriteVarintU32(rand.Uint32() >> 16)
		} else {
			e.WriteVarintU32(rand.Uint32())
		}
	}

	if b.N > 10000000 {
		b.Logf("VarintU32 origin_len=%-9d encode_len=%-9d compressRate=%d%%\n",
			b.N*4, len(e.Bytes()), len(e.Bytes())*100/(b.N*4))
	}

	d := &SimpleDecoder{}
	d.Init(e.Bytes())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.ReadVarintU32()
	}
}

func BenchmarkEncodeZigzagU32(b *testing.B) {
	u32s := []uint32{}
	for i := 0; i < b.N; i++ {
		mod := i % 10
		if mod >= 0 && mod < 3 {
			u32s = append(u32s, rand.Uint32()>>24)
		} else if mod >= 3 && mod < 8 {
			u32s = append(u32s, rand.Uint32()>>16)
		} else {
			u32s = append(u32s, rand.Uint32())
		}
	}
	e := &SimpleEncoder{buf: make([]byte, 0, b.N*4)}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.WriteZigzagU32(u32s[i])
	}
}

func BenchmarkDecodeZigzagU32(b *testing.B) {
	e := &SimpleEncoder{}
	for i := 0; i < b.N; i++ {
		mod := i % 10
		if mod >= 0 && mod < 3 {
			e.WriteZigzagU32(rand.Uint32() >> 24)
		} else if mod >= 3 && mod < 8 {
			e.WriteZigzagU32(rand.Uint32() >> 16)
		} else {
			e.WriteZigzagU32(rand.Uint32())
		}
	}

	if b.N > 10000000 {
		b.Logf("ZigzagU32 origin_len=%-9d encode_len=%-9d compressRate=%d%%\n",
			b.N*4, len(e.Bytes()), len(e.Bytes())*100/(b.N*4))
	}

	d := &SimpleDecoder{}
	d.Init(e.Bytes())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.ReadZigzagU32()
	}
}

func BenchmarkEncodeVarintU64(b *testing.B) {
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
		e.WriteVarintU64(u64s[i])
	}
}

func BenchmarkDecodeVarintU64(b *testing.B) {
	e := &SimpleEncoder{}
	for i := 0; i < b.N; i++ {
		mod := i % 10
		if mod >= 0 && mod < 3 {
			e.WriteVarintU64(uint64(rand.Uint32() >> 16))
		} else if mod >= 3 && mod < 8 {
			e.WriteVarintU64(uint64(rand.Uint32()))
		} else {
			e.WriteVarintU64(uint64(rand.Uint64()))
		}
	}

	if b.N > 10000000 {
		b.Logf("VarintU64 origin_len=%-9d encode_len=%-9d compressRate=%d%%\n",
			b.N*8, len(e.Bytes()), len(e.Bytes())*100/(b.N*8))
	}

	d := &SimpleDecoder{}
	d.Init(e.Bytes())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.ReadVarintU64()
	}
}

func BenchmarkEncodeZigzagU64(b *testing.B) {
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
		e.WriteZigzagU64(u64s[i])
	}
}

func BenchmarkDecodeZigzagU64(b *testing.B) {
	e := &SimpleEncoder{}
	for i := 0; i < b.N; i++ {
		mod := i % 10
		if mod >= 0 && mod < 3 {
			e.WriteZigzagU64(uint64(rand.Uint32() >> 16))
		} else if mod >= 3 && mod < 8 {
			e.WriteZigzagU64(uint64(rand.Uint32()))
		} else {
			e.WriteZigzagU64(uint64(rand.Uint64()))
		}
	}

	if b.N > 10000000 {
		b.Logf("ZigzagU64 origin_len=%-9d encode_len=%-9d compressRate=%d%%\n",
			b.N*8, len(e.Bytes()), len(e.Bytes())*100/(b.N*8))
	}

	d := &SimpleDecoder{}
	d.Init(e.Bytes())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.ReadZigzagU64()
	}
}
