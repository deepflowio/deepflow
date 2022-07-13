/*
 * Copyright (c) 2022 Yunshan Networks
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
BenchmarkBKDRHash-20               	20000000	        59.8 ns/op
BenchmarkSDBMHash-20               	20000000	        81.4 ns/op
BenchmarkDJBHash-20                	20000000	        58.2 ns/op
BenchmarkAPHash-20                 	10000000	       109 ns/op
BenchmarkMurmurHashString-20       	10000000	       179 ns/op
BenchmarkMurmurHashBytes-20        	30000000	        35.7 ns/op
*/

package utils

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

func BenchmarkBKDRHash(b *testing.B) {
	str := "k23123kasldjfaklsjfklasjdfklajsllskadjfklsjfksdjfks"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BKDRHash(100, str)
	}
}

func BenchmarkSDBMHash(b *testing.B) {
	str := "k23123kasldjfaklsjfklasjdfklajsllskadjfklsjfksdjfks"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SDBMHash(100, str)
	}
}

func BenchmarkDJBHash(b *testing.B) {
	str := "k23123kasldjfaklsjfklasjdfklajsllskadjfklsjfksdjfks"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DJBHash(100, str)
	}
}

func BenchmarkAPHash(b *testing.B) {
	str := "k23123kasldjfaklsjfklasjdfklajsllskadjfklsjfksdjfks"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		APHash(100, str)
	}
}

func BenchmarkMurmurHashString(b *testing.B) {
	str := "k23123kasldjfaklsjfklasjdfklajsllskadjfklsjfksdjfks"
	hash := rand.Uint32()
	for i := 0; i < b.N; i++ {
		by := []byte(str)
		for j := 0; j < len(str)-4; j++ {
			hash = MurmurHashAdd(hash, binary.LittleEndian.Uint32(by[j:j+4]))
		}
		MurmurHashFinish(hash)
	}
}

func BenchmarkMurmurHashBytes(b *testing.B) {
	str := "k23123kasldjfaklsjfklasjdfklajsllskadjfklsjfksdjfks"
	by := []byte(str)
	hash := rand.Uint32()
	for i := 0; i < b.N; i++ {
		for j := 0; j < len(str)-4; j++ {
			hash = MurmurHashAdd(hash, binary.LittleEndian.Uint32(by[j:j+4]))
		}
		MurmurHashFinish(hash)
	}
}
