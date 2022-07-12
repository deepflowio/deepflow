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

package keyhash

import (
	"testing"
)

func bashHash32(hash uint32) int32 {
	hash = (hash >> 16) ^ hash
	hash = (hash >> 8) ^ hash
	return int32(hash)
}

func bashHash(hash uint64) int32 {
	hash = (hash >> 32) ^ hash
	hash = (hash >> 16) ^ hash
	hash = (hash >> 8) ^ hash
	return int32(hash)
}

var testData = []uint64{0x4ce66700160000, 0x4ce46500160000, 0x4ce56400160000, 0x4ce76600160000}

func TestJenkins(t *testing.T) {
	table := make(map[int32]int)
	jTable := make(map[int32]int)
	for _, data := range testData {
		hash := bashHash(data) & 0x7fff
		table[hash]++
		hash = Jenkins(data) & 0x7fff
		jTable[hash]++
	}
	if len(table) > len(jTable) {
		t.Error("Jenkins hash error.")
		t.Errorf("jenkins: %v", jTable)
		t.Errorf("base: %v", table)
	}
}

var testData32 = []uint32{0x4ce667, 0x4ce465, 0x4ce564, 0x4ce766}

func TestJenkins32(t *testing.T) {
	table := make(map[int32]int)
	jTable := make(map[int32]int)
	for _, data := range testData32 {
		hash := bashHash32(data) & 0xff
		table[hash]++
		hash = Jenkins32(data) & 0xff
		jTable[hash]++
	}

	//jenkins hash计算时没有与数值的顺序绑定，输入值的位值变化就会输出不同的key具有很好的散列性
	//bashHash32 当输入值高8位相同时，其计算的hask key相同，均挂在map的同一table上，散列性不好
	if len(table) > len(jTable) {
		t.Error("Jenkins32 hash error.")
		t.Errorf("jenkins: %v", jTable)
		t.Errorf("base: %v", table)
	}
}

func BenchmarkBaseHash(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bashHash(uint64(i))
	}
}

func BenchmarkBaseHash32(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bashHash32(uint32(i))
	}
}

func BenchmarkJenkins128(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Jenkins128(uint64(i), uint64(i+100))
	}
}

func BenchmarkJenkins(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Jenkins(uint64(i))
	}
}

func BenchmarkJenkins32(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Jenkins32(uint32(i))
	}
}
