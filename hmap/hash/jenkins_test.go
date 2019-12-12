package hash

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
