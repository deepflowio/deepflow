package utils

import (
	"encoding/binary"
	"math/rand"
	"net"
	"testing"
)

func TestHashTwoIp(t *testing.T) {
	var tmp uint32
	var hash uint32
	var basis uint32 = rand.Uint32()
	ipSrc := net.ParseIP("192.168.0.3").To4()
	ipDst := net.ParseIP("192.168.0.2").To4()

	tmp = binary.LittleEndian.Uint32(ipSrc)
	hash1 := MurmurHashAdd(basis, tmp)
	t.Logf("tmp: %d, hash1: %d\n", tmp, hash1)

	tmp = binary.LittleEndian.Uint32(ipDst)
	hash2 := MurmurHashAdd(basis, tmp)
	t.Logf("tmp: %d, hash2: %d\n", tmp, hash2)

	hash = hash1 ^ hash2
	hash = MurmurHashFinish(hash)
	t.Log("hash:", hash)
}

func TestHashTwoPortAndProto(t *testing.T) {
	src := uint16(65123)
	dst := uint16(12225)
	proto := uint8(6)
	basis := rand.Uint32()

	hashsrc := MurmurHashAdd(basis, uint32(src))
	hashdst := MurmurHashAdd(basis, uint32(dst))
	hash := hashsrc ^ hashdst
	hash = MurmurHashAdd(hash, uint32(proto))
	hash = MurmurHashFinish(hash)
	t.Log("hash final:", hash)

	hashsrc = MurmurHashAdd(basis, uint32(dst))
	hashdst = MurmurHashAdd(basis, uint32(src))
	hash = hashsrc ^ hashdst
	hash = MurmurHashAdd(hash, uint32(proto))
	hash = MurmurHashFinish(hash)
	t.Log("symmetric hash final:", hash)
}

func BenchmarkHashTwoPortAndProto(b *testing.B) {
	basis := rand.Uint32()
	ip1 := rand.Uint32()
	ip2 := rand.Uint32()
	for i := 0; i < b.N; i++ {
		hash1 := MurmurHashAdd(basis, ip1)
		hash2 := MurmurHashAdd(basis, ip2)
		MurmurHashFinish(hash1 ^ hash2)
	}
}

func BenchmarkHashTwoIP(b *testing.B) {
	basis := rand.Uint32()
	port1 := rand.Uint32() >> 16
	port2 := rand.Uint32() >> 16
	proto := uint32(6)
	for i := 0; i < b.N; i++ {
		hash1 := MurmurHashAdd(basis, port1)
		hash2 := MurmurHashAdd(basis, port2)
		hash3 := MurmurHashAdd(hash1^hash2, proto)
		MurmurHashFinish(hash3)
	}
}
