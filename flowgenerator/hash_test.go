package flowgenerator

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
	hash1 := hashAdd(basis, tmp)
	t.Logf("tmp: %d, hash1: %d\n", tmp, hash1)

	tmp = binary.LittleEndian.Uint32(ipDst)
	hash2 := hashAdd(basis, tmp)
	t.Logf("tmp: %d, hash2: %d\n", tmp, hash2)

	hash = hash1 ^ hash2
	hash = hashFinish(hash)
	t.Log("hash:", hash)
}

func TestHashTwoPortAndProto(t *testing.T) {
	src := uint16(65123)
	dst := uint16(12225)
	proto := uint8(6)
	basis := rand.Uint32()

	hashsrc := hashAdd(basis, uint32(src))
	hashdst := hashAdd(basis, uint32(dst))
	hash := hashsrc ^ hashdst
	hash = hashAdd(hash, uint32(proto))
	hash = hashFinish(hash)
	t.Log("hash final:", hash)

	hashsrc = hashAdd(basis, uint32(dst))
	hashdst = hashAdd(basis, uint32(src))
	hash = hashsrc ^ hashdst
	hash = hashAdd(hash, uint32(proto))
	hash = hashFinish(hash)
	t.Log("symmetric hash final:", hash)
}

func BenchmarkHashTwoPortAndProto(b *testing.B) {
	basis := rand.Uint32()
	ip1 := rand.Uint32()
	ip2 := rand.Uint32()
	for i := 0; i < b.N; i++ {
		hash1 := hashAdd(basis, ip1)
		hash2 := hashAdd(basis, ip2)
		hashFinish(hash1 ^ hash2)
	}
}

func BenchmarkHashTwoIP(b *testing.B) {
	basis := rand.Uint32()
	port1 := rand.Uint32() >> 16
	port2 := rand.Uint32() >> 16
	proto := uint32(6)
	for i := 0; i < b.N; i++ {
		hash1 := hashAdd(basis, port1)
		hash2 := hashAdd(basis, port2)
		hash3 := hashAdd(hash1^hash2, proto)
		hashFinish(hash3)
	}
}
