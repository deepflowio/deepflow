package handler

import (
	"net"
	"unsafe"
)

type native struct{}

var Native native

func (n native) Uint16(b []byte) uint16 {
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func (n native) Uint32(b []byte) uint32 {
	return *(*uint32)(unsafe.Pointer(&b[0]))
}

func (n native) Uint64(b []byte) uint64 {
	return *(*uint64)(unsafe.Pointer(&b[0]))
}

func AlignUp(size int) int {
	return ((size + 3) >> 2) << 2
}

// compiler is intelligent enough to generate inline optimized code
func CopyField(dst, src []byte, size int) int {
	switch size {
	case 1:
		dst[0] = src[0]
	case 2:
		*(*uint16)(unsafe.Pointer(&dst[0])) = *(*uint16)(unsafe.Pointer(&src[0]))
	case 4:
		*(*uint32)(unsafe.Pointer(&dst[0])) = *(*uint32)(unsafe.Pointer(&src[0]))
	default:
		return 0
	}
	return size
}

func FieldEquals(a, b []byte, size int) bool {
	switch size {
	case 1:
		return a[0] == b[0]
	case 2:
		return *(*uint16)(unsafe.Pointer(&a[0])) == *(*uint16)(unsafe.Pointer(&b[0]))
	case 4:
		return *(*uint32)(unsafe.Pointer(&a[0])) == *(*uint32)(unsafe.Pointer(&b[0]))
	default:
		return false
	}
}

func CopyMac(to, from net.HardwareAddr) {
	*(*uint16)(unsafe.Pointer(&to[0])) = *(*uint16)(unsafe.Pointer(&from[0]))
	*(*uint32)(unsafe.Pointer(&to[2])) = *(*uint32)(unsafe.Pointer(&from[2]))
}

// 抓包接口mac和虚拟机mac首个octet不同，而后面5个octet相同，因此忽略第一个octet
func CompareVmMac(mac0, mac1 []byte) bool { // compiler hint for bool operation
	upper := mac0[1] == mac1[1]
	lower := *(*uint32)(unsafe.Pointer(&mac0[2])) == *(*uint32)(unsafe.Pointer(&mac1[2]))
	return upper && lower
}

func BytesCopy(a, b []byte, size int) int {
	return copy(a, b[:size])
}
