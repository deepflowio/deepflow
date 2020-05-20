package geo

import (
	"encoding/binary"
	"testing"
)

func TestGetFirstMask(t *testing.T) {
	expectedPrefix := []uint32{0x01000000, 0x01000080, 0x010000c0, 0x010000e0, 0x010000f0, 0x010000f8, 0x010000fc, 0x010000fe}
	expectedMaskLen := []uint8{25, 26, 27, 28, 29, 30, 31, 32}
	start := binary.BigEndian.Uint32([]byte{1, 0, 0, 0})
	end := binary.BigEndian.Uint32([]byte{1, 0, 0, 254})
	for loop := range expectedPrefix {
		prefix, maskLen := getFirstMask(start, end)
		if prefix != expectedPrefix[loop] || maskLen != expectedMaskLen[loop] {
			t.Error("CIDR拆分不正确")
			break
		}
		start += 1 << uint32(MAX_MASKLEN-maskLen)
	}

	expectedPrefix = []uint32{0x01000000}
	expectedMaskLen = []uint8{24}
	start = binary.BigEndian.Uint32([]byte{1, 0, 0, 0})
	end = binary.BigEndian.Uint32([]byte{1, 0, 0, 255})
	for loop := range expectedPrefix {
		prefix, maskLen := getFirstMask(start, end)
		if prefix != expectedPrefix[loop] || maskLen != expectedMaskLen[loop] {
			t.Error("CIDR拆分不正确")
			break
		}
		start += 1 << uint32(MAX_MASKLEN-maskLen)
	}
}

func TestNetmaskGeoTree(t *testing.T) {
	tree := NewNetmaskGeoTree()
	region, isp := tree.Query(3748071168)
	if DecodeRegion(region) != "天津" || DecodeISP(isp) != "移动" {
		t.Error("查询结果不正确")
	}
	region, isp = tree.Query(3748071168)
	if DecodeRegion(region) != "天津" || DecodeISP(isp) != "移动" {
		t.Error("查询结果不正确")
	}
}
