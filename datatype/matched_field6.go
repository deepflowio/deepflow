package datatype

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	MATCHED_FIELD6_BITS_LEN = 444 // 8(TapType) + 12(Vlan) + 8(Proto) + 16(L3EPC)*2 + 64(MAC + Port)*2 + 128(IP)*2
	MATCHED_FIELD6_LEN      = 7
)

const (
	// fields[0]
	MATCHED6_SRC_IP0 MatchFlags = iota
	// fields[1]
	MATCHED6_SRC_IP1
	// fields[2]
	MATCHED6_DST_IP0
	// fields[3]
	MATCHED6_DST_IP1
	// fields[4]
	MATCHED6_SRC_MAC
	MATCHED6_SRC_PORT

	// fields[5]
	MATCHED6_DST_MAC
	MATCHED6_DST_PORT

	// fields[6]
	MATCHED6_SRC_EPC
	MATCHED6_DST_EPC
	MATCHED6_PROTO
	MATCHED6_VLAN
	MATCHED6_TAP_TYPE
)

var field6Offset = [...]uint64{
	MATCHED6_SRC_IP0: 0,
	MATCHED6_SRC_IP1: 64,
	MATCHED6_DST_IP0: 128,
	MATCHED6_DST_IP1: 192,

	MATCHED6_SRC_MAC:  256,
	MATCHED6_SRC_PORT: 304,

	MATCHED6_DST_MAC:  320,
	MATCHED6_DST_PORT: 368,

	MATCHED6_SRC_EPC:  384,
	MATCHED6_DST_EPC:  400,
	MATCHED6_PROTO:    416,
	MATCHED6_VLAN:     424,
	MATCHED6_TAP_TYPE: 436,
}

var field6Mask = [...]uint64{
	MATCHED6_SRC_IP0: 0xffffffffffffffff,
	MATCHED6_SRC_IP1: 0xffffffffffffffff,
	MATCHED6_DST_IP0: 0xffffffffffffffff,
	MATCHED6_DST_IP1: 0xffffffffffffffff,

	MATCHED6_SRC_MAC:  0xffffffffffff,
	MATCHED6_SRC_PORT: 0xffff,

	MATCHED6_DST_MAC:  0xffffffffffff,
	MATCHED6_DST_PORT: 0xffff,

	MATCHED6_SRC_EPC:  0xffff,
	MATCHED6_DST_EPC:  0xffff,
	MATCHED6_PROTO:    0xff,
	MATCHED6_VLAN:     0xfff,
	MATCHED6_TAP_TYPE: 0xff,
}

type MatchedField6 struct {
	fields [MATCHED_FIELD6_LEN]uint64
}

var (
	blankMatchedField6ForInit MatchedField6 = MatchedField6{}
)

func (f *MatchedField6) GobEncode() ([]byte, error) {
	return []byte{}, nil
}

func (f *MatchedField6) GobDecode(in []byte) error {
	return nil
}

func (f *MatchedField6) Get(flag MatchFlags) uint64 {
	index := field6Offset[flag] >> NUM_64_OFFSET // field6Offset[flag] / 64
	offset := field6Offset[flag] & NUM_64_MASK   // field6Offset[flag] % 64
	return (f.fields[index] >> offset) & field6Mask[flag]
}

func (f *MatchedField6) Set(flag MatchFlags, value uint64) {
	index := field6Offset[flag] >> NUM_64_OFFSET // field6Offset[flag] / 64
	offset := field6Offset[flag] & NUM_64_MASK   // field6Offset[flag] % 64
	f.fields[index] &= ^(field6Mask[flag] << offset)
	f.fields[index] |= (value << offset)
}

func (f *MatchedField6) SetMask(flag MatchFlags, value uint64) {
	if value != 0 {
		value = field6Mask[flag]
	}
	f.Set(flag, value)
}

func (f *MatchedField6) SetBits(whichs ...int) {
	// MATCHED_FIELD6_LEN为7, 清理使用的位
	*f = blankMatchedField6ForInit
	for _, which := range whichs {
		index := which >> NUM_64_OFFSET     // which / 64
		offset := uint(which & NUM_64_MASK) // which % 64
		f.fields[index] |= (1 << offset)
	}
}

func (f *MatchedField6) GetAllTableIndex(maskVector, mask *MatchedField6, min, max int, vectorBits []int) []uint16 {
	// 若f为0101， maskVector为0111, mask为1001，返回{001,011,101,111}
	index := f.GetTableIndex(maskVector, min, max)
	indexOffset := make([]int, 0, 4) // indexOffset存储vector对应当前match field中为全采集的位，测试发现大于4的情况很少
	for i, offset := range vectorBits {
		// 掩码对应的位为0，表示全采集
		if mask.IsBitZero(offset) {
			indexOffset = append(indexOffset, i)
		}
	}
	// index 101 -> 001，将全采集的位至为0
	for _, offset := range indexOffset {
		index &= ^(1 << uint16(offset))
	}

	base := make([]uint16, 0, 16) // 根据indexOffset的大小，2^4为16
	base = append(base, index)
	for _, offset := range indexOffset {
		create := make([]uint16, len(base))
		for i, _ := range create {
			create[i] = base[i] | 1<<uint16(offset)
		}
		base = append(base, create...)
	}
	return base
}

func (f *MatchedField6) GetTableIndex(maskVector *MatchedField6, min, max int) uint16 {
	result := f.And(maskVector)
	index := uint16(0)
	offset := uint16(0)
	for i := min; i <= max; i++ {
		if !result.IsBitZero(i) {
			index |= 1 << offset
		}
		if !maskVector.IsBitZero(i) {
			offset++
		}
	}
	return index
}

func (f *MatchedField6) IsBitZero(offset int) bool {
	index := offset >> 6
	position := offset & 0x3f
	return (f.fields[index]>>uint64(position))&0x1 == 0
}

func (f *MatchedField6) Equal(n *MatchedField6) bool {
	return f.fields[0] == n.fields[0] &&
		f.fields[1] == n.fields[1] &&
		f.fields[2] == n.fields[2] &&
		f.fields[3] == n.fields[3] &&
		f.fields[4] == n.fields[4] &&
		f.fields[5] == n.fields[5] &&
		f.fields[6] == n.fields[6]
}

func (f *MatchedField6) Or(n *MatchedField6) MatchedField6 {
	result := MatchedField6{}
	result.fields[0] = f.fields[0] | n.fields[0]
	result.fields[1] = f.fields[1] | n.fields[1]
	result.fields[2] = f.fields[2] | n.fields[2]
	result.fields[3] = f.fields[3] | n.fields[3]
	result.fields[4] = f.fields[4] | n.fields[4]
	result.fields[5] = f.fields[5] | n.fields[5]
	result.fields[6] = f.fields[6] | n.fields[6]
	return result
}

func (f *MatchedField6) And(n *MatchedField6) MatchedField6 {
	result := MatchedField6{}
	result.fields[0] = f.fields[0] & n.fields[0]
	result.fields[1] = f.fields[1] & n.fields[1]
	result.fields[2] = f.fields[2] & n.fields[2]
	result.fields[3] = f.fields[3] & n.fields[3]
	result.fields[4] = f.fields[4] & n.fields[4]
	result.fields[5] = f.fields[5] & n.fields[5]
	result.fields[6] = f.fields[6] & n.fields[6]
	return result
}

func (f MatchedField6) String() string {
	srcIp, dstIp := make(net.IP, 16), make(net.IP, 16)
	binary.BigEndian.PutUint64(srcIp, f.Get(MATCHED6_SRC_IP0))
	binary.BigEndian.PutUint64(srcIp[8:], f.Get(MATCHED6_SRC_IP1))
	binary.BigEndian.PutUint64(dstIp, f.Get(MATCHED6_DST_IP0))
	binary.BigEndian.PutUint64(dstIp[8:], f.Get(MATCHED6_DST_IP1))
	return fmt.Sprintf("%x.%s.%d -> %x.%s.%d epc: %d -> %d vlan: %d proto: %d tap: %d",
		f.Get(MATCHED6_SRC_MAC), srcIp, f.Get(MATCHED6_SRC_PORT),
		f.Get(MATCHED6_DST_MAC), dstIp, f.Get(MATCHED6_DST_PORT),
		f.Get(MATCHED6_SRC_EPC), f.Get(MATCHED6_DST_EPC),
		f.Get(MATCHED6_VLAN), f.Get(MATCHED6_PROTO), f.Get(MATCHED6_TAP_TYPE))
}
