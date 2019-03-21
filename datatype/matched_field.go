package datatype

import (
	"fmt"
)

const (
	MATCHED_FIELD_BITS_LEN = 208 // 2(TapType) + 12(Vlan) + 2(Proto) + 16(Port)*2 + 64(MAC+IP)*2
	MATCHED_FIELD_LEN      = 4
)

type MatchFlags uint16

const (
	// fields[0]
	MATCHED_SRC_MAC MatchFlags = iota
	MATCHED_SRC_IP
	// fields[1]
	MATCHED_DST_MAC
	MATCHED_DST_IP

	// fields[2]
	MATCHED_SRC_PORT
	MATCHED_DST_PORT
	MATCHED_SRC_EPC
	MATCHED_DST_EPC
	// fields[3]
	MATCHED_PROTO
	MATCHED_VLAN
	MATCHED_TAP_TYPE
)

var fieldOffset = [...]uint64{
	MATCHED_SRC_MAC:  98,
	MATCHED_SRC_IP:   64,
	MATCHED_DST_MAC:  32,
	MATCHED_DST_IP:   0,
	MATCHED_SRC_PORT: 144,
	MATCHED_DST_PORT: 128,

	MATCHED_SRC_EPC:  176,
	MATCHED_DST_EPC:  160,
	MATCHED_PROTO:    192,
	MATCHED_VLAN:     194,
	MATCHED_TAP_TYPE: 206,
}

var fieldMask = [...]uint64{
	MATCHED_SRC_MAC: 0xffffffff,
	MATCHED_SRC_IP:  0xffffffff,

	MATCHED_DST_MAC: 0xffffffff,
	MATCHED_DST_IP:  0xffffffff,

	MATCHED_SRC_PORT: 0xffff,
	MATCHED_DST_PORT: 0xffff,
	MATCHED_SRC_EPC:  0xffff,
	MATCHED_DST_EPC:  0xffff,
	MATCHED_PROTO:    0x3,
	MATCHED_VLAN:     0xfff,
	MATCHED_TAP_TYPE: 0x3,
}

type MatchedField struct {
	fields [MATCHED_FIELD_LEN]uint64
}

func (f *MatchedField) Get(flag MatchFlags) uint32 {
	index := fieldOffset[flag] >> 6
	offset := fieldOffset[flag] & 0x3f
	return uint32((f.fields[index] >> offset) & fieldMask[flag])
}

func (f *MatchedField) Set(flag MatchFlags, value uint32) {
	index := fieldOffset[flag] >> 6
	offset := fieldOffset[flag] & 0x3f
	f.fields[index] &= ^(fieldMask[flag] << offset)
	f.fields[index] |= (uint64(value) << offset)
}

func (f *MatchedField) SetMask(flag MatchFlags, value uint32) {
	if value != 0 {
		value = uint32(fieldMask[flag])
	}
	f.Set(flag, value)
}

func (f *MatchedField) SetBits(whichs ...int) {
	f.fields[0] = 0
	f.fields[1] = 0
	f.fields[2] = 0
	f.fields[3] = 0

	for _, which := range whichs {
		index := which >> 6
		offset := uint(which & 0x3f)
		f.fields[index] |= (1 << offset)
	}
}

func (f *MatchedField) GetAllTableIndex(maskVector, mask *MatchedField, min, max int, vectorBits []int) []uint16 {
	index := f.GetTableIndex(maskVector, min, max)
	indexOffset := make([]int, 0, 4)
	for i, offset := range vectorBits {
		// 掩码对应的位为0，表示全采集
		if mask.IsBitZero(offset) {
			indexOffset = append(indexOffset, i)
		}
	}
	base := make([]uint16, 0, 16)
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

func (f *MatchedField) GetTableIndex(maskVector *MatchedField, min, max int) uint16 {
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

func (f *MatchedField) IsBitZero(offset int) bool {
	index := offset >> 6
	position := offset & 0x3f
	return (f.fields[index]>>uint64(position))&0x1 == 0
}

func (f *MatchedField) Equal(n *MatchedField) bool {
	return f.fields[0] == n.fields[0] && f.fields[1] == n.fields[1] && f.fields[2] == n.fields[2] && f.fields[3] == n.fields[3]
}

func (f *MatchedField) Or(n *MatchedField) MatchedField {
	result := MatchedField{}
	result.fields[0] = f.fields[0] | n.fields[0]
	result.fields[1] = f.fields[1] | n.fields[1]
	result.fields[2] = f.fields[2] | n.fields[2]
	result.fields[3] = f.fields[3] | n.fields[3]
	return result
}

func (f *MatchedField) And(n *MatchedField) MatchedField {
	result := MatchedField{}
	result.fields[0] = f.fields[0] & n.fields[0]
	result.fields[1] = f.fields[1] & n.fields[1]
	result.fields[2] = f.fields[2] & n.fields[2]
	result.fields[3] = f.fields[3] & n.fields[3]
	return result
}

func (f MatchedField) String() string {
	return fmt.Sprintf("%x:%x:%d -> %x:%x:%d epc: %d -> %d vlan: %d proto: %d tap: %d",
		f.Get(MATCHED_SRC_MAC), f.Get(MATCHED_SRC_IP), f.Get(MATCHED_SRC_PORT),
		f.Get(MATCHED_DST_MAC), f.Get(MATCHED_DST_IP), f.Get(MATCHED_DST_PORT),
		f.Get(MATCHED_SRC_EPC), f.Get(MATCHED_DST_EPC),
		f.Get(MATCHED_VLAN), f.Get(MATCHED_PROTO), f.Get(MATCHED_TAP_TYPE))
}
