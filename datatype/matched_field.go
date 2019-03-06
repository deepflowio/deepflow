package datatype

import (
	"fmt"
)

const (
	MATCHED_FIELD_BITS_LEN = 80 // 2(TapType) + 12(Vlan) + 2(Proto) + 16(Group)*2 + 16(Port)*2
	MATCHED_FIELD_LEN      = 2
)

type MatchFlags uint16

const (
	// fields[0]
	MATCHED_SRC_PORT MatchFlags = iota
	MATCHED_DST_PORT
	MATCHED_SRC_GROUP
	MATCHED_DST_GROUP

	// fields[1]
	MATCHED_PROTO
	MATCHED_VLAN
	MATCHED_TAP_TYPE
)

var fieldOffset = [...]uint64{
	MATCHED_SRC_PORT:  16,
	MATCHED_DST_PORT:  0,
	MATCHED_SRC_GROUP: 48,
	MATCHED_DST_GROUP: 32,

	MATCHED_PROTO:    64,
	MATCHED_VLAN:     66,
	MATCHED_TAP_TYPE: 78,
}

var fieldMask = [...]uint64{
	MATCHED_SRC_PORT:  0xffff,
	MATCHED_DST_PORT:  0xffff,
	MATCHED_SRC_GROUP: 0xffff,
	MATCHED_DST_GROUP: 0xffff,

	MATCHED_PROTO:    0x3,
	MATCHED_VLAN:     0xfff,
	MATCHED_TAP_TYPE: 0x3,
}

type MatchedField struct {
	fields [MATCHED_FIELD_LEN]uint64
}

func (f *MatchedField) Get(flag MatchFlags) uint16 {
	index := fieldOffset[flag] / 64
	offset := fieldOffset[flag] % 64
	return uint16((f.fields[index] >> offset) & fieldMask[flag])
}

func (f *MatchedField) Set(flag MatchFlags, value uint16) {
	index := fieldOffset[flag] / 64
	offset := fieldOffset[flag] % 64
	f.fields[index] &= ^(fieldMask[flag] << offset)
	f.fields[index] |= (uint64(value) << offset)
}

func (f *MatchedField) SetBits(whichs ...int) {
	f.fields[0] = 0
	f.fields[1] = 0

	for _, which := range whichs {
		index := which / 64
		offset := uint(which % 64)
		f.fields[index] |= (1 << offset)
	}
}

func (f *MatchedField) GetTableIndex(maskVector *MatchedField) uint16 {
	result := f.And(maskVector)
	index := uint16(0)
	offset := uint16(0)
	for i := 0; i < MATCHED_FIELD_BITS_LEN; i++ {
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
	index := offset / 64
	position := offset % 64
	return (f.fields[index]>>uint64(position))&0x1 == 0
}

func (f *MatchedField) Equal(n *MatchedField) bool {
	return f.fields[0] == n.fields[0] && f.fields[1] == n.fields[1]
}

func (f *MatchedField) Or(n *MatchedField) MatchedField {
	result := MatchedField{}
	result.fields[0] = f.fields[0] | n.fields[0]
	result.fields[1] = f.fields[1] | n.fields[1]
	return result
}

func (f *MatchedField) And(n *MatchedField) MatchedField {
	result := MatchedField{}
	result.fields[0] = f.fields[0] & n.fields[0]
	result.fields[1] = f.fields[1] & n.fields[1]
	return result
}

func (f MatchedField) String() string {
	return fmt.Sprintf("tap: %d vlan: %d proto: %d groups: %d %d ports: %d %d | 0x%016x0x%016x",
		f.Get(MATCHED_TAP_TYPE), f.Get(MATCHED_VLAN), f.Get(MATCHED_PROTO),
		f.Get(MATCHED_SRC_GROUP), f.Get(MATCHED_DST_GROUP),
		f.Get(MATCHED_SRC_PORT), f.Get(MATCHED_DST_PORT),
		f.fields[1], f.fields[0])
}
