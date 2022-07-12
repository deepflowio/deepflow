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

package datatype

import (
	"fmt"
)

const (
	NUM_64_OFFSET = 6
	NUM_64_MASK   = 0x3f
)

const (
	MATCHED_FIELD_BITS_LEN = 144 // 8(TapType) + 8(Proto) + 16(Port)*2 + 16(L3EPC)*2 + 32(IP)*2
	MATCHED_FIELD_LEN      = 3
)

type MatchFlags uint16

const (
	// fields[0]
	MATCHED_SRC_IP MatchFlags = iota
	MATCHED_DST_IP
	// fields[1]
	MATCHED_SRC_EPC
	MATCHED_DST_EPC
	MATCHED_SRC_PORT
	MATCHED_DST_PORT
	// fields[2]
	MATCHED_PROTO
	MATCHED_TAP_TYPE
)

var fieldOffset = [...]uint64{
	MATCHED_SRC_IP: 0,
	MATCHED_DST_IP: 32,

	MATCHED_SRC_EPC:  64,
	MATCHED_DST_EPC:  80,
	MATCHED_SRC_PORT: 96,
	MATCHED_DST_PORT: 112,

	MATCHED_PROTO:    128,
	MATCHED_TAP_TYPE: 136,
}

var fieldMask = [...]uint64{
	MATCHED_SRC_IP: 0xffffffff,
	MATCHED_DST_IP: 0xffffffff,

	MATCHED_SRC_EPC:  0xffff,
	MATCHED_DST_EPC:  0xffff,
	MATCHED_SRC_PORT: 0xffff,
	MATCHED_DST_PORT: 0xffff,

	MATCHED_PROTO:    0xff,
	MATCHED_TAP_TYPE: 0xff,
}

type MatchedField struct {
	fields [MATCHED_FIELD_LEN]uint64
}

var (
	blankMatchedFieldForInit MatchedField = MatchedField{}
)

func (f *MatchedField) GobEncode() ([]byte, error) {
	return []byte{}, nil
}

func (f *MatchedField) GobDecode(in []byte) error {
	return nil
}

func (f *MatchedField) Get(flag MatchFlags) uint64 {
	index := fieldOffset[flag] >> NUM_64_OFFSET // fieldOffset[flag] / 64
	offset := fieldOffset[flag] & NUM_64_MASK   // fieldOffset[flag] % 64
	return (f.fields[index] >> offset) & fieldMask[flag]
}

func (f *MatchedField) Set(flag MatchFlags, value uint64) {
	index := fieldOffset[flag] >> NUM_64_OFFSET // fieldOffset[flag] / 64
	offset := fieldOffset[flag] & NUM_64_MASK   // fieldOffset[flag] % 64
	f.fields[index] &= ^(fieldMask[flag] << offset)
	f.fields[index] |= (value << offset)
}

func (f *MatchedField) SetMask(flag MatchFlags, value uint64) {
	if value != 0 {
		value = fieldMask[flag]
	}
	f.Set(flag, value)
}

func (f *MatchedField) SetBits(whichs ...int) {
	// MATCHED_FIELD_LEN是4, 只清理了4个
	*f = blankMatchedFieldForInit
	for _, which := range whichs {
		index := which >> NUM_64_OFFSET     // which / 64
		offset := uint(which & NUM_64_MASK) // which % 64
		f.fields[index] |= (1 << offset)
	}
}

// TODO: 这个函数申请的内存比较多，考虑到内存不是常驻内存会GC掉目前不做优化
func (f *MatchedField) GetAllTableIndex(maskVector, mask *MatchedField, min, max int, vectorBits []int) []uint16 {
	// 若f为0101， maskVector为0111, mask为1001，返回{001,011,101,111}
	index := f.GetTableIndex(maskVector, min, max)
	indexOffset := make([]int, 0, 1)
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

	base := make([]uint16, 0, 1)
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
	return f.fields[0] == n.fields[0] && f.fields[1] == n.fields[1] && f.fields[2] == n.fields[2]
}

func (f *MatchedField) Or(n *MatchedField) MatchedField {
	result := MatchedField{}
	result.fields[0] = f.fields[0] | n.fields[0]
	result.fields[1] = f.fields[1] | n.fields[1]
	result.fields[2] = f.fields[2] | n.fields[2]
	return result
}

func (f *MatchedField) And(n *MatchedField) MatchedField {
	result := MatchedField{}
	result.fields[0] = f.fields[0] & n.fields[0]
	result.fields[1] = f.fields[1] & n.fields[1]
	result.fields[2] = f.fields[2] & n.fields[2]
	return result
}

func (f MatchedField) String() string {
	return fmt.Sprintf("%x:%d -> %x:%d epc: %d -> %d proto: %d tap: %d",
		f.Get(MATCHED_SRC_IP), f.Get(MATCHED_SRC_PORT),
		f.Get(MATCHED_DST_IP), f.Get(MATCHED_DST_PORT),
		f.Get(MATCHED_SRC_EPC), f.Get(MATCHED_DST_EPC),
		f.Get(MATCHED_PROTO), f.Get(MATCHED_TAP_TYPE))
}
