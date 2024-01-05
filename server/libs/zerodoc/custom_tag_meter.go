/*
 * Copyright (c) 2024 Yunshan Networks
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

package zerodoc

import (
	"encoding/binary"
	"sort"

	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/datatype/prompb"
	"github.com/deepflowio/deepflow/server/libs/pool"
)

type CustomTagMeterMeta struct {
	Tag   CustomTagMeta
	Meter CustomMeterMeta
}

func (t *CustomTagMeterMeta) Decode(decoder *codec.SimpleDecoder) {
	tagLen := int(decoder.ReadU8())
	t.Tag.Names = t.Tag.Names[:0]
	for i := 0; i < tagLen; i++ {
		t.Tag.Names = append(t.Tag.Names, decoder.ReadString255())
	}
	meterLen := int(decoder.ReadU8())
	t.Meter.Names = t.Meter.Names[:0]
	t.Meter.Types = t.Meter.Types[:0]
	for i := 0; i < meterLen; i++ {
		t.Meter.Names = append(t.Meter.Names, decoder.ReadString255())
		t.Meter.Types = append(t.Meter.Types, CustomMeterType(decoder.ReadU8()))
	}

	t.Tag.PopulateCache()
	t.Meter.PopulateCache()
}

func (t *CustomTagMeterMeta) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteU8(uint8(len(t.Tag.Names)))
	for _, name := range t.Tag.Names {
		encoder.WriteString255(name)
	}
	encoder.WriteU8(uint8(len(t.Meter.Names)))
	for i, name := range t.Meter.Names {
		encoder.WriteString255(name)
		encoder.WriteU8(uint8(t.Meter.Types[i]))
	}
}

type CustomTagMeta struct {
	Names []string

	nameToIndex map[string]int
}

func (m *CustomTagMeta) PopulateCache() {
	m.nameToIndex = make(map[string]int)
	for i, name := range m.Names {
		m.nameToIndex[name] = i
	}
}

func (m *CustomTagMeta) IndexOf(name string) int {
	if m.nameToIndex == nil {
		m.PopulateCache()
	}
	if id, in := m.nameToIndex[name]; in {
		return id
	}
	return -1
}

func (m *CustomTagMeta) Validate(ct *CustomTag) bool {
	return len(m.Names) == len(ct.Values)
}

type CustomMeterType uint8

const (
	CUSTOM_METER_U64 CustomMeterType = iota
	CUSTOM_METER_U32
)

type CustomMeterMeta struct {
	Names []string
	Types []CustomMeterType

	nameToIndex map[string]int
}

func (m *CustomMeterMeta) PopulateCache() {
	m.nameToIndex = make(map[string]int)
	for i, name := range m.Names {
		m.nameToIndex[name] = i
	}
}

func (m *CustomMeterMeta) IndexOf(name string) int {
	if m.nameToIndex == nil {
		m.PopulateCache()
	}
	if id, in := m.nameToIndex[name]; in {
		return id
	}
	return -1
}

func (m *CustomMeterMeta) Validate(cm *CustomMeter) bool {
	return len(m.Names) == len(cm.Values)
}

type CustomTag struct {
	Meta *CustomTagMeta

	id     string
	Values []string
	// 每一位表示对应index下的Values[i]有意义
	// 如 Code=3时Values[0]和Values[1]有意义
	Code uint64

	pool.ReferenceCount
}

var customTagPool = pool.NewLockFreePool(func() interface{} {
	return &CustomTag{}
})

func AcquireCustomTag() *CustomTag {
	t := customTagPool.Get().(*CustomTag)
	t.Reset()
	return t
}

func (t *CustomTag) Clone() Tagger {
	newTag := AcquireCustomTag()
	newTag.Meta = t.Meta
	newTag.id = t.id
	newTag.Values = append(newTag.Values[:0], t.Values...)
	newTag.Code = t.Code
	newTag.Reset()
	return newTag
}

func (t *CustomTag) PseudoClone() Tagger {
	t.AddReferenceCount()
	return t
}

func (t *CustomTag) Release() {
	if t.SubReferenceCount() {
		return
	}
	*t = CustomTag{Values: t.Values[:0]}
	customTagPool.Put(t)
}

func (t *CustomTag) Decode(decoder *codec.SimpleDecoder) {
	t.Values = t.Values[:0]
	offset := decoder.Offset()
	t.Code = decoder.ReadU64()
	code := t.Code
	for code > 0 {
		if code&1 == 0 {
			t.Values = append(t.Values, "")
		} else {
			t.Values = append(t.Values, decoder.ReadString255())
		}
		code >>= 1
	}

	if !decoder.Failed() {
		t.id = string(decoder.Bytes()[offset:decoder.Offset()]) // Encode内容就是它的id
	}
}

func (t *CustomTag) EncodeWithCode(code uint64, encoder *codec.SimpleEncoder) {
	encoder.WriteU64(code)
	for i, value := range t.Values {
		if code&(1<<i) != 0 {
			encoder.WriteString255(value)
		}
	}
}

func (t *CustomTag) Encode(encoder *codec.SimpleEncoder) {
	if t.id != "" {
		encoder.WriteRawString(t.id) // ID就是序列化bytes，避免重复计算
		return
	}
	t.EncodeWithCode(t.Code, encoder)
}

func (t *CustomTag) GetCode() uint64 {
	return t.Code
}

func (t *CustomTag) SetCode(code uint64) {
	t.Code = code
}

func (t *CustomTag) GetID(encoder *codec.SimpleEncoder) string {
	if t.id == "" {
		encoder.Reset()
		t.Encode(encoder)
		t.id = encoder.String()
	}
	return t.id
}

func (t *CustomTag) SetID(id string) {
	t.id = id
}

func (t *CustomTag) GetTAPType() uint8 {
	panic("not implemented")
}

func (t *CustomTag) MarshalTo(b []byte) int {
	Names := make([]string, len(t.Meta.Names))
	copy(Names, t.Meta.Names)
	sort.Strings(Names)
	offset := 0
	for _, name := range Names {
		index := t.Meta.IndexOf(name)
		if t.Code&(1<<index) == 0 {
			continue
		}
		if offset > 0 {
			b[offset] = ','
			offset++
		}
		offset += copy(b[offset:], name)
		b[offset] = '='
		offset++
		offset += copy(b[offset:], t.Values[index])
	}
	return offset
}

func (t *CustomTag) ToKVString() string {
	buffer := make([]byte, MAX_STRING_LENGTH)
	size := t.MarshalTo(buffer)
	return string(buffer[:size])
}

func (t *CustomTag) String() string {
	return t.ToKVString()
}

var _ Tagger = &CustomTag{}

type CustomMeter struct {
	Meta *CustomMeterMeta

	Values []uint64
}

func (m *CustomMeter) Decode(decoder *codec.SimpleDecoder) {
	m.Values = m.Values[:0]
	length := int(decoder.ReadU8())
	for i := 0; i < length; i++ {
		m.Values = append(m.Values, decoder.ReadU64())
	}
}

func (m *CustomMeter) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteU8(uint8(len(m.Values)))
	for _, value := range m.Values {
		encoder.WriteU64(value)
	}
}

func EncodeTSDBRow(encoder *codec.SimpleEncoder, timestamp uint64, columnValues []interface{}, isTag []bool, isNil []bool) {
	encoder.WriteU64(timestamp)
	code := uint64(0)
	offset := len(encoder.Bytes())
	encoder.WriteU64(0)
	for i, v := range columnValues {
		if isTag[i] && !isNil[i] {
			code = (code << 1) | 1
			if str, ok := v.(string); ok {
				encoder.WriteString255(str)
			} else {
				encoder.WriteString255("")
			}
		}
	}
	// 写入code
	binary.LittleEndian.PutUint64(encoder.Bytes()[offset:], code)

	l := byte(0)
	offset = len(encoder.Bytes())
	encoder.WriteU8(0)
	for i, v := range columnValues {
		if !isTag[i] && !isNil[i] {
			l++
			if i64, ok := v.(int64); ok {
				encoder.WriteU64(uint64(i64))
			} else if f64, ok := v.(float64); ok {
				encoder.WriteU64(uint64(f64))
			} else {
				encoder.WriteU64(0)
			}
		}
	}
	encoder.Bytes()[offset] = l
}

// EncodeCustomTagToPromLabels 将 CustomTag 编码成 prom Label
func EncodeCustomTagToPromLabels(tag *CustomTag) []prompb.Label {
	if tag == nil {
		return nil
	}
	buffer := make([]byte, MAX_STRING_LENGTH)
	size := tag.MarshalTo(buffer)
	return encodePromLabels(buffer[:size])
}
