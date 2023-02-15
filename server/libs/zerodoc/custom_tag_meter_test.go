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

package zerodoc

import (
	"reflect"
	"testing"

	"github.com/deepflowio/deepflow/server/libs/codec"
)

func TestCustomTagMeterMetaEncodeDecode(t *testing.T) {
	orig := CustomTagMeterMeta{
		Tag: CustomTagMeta{
			Names: []string{"l3_epc_id", "ip", "protocol", "direction"},
		},
		Meter: CustomMeterMeta{
			Names: []string{"rtt", "byte_tx", "byte_rx"},
			Types: []CustomMeterType{CUSTOM_METER_U32, CUSTOM_METER_U64, CUSTOM_METER_U64},
		},
	}
	orig.Tag.PopulateCache()
	orig.Meter.PopulateCache()
	encoder := codec.SimpleEncoder{}
	orig.Encode(&encoder)
	decoder := codec.SimpleDecoder{}
	decoder.Init(encoder.Bytes())
	newMeta := CustomTagMeterMeta{}
	newMeta.Decode(&decoder)
	if !reflect.DeepEqual(orig, newMeta) {
		t.Error("CustomTagMeterMeta encode/decode不正确")
	}
}

func TestCustomTagEncodeDecode(t *testing.T) {
	checkTagEqual := func(t1, t2 *CustomTag) bool {
		if t1.Code != t2.Code {
			return false
		}
		index := 0
		code := t1.Code
		for code > 0 {
			if code&1 != 0 {
				if index >= len(t1.Values) || index >= len(t2.Values) {
					return false
				}
				if t1.Values[index] != t2.Values[index] {
					return false
				}
			}
			code >>= 1
			index++
		}
		return true
	}
	encoder := codec.SimpleEncoder{}
	tag := CustomTag{
		Values: []string{"10.33.2.202", "6", "5201", "c2s", "", "4231"},
		Code:   0x2F,
	}
	tag.Encode(&encoder)
	decoder := codec.SimpleDecoder{}
	decoder.Init(encoder.Bytes())
	newTag := CustomTag{}
	newTag.Decode(&decoder)
	if !checkTagEqual(&tag, &newTag) {
		t.Error("CustomTag encode/decode不正确")
	}

	encoder.Reset()
	tag.Code = 0x3
	tag.Encode(&encoder)
	decoder.Init(encoder.Bytes())
	newTag = CustomTag{}
	newTag.Decode(&decoder)
	if !checkTagEqual(&tag, &newTag) {
		t.Error("CustomTag encode/decode不正确")
	}
}

func TestCustomMeterEncodeDecode(t *testing.T) {
	m := CustomMeter{
		Values: []uint64{1, 2, 3, 4, 5},
	}
	encoder := codec.SimpleEncoder{}
	m.Encode(&encoder)
	decoder := codec.SimpleDecoder{}
	decoder.Init(encoder.Bytes())
	newM := CustomMeter{}
	newM.Decode(&decoder)
	if !reflect.DeepEqual(&m, &newM) {
		t.Error("CustomMeter encode/decode不正确")
	}
}
