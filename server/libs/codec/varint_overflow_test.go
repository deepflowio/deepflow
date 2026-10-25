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

package codec

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestDecodeVarintTenthByte(t *testing.T) {
	for last := 0; last <= 255; last++ {
		buf := append(bytes.Repeat([]byte{0xff}, 9), byte(last))
		want, n := binary.Uvarint(buf)
		for _, slow := range []bool{false, true} {
			t.Run(fmt.Sprintf("last_%02x/slow_%t", last, slow), func(t *testing.T) {
				var d SimpleDecoder
				// Start after another field and leave a following field unread.
				d.Init(append(append([]byte{42}, buf...), 43))
				d.ReadU8()
				var got uint64
				if slow {
					var err error
					got, err = d.decodeVarintSlow()
					if (err != nil) != (n <= 0) {
						t.Fatalf("error = %v, standard library length = %d", err, n)
					}
				} else {
					got = d.DecodeVarint()
				}
				if d.Failed() != (n <= 0) {
					t.Fatalf("Failed() = %t, standard library length = %d", d.Failed(), n)
				}
				if n > 0 {
					if got != want || d.ReadU8() != 43 || !d.IsEnd() {
						t.Fatalf("decoded value or offset mismatch: got %d, want %d, offset %d", got, want, d.Offset())
					}
				} else if d.Offset() != 1 {
					t.Fatalf("overflow advanced offset to %d", d.Offset())
				}
			})
		}
	}
}
