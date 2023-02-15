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

package policy

import (
	"math"

	. "github.com/deepflowio/deepflow/server/libs/datatype"
)

type portSegment struct {
	port, mask uint16
}

var (
	allPortSegment portSegment = portSegment{0, 0}
)

func calcZeroCount(port uint16) uint16 {
	count := uint16(0)
	for i := uint16(0); i < uint16(16); i++ {
		if port>>i&0x1 != 0 {
			break
		}
		count++
	}
	return count
}

func calcMask(port, maxPort, count uint16) (uint16, uint16) {
	for i := uint16(0); i < count; i++ {
		if maxPort >= port+(1<<(count-i))-1 {
			return math.MaxUint16 << (count - i), count - i
		}
	}
	return math.MaxUint16, 0
}

func newPortSegments(port PortRange) []portSegment {
	segments := make([]portSegment, 0, 2)
	for i := port.Min(); i <= port.Max(); {
		segment := portSegment{}
		n := calcZeroCount(i)
		mask, n := calcMask(i, port.Max(), n)

		segment.mask = mask
		segment.port = i
		segments = append(segments, segment)
		i = i + 1<<n
		if i == 0 {
			break
		}
	}

	return segments
}
