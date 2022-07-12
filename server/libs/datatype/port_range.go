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
	"math"
)

type PortRange uint32
type PortStatus uint8

const (
	RANGE_NONE PortStatus = iota
	RANGE_IN
	RANGE_EDGE
	RANGE_LEFT
	RANGE_RIGHT
)

func (p PortRange) Min() uint16 {
	return uint16(p >> 16)
}

func (p PortRange) Max() uint16 {
	return uint16(p & 0xffff)
}

func (p PortRange) String() string {
	return fmt.Sprintf("%v-%v", p.Min(), p.Max())
}

func NewPortRange(min, max uint16) PortRange {
	return PortRange(uint32(min)<<16 | uint32(max))
}

func createPortStatusTable(raw []PortRange) []PortStatus {
	table := make([]PortStatus, math.MaxUint16+1)

	for _, port := range raw {
		if port.Min() == port.Max() {
			table[port.Min()] = RANGE_EDGE
			continue
		}
		if table[port.Min()] == RANGE_RIGHT || table[port.Min()] == RANGE_EDGE {
			table[port.Min()] = RANGE_EDGE
		} else {
			table[port.Min()] = RANGE_LEFT
		}
		if table[port.Max()] == RANGE_LEFT || table[port.Max()] == RANGE_EDGE {
			table[port.Max()] = RANGE_EDGE
		} else {
			table[port.Max()] = RANGE_RIGHT
		}

		for i := port.Min() + 1; i < port.Max(); i++ {
			if table[i] == RANGE_NONE {
				table[i] = RANGE_IN
			}
		}
	}
	return table
}

func createPortRangeByTable(table []PortStatus) []PortRange {
	portRanges := make([]PortRange, 0, 1000)

	lastPort := -1
	for port := 0; port <= math.MaxUint16; port++ {
		status := table[port]

		switch status {
		case RANGE_NONE:
		case RANGE_EDGE:
			if lastPort >= 0 && lastPort != port && table[lastPort] != RANGE_NONE {
				portRanges = append(portRanges, NewPortRange(uint16(lastPort), uint16(port)-1))
			}
			portRanges = append(portRanges, NewPortRange(uint16(port), uint16(port)))
			lastPort = port + 1
		case RANGE_LEFT:
			if lastPort >= 0 && lastPort != port && table[lastPort] != RANGE_NONE {
				portRanges = append(portRanges, NewPortRange(uint16(lastPort), uint16(port)-1))
			}
			lastPort = port
		case RANGE_RIGHT:
			if table[lastPort] != RANGE_NONE {
				portRanges = append(portRanges, NewPortRange(uint16(lastPort), uint16(port)))
			}
			lastPort = port + 1
		}
	}
	return portRanges
}

func GetPortRanges(raw []PortRange) []PortRange {
	if raw == nil || len(raw) == 0 {
		return raw
	}
	table := createPortStatusTable(raw)
	return createPortRangeByTable(table)
}
