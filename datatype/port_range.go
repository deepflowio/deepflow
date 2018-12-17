package datatype

import (
	"fmt"
	"math"
)

type PortRange uint32
type PortStatus uint8

const (
	RANGE_NONE PortStatus = iota
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
	}
	return table
}

func createPortRangeByTable(table []PortStatus) []PortRange {
	portRanges := make([]PortRange, 0, 1000)

	start := 0
	end := 0
	first := true
	for port := 1; port <= math.MaxUint16; port++ {
		status := table[port]
		if start == 0 {
			start = port
			end = port
			if status != RANGE_EDGE {
				first = false
				continue
			}
		}

		switch status {
		case RANGE_NONE:
			end = port
		case RANGE_EDGE:
			if !first {
				portRanges = append(portRanges, NewPortRange(uint16(start), uint16(end)))
			}
			portRanges = append(portRanges, NewPortRange(uint16(port), uint16(port)))
			start = port + 1
			end = start
		case RANGE_LEFT:
			if end > start {
				portRanges = append(portRanges, NewPortRange(uint16(start), uint16(end)))
			}
			start = port
			end = start
		case RANGE_RIGHT:
			portRanges = append(portRanges, NewPortRange(uint16(start), uint16(port)))
			start = port + 1
			end = start
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
