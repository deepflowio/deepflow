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

	left := 0
	right := 0
	for port := 1; port <= math.MaxUint16; port++ {
		status := table[port]

		switch status {
		case RANGE_NONE:
		case RANGE_EDGE:
			if left > 0 && left != port {
				portRanges = append(portRanges, NewPortRange(uint16(left), uint16(port)-1))
			}
			portRanges = append(portRanges, NewPortRange(uint16(port), uint16(port)))
			left = port + 1
		case RANGE_LEFT:
			if left > 0 && left != port {
				portRanges = append(portRanges, NewPortRange(uint16(left), uint16(port)-1))
			}
			left = port
		case RANGE_RIGHT:
			if left > 0 {
				portRanges = append(portRanges, NewPortRange(uint16(left), uint16(port)))
				left = 0
				right = port + 1
			} else if right > 0 {
				portRanges = append(portRanges, NewPortRange(uint16(right), uint16(port)))
				right = port + 1
			}
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
