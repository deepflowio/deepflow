package endpoint

import (
	"fmt"

	outputtype "gitlab.x.lan/yunshan/droplet-libs/zerodoc"
)

const (
	ZERO EndPoint = iota
	ONE
)

type EndPoint uint8

const (
	OVS   DfiInPortRange = iota
	ISP   DfiInPortRange = 0x10000
	SPINE DfiInPortRange = 0x20000
	TOR   DfiInPortRange = 0x30000
)

func GetEpcFlowTopoEndpoints(inPort0 uint32, packetCount uint64) []EndPoint {
	ispPortRange := DfiInPortRange(ISP)
	spinePortRange := DfiInPortRange(SPINE)
	endpoints := make([]EndPoint, 2)

	if ispPortRange.IsPortInRange(inPort0) || spinePortRange.IsPortInRange(inPort0) || packetCount == 0 {
		return endpoints[:0]
	}
	endpoints[0] = ZERO
	endpoints[1] = ONE
	return endpoints
}

func GetOppositeEndpoint(val EndPoint) EndPoint {
	if val == ZERO {
		return ONE
	} else {
		return ZERO
	}
}

type DfiInPortRange uint32

func (p DfiInPortRange) IsPortInRange(port uint32) bool {
	return uint32(p) == (port & 0xFFFF0000)
}

func TAPTypeFromInPort(inPort uint32) outputtype.TAPTypeEnum {
	switch {
	case ISP.IsPortInRange(inPort):
		tapType := outputtype.TAPTypeEnum(inPort - uint32(ISP))
		if tapType == 3 || tapType >= 31 {
			panic(fmt.Sprintf("ISP InPort %d not in range", tapType))
		}

		return tapType
	case TOR.IsPortInRange(inPort):
		return outputtype.ToR
	}
	panic(fmt.Sprintf("InPort %d not in range", inPort))
}
