package datatype

import (
	"fmt"
)

type TapType uint16

// tapType
// TAP_ANY(0)              -> ALL
// TAP_TOR(3)              -> inPort=0x3xxxx
// TAP_ISP(n = [1-2,4-30]) -> inPort=0x10000 | n
const (
	TAP_ANY     = TapType(0)
	TAP_ISP_MIN = TapType(1)
	TAP_TOR     = TapType(3)
	TAP_MAX     = TapType(256)

	TAP_MIN TapType = TAP_ANY + 1
)

// FIXME: 目前仅DDBS算法支持探针点的精确匹配，后面需要完善原算法
func GetTapType(inPort uint32) TapType {
	if PACKET_SOURCE_TOR == ((inPort) & PACKET_SOURCE_TOR) {
		return TAP_TOR
	}
	n := TapType(inPort & 0xff)
	if n >= TAP_MAX || n == TAP_ANY || n == TAP_TOR {
		panic(fmt.Sprintf("GetTapType(): invalid inPort %d", inPort))
	}
	return n
}
