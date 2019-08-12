package endpoint

import (
	"fmt"

	inputtype "gitlab.x.lan/yunshan/droplet-libs/datatype"
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

func GetIspEndpoints(inPort0 uint32, l3EpcId0 uint32, l3EpcId1 uint32) []EndPoint {
	endpoints := make([]EndPoint, 2)
	ispPortRange := DfiInPortRange(ISP)
	index := 0
	if ispPortRange.IsPortInRange(inPort0) {
		if l3EpcId0 != 0 {
			endpoints[index] = ZERO
			index++
		}
		if l3EpcId1 != 0 {
			endpoints[index] = ONE
			index++
		}
	}
	return endpoints[:index]
}

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

// 1. 对于单侧Tag，判断点设置为本端，即使用l3EpcID[thisEnd]、isL2End[thisEnd]、isL3End[thisEnd]调用
// 2. 考虑到当tag含有ServerPort时对端表示服务端，对于双侧Tag，判断点设置为对端，即使用otherEnd调用
//
// 虚拟网络判断逻辑：
//   tagCode不含有L2信息：
//     TAG             IP1 -------> (1)router(2) --------> IP2
//                         ^     ^               ^      ^          <-- 抓包点
//     IP1                 -     DUP             DUP    DUP
//     IP2                 DUP   DUP             DUP    -
//     IP1->IP2            DUP   DUP             DUP    -
//     IP2->IP1            -     DUP             DUP    DUP
//
//   tagCode含有L2信息：
//     TAG             IP1 -------> (1)router(2) --------> IP2
//                         ^     ^               ^      ^          <-- 抓包点
//     MAC1                -     DUP             N/A    N/A
//     RouterMAC1          DUP   -               N/A    N/A
//     RouterMAC2          N/A   N/A             -      DUP
//     MAC2                N/A   N/A             DUP    -
//     MAC1->RouterMAC1    DUP   -               N/A    N/A
//     RouterMAC1->MAC1    -     DUP             N/A    N/A
//     RouterMAC2->MAC2    N/A   N/A             DUP    -
//     MAC2->RouterMAC2    N/A   N/A             -      DUP
//
func IsDupTraffic(inPort uint32, isL2End, isL3End bool, tagCode outputtype.Code) bool {
	if ISP.IsPortInRange(inPort) {
		// 接入网络流量只有一份，不存在Dup
		return false
	} else if TOR.IsPortInRange(inPort) {
		// 虚拟网络存在多份，需要做Dedup:
		// 1. 经过交换机转发（isL2End）的一侧认为是DupTraffic
		// 2. tagCode不含有L2信息、且经过路由器转发（isL3End）的一侧认为是DupTraffic
		return !isL2End || (!tagCode.HasL2TagField() && !isL3End)
	}
	return false
}

// 不含ACL的Tag
func IsWrongEndPoint(thisEnd EndPoint, tagCode outputtype.Code) bool {
	if tagCode.HasEdgeTagField() {
		// 双侧Tag，永远只统计ZERO侧的数据：即统计量表示客户端的Tx/Rx
		return thisEnd == ONE
	} else {
		// 含端口号的单侧Tag，永远只统计ONE侧的数据：
		//   - 即统计量表示服务端（包统计不会有端口号Tag，目的端即是服务端）的Tx/Rx
		if tagCode&outputtype.ServerPort != 0 {
			return thisEnd == ZERO
		}
		// 其它情况下：
		//   - 如果Tag是重复的（对称字段，或非对称字段但重复），通过Tag Field的去重机制，统计量优先表示源端的Tx/Rx（ZERO）
		//   - 如果Tag是不重复的，只要是通过IsDupTraffic检测的两侧都会有各自的统计量（ZERO及ONE）
		return false
	}
}

// 含ACL的Tag，仅考虑ACL正向匹配的情况
func IsWrongEndPointWithACL(thisEnd EndPoint, aclDirection inputtype.DirectionType, tagCode outputtype.Code) bool {
	if tagCode&outputtype.ACLGID == 0 {
		panic("Tag必须包含ACLGID字段")
	}
	if tagCode&outputtype.ACLDirection == 0 {
		panic("Tag必须包含ACLDirection字段")
	}
	if aclDirection&inputtype.FORWARD == 0 {
		return true
	}
	return IsWrongEndPoint(thisEnd, tagCode)
}
