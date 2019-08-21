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

func IsNorthSourceTraffic(l3EpcID0, l3EpcID1 int32) bool {
	return l3EpcID0 == 0 || l3EpcID1 == 0 // 0: Internet
}

// 虚拟网络东西向流量判断逻辑：
//     TAG             IP1 -------> (1)router(2) --------> IP2
//                         ^     ^               ^      ^          <-- 抓包点
//     IP1                 -     DUP             DUP    DUP
//     IP2                 DUP   DUP             DUP    -
//     IP1->IP2            DUP   DUP             DUP    -
//     IP2->IP1            -     DUP             DUP    DUP
//
func IsDupTraffic(inPort uint32, isL2L3EndThisEnd, isL2L3EndOtherEnd, isNorthSouthTraffic bool, tagCode outputtype.Code) bool {
	if ISP.IsPortInRange(inPort) {
		// 接入网络流量只有一份，不存在Dup
		return false
	} else if TOR.IsPortInRange(inPort) {
		// 虚拟网络流量可能存在多份，需要忽略交换机和路由器二、三层转发后的流量:
		// 1. 对于南北向流量，肯定有一端未被采集点覆盖，
		//    取客户端或服务端所在位置有采集器的流量
		// 2. 对于东西向流量，认为两段均被采集点覆盖
		//    2.1. 对于双端统计量，取对端所在位置有采集器的流量，
		//         但是IsWrongEndPoint会过滤掉对端是客户端的场景
		//    2.2. 对于单端统计量，取本端所在位置有采集器的流量，
		//         但是IsWrongEndPoint会过滤掉带ServerPort且本端是客户端的场景
		if isNorthSouthTraffic {
			return !(isL2L3EndThisEnd || isL2L3EndOtherEnd)
		}
		if tagCode.HasEdgeTagField() {
			return !isL2L3EndOtherEnd
		} else {
			return !isL2L3EndThisEnd
		}
	}
	return true // never happen
}

// 不含ACL的Tag
func IsWrongEndPoint(thisEnd EndPoint, tagCode outputtype.Code) bool {
	if tagCode.HasEdgeTagField() {
		// 双侧Tag，永远只统计ZERO侧的数据：即统计量表示客户端的Tx/Rx
		return thisEnd == ONE
	} else {
		// 含端口号的单侧Tag，永远只统计ONE侧的数据：即统计量表示服务端的Tx/Rx
		if tagCode&outputtype.ServerPort != 0 {
			return thisEnd == ZERO
		}
		// 其它单侧统计量，表示本侧的Tx/Rx
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
