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
func IsDupTraffic(inPort uint32, l3EpcID int32, isL2End, isL3End bool, tagCode outputtype.Code) bool {
	if ISP.IsPortInRange(inPort) {
		if tagCode.HasEdgeTagField() || (tagCode&outputtype.ACLGID != 0 && tagCode.IsSymmetric()) {
			// 双侧Tag，永远只统计ZERO侧的数据（用IsWrongEndpoint去重）
			// 有acl的、对称的，tx/rx站在acl的角度；
			// 其它的，单侧的、非dup的都要看。
			return false
		} else {
			// 不属于云内IP（l3EpcID）的一侧认为是DupTraffic
			return l3EpcID == 0
		}
	} else if TOR.IsPortInRange(inPort) {
		// 1. 有acl的对称字段，通过IsWrongEndPointWithACL去重
		if tagCode&outputtype.ACLGID != 0 && tagCode.IsSymmetric() {
			if l3EpcID <= 0 { // 有一侧未部署虚拟探针，不需要去重
				return false
			}
			// 限制：假设l3EpcId > 0意味着部署了探针
		}
		// 2. 经过交换机转发（isL2End）的一侧认为是DupTraffic
		// 3. tagCode不含有L2信息、且经过路由器转发（isL3End）的一侧认为是DupTraffic
		return !isL2End || (!tagCode.HasL2TagField() && !isL3End)
	}
	return false
}

// 不含ACL的Tag
func IsWrongEndPoint(thisEnd EndPoint, tagCode outputtype.Code) bool {
	if tagCode.HasEdgeTagField() {
		// 双侧Tag，永远只统计ZERO侧的数据：
		//   - 即统计量表示客户端（包统计不会有双侧Tag，源端即是客户端）的Tx/Rx
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

// 含ACL的Tag
func IsWrongEndPointWithACL(thisEnd EndPoint, aclDirection inputtype.DirectionType, tagCode outputtype.Code) bool {
	if tagCode&outputtype.ACLGID == 0 {
		panic("Tag必须包含ACLGID字段")
	}
	if tagCode&outputtype.ACLDirection != 0 {
		// 情况A：包含ACLDirection（性能量化、白名单）的Tag仅考虑ACL正向匹配的情况
		if aclDirection&inputtype.FORWARD == 0 {
			return true
		}
		// 情况A2：ACL正向匹配时，对于有ACL的对称字段，只统计ZERO侧的数据（ONE侧统计方向不对，并且DUP）
		if tagCode.IsSymmetric() {
			return thisEnd == ONE
		}
		return IsWrongEndPoint(thisEnd, tagCode)
	} else {
		if aclDirection&inputtype.FORWARD != 0 {
			// 情况B1：对于有ACL的对称字段，只统计ZERO侧的数据（ONE侧统计方向不对，并且DUP）
			if tagCode.IsSymmetric() {
				return thisEnd == ONE
			}
			// 情况B2：若ACL正向匹配，则照常判断
			return IsWrongEndPoint(thisEnd, tagCode)
		} else {
			// 情况C：若ACL **仅** 反向匹配
			if tagCode&outputtype.ServerPort != 0 {
				// 不统计带端口号的Tag组合（包统计不会有带端口号的Tag）：
				//   - ACL虽然匹配了，但与流的方向不一致，不能为此ACL统计服务端口号
				return true
			}
			if tagCode.IsSymmetric() {
				// 对于对称字段的Tag：
				//   - 永远只统计ONE侧的数据，统计量表示ACL源端的Tx/Rx；
				return thisEnd == ZERO
			}
			if tagCode.HasEdgeTagField() {
				// 对于双侧Tag（包统计不会有双侧Tag）：
				//   - 永远只统计ZERO侧的数据，统计量表示客户端到服务端的Tx/Rx；
				return thisEnd == ONE
			}
			// 其它Tag组合（不含端口号、非对称字段、单侧）：
			//   - 如果Tag是重复的（非对称字段但重复），通过Tag Field的去重机制，统计量优先表示源端的Tx/Rx（ZERO）
			//     这可能导致某些统计量难以理解：例如一个ACL匹配的流量中某个EPC的Tx/Rx，
			//     其中该EPC的内部流量（源、目的均为此EPC）Tx/Rx可能是混乱叠加的。
			//     实际上这种情况下如何定义Tx/Rx都是不合理的，应该避免使用此类Tag组合的Tx/Rx统计量。
			//   - 如果Tag是不重复的，只要是通过IsDupTraffic检测的两侧都会有各自的统计量（ZERO及ONE）
			return false
		}
	}
}
