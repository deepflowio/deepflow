package endpoint

import (
	"fmt"
	"testing"

	inputtype "gitlab.x.lan/yunshan/droplet-libs/datatype"
	outputtype "gitlab.x.lan/yunshan/droplet-libs/zerodoc"
)

const (
	zero  = "zero"
	one   = "one"
	both  = "both"
	empty = "empty"

	internet = inputtype.EPC_FROM_INTERNET
)

type scenario struct {
	inPort uint32

	l3EpcID0   int32
	l3EpcID1   int32
	isL2L3End0 bool
	isL2L3End1 bool

	edgeEndPoints     string
	nodePortEndPoints string
	nodeEndPoints     string
}

var scenarios = []scenario{
	// 接入网络（假定：流量只有一份）
	// 南北向-服务端在云外
	scenario{0x10001, 1, internet, true, true, zero, one, both},
	scenario{0x10001, 1, internet, true, false, zero, one, both},
	scenario{0x10001, 1, internet, false, true, zero, one, both},
	scenario{0x10001, 1, internet, false, false, zero, one, both},
	// 南北向-客户端在云外
	scenario{0x10001, internet, 1, true, true, zero, one, both},
	scenario{0x10001, internet, 1, true, false, zero, one, both},
	scenario{0x10001, internet, 1, false, true, zero, one, both},
	scenario{0x10001, internet, 1, false, false, zero, one, both},
	// 等同于南北向-都在云外
	scenario{0x10001, internet, internet, true, true, zero, one, both},
	scenario{0x10001, internet, internet, true, false, zero, one, both},
	scenario{0x10001, internet, internet, false, true, zero, one, both},
	scenario{0x10001, internet, internet, false, false, zero, one, both},
	// 等同于南北向-都在云内
	scenario{0x10001, 1, 1, true, true, zero, one, both},
	scenario{0x10001, 1, 1, true, false, zero, one, both},
	scenario{0x10001, 1, 1, false, true, zero, one, both},
	scenario{0x10001, 1, 1, false, false, zero, one, both},

	// 虚拟网络
	// 南北向-服务端在云外
	scenario{0x30000, 1, internet, true, true, zero, one, both}, // 假定：流量只有一份
	scenario{0x30000, 1, internet, true, false, zero, one, both},
	scenario{0x30000, 1, internet, false, true, zero, one, both},
	scenario{0x30000, 1, internet, false, false, empty, empty, empty},
	// 南北向-客户端在云外
	scenario{0x30000, internet, 1, true, true, zero, one, both}, // 假定：流量只有一份
	scenario{0x30000, internet, 1, true, false, zero, one, both},
	scenario{0x30000, internet, 1, false, true, zero, one, both},
	scenario{0x30000, internet, 1, false, false, empty, empty, empty},
	// 等同于南北向-都在云外
	scenario{0x30000, internet, internet, true, true, zero, one, both}, // 假定：流量只有一份
	scenario{0x30000, internet, internet, true, false, zero, one, both},
	scenario{0x30000, internet, internet, false, true, zero, one, both},
	scenario{0x30000, internet, internet, false, false, empty, empty, empty},
	// 东西向-都在云内
	scenario{0x30000, 1, 1, true, true, zero, one, both}, // 假定：流量只有一份
	scenario{0x30000, 1, 1, true, false, empty, empty, zero},
	scenario{0x30000, 1, 1, false, true, zero, one, one},
	scenario{0x30000, 1, 1, false, false, empty, empty, empty},
}

func (s *scenario) String() string {
	return fmt.Sprintf("inPort=%x l3EpcID=[%d,%d], l2L3End=[%v,%v]", s.inPort, s.l3EpcID0, s.l3EpcID1, s.isL2L3End0, s.isL2L3End1)
}

func checkEndPoints(endPoints []EndPoint, expect string) bool {
	if expect == both {
		return len(endPoints) == 2 && endPoints[0] == ZERO && endPoints[1] == ONE
	} else if expect == one {
		return len(endPoints) == 1 && endPoints[0] == ONE
	} else if expect == zero {
		return len(endPoints) == 1 && endPoints[0] == ZERO
	} else if expect == empty {
		return len(endPoints) == 0
	}
	return false
}

func TestEndPoint(t *testing.T) {
	for _, s := range scenarios {
		edgeCode := outputtype.Code(outputtype.IndexToCode(0x0) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.IPPath | outputtype.ServerPort | outputtype.TAPType)
		endPoints := EndPointFilter(s.inPort, s.l3EpcID0, s.l3EpcID1, []bool{s.isL2L3End0, s.isL2L3End1}, inputtype.FORWARD, edgeCode)
		if !checkEndPoints(endPoints, s.edgeEndPoints) {
			t.Errorf("Edge 场景判断错误 %s: result=%v, expect=%s", s.String(), endPoints, s.edgeEndPoints)
		}

		nodePortCode := outputtype.Code(outputtype.IndexToCode(0x1) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.IP | outputtype.ServerPort | outputtype.TAPType)
		endPoints = EndPointFilter(s.inPort, s.l3EpcID0, s.l3EpcID1, []bool{s.isL2L3End0, s.isL2L3End1}, inputtype.FORWARD, nodePortCode)
		if !checkEndPoints(endPoints, s.nodePortEndPoints) {
			t.Errorf("Port 场景判断错误 %s: result=%v, expect=%s", s.String(), endPoints, s.nodePortEndPoints)
		}

		nodeCode := outputtype.Code(outputtype.IndexToCode(0x2) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.IP | outputtype.TAPType)
		endPoints = EndPointFilter(s.inPort, s.l3EpcID0, s.l3EpcID1, []bool{s.isL2L3End0, s.isL2L3End1}, inputtype.FORWARD, nodeCode)
		if !checkEndPoints(endPoints, s.nodeEndPoints) {
			t.Errorf("Node 场景判断错误 %s: result=%v, expect=%s", s.String(), endPoints, s.nodeEndPoints)
		}
	}
}

func EndPointFilter(inPort uint32, l3EpcID0, l3EpcID1 int32, isL2L3Ends []bool, aclDirection inputtype.DirectionType, tagCode outputtype.Code) []EndPoint {

	endPoints := []EndPoint{ZERO, ONE}
	results := make([]EndPoint, 0, 2)
	for _, thisEnd := range [...]EndPoint{ZERO, ONE} {
		otherEnd := GetOppositeEndpoint(thisEnd)
		if IsDupTraffic(inPort, isL2L3Ends[thisEnd], isL2L3Ends[otherEnd], IsNorthSourceTraffic(l3EpcID0, l3EpcID1), tagCode) {
			continue
		}

		if IsWrongEndPointWithACL(endPoints[thisEnd], aclDirection, tagCode) {
			continue
		}

		results = append(results, endPoints[thisEnd])
	}

	return results
}
