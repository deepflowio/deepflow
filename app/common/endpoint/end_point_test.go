package endpoint

import (
	"testing"

	inputtype "gitlab.x.lan/yunshan/droplet-libs/datatype"
	outputtype "gitlab.x.lan/yunshan/droplet-libs/zerodoc"
)

func TestEndPoint(t *testing.T) {

	l3EpcIDs := []int32{-1, 1}
	isL2Ends := []bool{true, true}
	isL3Ends := []bool{true, true}

	policyEdgeCode := outputtype.Code(outputtype.IndexToCode(0x17) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.L3EpcIDPath | outputtype.IPPath | outputtype.TAPType)
	endPoints := EndPointFilter(65536, l3EpcIDs, isL2Ends, isL3Ends, inputtype.FORWARD, policyEdgeCode)
	if len(endPoints) != 1 || endPoints[0] != ZERO {
		t.Error("双侧Tag，永远只统计ZERO侧的数据")
	}

	policyNodeCode := outputtype.Code(outputtype.IndexToCode(0x11) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.IP | outputtype.Protocol | outputtype.TAPType)
	endPoints = EndPointFilter(65536, l3EpcIDs, isL2Ends, isL3Ends, inputtype.FORWARD, policyNodeCode)
	if len(endPoints) != 2 {
		t.Error("有acl的，tx/rx站在acl的角度")
	}

	policyServerPortCode := outputtype.Code(outputtype.IndexToCode(0x11) | outputtype.ACLGID | outputtype.ACLDirection | outputtype.IP | outputtype.Protocol | outputtype.ServerPort | outputtype.TAPType)
	endPoints = EndPointFilter(65536, l3EpcIDs, isL2Ends, isL3Ends, inputtype.FORWARD, policyServerPortCode)
	if len(endPoints) != 1 || endPoints[0] != ONE {
		t.Error("带有server_port的，只统计服务侧的")
	}
}

func EndPointFilter(inPort uint32, l3EpcIDs []int32, isL2Ends []bool, isL3Ends []bool, aclDirection inputtype.DirectionType, tagCode outputtype.Code) []EndPoint {

	endPoints := []EndPoint{ZERO, ONE}
	results := make([]EndPoint, 0, 2)
	for _, thisEnd := range [...]EndPoint{ZERO, ONE} {
		if IsDupTraffic(inPort, isL2Ends[thisEnd], isL3Ends[thisEnd], tagCode) {
			continue
		}

		if IsWrongEndPointWithACL(endPoints[thisEnd], aclDirection, tagCode) {
			continue
		}

		results = append(results, endPoints[thisEnd])
	}

	return results
}
