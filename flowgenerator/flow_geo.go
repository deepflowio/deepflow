package flowgenerator

import (
	"github.com/google/gopacket/layers"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/geo"
)

type FlowGeo struct {
	geo.GeoTree
}

type EndPoint uint8

const (
	ZERO EndPoint = iota
	ONE
)

var (
	innerFlowGeo FlowGeo // 在base.go中初始化，避免droplet-ctl等cmd做初始化
)

func newFlowGeo() FlowGeo {
	return FlowGeo{geo.NewNetmaskGeoTree()}
}

func getOppositeEndpoint(val EndPoint) EndPoint {
	if val == ZERO {
		return ONE
	} else {
		return ZERO
	}
}

func (f *FlowGeo) fillGeoInfo(taggedFlow *TaggedFlow) {
	taggedFlow.GeoEnd = uint8(0xFF)
	actionFlags := taggedFlow.PolicyData.ActionFlags
	// 目前IPv6准确的位置信息无法获取，直接忽略
	if actionFlags&ACTION_GEO_POSITIONING == 0 || taggedFlow.EthType == layers.EthernetTypeIPv6 {
		return
	}
	ips := [2]uint32{taggedFlow.IPSrc, taggedFlow.IPDst}
	l3EpcIDs := [2]int32{taggedFlow.FlowMetricsPeerSrc.L3EpcID, taggedFlow.FlowMetricsPeerDst.L3EpcID}
	// we want to query Src IP as possible so the first check is `ONE` (dst) but not `ZERO` (src)
	for _, thisEnd := range [...]EndPoint{ONE, ZERO} {
		if l3EpcIDs[thisEnd] == EPC_FROM_INTERNET {
			continue
		}
		queryEnd := getOppositeEndpoint(thisEnd)
		if l3EpcIDs[thisEnd] == EPC_FROM_DEEPFLOW && l3EpcIDs[queryEnd] > 0 {
			queryEnd = thisEnd
		}
		geoInfo := f.GeoTree.Query(ips[queryEnd])
		if geoInfo == nil {
			continue
		}
		taggedFlow.GeoEnd = uint8(queryEnd)
		taggedFlow.Country = geoInfo.Country
		taggedFlow.Region = geoInfo.Region
		taggedFlow.ISP = geoInfo.ISP
		return
	}
}
