package flowgenerator

import (
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

var innerFlowGeo FlowGeo

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
	actionFlags := taggedFlow.PolicyData.ActionFlags
	if actionFlags&ACTION_GEO_POSITIONING == 0 {
		return
	}
	ips := [2]uint32{taggedFlow.IPSrc, taggedFlow.IPDst}
	l3EpcIDs := [2]int32{taggedFlow.FlowMetricsPeerSrc.L3EpcID, taggedFlow.FlowMetricsPeerDst.L3EpcID}
	// we want to query Src IP as possible so the first check is `ONE` (dst) but not `ZERO` (src)
	for _, thisEnd := range [...]EndPoint{ONE, ZERO} {
		if l3EpcIDs[thisEnd] == 0 {
			continue
		}
		queryEnd := getOppositeEndpoint(thisEnd)
		if l3EpcIDs[thisEnd] == -1 && l3EpcIDs[queryEnd] > 0 {
			queryEnd = thisEnd
		}
		geoInfo := f.GeoTree.Query(ips[queryEnd])
		if geoInfo == nil {
			continue
		}
		taggedFlow.Country = geoInfo.Country
		taggedFlow.Region = geoInfo.Region
		taggedFlow.ISP = geoInfo.ISP
		return
	}
}

func init() {
	innerFlowGeo = FlowGeo{geo.NewNetmaskGeoTree()}
}
