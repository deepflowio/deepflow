package geo

import (
	"gitlab.yunshan.net/yunshan/droplet-libs/geo"
)

var geoTree geo.GeoTree

func NewGeoTree() {
	geoTree = geo.NewNetmaskGeoTree()
}

func QueryProvince(ip uint32) string {
	region, _ := geoTree.Query(ip)
	return geo.DecodeRegion(region)
}
