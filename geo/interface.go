package geo

type GeoInfo struct {
	IPStart uint32
	IPEnd   uint32
	Country uint8
	Region  uint8
	ISP     uint8
}

type GeoTree interface {
	Query(ip uint32) (uint8, uint8)
}
