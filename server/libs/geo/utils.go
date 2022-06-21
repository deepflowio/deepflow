package geo

import (
	tree "gitlab.yunshan.net/yunshan/droplet-libs/segmenttree"
)

func DecodeCountry(country uint8) string {
	return decode(COUNTRY_NAMES[:], country)
}

func DecodeRegion(region uint8) string {
	return decode(REGION_NAMES[:], region)
}

func DecodeISP(isp uint8) string {
	return decode(ISP_NAMES[:], isp)
}

func decode(list []string, key uint8) string {
	if int(key) >= len(list) {
		return "未知"
	}
	return list[key]
}

func EncodeCountry(country string) uint8 {
	if v, ok := COUNTRY_NAMES_MAP[country]; ok {
		return v
	}
	return 0
}

func EncodeRegion(region string) uint8 {
	if v, ok := REGION_NAMES_MAP[region]; ok {
		return v
	}
	return 0
}

func EncodeISP(isp string) uint8 {
	if v, ok := ISP_NAMES_MAP[isp]; ok {
		return v
	}
	return 0
}

type IPRange struct {
	lower uint32
	upper uint32
}

func newIPPoint(ip uint32) *IPRange {
	return &IPRange{ip, ip}
}

func newIPRange(lower, upper uint32) *IPRange {
	return &IPRange{lower, upper}
}

func (r *IPRange) Lower() (endpoint tree.Endpoint, closed bool) {
	return int64(r.lower), true
}

func (r *IPRange) Upper() (endpoint tree.Endpoint, closed bool) {
	return int64(r.upper), true
}
