package policy

import (
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

type ipSegment struct {
	ip, mask uint32
	epcId    uint16
}

var (
	emptyIpSegment ipSegment = ipSegment{}
)

// 192.168.10.100/24 -> 192.168.10.0/0xffffff00
func newIpSegment(ips string, epcId uint16) (ipSegment, bool) {
	segment := ipSegment{}
	ip, maskCount, _ := IpNetmaskFromStringCIDR(ips)
	if len(ip) == 16 {
		return segment, false
	}
	segment.ip = IpToUint32(ip)
	segment.mask = 0xffffffff << (32 - maskCount)
	segment.ip = segment.ip & segment.mask
	segment.epcId = epcId
	return segment, true
}

func (s *ipSegment) getEpcId() uint16 {
	return s.epcId
}

func (s *ipSegment) getIp() uint32 {
	return s.ip
}

func (s *ipSegment) getMask() uint32 {
	return s.mask
}
