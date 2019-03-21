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
func newIpSegment(ips string, epcId uint16) ipSegment {
	segment := ipSegment{}
	maskCount := uint32(0)
	segment.ip, maskCount, _ = IpNetmaskFromStringCIDR(ips)
	segment.mask = 0xffffffff << (32 - maskCount)
	segment.epcId = epcId
	return segment
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
