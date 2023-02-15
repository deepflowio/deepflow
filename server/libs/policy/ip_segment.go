/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package policy

import (
	"encoding/binary"
	"net"

	. "github.com/deepflowio/deepflow/server/libs/utils"
)

type ipSegment struct {
	// ip4
	ip, mask uint32
	// ip6
	ip0, ip1     uint64
	mask0, mask1 uint64

	epcId uint16
	ipv6  bool
}

var (
	emptyIpSegment  ipSegment = ipSegment{}
	emptyIp6Segment ipSegment = ipSegment{ipv6: true}
)

// 192.168.10.100/24 -> 192.168.10.0/0xffffff00
func newIpSegment(ips string, epcId uint16) (ipSegment, bool) {
	segment := ipSegment{}
	ip, maskCount, _ := IpNetmaskFromStringCIDR(ips)
	segment.epcId = epcId
	if len(ip) == 16 {
		segment.ipv6 = true
		segment.ip0 = binary.BigEndian.Uint64(ip)
		segment.ip1 = binary.BigEndian.Uint64(ip[8:])
		mask := net.CIDRMask(int(maskCount), 128)
		segment.mask0 = binary.BigEndian.Uint64(mask)
		segment.mask1 = binary.BigEndian.Uint64(mask[8:])
		segment.ip0 = segment.ip0 & segment.mask0
		segment.ip1 = segment.ip1 & segment.mask1
		return segment, true
	} else if len(ip) == 4 {
		segment.ip = IpToUint32(ip)
		segment.mask = 0xffffffff << (32 - maskCount)
		segment.ip = segment.ip & segment.mask
		return segment, true
	} else {
		return segment, false
	}
}

func (s *ipSegment) isIpv6() bool {
	return s.ipv6
}

func (s *ipSegment) getEpcId() uint16 {
	return s.epcId
}

func (s *ipSegment) getIp() uint32 {
	return s.ip
}

func (s *ipSegment) getIp6() (uint64, uint64) {
	return s.ip0, s.ip1
}

func (s *ipSegment) getMask() uint32 {
	return s.mask
}

func (s *ipSegment) getMask6() (uint64, uint64) {
	return s.mask0, s.mask1
}
