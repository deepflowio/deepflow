/*
 * Copyright (c) 2024 Yunshan Networks
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

package datatype

import (
	"encoding/binary"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/deepflowio/deepflow/server/libs/utils"
)

var (
	MAX_NETMASK = utils.MaskLenToNetmask(MAX_MASK_LEN)
	_ip6Max     = net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
)

func ipv4RangeConvert(startIp, endIp net.IP) []net.IPNet {
	start := utils.IpToUint32(startIp)
	end := utils.IpToUint32(endIp)
	var ips []net.IPNet
	for start <= end {
		maskLen := getFirstMask(start, end)
		ip := utils.IpFromUint32(start)
		ipMask := net.CIDRMask(int(maskLen), MAX_MASK_LEN)
		ips = append(ips, net.IPNet{IP: ip, Mask: ipMask})
		lastIp := getLastIp(start, maskLen)
		if lastIp == MAX_NETMASK {
			break
		}
		start += 1 << uint32(MAX_MASK_LEN-maskLen)
	}
	return ips
}

type ip6Field struct {
	ip [2]uint64
}

func newIp6Field(ip net.IP) *ip6Field {
	field := &ip6Field{}
	field.ip[0] = binary.BigEndian.Uint64(ip)
	field.ip[1] = binary.BigEndian.Uint64(ip[8:])
	return field
}

func (f *ip6Field) lessOrEqual(m *ip6Field) bool {
	if f.ip[0] > m.ip[0] {
		return false
	} else if f.ip[0] < m.ip[0] {
		return true
	}
	if f.ip[1] > m.ip[1] {
		return false
	}
	return true
}

func (f *ip6Field) add(n uint64) bool {
	if n == 0 {
		return false
	}
	if diff := math.MaxUint64 - f.ip[1]; diff < n {
		if f.ip[0] == math.MaxUint64 {
			f.ip[1] = math.MaxUint64
			return true
		} else {
			f.ip[0] += 1
			f.ip[1] = n - diff - 1
		}
	} else {
		f.ip[1] += n
	}
	return false
}

func (f *ip6Field) sub(n uint64) {
	if n == 0 {
		return
	}
	if n > f.ip[1] {
		f.ip[0] -= 1
		f.ip[1] = math.MaxUint64 - n + f.ip[1] + 1
	} else {
		f.ip[1] -= n
	}
}

func (f *ip6Field) addbyBitOffsetAndSub(offset uint64, count uint64) {
	overflow := false
	if offset < 64 {
		overflow = f.add(1 << offset)
	} else if offset < 128 {
		offset -= 64
		f.ip[0] += 1 << offset
	} else {
		f.ip[1] = math.MaxUint64
		f.ip[0] = math.MaxUint64
	}
	if !overflow {
		f.sub(count)
	}
}

func (f *ip6Field) getMask() uint64 {
	i := 128
	for i = 128; i > 64; i-- {
		position := 128 - i
		if f.ip[1]&(1<<uint64(position)) != 0 {
			return uint64(i)
		}
	}
	for i = 64; i > 0; i-- {
		position := 64 - i
		if f.ip[0]&(1<<uint64(position)) != 0 {
			return uint64(i)
		}
	}
	return uint64(0)
}

func (f *ip6Field) makeIp() net.IP {
	ip := make(net.IP, 16)
	binary.BigEndian.PutUint64(ip, f.ip[0])
	binary.BigEndian.PutUint64(ip[8:], f.ip[1])
	return ip
}

func ipv6RangeConvert(startIp, endIp net.IP) []net.IPNet {
	start := newIp6Field(startIp)
	end := newIp6Field(endIp)
	ips := make([]net.IPNet, 0, 4)
	for start.lessOrEqual(end) && !start.makeIp().Equal(_ip6Max) {
		mask := start.getMask()
		for ; mask < 128; mask++ {
			tmp := *start
			tmp.addbyBitOffsetAndSub(128-mask, 1)
			if tmp.lessOrEqual(end) {
				break
			}
		}
		ipMask := net.CIDRMask(int(mask), 128)
		ip := start.makeIp()
		ips = append(ips, net.IPNet{IP: ip, Mask: ipMask})
		start.addbyBitOffsetAndSub(128-mask, 0)
	}
	return ips
}

func IpRangeConvert2CIDR(startIp, endIp net.IP) []net.IPNet {
	if len(startIp) == net.IPv4len && len(endIp) == net.IPv4len {
		return ipv4RangeConvert(startIp, endIp)
	} else if len(startIp) == net.IPv6len && len(endIp) == net.IPv6len {
		return ipv6RangeConvert(startIp, endIp)
	} else {
		log.Warningf("ip version are different in %s-%s\n", startIp, endIp)
		return nil
	}
}

func getFirstMask(start, end uint32) uint8 {
	maxLen := MAX_MASK_LEN
	for ; maxLen > MIN_MASK_LEN; maxLen-- {
		if start&(1<<uint32(MAX_MASK_LEN-maxLen)) != 0 {
			// maxLen继续减少将会使得start不是所在网段的第一个IP
			break
		}
		if start+^utils.MaskLenToNetmask(uint32(maxLen)) >= end || start+^utils.MaskLenToNetmask(uint32(maxLen-1)) > end {
			// maxLen继续减少将会使得网段包含end之后的IP
			break
		}
	}
	return uint8(maxLen)
}

func getLastIp(ip uint32, mask uint8) uint32 {
	ip += ^utils.MaskLenToNetmask(uint32(mask))
	return ip
}

func SplitGroup2Int(src []int32) []uint32 {
	groups := make([]uint32, 0, 8)
	for _, group := range src {
		groups = append(groups, uint32(group&0xffff))
	}

	return groups
}

func getPorts(src string) []PortRange {
	splitSrcPorts := strings.Split(src, "-")
	ports := make([]PortRange, 0, 8)
	if len(splitSrcPorts) < 2 {
		portInt, err := strconv.Atoi(src)
		if err == nil {
			ports = append(ports, NewPortRange(uint16(portInt), uint16(portInt)))
		}
		return ports
	}

	min, err := strconv.Atoi(splitSrcPorts[0])
	if err != nil {
		return ports
	}

	max, err := strconv.Atoi(splitSrcPorts[1])
	if err != nil {
		return ports
	}

	ports = append(ports, NewPortRange(uint16(min), uint16(max)))
	return ports
}

func SplitPort2Int(src string) []PortRange {
	ports := make([]PortRange, 0, 8)
	if len(src) == 0 {
		ports := append(ports, NewPortRange(0, 65535))
		return ports
	}

	splitSrcPorts := strings.Split(src, ",")
	for _, srcPorts := range splitSrcPorts {
		ports = append(ports, getPorts(srcPorts)...)
	}

	// 从小到大排序
	sort.Slice(ports, func(i, j int) bool { return ports[i].Min() < ports[j].Min() })
	deleteFlags := make([]bool, len(ports))
	for i := 0; i < len(ports); i++ {
		if i == len(ports)-1 {
			continue
		}
		// 合并连续的端口号
		if ports[i].Max()+1 >= ports[i+1].Min() {
			max := ports[i+1].Max()
			if ports[i].Max() > max {
				max = ports[i].Max()
			}
			ports[i+1] = NewPortRange(ports[i].Min(), max)
			deleteFlags[i] = true
		}
	}
	newPorts := make([]PortRange, 0, len(ports))
	// 删除无效数据
	for i := 0; i < len(ports); i++ {
		if deleteFlags[i] {
			continue
		}
		newPorts = append(newPorts, ports[i])
	}
	return newPorts
}
