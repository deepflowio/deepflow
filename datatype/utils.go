package datatype

import (
	"net"
	"strconv"
	"strings"

	"gitlab.x.lan/yunshan/droplet-libs/utils"
)

var MAX_NETMASK = utils.MaskLenToNetmask(MAX_MASK_LEN)

func IpRangeConvert2CIDR(startIp, endIp net.IP) []net.IPNet {
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

func SplitGroup2Int(src string) []uint32 {
	splitSrcGroups := strings.Split(src, ",")
	groups := make([]uint32, 0, 8)
	for _, group := range splitSrcGroups {
		groupInt, err := strconv.Atoi(group)
		if err == nil {
			groups = append(groups, uint32(groupInt&0xffff))
		}
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
	splitSrcPorts := strings.Split(src, ",")
	for _, srcPorts := range splitSrcPorts {
		ports = append(ports, getPorts(srcPorts)...)
	}
	return ports
}
