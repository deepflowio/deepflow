/**
 * Copyright (c) 2023 Yunshan Networks
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

package common

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/mikioh/ipaddr"
	"inet.af/netaddr"

	"github.com/deepflowio/deepflow/server/controller/common"
)

func GenerateIPMask(ip string) int {
	netO, err := netaddr.ParseIPPrefix(ip)
	if err == nil {
		maskLen, _ := netO.IPNet().Mask.Size()
		return maskLen
	}
	if strings.Contains(ip, ":") {
		return common.IPV6_MAX_MASK
	}
	return common.IPV4_MAX_MASK
}

func IPAndMaskToCIDR(ip string, mask int) (string, error) {
	ipO, err := netaddr.ParseIP(ip)
	if err != nil {
		return "", errors.New("ip and mask to cidr ip format error:" + err.Error())
	}
	IPString := ipO.String() + "/" + strconv.Itoa(mask)
	netO, err := netaddr.ParseIPPrefix(IPString)
	if err != nil {
		return "", errors.New("ip and mask to cidr format error" + err.Error())
	}
	netRange, ok := netO.Range().Prefix()
	if !ok {
		return "", errors.New("ip and mask to cidr format not valid")
	}
	return netRange.String(), nil
}

func TidyIPString(ipsString []string) (v4Prefix, v6Prefix []netaddr.IPPrefix, err error) {
	for _, ipS := range ipsString {
		_, ignoreErr := netaddr.ParseIPPrefix(ipS)
		if ignoreErr != nil {
			switch {
			case strings.Contains(ipS, "."):
				ipS = ipS + "/32"
			case strings.Contains(ipS, ":"):
				ipS = ipS + "/128"
			}
		}
		ipPrefix, prefixErr := netaddr.ParseIPPrefix(ipS)
		if prefixErr != nil {
			err = prefixErr
			return
		}
		switch {
		case ipPrefix.IP().Is4():
			v4Prefix = append(v4Prefix, ipPrefix)
		case ipPrefix.IP().Is6():
			v6Prefix = append(v6Prefix, ipPrefix)
		}
	}
	return
}

func AggregateCIDR(ips []netaddr.IPPrefix, maxMask int) (cirdsString []string) {
	CIDRs := []*ipaddr.Prefix{}
	for _, Prefix := range ips {
		aggFlag := false
		ipNet := ipaddr.NewPrefix(Prefix.IPNet())
		for i, CIDR := range CIDRs {
			pSlice := []ipaddr.Prefix{*ipNet, *CIDR}
			aggCIDR := ipaddr.Supernet(pSlice)
			if aggCIDR == nil {
				continue
			}
			aggCIDRMask, _ := aggCIDR.IPNet.Mask.Size()
			if aggCIDRMask >= maxMask {
				CIDRs[i] = aggCIDR
				aggFlag = true
				break
			} else {
				continue
			}
		}
		if !aggFlag {
			CIDRs = append(CIDRs, ipNet)
		}
	}
	for _, i := range CIDRs {
		cirdsString = append(cirdsString, i.String())
	}
	return
}

func GenerateCIDR(ips []netaddr.IPPrefix, maxMask int) (cirds []netaddr.IPPrefix) {
	CIDRs := []*ipaddr.Prefix{}
	for _, Prefix := range ips {
		aggFlag := false
		ipNet := ipaddr.NewPrefix(Prefix.IPNet())
		for i, CIDR := range CIDRs {
			if CIDR.Contains(ipNet) {
				aggFlag = true
				break
			}
			pSlice := []ipaddr.Prefix{*ipNet, *CIDR}
			aggCIDR := ipaddr.Supernet(pSlice)
			if aggCIDR == nil {
				continue
			}
			aggCIDRMask, _ := aggCIDR.IPNet.Mask.Size()
			if aggCIDRMask >= maxMask {
				CIDRs[i] = aggCIDR
				aggFlag = true
				break
			} else {
				continue
			}
		}
		if !aggFlag {
			CIDRs = append(CIDRs, ipNet)
		}
	}
	for _, i := range CIDRs {
		cirds = append(cirds, netaddr.MustParseIPPrefix(i.String()))
	}
	return
}

func IsIPInCIDR(ip, cidr string) bool {
	if strings.Contains(cidr, "/") {
		_, nCIDR, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Errorf("parse cidr failed: %v", err)
			return false
		}
		return nCIDR.Contains(net.ParseIP(ip))
	} else {
		if ip == cidr {
			return true
		}
		return false
	}
}

func ContainsIP(cidrs []string, ip string) bool {
	if len(cidrs) == 0 {
		return false
	}
	for _, cidr := range cidrs {
		if IsIPInCIDR(ip, cidr) {
			return true
		}
	}
	return false
}
