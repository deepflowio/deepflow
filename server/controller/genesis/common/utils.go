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

package common

import (
	. "encoding/binary"
	"github.com/mikioh/ipaddr"
	"inet.af/netaddr"
	"net"
	"regexp"
	"strconv"
	"strings"
)

type VifInfo struct {
	MaskLen int
	Address string
	Scope   string
}

type Iface struct {
	Index     int
	PeerIndex int
	MAC       string
	Name      string
	Peer      string
	IPs       []VifInfo
}

var IfaceRegex = regexp.MustCompile(`^(\d+):\s+([\w\.-]+)(@.*)?:`)
var MACRegex = regexp.MustCompile(`^\s+link/\S+\s+(([\dA-Za-z]{2}:){5}[\dA-Za-z]{2}) brd.*$`)
var IPRegex = regexp.MustCompile(`^\s+inet6?\s+([\d\.A-Za-z:]+)/(\d+)\s+.*scope\s+(global|link|host)`)

func ParseIPOutput(s string) ([]Iface, error) {
	ifaces := []Iface{}
	if s == "" {
		return ifaces, nil
	}
	iface := Iface{Index: -1}
	lines := strings.Split(s, "\n")
	if len(lines) == 1 && lines[0] == "" {
		return ifaces, nil
	}
	for _, line := range lines {
		ifaceMatched := IfaceRegex.FindStringSubmatch(line)
		if ifaceMatched != nil {
			if iface.Index != -1 {
				ifaces = append(ifaces, iface)
				iface = Iface{}
			}
			index, err := strconv.Atoi(ifaceMatched[1])
			if err != nil {
				return []Iface{}, err
			}
			iface.Index = index
			iface.Name = ifaceMatched[2]
			if ifaceMatched[3] != "" {
				iface.Peer = ifaceMatched[3][1:]
			}
			if iface.Peer != "" && strings.HasPrefix(iface.Peer, "if") {
				peerIndex, err := strconv.Atoi(iface.Peer[2:])
				if err != nil {
					return []Iface{}, err
				}
				iface.PeerIndex = peerIndex
			}
			continue
		}

		macMatched := MACRegex.FindStringSubmatch(line)
		if macMatched != nil {
			iface.MAC = macMatched[1]
			continue
		} else if strings.HasPrefix(iface.Name, "tunl0") {
			iface.MAC = "00:00:00:00:00:00"
			continue
		}
		ipMatched := IPRegex.FindStringSubmatch(line)
		if ipMatched != nil {
			maskLen, err := strconv.Atoi(ipMatched[2])
			if err != nil {
				return []Iface{}, err
			}
			iface.IPs = append(iface.IPs, VifInfo{
				Address: ipMatched[1],
				Scope:   ipMatched[3],
				MaskLen: maskLen,
			})
		}
	}
	ifaces = append(ifaces, iface)
	return ifaces, nil
}

func Uint64ToMac(v uint64) net.HardwareAddr {
	bytes := [8]byte{}
	BigEndian.PutUint64(bytes[:], v)
	return net.HardwareAddr(bytes[2:])
}

func AggregateCIDR(ips []netaddr.IPPrefix, maxMask int) (cirds []netaddr.IPPrefix) {
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
		cirds = append(cirds, netaddr.MustParseIPPrefix(i.String()))
	}
	return
}
