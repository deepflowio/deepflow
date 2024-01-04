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

package policy

import (
	"net"
	"reflect"
	"testing"

	. "github.com/google/gopacket/layers"

	. "github.com/deepflowio/deepflow/server/libs/datatype"
	. "github.com/deepflowio/deepflow/server/libs/utils"
)

var (
	forward       = toNpbAction(10, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_SRC, 0)
	backward      = toNpbAction(10, 0, NPB_TUNNEL_TYPE_PCAP, TAPSIDE_DST, 0)
	ttl           = uint8(64)
	ip1           = NewIPFromString("192.168.2.12").Int()
	ip2           = NewIPFromString("192.168.2.0").Int()
	ip3           = NewIPFromString("192.168.0.11").Int()
	ip4           = NewIPFromString("192.168.0.12").Int()
	ip5           = NewIPFromString("1.1.1.1").Int()
	ip6           = NewIPFromString("10.25.1.10").Int()
	ip7           = NewIPFromString("192.168.10.10").Int()
	ip8           = NewIPFromString("10.25.2.2").Int()
	ip9           = NewIPFromString("172.16.10.10").Int()
	ip10          = NewIPFromString("172.16.10.20").Int()
	ip11          = NewIPFromString("255.255.255.255").Int()
	ip12          = net.ParseIP("1234::abcd")
	ip13          = net.ParseIP("abcd::1234")
	ip14          = net.ParseIP("abcd::abcd")
	ipNet1        = "192.168.0.12/24"
	ipNet10       = "10.90.0.0/16"
	ipNet11       = "10.90.9.0/24"
	ipNet12       = "10.0.0.0/8"
	ipNet13       = "10.90.0.0/16"
	ipNet14       = "10.90.9.123/32"
	ipNet15       = "0.0.0.0/0"
	ip6Net1       = "1234::abcd/128"
	ip6Net2       = "abcd::1234/128"
	groupEpcOther = int32(EPC_FROM_DEEPFLOW)
	groupEpcAny   = int32(0)
	groupAny      = uint32(0)
	subnetAny     = uint32(0)
	protoAny      = 256
	portAny       = -1
	vlanAny       = uint32(0)
	vlan1         = uint32(10)
	macAny        = uint64(0)
	mac1          = NewMACAddrFromString("08:00:27:a4:2b:f0").Int()
	mac2          = NewMACAddrFromString("08:00:27:a4:2b:fa").Int()
	mac3          = NewMACAddrFromString("08:00:27:a4:2b:fb").Int()
	mac4          = NewMACAddrFromString("08:00:27:a4:2b:fc").Int()
	mac5          = NewMACAddrFromString("08:00:27:a4:2b:fd").Int()
	l2EndBool     = []bool{false, true}
	l3EndBool     = []bool{false, true}
	srcIp         = []string{
		"10.133.152.1/32",
		"10.133.152.10/32",
		"10.133.152.2/32",
		"10.133.152.3/32",
		"10.133.152.4/32",
		"10.133.152.5/32",
		"10.133.152.6/32",
		"10.133.152.7/32",
		"10.133.152.8/32",
		"10.133.152.9/32",
		"10.133.153.155/32",
		"10.133.153.156/32",
		"10.133.153.157/32",
		"10.133.153.158/32",
		"10.133.153.171/32",
		"10.133.153.172/32",
		"10.133.153.173/32",
		"10.133.153.174/32",
		"10.133.212.190/32",
		"10.133.212.191/32",
		"10.133.212.238/32",
		"10.133.214.123/32",
		"10.133.214.124/32",
		"10.133.214.125/32",
		"10.133.214.126/32",
		"10.133.216.16/32",
		"10.133.216.17/32",
		"10.133.216.18/32",
		"10.133.235.12/32",
		"10.133.235.13/32",
		"10.133.235.14/32",
		"10.133.235.15/32",
		"10.133.235.55/32",
		"10.133.235.56/32",
		"10.133.235.57/32",
		"10.133.235.58/32",
		"10.133.60.125/32",
		"10.133.60.126/32",
		"10.133.60.127/32",
		"10.133.60.128/32",
		"10.133.60.129/32",
		"10.133.60.130/32",
		"10.133.60.131/32",
		"10.133.60.132/32",
		"10.133.60.133/32",
		"10.133.60.134/32",
		"10.139.52.53/32",
		"10.139.52.54/32",
		"10.139.52.55/32",
		"10.139.52.58/32",
		"10.139.52.59/32",
		"10.139.52.60/32",
		"10.139.52.61/32",
		"10.139.52.63/32",
		"10.139.52.64/32",
		"10.139.52.65/32",
		"10.139.72.162/32",
		"10.139.72.163/32",
		"10.139.72.164/32",
		"10.139.72.165/32",
		"10.139.72.166/32",
		"10.139.72.167/32",
		"10.139.72.168/32",
		"10.139.72.169/32",
		"10.139.72.20/32",
		"10.139.72.21/32",
		"10.139.72.22/32",
		"10.139.72.23/32",
		"10.139.72.24/32",
		"10.139.72.25/32",
		"10.139.72.26/32",
		"10.139.72.27/32",
		"10.139.72.28/32",
		"10.139.72.29/32",
		"10.139.72.30/32",
		"10.139.72.31/32",
		"10.139.72.32/32",
		"10.139.72.33/32",
		"10.139.72.34/32",
		"10.139.72.35/32",
		"10.139.72.36/32",
		"10.139.72.37/32",
	}
	dstIp = []string{
		"10.133.12.20/32",
		"10.133.210.204/32",
		"10.133.212.41/32",
		"10.133.219.11/32",
		"10.133.230.125/32",
		"10.133.232.79/32",
		"10.133.235.84/32",
		"10.133.240.251/32",
		"10.134.208.6/32",
		"10.135.33.249/32",
		"10.151.9.130/32",
		"10.155.11.46/32",
		"10.157.0.143/32",
		"10.160.15.208/32",
		"10.252.126.25/32",
		"10.8.145.26/32",
		"10.8.145.62/32",
		"10.8.147.2/32",
		"10.8.148.35/32",
		"10.8.149.201/32",
		"10.8.8.8/32",
		"12.1.37.65/32",
		"14.1.33.165/32",
		"16.1.34.60/32",
		"18.1.32.82/32",
		"20.8.32.137/32",
		"22.1.32.201/32",
		"24.1.32.188/32",
		"26.1.33.71/32",
		"28.1.32.110/32",
		"30.4.32.26/32",
		"32.1.31.18/32",
		"32.1.32.231/32",
		"35.1.32.76/32",
		"36.1.32.12/32",
		"38.1.32.150/32",
		"40.7.1.111/32",
		"42.1.32.55/32",
		"44.1.32.120/32",
		"46.1.200.100/32",
		"48.1.32.188/32",
		"50.2.32.97/32",
		"52.1.38.9/32",
		"54.1.33.176/32",
		"56.1.80.181/32",
		"58.1.1.113/32",
		"60.1.31.82/32",
		"62.1.32.66/32",
		"64.1.35.22/32",
		"66.1.32.184/32",
		"68.1.32.66/32",
		"70.1.32.155/32",
		"72.1.1.100/32",
		"74.1.58.100/32",
		"76.1.40.180/32",
		"78.1.32.124/32",
		"80.1.32.146/32",
		"82.1.45.211/32",
		"10.133.210.40/29",
		"10.133.210.48/28",
		"10.133.210.64/26",
		"10.133.210.128/26",
		"10.133.210.192/29",
		"10.133.210.200/32",
		"10.133.126.207/32",
		"10.133.126.208/28",
		"10.133.212.55/32",
		"10.133.212.56/29",
		"10.133.212.64/31",
		"10.133.212.66/32",
		"10.134.248.1/32",
		"10.134.248.2/31",
		"10.134.248.4/30",
		"10.134.248.8/29",
		"10.134.248.16/28",
		"10.134.248.32/27",
		"10.134.248.64/28",
		"10.134.248.80/29",
		"10.134.248.88/31",
		"10.134.248.90/32",
		"10.133.240.44/30",
		"10.133.240.48/28",
		"10.133.240.64/27",
		"10.133.240.96/28",
		"10.133.240.112/32",
		"10.134.128.16/28",
		"10.134.128.32/27",
		"10.134.128.64/26",
		"10.134.128.128/26",
		"10.134.128.192/27",
		"10.134.128.224/28",
		"10.134.128.240/29",
		"10.134.128.248/31",
		"10.134.129.16/28",
		"10.134.129.32/27",
		"10.134.129.64/26",
		"10.134.129.128/26",
		"10.134.129.192/27",
		"10.134.129.224/28",
		"10.134.129.240/29",
		"10.134.129.248/31",
		"10.134.130.16/28",
		"10.134.130.32/27",
		"10.134.130.64/26",
		"10.134.130.128/26",
		"10.134.130.192/27",
		"10.134.130.224/28",
		"10.134.130.240/29",
		"10.134.130.248/31",
		"10.134.131.16/28",
		"10.134.131.32/27",
		"10.134.131.64/26",
		"10.134.131.128/26",
		"10.134.131.192/27",
		"10.134.131.224/28",
		"10.134.131.240/29",
		"10.134.131.248/31",
		"10.134.132.16/28",
		"10.134.132.32/27",
		"10.134.132.64/26",
		"10.134.132.128/27",
		"10.134.132.160/28",
		"10.134.132.176/31",
		"10.134.132.178/32",
		"10.134.133.24/29",
		"10.134.133.32/27",
		"10.134.133.64/27",
		"10.134.133.96/28",
		"10.134.133.112/29",
		"10.134.133.120/32",
		"10.134.134.16/28",
		"10.134.134.32/27",
		"10.134.134.64/26",
		"10.134.134.128/27",
		"10.134.134.160/28",
		"10.134.134.176/32",
		"10.134.135.24/29",
		"10.134.135.32/27",
		"10.134.135.64/27",
		"10.134.135.96/28",
		"10.134.135.112/29",
		"10.134.135.120/32",
		"10.134.136.16/28",
		"10.134.136.32/27",
		"10.134.136.64/27",
		"10.134.136.96/28",
		"10.134.136.112/31",
		"10.134.136.114/32",
		"10.134.137.24/29",
		"10.134.137.32/27",
		"10.134.137.64/27",
		"10.134.137.96/28",
		"10.134.137.112/29",
		"10.134.137.120/32",
		"10.134.138.16/28",
		"10.134.138.32/27",
		"10.134.138.64/27",
		"10.134.138.96/28",
		"10.134.138.112/31",
		"10.134.138.114/32",
		"10.133.240.112/28",
		"10.133.240.128/26",
		"10.133.240.192/27",
		"10.133.240.224/28",
		"10.233.210.40/29",
		"10.233.210.48/28",
		"10.233.210.64/26",
		"10.233.210.128/26",
		"10.233.210.192/29",
		"10.233.210.200/32",
		"10.233.126.207/32",
		"10.233.126.208/28",
		"10.233.212.55/32",
		"10.233.212.56/29",
		"10.233.212.64/31",
		"10.233.212.66/32",
		"10.234.248.1/32",
		"10.234.248.2/31",
		"10.234.248.4/30",
		"10.234.248.8/29",
		"10.234.248.16/28",
		"10.234.248.32/27",
		"10.234.248.64/28",
		"10.234.248.80/29",
		"10.234.248.88/31",
		"10.234.248.90/32",
		"10.233.240.44/30",
		"10.233.240.48/28",
		"10.233.240.64/27",
		"10.233.240.96/28",
		"10.233.240.112/32",
		"10.234.128.16/28",
		"10.234.128.32/27",
		"10.234.128.64/26",
		"10.234.128.128/26",
		"10.234.128.192/27",
		"10.234.128.224/28",
		"10.234.128.240/29",
		"10.234.128.248/31",
		"10.234.129.16/28",
		"10.234.129.32/27",
		"10.234.129.64/26",
		"10.234.129.128/26",
		"10.234.129.192/27",
		"10.234.129.224/28",
		"10.234.129.240/29",
		"10.234.129.248/31",
		"10.234.130.16/28",
		"10.234.130.32/27",
		"10.234.130.64/26",
		"10.234.130.128/26",
		"10.234.130.192/27",
		"10.234.130.224/28",
		"10.234.130.240/29",
		"10.234.130.248/31",
		"10.234.131.16/28",
		"10.234.131.32/27",
		"10.234.131.64/26",
		"10.234.131.128/26",
		"10.234.131.192/27",
		"10.234.131.224/28",
		"10.234.131.240/29",
		"10.234.131.248/31",
		"10.234.132.16/28",
		"10.234.132.32/27",
		"10.234.132.64/26",
		"10.234.132.128/27",
		"10.234.132.160/28",
		"10.234.132.176/31",
		"10.234.132.178/32",
		"10.234.133.24/29",
		"10.234.133.32/27",
		"10.234.133.64/27",
		"10.234.133.96/28",
		"10.234.133.112/29",
		"10.234.133.120/32",
		"10.234.134.16/28",
		"10.234.134.32/27",
		"10.234.134.64/26",
		"10.234.134.128/27",
		"10.234.134.160/28",
		"10.234.134.176/32",
		"10.234.135.24/29",
		"10.234.135.32/27",
		"10.234.135.64/27",
		"10.234.135.96/28",
		"10.234.135.112/29",
		"10.234.135.120/32",
		"10.234.136.16/28",
		"10.234.136.32/27",
		"10.234.136.64/27",
		"10.234.136.96/28",
		"10.234.136.112/31",
		"10.234.136.114/32",
		"10.234.137.24/29",
		"10.234.137.32/27",
		"10.234.137.64/27",
		"10.234.137.96/28",
		"10.234.137.112/29",
		"10.234.137.120/32",
		"10.234.138.16/28",
		"10.234.138.32/27",
		"10.234.138.64/27",
		"10.234.138.96/28",
		"10.234.138.112/31",
		"10.234.138.114/32",
		"10.233.240.112/28",
		"10.233.240.128/26",
		"10.233.240.192/27",
		"10.233.240.224/28",
		"12.233.210.40/29",
		"12.233.210.48/28",
		"12.233.210.64/26",
		"12.233.210.128/26",
		"12.233.210.192/29",
		"12.233.210.200/32",
		"12.233.126.207/32",
		"12.233.126.208/28",
		"12.233.212.55/32",
		"12.233.212.56/29",
		"12.233.212.64/31",
		"12.233.212.66/32",
		"12.234.248.1/32",
		"12.234.248.2/31",
		"12.234.248.4/30",
		"12.234.248.8/29",
		"12.234.248.16/28",
		"12.234.248.32/27",
		"12.234.248.64/28",
		"12.234.248.80/29",
		"12.234.248.88/31",
		"12.234.248.90/32",
		"12.233.240.44/30",
		"12.233.240.48/28",
		"12.233.240.64/27",
		"12.233.240.96/28",
		"12.233.240.112/32",
		"12.234.128.16/28",
		"12.234.128.32/27",
		"12.234.128.64/26",
		"12.234.128.128/26",
		"12.234.128.192/27",
		"12.234.128.224/28",
		"12.234.128.240/29",
		"12.234.128.248/31",
		"12.234.129.16/28",
		"12.234.129.32/27",
		"12.234.129.64/26",
		"12.234.129.128/26",
		"12.234.129.192/27",
		"12.234.129.224/28",
		"12.234.129.240/29",
		"12.234.129.248/31",
		"12.234.130.16/28",
		"12.234.130.32/27",
		"12.234.130.64/26",
		"12.234.130.128/26",
		"12.234.130.192/27",
		"12.234.130.224/28",
		"12.234.130.240/29",
		"12.234.130.248/31",
		"12.234.131.16/28",
		"12.234.131.32/27",
		"12.234.131.64/26",
		"12.234.131.128/26",
		"12.234.131.192/27",
		"12.234.131.224/28",
		"12.234.131.240/29",
		"12.234.131.248/31",
		"12.234.132.16/28",
		"12.234.132.32/27",
		"12.234.132.64/26",
		"12.234.132.128/27",
		"12.234.132.160/28",
		"12.234.132.176/31",
		"12.234.132.178/32",
		"12.234.133.24/29",
		"12.234.133.32/27",
		"12.234.133.64/27",
		"12.234.133.96/28",
		"12.234.133.112/29",
		"12.234.133.120/32",
		"12.234.134.16/28",
		"12.234.134.32/27",
		"12.234.134.64/26",
		"12.234.134.128/27",
		"12.234.134.160/28",
		"12.234.134.176/32",
		"12.234.135.24/29",
		"12.234.135.32/27",
		"12.234.135.64/27",
		"12.234.135.96/28",
		"12.234.135.112/29",
		"12.234.135.120/32",
		"12.234.136.16/28",
		"12.234.136.32/27",
		"12.234.136.64/27",
		"12.234.136.96/28",
		"12.234.136.112/31",
		"12.234.136.114/32",
		"12.234.137.24/29",
		"12.234.137.32/27",
		"12.234.137.64/27",
		"12.234.137.96/28",
		"12.234.137.112/29",
		"12.234.137.120/32",
		"12.234.138.16/28",
		"12.234.138.32/27",
		"12.234.138.64/27",
		"12.234.138.96/28",
		"12.234.138.112/31",
		"12.234.138.114/32",
		"12.233.240.112/28",
		"12.233.240.128/26",
		"12.233.240.192/27",
		"12.233.240.224/28",
	}
)

// 和云平台结合起来的测试例所需常量定义
var (
	group    = []uint32{0, 10, 20, 30, 40, 50, 60, 70, 2, 3, 4, 11, 12, 13, 14, 15, 16, 17, 18, 19}
	groupEpc = []int32{0, 10, 20, 0, 40, 50, 0, 70, 40, 11, 12, 17}
	ipGroup6 = group[6] + IP_GROUP_ID_FLAG

	group1Ip1Net = "192.168.1.0/24"
	group1Ip2Net = "1234::abcd/128"
	group1Ip1    = NewIPFromString("192.168.1.10").Int()
	group1Ip2    = NewIPFromString("192.168.1.20").Int()
	group1Ip3    = NewIPFromString("102.168.33.22").Int()
	group1Mac    = NewMACAddrFromString("11:11:11:11:11:11").Int()
	group1Mac2   = NewMACAddrFromString("11:11:11:11:11:12").Int()

	group2Ip1Net = "10.30.1.0/24"
	group2Ip2Net = "abcd::1234/128"
	group2Ip1    = NewIPFromString("10.30.1.10").Int()
	group2Ip2    = NewIPFromString("10.30.1.20").Int()
	group2Mac    = NewMACAddrFromString("22:22:22:22:22:22").Int()

	group3Ip1      = NewIPFromString("192.168.20.112").Int() // group3/group4
	group3Ip2      = NewIPFromString("172.16.1.200").Int()   // group3/group4
	group3Ip3      = NewIPFromString("10.30.1.100").Int()    // group3
	group3Mac1     = NewMACAddrFromString("00:33:33:33:33:31").Int()
	ipGroup3IpNet1 = "10.25.1.2/24"
	ipGroup3IpNet2 = "10.30.1.2/24"
	ipGroup3IpNet3 = "192.168.20.112/32"

	group4Ip1      = NewIPFromString("192.168.20.112").Int() // group3/group4
	group4Ip2      = NewIPFromString("172.16.1.200").Int()   // group3/group4
	group4Mac1     = NewMACAddrFromString("00:44:44:44:44:41").Int()
	ipGroup4IpNet1 = "172.16.1.200/32"

	group5Ip1  = NewIPFromString("172.16.2.100").Int()
	group5Ip2  = NewIPFromString("10.33.1.10").Int()
	group5Mac1 = NewMACAddrFromString("55:55:55:55:55:51").Int()
	group5Mac2 = NewMACAddrFromString("55:55:55:55:55:52").Int()

	ipGroup5IpNet1 = "192.168.10.10/24" // ipGroup5/ipGroup6/ipGroup7
	ipGroup5IpNet2 = "10.33.1.10/32"
	ipGroup5IpNet3 = "172.16.2.100/32"
	ipGroup5Ip1    = NewIPFromString("192.168.10.10").Int()
	ipGroup5Ip2    = NewIPFromString("192.168.10.123").Int()
	ipGroup5Mac1   = NewMACAddrFromString("55:55:55:55:55:51").Int()

	ipGroup6IpNet1 = "192.168.10.10/24"  // ipGroup5/ipGroup6/ipGroup7
	ipGroup6IpNet2 = "192.168.20.112/32" // ipGroup6/ipGroup7
	ipGroup6IpNet3 = "192.168.20.100/32" // ipGroup6
	ipGroup6Ip1    = NewIPFromString("192.168.10.10").Int()
	ipGroup6Ip2    = NewIPFromString("192.168.20.112").Int()
	ipGroup6Ip3    = NewIPFromString("192.168.10.123").Int()
	ipGroup6Ip4    = NewIPFromString("192.168.20.100").Int()
	ipGroup6Mac1   = NewMACAddrFromString("66:66:66:66:66:61").Int()

	ipGroup7IpNet1 = "192.168.10.10/24"  // ipGroup5/ipGroup6/ipGroup7
	ipGroup7IpNet2 = "192.168.20.112/32" // ipGroup6/ipGroup7
	ipGroup7Ip1    = NewIPFromString("192.168.10.10").Int()
	ipGroup7Ip2    = NewIPFromString("192.168.20.112").Int()
	ipGroup7Ip3    = NewIPFromString("192.168.10.123").Int()
	ipGroup7Mac1   = NewMACAddrFromString("77:77:77:77:77:71").Int()
	ipGroup8IpNet1 = "1.1.1.0/24"
	ipGroup8IpNet2 = "1.1.2.0/24"
	ipGroup9IpNet  = "0.0.0.0/32"
	ipGroup10IpNet = "2002:abcd::123/128"
	ipGroup10Ip1   = net.ParseIP("2002:abcd::123")
	ipGroup11IpNet = "2002:abcd::124/128"
	ipGroup11Ip1   = net.ParseIP("2002:abcd::124")

	group16Ip1 = NewIPFromString("1.1.1.2").Int()

	testIp1  = NewIPFromString("10.30.1.21").Int()
	testMac1 = NewMACAddrFromString("ab:cd:11:11:11:11").Int()
	testIp2  = NewIPFromString("10.20.30.0").Int()
	testMac2 = NewMACAddrFromString("ab:cd:22:11:11:11").Int()
	testIp3  = NewIPFromString("10.10.0.0").Int()
	testMac3 = NewMACAddrFromString("ab:cd:33:11:11:11").Int()
	testIp4  = NewIPFromString("20.0.0.0").Int()
	testMac4 = NewMACAddrFromString("ab:cd:44:11:11:11").Int()
	queryIp  = NewIPFromString("20.30.1.100").Int()
)

type EndInfo struct {
	L2End0 bool
	L3End0 bool
	L2End1 bool
	L3End1 bool
}

type EpcInfo struct {
	L2EpcId0 int32
	L3EpcId0 int32
	L2EpcId1 int32
	L3EpcId1 int32
}

func generateEpcInfo(l2EpcId0, l3EpcId0, l2EpcId1, l3EpcId1 int32) *EpcInfo {
	basicData := &EpcInfo{
		L2EpcId0: l2EpcId0,
		L3EpcId0: l3EpcId0,
		L2EpcId1: l2EpcId1,
		L3EpcId1: l3EpcId1,
	}
	if l2EpcId0 < 0 {
		basicData.L2EpcId0 = 0
	}
	if l2EpcId1 < 0 {
		basicData.L2EpcId1 = 0
	}
	return basicData
}

func generateEndInfo(l2End0, l3End0, l2End1, l3End1 bool) *EndInfo {
	basicEnd := &EndInfo{
		L2End0: l2End0,
		L3End0: l3End0,
		L2End1: l2End1,
		L3End1: l3End1,
	}
	return basicEnd
}

func generateEndpointInfo(l2EpcId, l3EpcId int32, l2End, l3End bool, isDevice bool) *EndpointInfo {
	basicEndpointInfo := &EndpointInfo{
		L2EpcId:  l2EpcId,
		L2End:    l2End,
		L3EpcId:  l3EpcId,
		L3End:    l3End,
		IsDevice: isDevice,
	}
	if l2EpcId == EPC_FROM_INTERNET {
		basicEndpointInfo.L2EpcId = 0
	}
	return basicEndpointInfo
}

func generateIpNet6(ip net.IP, subnetId uint32, mask uint32) IpNet {
	ipInfo := IpNet{
		RawIp:    ip,
		SubnetId: subnetId,
		Netmask:  mask,
	}
	return ipInfo
}

func generateIpNet(ip uint32, subnetId uint32, mask uint32) IpNet {
	ipInfo := IpNet{
		RawIp:    IpFromUint32(ip).To4(),
		SubnetId: subnetId,
		Netmask:  mask,
	}
	return ipInfo
}

func generateIpGroup(groupId uint32, epcId int32, ip ...string) *IpGroupData {
	ipGroup := IpGroupData{
		Id:    groupId,
		EpcId: epcId,
	}
	ipGroup.Ips = append(ipGroup.Ips, ip...)
	return &ipGroup
}

func generatePlatformDataByIp(epcId int32, mac uint64, ip ...IpNet) PlatformData {
	data := PlatformData{
		EpcId: epcId,
		Mac:   mac,
		Ips:   ip,
	}
	return data
}

func generatePlatformDataExtension(epcId int32, ifType uint8, mac uint64) PlatformData {
	data := PlatformData{
		EpcId:  epcId,
		IfType: ifType,
		Mac:    mac,
	}
	return data
}

func generatePlatformDataByParam(ip uint32, mac uint64, epcId int32, Iftype uint8) PlatformData {
	ipInfo := generateIpNet(ip, 121, 32)
	vifData := generatePlatformDataExtension(epcId, Iftype, mac)
	vifData.Ips = append(vifData.Ips, ipInfo)
	return vifData
}

func generatePeerConnection(id uint32, src, dst int32) *PeerConnection {
	return &PeerConnection{
		Id:        id,
		LocalEpc:  src,
		RemoteEpc: dst,
	}
}

func generatePolicyAcl(table *PolicyTable, action NpbActions, aclID uint32, args ...interface{}) *Acl {
	var srcGroupId, dstGroupId uint32
	var proto uint16
	var port int

	for i, arg := range args {
		switch i {
		case 0:
			srcGroupId = arg.(uint32)
		case 1:
			dstGroupId = arg.(uint32)
		case 2:
			if netProto, ok := arg.(IPProtocol); ok {
				proto = uint16(netProto)
			} else {
				proto = uint16(arg.(int))
			}
		case 3:
			if _, ok := arg.(int); ok {
				port = arg.(int)
			} else {
				port = int(arg.(uint16))
			}
		}
	}

	srcGroups := make([]uint32, 0, 1)
	dstGroups := make([]uint32, 0, 1)
	dstPorts := make([]PortRange, 0, 1)
	if srcGroupId != 0 {
		srcGroups = append(srcGroups, srcGroupId)
	}
	if dstGroupId != 0 {
		dstGroups = append(dstGroups, dstGroupId)
	}
	if port >= 0 {
		dstPorts = append(dstPorts, NewPortRange(uint16(port), uint16(port)))
	} else if port < 0 {
		dstPorts = append(dstPorts, NewPortRange(0, 65535))
	}
	acl := &Acl{
		Id:           aclID,
		TapType:      TAP_CLOUD,
		SrcGroups:    srcGroups,
		DstGroups:    dstGroups,
		SrcPortRange: []PortRange{NewPortRange(0, 65535)},
		DstPortRange: dstPorts,
		Proto:        uint16(proto),
		NpbActions:   []NpbActions{action},
	}
	return acl
}

func generateLookupKey6(srcMac, dstMac uint64, srcIp, dstIp net.IP,
	proto IPProtocol, srcPort, dstPort uint16, flags ...FeatureFlags) *LookupKey {
	key := &LookupKey{
		SrcMac:      srcMac,
		DstMac:      dstMac,
		Src6Ip:      srcIp,
		Dst6Ip:      dstIp,
		Proto:       uint8(proto),
		SrcPort:     srcPort,
		DstPort:     dstPort,
		TapType:     TAP_CLOUD,
		FeatureFlag: NPM,
	}
	if len(flags) > 0 {
		key.FeatureFlag = flags[0]
	}
	return key
}

func generateLookupKey(srcMac, dstMac uint64, srcIp, dstIp uint32,
	proto IPProtocol, srcPort, dstPort uint16, flags ...FeatureFlags) *LookupKey {
	key := &LookupKey{
		SrcMac:      srcMac,
		DstMac:      dstMac,
		SrcIp:       srcIp,
		DstIp:       dstIp,
		Proto:       uint8(proto),
		SrcPort:     srcPort,
		DstPort:     dstPort,
		TapType:     TAP_CLOUD,
		FeatureFlag: NPM,
	}
	if len(flags) > 0 {
		key.FeatureFlag = flags[0]
	}
	return key
}

func toPcapAction(aclGid, id uint32, tunnelType, tapSide uint8, slice uint16) NpbActions {
	return ToNpbActions(aclGid, id, tunnelType, tapSide, slice)
}

func toNpbAction(aclGid, id uint32, tunnelType, tapSide uint8, slice uint16) NpbActions {
	return ToNpbActions(aclGid, id, tunnelType, tapSide, slice)
}

// 设置key的其他参数
func setEthTypeAndOthers(key *LookupKey, ethType EthernetType, ttl uint8, l2End0, l2End1 bool) *LookupKey {
	key.EthType = ethType
	if ttl == 128 || ttl == 64 || ttl == 255 {
		key.L3End0 = true
	}
	key.L2End0 = l2End0
	key.L2End1 = l2End1
	return key
}

func generateClassicLookupKey(srcMac, dstMac uint64, srcIp, dstIp uint32,
	srcPort, dstPort uint16, ethType EthernetType) *LookupKey {
	key := &LookupKey{
		SrcMac:      srcMac,
		DstMac:      dstMac,
		SrcIp:       srcIp,
		DstIp:       dstIp,
		SrcPort:     srcPort,
		DstPort:     dstPort,
		EthType:     ethType,
		TapType:     TAP_CLOUD,
		FeatureFlag: NPM,
	}
	return key
}

func (policy *PolicyTable) UpdateAcls(acl []*Acl) error {
	err := policy.UpdateAclData(acl)
	policy.EnableAclData()
	return err
}

// 生成特定IP资源组信息
func generateIpgroupData(policy *PolicyTable) {
	ipGroups := make([]*IpGroupData, 0, 3)
	// groupEpc[8] = groupEpc[4], group[8] != group[4]
	ipGroup1 := generateIpGroup(group[4], groupEpc[4], ipNet1)
	ipGroup2 := generateIpGroup(group[5], groupEpc[5], ipNet1)
	ipGroup3 := generateIpGroup(group[8], groupEpc[8], ipNet1)

	ipGroups = append(ipGroups, ipGroup1, ipGroup2, ipGroup3)
	policy.UpdateIpGroupData(ipGroups)
}

// 生成特定平台信息
func generatePlatformData(policy *PolicyTable) {
	// epcId:40 IfType:4
	datas := make([]PlatformData, 0, 2)
	vifData := generatePlatformDataByParam(ip4, mac4, groupEpc[4], 4)
	datas = append(datas, vifData)

	policy.UpdateInterfaceData(datas)
}

// 生成特定平台和资源组信息
func generatePolicyTable(ids ...TableID) *PolicyTable {
	policy := NewPolicyTable(1, 8, 1024, false, ids...)
	datas := make([]PlatformData, 0, 2)
	ipGroups := make([]*IpGroupData, 0, 3)
	connections := make([]*PeerConnection, 0, 8)

	ip1 := generateIpNet(group1Ip1, 121, 32)
	ip2 := generateIpNet(group1Ip2, 121, 32)
	ip3 := generateIpNet6(ip12, 121, 128)
	data1 := generatePlatformDataByIp(groupEpc[1], group1Mac, ip1, ip2, ip3)

	ip1 = generateIpNet(group1Ip3, 121, 32)
	data2 := generatePlatformDataByIp(EPC_FROM_DEEPFLOW, group1Mac2, ip1)

	ip1 = generateIpNet(group2Ip1, 122, 32)
	ip2 = generateIpNet(group2Ip2, 122, 32)
	ip3 = generateIpNet6(ip13, 122, 128)
	data3 := generatePlatformDataByIp(groupEpc[2], group2Mac, ip1, ip2, ip3)

	ip1 = generateIpNet(group2Ip1, 110, 32)
	data4 := generatePlatformDataByIp(groupEpc[10], mac5, ip1)
	data4.IfType = 4

	datas = append(datas, data1, data2, data3, data4)

	ip1 = generateIpNet(group3Ip1, 121, 24)
	ip2 = generateIpNet(group3Ip2, 121, 32)
	// group3无epc，group4有epc  ip:group3Ip1/group4Ip1 + group3Ip2/group4Ip2
	data5 := generatePlatformDataByIp(groupEpc[3], group3Mac1, ip1, ip2)

	ip1 = generateIpNet(group4Ip1, 121, 24)
	ip2 = generateIpNet(group4Ip2, 121, 32)
	data6 := generatePlatformDataByIp(groupEpc[4], group4Mac1, ip1, ip2)

	ip1 = generateIpNet(group5Ip1, 121, 24)
	ip2 = generateIpNet(group5Ip2, 121, 32)
	// group5有epc和无epc ip:group5Ip1 + group5Ip2
	data7 := generatePlatformDataByIp(groupEpc[5], group5Mac2, ip1, ip2)
	groupEpc[5] = groupEpcAny
	data8 := generatePlatformDataByIp(groupEpc[5], group5Mac1, ip1, ip2)
	datas = append(datas, data5, data6, data7, data8)

	policy.UpdateInterfaceData(datas)

	ipGroup1 := generateIpGroup(group[1], groupEpc[1], group1Ip1Net, group1Ip2Net)
	ipGroup2 := generateIpGroup(group[2], groupEpc[2], group2Ip1Net, group2Ip2Net)
	ipGroup3 := generateIpGroup(group[3], groupEpc[3], ipGroup3IpNet1, ipGroup3IpNet2, ipGroup3IpNet3)
	ipGroup4 := generateIpGroup(group[4], groupEpc[4], ipGroup4IpNet1)
	ipGroup5 := generateIpGroup(group[5], groupEpc[5], ipGroup5IpNet1, ipGroup5IpNet2, ipGroup5IpNet3)
	groupEpc[5] = 50
	ipGroup6 := generateIpGroup(group[6], groupEpc[6], ipGroup6IpNet1, ipGroup6IpNet2, ipGroup6IpNet3)
	ipGroup7 := generateIpGroup(group[7], groupEpc[7], ipGroup7IpNet1, ipGroup7IpNet2)
	ipGroup16 := generateIpGroup(group[16], groupEpc[1], group1Ip1Net, group2Ip1Net)
	ipGroup5.Type = 3
	ipGroup17 := generateIpGroup(group[17], groupEpc[0], ipGroup9IpNet)
	ipGroup10 := generateIpGroup(group[10], groupEpc[0], ipGroup10IpNet)
	ipGroup11 := generateIpGroup(group[11], groupEpc[0], ipGroup11IpNet)
	ipGroup18 := generateIpGroup(group[18], groupEpc[0], srcIp...)
	ipGroup19 := generateIpGroup(group[19], groupEpc[0], dstIp...)
	ipGroups = append(ipGroups, ipGroup1, ipGroup2, ipGroup3, ipGroup4,
		ipGroup5, ipGroup6, ipGroup7, ipGroup16, ipGroup17,
		ipGroup10, ipGroup11, ipGroup18, ipGroup19)

	policy.UpdateIpGroupData(ipGroups)

	// Peer Connection
	connection := generatePeerConnection(1, groupEpc[1], groupEpc[2])
	connections = append(connections, connection)
	policy.UpdatePeerConnection(connections)

	UpdateTunnelMaps([]uint16{10, 11, 12, 13, 20, 21, 22, 23, 30},
		[]uint16{10, 10, 10, 10, 20, 20, 20, 20, 30},
		[]net.IP{ip12, ip12, ip12, ip12, ip13, ip13, ip13, ip13, ip14})
	return policy
}

// 生成特定Acl规则
func generateAclData(policy *PolicyTable) {
	dstPorts := []uint16{0, 8000}
	action1 := toNpbAction(10, 0, NPB_TUNNEL_TYPE_PCAP, 0, 0)
	acl1 := generatePolicyAcl(policy, action1, 10, groupAny, groupAny, IPProtocolTCP, dstPorts[1])
	action2 := toNpbAction(20, 0, NPB_TUNNEL_TYPE_PCAP, 0, 0)
	acl2 := generatePolicyAcl(policy, action2, 20, groupAny, groupAny, IPProtocolTCP, dstPorts[0])
	policy.UpdateAcls([]*Acl{acl1, acl2})
}

func getEndpointData(table *PolicyTable, key *LookupKey) *EndpointData {
	endpoint := table.cloudPlatformLabeler.GetEndpointData(key)
	if endpoint != nil {
		store := &EndpointStore{}
		store.InitPointer(endpoint)
		endpoint = table.cloudPlatformLabeler.UpdateEndpointData(store, key)
	}
	return endpoint
}

func modifyEndpointDataL3End(table *PolicyTable, key *LookupKey, l3End0, l3End1 bool) *EndpointData {
	endpoint := table.cloudPlatformLabeler.GetEndpointData(key)
	if endpoint != nil {
		endpoint.SrcInfo.L3End = l3End0
		endpoint.DstInfo.L3End = l3End1
	}
	return endpoint
}

func getPolicyByFastPath(table *PolicyTable, key *LookupKey) (*EndpointData, *PolicyData) {
	policy := new(PolicyData)
	store := table.operator.GetPolicyByFastPath(key, policy)
	if store != nil {
		endpoint := table.cloudPlatformLabeler.UpdateEndpointData(store, key)
		return endpoint, policy
	}
	return nil, nil
}

func getPolicyByFirstPath(table *PolicyTable, endpoint *EndpointData, key *LookupKey) *PolicyData {
	policy := new(PolicyData)
	table.operator.GetPolicyByFirstPath(key, policy, endpoint)
	return policy
}

func CheckPolicyResult(t *testing.T, basicPolicy *PolicyData, targetPolicy *PolicyData) bool {
	if !reflect.DeepEqual(basicPolicy, targetPolicy) {
		t.Log("Result:", targetPolicy, "\n")
		t.Log("Expect:", basicPolicy, "\n")
		return false
	} else {
		return true
	}
}

func CheckEpcTestResult(t *testing.T, basicEpcInfo *EpcInfo, targetEndpointData *EndpointData) bool {
	if !((basicEpcInfo.L2EpcId0 == targetEndpointData.SrcInfo.L2EpcId) &&
		(basicEpcInfo.L3EpcId0 == targetEndpointData.SrcInfo.L3EpcId) &&
		(basicEpcInfo.L2EpcId1 == targetEndpointData.DstInfo.L2EpcId) &&
		(basicEpcInfo.L3EpcId1 == targetEndpointData.DstInfo.L3EpcId)) {
		t.Log("Result:", targetEndpointData, "\n")
		t.Log("Expect:", basicEpcInfo, "\n")
		return false
	} else {
		return true
	}
}

func CheckEndpointDataResult(t *testing.T, basicEndpointData *EndpointData, targetEndpointData *EndpointData) bool {
	if !(reflect.DeepEqual(basicEndpointData.SrcInfo, targetEndpointData.SrcInfo) &&
		reflect.DeepEqual(basicEndpointData.DstInfo, targetEndpointData.DstInfo)) {
		t.Log("ResultSrcInfo:", targetEndpointData.SrcInfo, "\n")
		t.Log("ExpectSrcInfo:", basicEndpointData.SrcInfo, "\n")
		t.Log("ResultDstInfo:", targetEndpointData.DstInfo, "\n")
		t.Log("ExpectDstInfo:", basicEndpointData.DstInfo, "\n")
		return false
	} else {
		return true
	}
}
