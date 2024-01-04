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

package common

import (
	"net"
)

func CIDRToPreNetMask(cidr string) (string, string, error) {
	var prefix string
	var netmask string
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return prefix, netmask, err
	}
	prefix = ip.String()
	netmask = net.IP(ipNet.Mask).String()
	return prefix, netmask, err
}

func FormatIP(ip string) string {
	i := net.ParseIP(ip)
	if i == nil {
		return ""
	}
	return i.String()
}
