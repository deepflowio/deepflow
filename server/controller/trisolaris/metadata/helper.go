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

package metadata

import (
	"net"
	"strings"
)

func netmask2masklen(netmask string) (length int) {
	ipNet := net.ParseIP(netmask)
	if ipNet.To4() != nil {
		stringMask := net.IPMask(ipNet.To4())
		length, _ = stringMask.Size()
	} else if ipNet.To16() != nil {
		stringMask := net.IPMask(ipNet.To16())
		length, _ = stringMask.Size()
	}
	return
}

func judgeNet(prefix string, netmask int) bool {
	if prefix == "" || netmask == 0 {
		return false
	}
	if prefix == "0.0.0.0" && netmask == 32 {
		return false
	} else if prefix == "::" && netmask == 128 {
		return false
	}

	return true
}

func ConvertToCIDR(ips []string) {
	for index, _ := range ips {
		if strings.Contains(ips[index], "/") {
			continue
		} else if strings.Contains(ips[index], ":") {
			ips[index] = ips[index] + "/128"
		} else {
			ips[index] = ips[index] + "/32"
		}
	}
}
