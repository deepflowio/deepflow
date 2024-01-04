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
	"strings"

	"github.com/vishvananda/netlink"
)

func GetDefaultRouteIP() string {
	defaultRouteIP := "127.0.0.1"
	routeList, _ := netlink.RouteList(nil, netlink.FAMILY_V4)
	for _, route := range routeList {
		// a nil Dst means that this is the default route.
		if route.Dst == nil {
			i, err := net.InterfaceByIndex(route.LinkIndex)
			if err != nil {
				continue
			}
			addresses, _ := i.Addrs()
			for _, address := range addresses {
				defaultRouteIP = strings.Split(address.String(), "/")[0]
				break
			}
		}
	}
	return defaultRouteIP
}
