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
	"net"
	"sort"
	"strconv"
	"strings"
)

func IntArrayToString(array []int) string {
	str := ""
	for i, v := range array {
		if i == len(array)-1 {
			str += strconv.Itoa(v)
		} else {
			str += strconv.Itoa(v) + ","
		}
	}
	return str
}

func StringToIntArray(str string) []int {
	array := []int{}
	for _, v := range strings.Split(str, ",") {
		if v != "" {
			i, err := strconv.Atoi(v)
			if err == nil {
				array = append(array, i)
			}
		}
	}
	return array
}

func AreElementsSameInTwoArray[T string | int](array1, array2 []T) bool {
	if len(array1) != len(array2) {
		return false
	}
	sortedArray1 := array1
	sortedArray2 := array2
	sort.Slice(sortedArray1, func(i, j int) bool {
		return sortedArray1[i] > sortedArray1[j]
	})
	sort.Slice(sortedArray2, func(i, j int) bool {
		return sortedArray1[i] > sortedArray1[j]
	})
	for i := 0; i < len(sortedArray1); i++ {
		if sortedArray1[i] != sortedArray2[i] {
			return false
		}
	}
	return true
}

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
