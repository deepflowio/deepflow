/**
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
	"fmt"
	"strconv"
	"strings"
)

func ParseRangePorts(rangePort string) ([]int, error) {
	if rangePort == "" {
		return []int{}, nil
	}

	portMap := map[int]bool{}
	rangePort = strings.ReplaceAll(rangePort, "，", ",")
	for _, portString := range strings.Split(rangePort, ",") {
		if portString == "" {
			continue
		}
		portString = strings.TrimSpace(portString)
		if strings.Contains(portString, "-") {
			bounds := strings.Split(portString, "-")
			if len(bounds) != 2 {
				return []int{}, fmt.Errorf("invalid exposed port (%s)", portString)
			}
			start, err := strconv.Atoi(bounds[0])
			if err != nil {
				return []int{}, fmt.Errorf("invalid exposed port (%s)", bounds[0])
			}
			end, err := strconv.Atoi(bounds[1])
			if err != nil {
				return []int{}, fmt.Errorf("invalid exposed port (%s)", bounds[1])
			}
			if start > end {
				start, end = end, start
			}
			for i := start; i <= end; i++ {
				portMap[i] = false
			}
		} else {
			port, err := strconv.Atoi(portString)
			if err != nil {
				return []int{}, fmt.Errorf("invalid exposed port (%s)", portString)
			}
			portMap[port] = false
		}
	}
	var ports []int
	for port := range portMap {
		ports = append(ports, port)
	}
	return ports, nil
}
