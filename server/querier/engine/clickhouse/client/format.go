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

package client

import (
	"math"
	"net"
	"time"
)

func TransType(typeName string, value interface{}) (interface{}, error) {
	switch typeName {
	case "UInt64":
		return int(value.(uint64)), nil
	case "UInt32":
		return int(value.(uint32)), nil
	case "DateTime":
		return value.(time.Time).String(), nil
	case "IPv4", "IPv6":
		return value.(net.IP).String(), nil
	case "Float64":
		// NaN, Inf
		if math.IsNaN(value.(float64)) || value.(float64) == math.Inf(1) || value.(float64) == math.Inf(-1) {
			return nil, nil
		}
		return value.(float64), nil
	default:
		return value, nil
	}
}
