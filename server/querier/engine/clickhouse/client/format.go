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

const (
	VALUE_TYPE_INT     = "Int"
	VALUE_TYPE_STRING  = "String"
	VALUE_TYPE_FLOAT64 = "Float64"
)

var VALUE_TYPE_MAP = map[string]int{
	VALUE_TYPE_INT:     0,
	VALUE_TYPE_STRING:  1,
	VALUE_TYPE_FLOAT64: 2,
}

func TransType(typeName string, value interface{}) (interface{}, string, error) {
	switch typeName {
	case "Int8":
		return int(value.(int8)), VALUE_TYPE_INT, nil
	case "Int16":
		return int(value.(int16)), VALUE_TYPE_INT, nil
	case "Int32":
		return int(value.(int32)), VALUE_TYPE_INT, nil
	case "Int64":
		return int(value.(int64)), VALUE_TYPE_INT, nil
	case "UInt8":
		return int(value.(uint8)), VALUE_TYPE_INT, nil
	case "UInt16":
		return int(value.(uint16)), VALUE_TYPE_INT, nil
	case "UInt64":
		return int(value.(uint64)), VALUE_TYPE_INT, nil
	case "UInt32":
		return int(value.(uint32)), VALUE_TYPE_INT, nil
	case "DateTime":
		return value.(time.Time).String(), VALUE_TYPE_STRING, nil
	case "IPv4", "IPv6":
		return value.(net.IP).String(), VALUE_TYPE_STRING, nil
	case "Float64":
		// NaN, Inf
		if math.IsNaN(value.(float64)) || value.(float64) == math.Inf(1) || value.(float64) == math.Inf(-1) {
			return nil, VALUE_TYPE_FLOAT64, nil
		}
		return value.(float64), VALUE_TYPE_FLOAT64, nil
	case "LowCardinality(String)":
		return value.(string), VALUE_TYPE_STRING, nil
	default:
		return value, typeName, nil
	}
}
