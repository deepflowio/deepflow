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

package client

import (
	"math"
	"net"
	"reflect"
	"time"
)

func TransType(value interface{}) interface{} {
	switch v := value.(type) {
	case *int8:
		return *v
	case *int16:
		return *v
	case *int32:
		return *v
	case *int64:
		return *v
	case **int8: // for nullable
		return *v
	case **int16: // for nullable
		return *v
	case **int32: // for nullable
		return *v
	case **int64: // for nullable
		return *v
	case *uint8:
		return *v
	case *uint16:
		return *v
	case *uint32:
		return *v
	case *uint64:
		return *v
	case **uint8: // for nullable
		return *v
	case **uint16: // for nullable
		return *v
	case **uint32: // for nullable
		return *v
	case **uint64: // for nullable
		return *v
	case *time.Time:
		return *v
	case *net.IP:
		return *v
	case **float64: // Nullable(float64)
		// NaN, Inf
		if *v == nil || math.IsNaN(**v) || **v == math.Inf(1) || **v == math.Inf(-1) {
			var val *float64
			return val
		}
		return *v
	case *float64:
		// NaN, Inf
		if math.IsNaN(*v) || *v == math.Inf(1) || *v == math.Inf(-1) {
			var val float64
			return val
		}
		return *v
	case *string:
		return *v
	case *[]int8:
		return *v
	case *[]int16:
		return *v
	case *[]int32:
		return *v
	case *[]int64:
		return *v
	case *[]uint8:
		return *v
	case *[]uint16:
		return *v
	case *[]uint32:
		return *v
	case *[]uint64:
		return *v
	case *[]time.Time:
		return *v
	case *[]net.IP:
		return *v
	case *[]float64:
		return *v
	case *[]string:
		return *v
	case **[]int8:
		return *v
	case **[]int16:
		return *v
	case **[]int32:
		return *v
	case **[]int64:
		return *v
	case **[]uint8:
		return *v
	case **[]uint16:
		return *v
	case **[]uint32:
		return *v
	case **[]uint64:
		return *v
	case **[]float64:
		return *v
	case *[]interface{}:
		return *v
	case *[][]interface{}:
		return *v
	default:
		// unkown type field
		refValue := reflect.ValueOf(value)
		elemValue := refValue.Elem()
		realValue := elemValue.Interface()
		return realValue
	}
}
