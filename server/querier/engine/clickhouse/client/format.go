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
	//"errors"
	//"fmt"
	"math"
	"net"
	"time"
)

const (
	VALUE_TYPE_INT     = "Int"
	VALUE_TYPE_STRING  = "String"
	VALUE_TYPE_FLOAT64 = "Float64"
	VALUE_TYPE_TUPLE   = "Tuple"
	VALUE_TYPE_ARRAY   = "Array"
)

var VALUE_TYPE_MAP = map[string]int{
	VALUE_TYPE_INT:     0,
	VALUE_TYPE_STRING:  1,
	VALUE_TYPE_FLOAT64: 2,
}

func TransType(value interface{}, columnName, columnDatabaseTypeName string) (interface{}, string, error) {
	switch v := value.(type) {
	case *int8:
		return int(*v), VALUE_TYPE_INT, nil
	case *int16:
		return int(*v), VALUE_TYPE_INT, nil
	case *int32:
		return int(*v), VALUE_TYPE_INT, nil
	case *int64:
		return int(*v), VALUE_TYPE_INT, nil
	case **int8: // for nullable
		if *v == nil {
			return nil, VALUE_TYPE_INT, nil
		}
		return int(**v), VALUE_TYPE_INT, nil
	case **int16: // for nullable
		if *v == nil {
			return nil, VALUE_TYPE_INT, nil
		}
		return int(**v), VALUE_TYPE_INT, nil
	case **int32: // for nullable
		if *v == nil {
			return nil, VALUE_TYPE_INT, nil
		}
		return int(**v), VALUE_TYPE_INT, nil
	case **int64: // for nullable
		if *v == nil {
			return nil, VALUE_TYPE_INT, nil
		}
		return int(**v), VALUE_TYPE_INT, nil
	case *uint8:
		return int(*v), VALUE_TYPE_INT, nil
	case *uint16:
		return int(*v), VALUE_TYPE_INT, nil
	case *uint32:
		return int(*v), VALUE_TYPE_INT, nil
	case *uint64:
		return int(*v), VALUE_TYPE_INT, nil
	case **uint8: // for nullable
		if *v == nil {
			return nil, VALUE_TYPE_INT, nil
		}
		return int(**v), VALUE_TYPE_INT, nil
	case **uint16: // for nullable
		if *v == nil {
			return nil, VALUE_TYPE_INT, nil
		}
		return int(**v), VALUE_TYPE_INT, nil
	case **uint32: // for nullable
		if *v == nil {
			return nil, VALUE_TYPE_INT, nil
		}
		return int(**v), VALUE_TYPE_INT, nil
	case **uint64: // for nullable
		if *v == nil {
			return nil, VALUE_TYPE_INT, nil
		}
		return int(**v), VALUE_TYPE_INT, nil
	case *time.Time:
		return *v, VALUE_TYPE_STRING, nil
	case *net.IP:
		return *v, VALUE_TYPE_STRING, nil
	case **float64: // Nullable(float64)
		// NaN, Inf
		if *v == nil || math.IsNaN(**v) || **v == math.Inf(1) || **v == math.Inf(-1) {
			return nil, VALUE_TYPE_FLOAT64, nil
		}
		return **v, VALUE_TYPE_FLOAT64, nil
	case *float64:
		// NaN, Inf
		if math.IsNaN(*v) || *v == math.Inf(1) || *v == math.Inf(-1) {
			return nil, VALUE_TYPE_FLOAT64, nil
		}
		return *v, VALUE_TYPE_FLOAT64, nil
	case *string:
		return *v, VALUE_TYPE_STRING, nil
	case *[]int8:
		return *v, VALUE_TYPE_ARRAY, nil
	case *[]int16:
		return *v, VALUE_TYPE_ARRAY, nil
	case *[]int32:
		return *v, VALUE_TYPE_ARRAY, nil
	case *[]int64:
		return *v, VALUE_TYPE_ARRAY, nil
	case *[]uint8:
		return *v, VALUE_TYPE_ARRAY, nil
	case *[]uint16:
		return *v, VALUE_TYPE_ARRAY, nil
	case *[]uint32:
		return *v, VALUE_TYPE_ARRAY, nil
	case *[]uint64:
		return *v, VALUE_TYPE_ARRAY, nil
	case *[]time.Time:
		return *v, VALUE_TYPE_ARRAY, nil
	case *[]net.IP:
		return *v, VALUE_TYPE_ARRAY, nil
	case *[]float64:
		return *v, VALUE_TYPE_ARRAY, nil
	case *[]string:
		return *v, VALUE_TYPE_ARRAY, nil
	case **[]int8:
		if *v == nil {
			return nil, VALUE_TYPE_ARRAY, nil
		}
		return **v, VALUE_TYPE_ARRAY, nil
	case **[]int16:
		if *v == nil {
			return nil, VALUE_TYPE_ARRAY, nil
		}
		return **v, VALUE_TYPE_ARRAY, nil
	case **[]int32:
		if *v == nil {
			return nil, VALUE_TYPE_ARRAY, nil
		}
		return **v, VALUE_TYPE_ARRAY, nil
	case **[]int64:
		if *v == nil {
			return nil, VALUE_TYPE_ARRAY, nil
		}
		return **v, VALUE_TYPE_ARRAY, nil
	case **[]uint8:
		if *v == nil {
			return nil, VALUE_TYPE_ARRAY, nil
		}
		return **v, VALUE_TYPE_ARRAY, nil
	case **[]uint16:
		if *v == nil {
			return nil, VALUE_TYPE_ARRAY, nil
		}
		return **v, VALUE_TYPE_ARRAY, nil
	case **[]uint32:
		if *v == nil {
			return nil, VALUE_TYPE_ARRAY, nil
		}
		return **v, VALUE_TYPE_ARRAY, nil
	case **[]uint64:
		if *v == nil {
			return nil, VALUE_TYPE_ARRAY, nil
		}
		return **v, VALUE_TYPE_ARRAY, nil
	case **[]float64:
		if *v == nil {
			return nil, VALUE_TYPE_ARRAY, nil
		}
		return **v, VALUE_TYPE_ARRAY, nil
	case *[]interface{}:
		return *v, VALUE_TYPE_TUPLE, nil
	case *[][]interface{}:
		return *v, columnDatabaseTypeName, nil
	default:
		// unkown type field return origin type
		return value, columnDatabaseTypeName, nil
		//return nil, "", errors.New(fmt.Sprintf("Unknown db field with name %s, golang type %T, clickhouse type %s, value: %v (%v)",
		//	columnName, v, columnDatabaseTypeName, value, v))
	}
}
