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
	"reflect"
	"strconv"
	"strings"
	"sync"
)

// typeCache 缓存类型的基本大小，避免重复计算
var typeCache sync.Map

// GetVarSize 计算任意变量的内存占用大小
// 对于复杂类型（如 struct、slice、map 等），会递归计算其字段或元素的大小
// 对于指针类型，会检测循环引用
func GetVarSize(val any) uint64 {
	return getVarSizeInternal(val, make(map[uintptr]bool))
}

func getVarSizeInternal(val any, visited map[uintptr]bool) uint64 {
	if val == nil {
		return 0
	}

	vl := reflect.ValueOf(val)
	tp := reflect.TypeOf(val)

	// 处理基本类型
	switch vl.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8,
		reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr, reflect.Float32, reflect.Float64, reflect.Complex64,
		reflect.Complex128:
		return uint64(tp.Size())
	case reflect.String:
		// 对于字符串，直接返回其长度加上字符串头的大小
		return uint64(tp.Size()) + uint64(vl.Len())

	case reflect.Map:
		if vl.IsNil() {
			return uint64(tp.Size())
		}

		// 获取或计算 map 每个 bucket 的基本大小
		var mapSize uint64
		bucketSize, ok := typeCache.Load(tp)
		if !ok {
			// map 的基本大小加上每个 bucket 的预估大小
			// Go 的 map 实现中，每个 bucket 可以存储最多 8 个键值对
			mapSize = uint64(tp.Size()) + 8*(uint64(tp.Key().Size())+uint64(tp.Elem().Size()))
			typeCache.Store(tp, mapSize)
		} else {
			// 安全的类型断言
			if size, ok := bucketSize.(uint64); ok {
				mapSize = size
			} else {
				// 如果类型断言失败，重新计算
				mapSize = uint64(tp.Size()) + 8*(uint64(tp.Key().Size())+uint64(tp.Elem().Size()))
				typeCache.Store(tp, mapSize)
			}
		}

		forSize := mapSize

		// 计算所有键值对的实际大小
		for _, key := range vl.MapKeys() {
			forSize += getVarSizeInternal(key.Interface(), visited) +
				getVarSizeInternal(vl.MapIndex(key).Interface(), visited)
		}
		return forSize

	case reflect.Array, reflect.Slice:
		if vl.IsNil() {
			return uint64(tp.Size())
		}

		// 获取或计算元素类型的基本大小
		var elemSize uint64
		cachedSize, ok := typeCache.Load(tp.Elem())
		if !ok {
			elemSize = uint64(tp.Elem().Size())
			typeCache.Store(tp.Elem(), elemSize)
		} else {
			// 安全的类型断言
			if size, ok := cachedSize.(uint64); ok {
				elemSize = size
			} else {
				// 如果类型断言失败，重新计算
				elemSize = uint64(tp.Elem().Size())
				typeCache.Store(tp.Elem(), elemSize)
			}
		}

		forSize := uint64(tp.Size())

		// 对于 slice，计算底层数组的容量占用
		if vl.Kind() == reflect.Slice {
			forSize += uint64(vl.Cap()) * elemSize
		}

		// 计算每个元素的实际大小
		if tp.Elem().Kind() == reflect.Uint8 {
			// 对于 []byte 类型特殊处理，避免逐字节计算
			return forSize
		}

		for i := 0; i < vl.Len(); i++ {
			if elemVal := vl.Index(i); elemVal.CanInterface() {
				forSize += getVarSizeInternal(elemVal.Interface(), visited)
			}
		}
		return forSize

	case reflect.Chan:
		// channel 只计算其本身的大小，不计算缓冲区
		return uint64(tp.Size())
	case reflect.Func:
		return uint64(tp.Size())

	case reflect.Interface, reflect.Pointer:
		forSize := uint64(tp.Size())
		if vl.IsNil() {
			return forSize
		}

		// 检查循环引用
		ptr := vl.Pointer()
		if visited[ptr] {
			return 0
		}
		visited[ptr] = true
		defer delete(visited, ptr)

		return forSize + getVarSizeInternal(vl.Elem().Interface(), visited)

	case reflect.Struct:
		forSize := uint64(tp.Size())

		// 特殊处理 time.Time 类型
		if tp.Name() == "Time" && tp.PkgPath() == "time" {
			return forSize + 24 // time.Time 的基本大小
		}

		for i := 0; i < vl.NumField(); i++ {
			tpField := tp.Field(i)
			vlField := vl.Field(i)

			// 处理不可导出字段
			if !tpField.IsExported() {
				forSize += uint64(vlField.Type().Size())
				continue
			}

			// 处理无法获取接口的字段
			if !vlField.CanInterface() {
				forSize += uint64(vlField.Type().Size())
				continue
			}

			// 处理特殊类型的字段
			switch vlField.Kind() {
			case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.UnsafePointer,
				reflect.Interface, reflect.Slice:
				if vlField.IsNil() {
					forSize += uint64(vlField.Type().Size())
					continue
				}
			}

			forSize += getVarSizeInternal(vlField.Interface(), visited)
		}
		return forSize
	case reflect.UnsafePointer:
		forSize := uint64(tp.Size())
		return forSize
	default:
		log.Debugf("Unsupported kind %v for type %T, size=%d", vl.Kind(), val, uint64(tp.Size()))
		return uint64(tp.Size())
	}
}

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
