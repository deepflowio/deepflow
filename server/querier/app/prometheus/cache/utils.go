/*
 * Copyright (c) 2023 Yunshan Networks
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

package cache

import (
	"reflect"
	"strings"
	"unsafe"

	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/prometheus/prometheus/prompb"
)

type CacheHit int

const (
	CacheMiss CacheHit = iota
	CacheHitPart
	CacheHitFull
)

// start time & end time align to 0 second
// e.g.: query 13s-117s, cache 0s-120s
func timeAlign(startMs int64) int64 {
	return startMs - startMs%60000
}

func promRequestToCacheKey(q *prompb.Query) (string, string, int64, int64) {
	matcher := &strings.Builder{}
	var metric string
	for i := 0; i < len(q.Matchers); i++ {
		matcher.WriteString(q.Matchers[i].GetName() + q.Matchers[i].Type.String() + q.Matchers[i].GetValue())
		matcher.WriteByte('-')

		if q.Matchers[i].Name == "__name__" {
			metric = q.Matchers[i].Value
		}
	}
	return matcher.String(), metric, q.Hints.StartMs, q.Hints.EndMs
}

func unsafeSize(d *common.Result) uint64 {
	if d == nil || len(d.Values) == 0 {
		return 0
	}
	v1 := d.Values[0].([]interface{})
	var size uintptr
	if v1 != nil {
		for i := 0; i < len(v1); i++ {
			// for slice/array: calcute size of every element
			// for string: add len(string)
			// for others: only add sizeof(v) now
			c := reflect.Indirect(reflect.ValueOf(v1[i]))
			switch c.Kind() {
			case reflect.Slice:
				if c.Len() > 0 {
					size += unsafe.Sizeof(c.Index(0)) * uintptr(c.Len())
				}
			case reflect.Array:
				if c.Len() > 0 {
					size += unsafe.Sizeof(c.Index(0)) * uintptr(c.Len())
				}
			case reflect.String:
				size += uintptr(len(c.String()))
			default:
				size += unsafe.Sizeof(v1[i])
			}
		}
	}
	// d.values would have the same structure, so simply just sizeof(0)*len(value) would probably equals real size(not 100% exactly)
	return uint64(size) * uint64(len(d.Values))
}
