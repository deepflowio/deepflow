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
	"github.com/op/go-logging"
	"github.com/prometheus/prometheus/prompb"
)

var log = logging.MustGetLogger("prometheus.cache")

type CacheHit int

const (
	CacheMiss CacheHit = iota
	CacheHitPart
	CacheHitFull
	CacheKeyNotFound
	CacheKeyFoundNil
)

// start time & end time align to 0 second
// e.g.: query 13s-117s, cache 0s-120s
func timeAlign(startSeconds int64) int64 {
	return startSeconds - startSeconds%60
}

func GetPromRequestQueryTime(q *prompb.Query) (int64, int64) {
	// remind that we storage seconds for prometheus samples
	// if the sample storage changes to milliseconds, it shoudld remove `/1000` here
	endTime := q.Hints.EndMs / 1000
	// if endTime is not multiple of 1000, add 1 for endTime for data points outside end
	if q.Hints.EndMs%1000 > 0 {
		endTime += 1
	}
	return q.Hints.StartMs / 1000, endTime
}

func promRequestToCacheKey(q *prompb.Query) (string, string) {
	matcher := &strings.Builder{}
	var metric string
	for i := 0; i < len(q.Matchers); i++ {
		matcher.WriteString(q.Matchers[i].GetName() + q.Matchers[i].Type.String() + q.Matchers[i].GetValue())
		matcher.WriteByte('-')

		if q.Matchers[i].Name == "__name__" {
			metric = q.Matchers[i].Value
		}
	}
	return matcher.String(), metric
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
