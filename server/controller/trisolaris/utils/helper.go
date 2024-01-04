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

package utils

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/vishvananda/netlink"
)

type ctxKeyWaitGroup struct{}

func GetWaitGroupInCtx(ctx context.Context) *sync.WaitGroup {
	if wg, ok := ctx.Value(ctxKeyWaitGroup{}).(*sync.WaitGroup); ok {
		return wg
	}

	return nil
}

func NewWaitGroupCtx() (context.Context, context.CancelFunc) {
	return context.WithCancel(context.WithValue(context.Background(), ctxKeyWaitGroup{}, new(sync.WaitGroup)))
}

type Number interface {
	~int | ~string | uint32
}

func SliceEqual[T Number](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}

	if (a == nil) != (b == nil) {
		return false
	}

	for i, v := range a {
		if v != b[i] {
			return false
		}
	}

	return true
}

func Find[T Number](slice []T, val T) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

func ConvertStrToU32List(convertStr string) ([]uint32, error) {
	if len(convertStr) == 0 {
		return []uint32{}, nil
	}
	splitStr := strings.Split(convertStr, ",")
	result := make([]uint32, len(splitStr), len(splitStr))
	for index, src := range splitStr {
		target, err := strconv.Atoi(src)
		if err != nil {
			return []uint32{}, err
		} else {
			result[index] = uint32(target)
		}
	}

	return result, nil
}

func MaxTime(t1 time.Time, t2 time.Time) time.Time {
	if t1.After(t2) {
		return t1
	} else {
		return t2
	}
}

func MacStrToU64(mac string) (uint64, error) {
	fn := func(c rune) rune {
		if strings.ContainsRune(" .:-", c) {
			return -1
		} else {
			return c
		}
	}
	mapStr := strings.Map(fn, mac)
	n, err := strconv.ParseUint(string(mapStr), 16, 0)
	if err != nil {
		return 0, err
	}

	return uint64(n), nil
}

func Lookup(host net.IP) (net.IP, error) {
	routes, err := netlink.RouteGet(host)
	if err != nil {
		return nil, fmt.Errorf("RouteGet %v %s", host, err)
	}
	route := routes[0]
	src := route.Src
	if route.Src.To4() != nil {
		src = route.Src.To4()
	}
	return src, nil
}

func IsVMofBMHtype(htype int) bool {
	if Find[int]([]int{common.VM_HTYPE_BM_C, common.VM_HTYPE_BM_N, common.VM_HTYPE_BM_S}, htype) == true {
		return true
	}
	return false
}
