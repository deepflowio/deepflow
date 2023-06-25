/**
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

package encoder

import (
	"errors"
	"fmt"
	"sort"

	mapset "github.com/deckarep/golang-set/v2"
)

type idAllocator struct {
	resourceType    string
	max             int
	usableIDs       []int
	rawDataProvider rawDataProvider
}

func (ia *idAllocator) refresh() error {
	log.Infof("refresh %s id pools started", ia.resourceType)
	inUseIDsSet, err := ia.rawDataProvider.load()
	if err != nil {
		return err
	}
	allIDsSet := mapset.NewSet[int]()
	for i := 1; i <= ia.max; i++ {
		allIDsSet.Add(i)
	}
	// 可用ID = 所有ID（1~max）- db中正在使用的ID
	// 排序原则：大于db正在使用的max值的ID（未曾被使用过的ID）优先，小于db正在使用的max值的ID（已被使用过且已回收的ID）在后
	var usableIDs []int
	if inUseIDsSet.Cardinality() != 0 {
		inUseIDs := inUseIDsSet.ToSlice()
		sort.IntSlice(inUseIDs).Sort()
		maxInUseID := inUseIDs[len(inUseIDs)-1]

		usableIDsSet := allIDsSet.Difference(inUseIDsSet)
		usedIDs := []int{}
		usableIDs = usableIDsSet.ToSlice()
		sort.IntSlice(usableIDs).Sort()
		for _, id := range usableIDs {
			if id < maxInUseID {
				usedIDs = append(usedIDs, id)
				usableIDsSet.Remove(id)
			} else {
				break
			}
		}
		usableIDs = usableIDsSet.ToSlice()
		sort.IntSlice(usableIDs).Sort()
		sort.IntSlice(usedIDs).Sort()
		usableIDs = append(usableIDs, usedIDs...)
	} else {
		usableIDs = allIDsSet.ToSlice()
		sort.IntSlice(usableIDs).Sort()
	}
	ia.usableIDs = usableIDs

	log.Infof("refresh %s id pools (usable ids count: %d) completed", ia.resourceType, len(ia.usableIDs))
	return nil
}

// 批量分配ID，若ID池中数量不足，分配ID池所有ID；反之分配指定个数ID。
// 分配的ID中，若已有被实际使用的ID（闭源页面创建使用），排除已使用ID，仅分配剩余部分。
func (ia *idAllocator) allocate(count int) (ids []int, err error) {
	if len(ia.usableIDs) == 0 {
		return nil, errors.New(fmt.Sprintf("%s has no more usable ids", ia.resourceType))
	}

	if len(ia.usableIDs) < count {
		return nil, errors.New(fmt.Sprintf("%s has no more usable ids", ia.resourceType))
	}
	ids = make([]int, count)
	copy(ids, ia.usableIDs[:count])

	inUseIDs, err := ia.rawDataProvider.check(ids)
	if err != nil {
		return
	}
	if len(inUseIDs) != 0 {
		return nil, errors.New(fmt.Sprintf("%s some ids are in use", ia.resourceType))
	}
	log.Infof("allocate %s ids: %v (expected count: %d, true count: %d)", ia.resourceType, ids, count, len(ids))
	ia.usableIDs = ia.usableIDs[count:]
	return
}

type rawDataProvider interface {
	load() (mapset.Set[int], error)
	check([]int) ([]int, error)
}
